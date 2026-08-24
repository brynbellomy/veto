// Package pypa implements intel.Source for the Python Packaging Authority's
// advisory database at https://github.com/pypa/advisory-database.
//
// Why add PyPA when OSV already mirrors it: OSV's bulk-export aggregator
// can lag the upstream by hours or days. A direct PyPA pull catches the
// freshest MAL-* entries and gives independent verification — if PyPA
// flags a package and OSV hasn't picked it up yet, we still refuse.
//
// Fetch model: download the main-branch tarball from GitHub, walk it
// for `vulns/*/*.yaml` (the per-advisory files), parse each as OSV
// schema, filter to malware (MAL-* IDs). Same caching shape as the
// OSV/Aikido/OpenSSF sources — etag-conditional GET, on-disk fallback
// when upstream is unreachable.
//
// Coverage is PyPI-only by design. PyPA does not publish advisories for
// other ecosystems; Fetch returns intel.ErrUnsupportedEcosystem for
// anything else.
package pypa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/osvschema"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	// defaultBaseURL is the tarball endpoint. GitHub redirects this to a
	// codeload.github.com URL with the actual gzip stream.
	defaultBaseURL = "https://github.com/pypa/advisory-database/archive/refs/heads/main.tar.gz"
	sourceID       = "pypa"

	// maxAdvisoryBytes guards against a malicious oversized YAML entry
	// hanging the parser. Real advisories are <10 KB; 1 MB is a generous
	// safety cap.
	maxAdvisoryBytes = 1 << 20

	// maxFeedBytes caps the whole-tarball download. PyPA's advisory-db
	// archive sits in the low-tens-of-MB range today; 512 MiB leaves
	// growth room while bounding a compromised upstream that streams a
	// multi-GB body. Paired with io.LimitReader+1 truncation detection.
	maxFeedBytes = 512 << 20

	// staleCacheThreshold mirrors the aikido source: warn loudly when
	// we serve from a cache file older than this on the network-fail
	// fallback path.
	staleCacheThreshold = 24 * time.Hour
)

// Options configures the PyPA source.
type Options struct {
	// URL overrides the tarball URL. Defaults to the main-branch tarball
	// on github.com/pypa/advisory-database.
	URL string

	// CacheDir is where the fetched tarball + etag persist between runs.
	// Required; typically ~/.cache/veto/pypa.
	CacheDir string

	// HTTPClient defaults to a 2-minute-timeout client. The tarball is
	// ~5 MB compressed; 2m headroom covers slow links and follow
	// redirects.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the PyPA advisory-db implementation of intel.Source.
type Source struct {
	url    string
	cache  string
	client *http.Client
	logger zerolog.Logger

	// sweepOnce bounds the orphan-temp sweep to one pass per process. This
	// is a COST guard, not a correctness lock: the sweep's safety comes
	// from the 24h age threshold (a live writer's temp can never be that
	// old), so concurrent processes sweeping the same directory are safe.
	sweepOnce sync.Once
}

var _ intel.Source = (*Source)(nil)

// New builds a PyPA source. CacheDir is required.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("pypa: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "pypa: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "pypa: tighten cache dir perms").Set("path", opts.CacheDir)
	}
	url := opts.URL
	if url == "" {
		url = defaultBaseURL
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	return &Source{
		url:    url,
		cache:  opts.CacheDir,
		client: client,
		logger: opts.Logger.With().Str("component", "intel.pypa").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. Returns ErrUnsupportedEcosystem for
// anything other than PyPI — PyPA does not publish advisories outside
// its own ecosystem.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemPyPI {
		return nil, intel.ErrUnsupportedEcosystem
	}

	// Hygiene, not a gate: drop download temps this source's own dead runs
	// left behind. Non-fatal by contract (see fsutil.SweepOrphanTemps);
	// once per process keeps it off the per-ecosystem hot path.
	s.sweepOnce.Do(s.sweepOrphanTemps)

	tarballPath := filepath.Join(s.cache, "advisory-database.tar.gz")
	etagPath := filepath.Join(s.cache, "advisory-database.etag")
	payload, err := s.fetchWithCache(ctx, tarballPath, etagPath)
	if err != nil {
		return nil, errors.With(err, "pypa fetch")
	}
	reports, err := parseTarball(payload, s.logger)
	if err != nil {
		// Drop the pending etag so it isn't promoted; also drop the
		// canonical etag so the next refresh re-downloads instead of
		// 304-looping on the broken payload. The content-hash sidecar
		// goes too — the bytes are what we stored, but they're not
		// parseable, and a future fetch must not treat them as
		// validated-good.
		if rmErr := os.Remove(etagPath + ".pending"); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag.pending after parse failure")
		}
		if rmErr := os.Remove(etagPath); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		fsutil.RemovePayloadHash(tarballPath)
		return nil, err
	}
	// Phase 1.9: parse succeeded — promote the pending etag.
	if _, statErr := os.Stat(etagPath + ".pending"); statErr == nil {
		if mvErr := os.Rename(etagPath+".pending", etagPath); mvErr != nil {
			s.logger.Warn().Err(mvErr).Msg("commit etag")
		}
	}
	return reports, nil
}

// fetchWithCache mirrors the aikido source's logic: etag-conditional
// GET, fall back to on-disk cache on network failure. Kept in this file
// rather than abstracted because each source's failure-mode policy
// differs slightly (which 3xx/4xx is treated as "stale OK" etc.) and
// abstracting too early would make those differences harder to spot.
//
// The 304-with-missing-cache fallback is bounded to a single retry —
// see the aikido source for the same pattern and rationale.
func (s *Source) fetchWithCache(ctx context.Context, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, payloadPath, etagPath, true)
}

func (s *Source) fetchWithCacheBounded(ctx context.Context, payloadPath, etagPath string, retryAllowed bool) ([]byte, error) {
	prevEtag, _ := os.ReadFile(etagPath)

	// Cache-integrity gate: the etag names the upstream representation,
	// not the bytes on disk. A hash mismatch downgrades this fetch to a
	// cache miss so the 200 path re-downloads and re-records. Unrecorded
	// (pre-integrity-fix cache) stays a conditional GET; the 200 path
	// writes the sidecar on the next body.
	//
	// This MUST be computed before the cache-only directive below. Serving
	// from disk without consulting it is the whole vulnerability.
	hashVerdict := fsutil.PayloadHashVerdict(payloadPath)

	// Cache-only directive: the caller's freshness window says the advisory
	// set was fetched moments ago, so serve the on-disk tarball without a
	// network round-trip. No usable cache falls through to the normal path —
	// the directive is an optimization, never a correctness gate.
	//
	// Two rules make it safe, and both are easy to lose in a merge:
	//
	//  1. A HashMismatch does NOT short-circuit. It falls through to the
	//     network path, which re-downloads and re-records — or, if upstream
	//     is unreachable, fails closed with ErrDamagedCache below. A
	//     freshness window saying "we fetched recently" is not evidence that
	//     the bytes on disk are the bytes we fetched.
	//  2. HashUnrecorded (a pre-integrity-fix cache) is served but NEVER
	//     adopted here. The adoption path exists only under a live 304,
	//     where upstream confirmed the etag names these bytes. Under
	//     cache-only nothing confirms anything, so recording a hash now
	//     would bless whatever happens to be on disk — laundering existing
	//     damage into "verified" and permanently blinding this gate. The
	//     persistent per-source baseline is the backstop for that case.
	if intel.CacheOnly(ctx) && hashVerdict != fsutil.HashMismatch {
		if cached, err := os.ReadFile(payloadPath); err == nil {
			if hashVerdict == fsutil.HashUnrecorded {
				s.logger.Warn().
					Str("payload_path", payloadPath).
					Msg("serving pre-integrity cache under cache-only directive; not adopting its hash without upstream validation")
			}
			return cached, nil
		}
	}
	if hashVerdict == fsutil.HashMismatch && len(prevEtag) > 0 {
		s.logger.Warn().
			Str("payload_path", payloadPath).
			Msg("cached tarball failed content-hash verification; forcing full refetch")
		prevEtag = nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, errors.With(err, "build request")
	}
	if len(prevEtag) > 0 {
		req.Header.Set("If-None-Match", string(prevEtag))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// Network failure — the integrity gate applies more strictly here:
		// with no network there is no way to repair a damaged payload, and
		// serving it would silently reduce this source's coverage.
		// Mismatch → fail closed with ErrDamagedCache.
		if hashVerdict == fsutil.HashMismatch {
			return nil, errors.With(intel.ErrDamagedCache, "cached tarball is damaged and upstream is unreachable").
				Set("url", s.url).Set("payload_path", payloadPath)
		}
		if cached, readErr := os.ReadFile(payloadPath); readErr == nil {
			logEvt := s.logger.Warn().Err(err).Str("url", s.url)
			if stat, statErr := os.Stat(payloadPath); statErr == nil {
				age := time.Since(stat.ModTime())
				logEvt = logEvt.Dur("cache_age", age)
				if age > staleCacheThreshold {
					logEvt = logEvt.Bool("cache_stale", true)
				}
			}
			logEvt.Msg("upstream unreachable, using cached tarball")
			return cached, nil
		}
		return nil, errors.With(err, "http request")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		cached, err := os.ReadFile(payloadPath)
		if err != nil {
			if !retryAllowed {
				return nil, errors.With(err, "304 with missing cache after retry").
					Set("url", s.url).Set("payload_path", payloadPath)
			}
			s.logger.Warn().Err(err).Msg("304 received but cached tarball missing; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchWithCacheBounded(ctx, payloadPath, etagPath, false)
		}
		// The 304 validated the etag; re-verify the payload hash now so a
		// damaged or grandfathered-Unrecorded payload cannot ride a 304.
		// Mismatch → drop the etag and refetch ONCE.
		switch fsutil.PayloadHashVerdict(payloadPath) {
		case fsutil.HashMismatch:
			if !retryAllowed {
				return nil, errors.With(intel.ErrDamagedCache, "304 validated etag but cached tarball is damaged").
					Set("url", s.url).Set("payload_path", payloadPath)
			}
			s.logger.Warn().
				Str("payload_path", payloadPath).
				Msg("304 validated etag but cached tarball failed content-hash verification; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchWithCacheBounded(ctx, payloadPath, etagPath, false)
		case fsutil.HashUnrecorded:
			// FIX 1: a live 304 validates the ETAG, not the bytes on
			// disk. An Unrecorded sidecar means nothing binds this payload
			// (crash between WriteAtomic and RecordPayloadHash, a deleted
			// sidecar, or a pre-sidecar cache), so adopting the on-disk
			// bytes now would bless whatever happens to be there -- gutted
			// bytes would read HashMatch forever after. Treat Unrecorded
			// exactly like Mismatch: drop the etag and refetch, so only
			// bytes read off the wire in THIS request ever get bound.
			if !retryAllowed {
				return nil, errors.With(intel.ErrDamagedCache, "304 validated etag but payload hash is unrecorded; refusing to adopt unbound disk bytes").
					Set("payload_path", payloadPath)
			}
			s.logger.Warn().
				Str("payload_path", payloadPath).
				Msg("304 validated etag but payload hash is unrecorded; forcing refetch to bind wire bytes")
			_ = os.Remove(etagPath)
			return s.fetchWithCacheBounded(ctx, payloadPath, etagPath, false)
		}
		return cached, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "url", s.url)
	}

	// Cap the body at maxFeedBytes so a compromised or MITM'd upstream
	// can't OOM veto by serving a multi-GB tarball. The +1 sentinel
	// lets us tell "exactly at limit" from "tried to exceed limit."
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, errors.With(err, "read body")
	}
	if len(body) > maxFeedBytes {
		return nil, errors.WithNew("pypa tarball exceeds size limit").
			Set("limit_bytes", maxFeedBytes).Set("url", s.url)
	}
	if err := fsutil.WriteAtomic(payloadPath, body); err != nil {
		return nil, errors.With(err, "cache payload")
	}
	// Bind the payload to its content hash so a later 304 revalidates the
	// bytes on disk, not just the upstream representation.
	if err := fsutil.RecordPayloadHash(payloadPath, body); err != nil {
		s.logger.Warn().Err(err).Msg("record payload hash")
	}
	// Phase 1.9: etag goes to a `.pending` sibling. The caller promotes
	// it after parseTarball succeeds.
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := fsutil.WriteAtomic(etagPath+".pending", []byte(etag)); err != nil {
			s.logger.Warn().Err(err).Msg("write etag.pending")
		}
	}
	return body, nil
}

// parseTarball walks a gzipped tar of the advisory-database repo and
// emits MalwareReports for every malware-flavored entry it finds.
//
// We expect the tarball layout produced by GitHub's archive endpoint:
//
//	advisory-database-main/
//	  vulns/
//	    pypi/
//	      <PYSEC-or-MAL-id>/
//	        PYSEC-XXXX-YY.yaml
//
// Anything outside `vulns/.../*.yaml` is skipped.
func parseTarball(payload []byte, logger zerolog.Logger) ([]intel.MalwareReport, error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, errors.With(err, "decompress tarball")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var out []intel.MalwareReport
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.With(err, "read tar header")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !isVulnYAML(hdr.Name) {
			continue
		}
		// Bounded read — we accept a generous limit per file but never
		// trust the tar header's claimed size enough to allocate that big.
		body, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			logger.Warn().Err(err).Str("entry", hdr.Name).Msg("read entry; skipping")
			continue
		}
		if len(body) > maxAdvisoryBytes {
			logger.Warn().Str("entry", hdr.Name).Int("size", len(body)).Msg("advisory exceeds size cap; skipping")
			continue
		}
		adv, err := parseYAMLAdvisory(body)
		if err != nil {
			// Malformed individual advisory: log and continue. One bad file
			// must not stop the whole feed.
			logger.Debug().Err(err).Str("entry", hdr.Name).Msg("parse advisory; skipping")
			continue
		}
		if !osvschema.IsMalware(adv) {
			continue
		}
		out = append(out, osvschema.Reports(adv, sourceID)...)
	}
	return out, nil
}

// isVulnYAML matches `*/vulns/.../*.yaml` paths inside the tarball. Tar
// entries from GitHub archives start with a project-prefixed top-level
// directory we don't pin (it's `advisory-database-main` today but could
// rotate); pattern-match by suffix instead.
// sweepOrphanTemps removes abandoned download temps from this source's
// cache dir. Runs once per process (sweepOnce); failures are logged, never
// propagated — a cache that can't be cleaned must not fail a fetch.
func (s *Source) sweepOrphanTemps() {
	fsutil.SweepOrphanTemps(s.cache, s.logger)
}

func isVulnYAML(name string) bool {
	if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
		return false
	}
	return strings.Contains(name, "/vulns/")
}

// parseYAMLAdvisory unmarshals one PyPA YAML file into osvschema.Advisory.
// The Advisory struct uses json: tags but yaml.v3 honors them when no
// yaml: tag is present (case-insensitive lowercase match), so the same
// shape works for both formats.
func parseYAMLAdvisory(body []byte) (osvschema.Advisory, error) {
	var adv osvschema.Advisory
	if err := yaml.Unmarshal(body, &adv); err != nil {
		return osvschema.Advisory{}, errors.With(err, "yaml unmarshal")
	}
	return adv, nil
}
