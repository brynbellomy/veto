// Package gemnasium implements intel.Source for GitLab's community advisory
// database at https://gitlab.com/gitlab-org/advisories-community.
//
// advisories-community is the MIT-licensed, time-delayed export of GitLab's
// gemnasium-db, published expressly for third-party integrators (the canonical
// gemnasium-db is under proprietary "GitLab Advisory Database Terms" that
// forbid automated access — veto must NOT scrape it). The export keeps the
// gemnasium YAML schema: one advisory per file at
// `<ecosystem>/<package>/<identifier>.yml`, with fields identifier(s),
// package_slug, title, description, affected_range, fixed_versions, pubdate.
//
// Unlike veto's malware-only defaults, this feed is general vulnerability
// intelligence (it overlaps heavily with the GHSA source — both ultimately
// draw on CVE/GHSA). Keep it opt-in until the product has first-class
// vulnerability policy controls separate from malware blocking.
//
// Fetch model mirrors the pypa source: download the main-branch tarball from
// GitLab's archive endpoint (etag-conditional GET), walk it for
// `<eco>/<pkg>/*.yml`, translate each advisory's affected_range into
// intel.VersionRange, and emit one report per OR-alternative. Range forms intel
// cannot represent (notably strict `>` lower bounds) are dropped with a
// structured warning rather than guessed.
//
// Coverage: npm, PyPI, Go, and crates.io (gemnasium `cargo`). Ecosystems veto
// does not gate (gem, maven, packagist, nuget, conan, swift, pub) are skipped.
package gemnasium

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
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	// defaultURL is the main-branch tarball of the MIT-licensed community
	// export. GitLab redirects/serves this as an application/octet-stream
	// gzip with an ETag header, so the etag-conditional caching path works.
	defaultURL = "https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz"
	sourceID   = "gemnasium"

	// maxAdvisoryBytes guards against a single oversized YAML entry. Real
	// gemnasium advisories are a few KB; 1 MiB is a generous safety cap.
	maxAdvisoryBytes = 1 << 20

	// maxFeedBytes caps the whole-tarball download. The community export sits
	// in the low-hundreds-of-MB range; 1 GiB bounds a compromised or MITM'd
	// upstream that streams a multi-GB body. Paired with io.LimitReader+1
	// truncation detection.
	maxFeedBytes = 1024 << 20

	// staleCacheThreshold mirrors the pypa source: warn loudly when serving
	// from a cache file older than this on the network-failure fallback path.
	staleCacheThreshold = 24 * time.Hour
)

// Options configures the gemnasium source.
type Options struct {
	// URL overrides the tarball URL. Defaults to the main-branch tarball of
	// gitlab.com/gitlab-org/advisories-community.
	URL string

	// CacheDir is where the fetched tarball + etag persist between runs.
	// Required; typically ~/.cache/veto/gemnasium.
	CacheDir string

	// HTTPClient defaults to a 5-minute-timeout client. The tarball is large
	// (hundreds of MB) and GitLab archive generation can be slow; 5m headroom
	// covers cold-cache archive builds and redirects.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the gemnasium advisories-community implementation of intel.Source.
type Source struct {
	url    string
	cache  string
	client *http.Client
	logger zerolog.Logger
}

var _ intel.Source = (*Source)(nil)

// New builds a gemnasium source. CacheDir is required.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("gemnasium: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "gemnasium: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "gemnasium: tighten cache dir perms").Set("path", opts.CacheDir)
	}
	url := opts.URL
	if url == "" {
		url = defaultURL
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Source{
		url:    url,
		cache:  opts.CacheDir,
		client: client,
		logger: opts.Logger.With().Str("component", "intel.gemnasium").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. Returns ErrUnsupportedEcosystem for
// ecosystems gemnasium publishes but veto does not gate, and for the (only)
// ecosystem set veto understands but gemnasium might add later. The first
// call for any ecosystem downloads or revalidates the shared tarball; the
// per-ecosystem filter happens during the walk.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if !supportedEcosystem(eco) {
		return nil, intel.ErrUnsupportedEcosystem
	}

	tarballPath := filepath.Join(s.cache, "advisories-community.tar.gz")
	etagPath := filepath.Join(s.cache, "advisories-community.etag")

	payload, err := s.fetchWithCache(ctx, tarballPath, etagPath)
	if err != nil {
		return nil, errors.With(err, "gemnasium fetch")
	}

	reports, err := parseTarball(payload, eco, s.logger)
	if err != nil {
		// Drop the pending etag so it isn't promoted; also drop the canonical
		// etag so the next refresh re-downloads instead of 304-looping on a
		// broken payload. Same policy as the pypa/ghsa sources. The
		// content-hash sidecar goes too — the bytes are what we stored, but
		// they're not parseable, and a future fetch must not treat them as
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
	// Parse succeeded — promote the pending etag.
	if _, statErr := os.Stat(etagPath + ".pending"); statErr == nil {
		if mvErr := os.Rename(etagPath+".pending", etagPath); mvErr != nil {
			s.logger.Warn().Err(mvErr).Msg("commit etag")
		}
	}
	return reports, nil
}

// fetchWithCache performs an etag-conditional GET, falling back to the on-disk
// tarball when upstream is unreachable. The 304-with-missing-cache fallback is
// bounded to a single retry. Mirrors the pypa source's policy.
func (s *Source) fetchWithCache(ctx context.Context, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, payloadPath, etagPath, true)
}

func (s *Source) fetchWithCacheBounded(ctx context.Context, payloadPath, etagPath string, retryAllowed bool) ([]byte, error) {
	// Cache-only directive (freshness window): serve the on-disk tarball
	// without a network round-trip. Missing cache falls through to the
	// normal network path.
	if intel.CacheOnly(ctx) {
		if cached, err := os.ReadFile(payloadPath); err == nil {
			return cached, nil
		}
	}

	prevEtag, _ := os.ReadFile(etagPath)

	// Cache-integrity gate: the etag names the upstream representation,
	// not the bytes on disk. A hash mismatch downgrades this fetch to a
	// cache miss so the 200 path re-downloads and re-records. Unrecorded
	// (pre-integrity-fix cache) stays a conditional GET; the 200 path
	// writes the sidecar on the next body.
	hashVerdict := fsutil.PayloadHashVerdict(payloadPath)
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
			// Grandfathered payload (pre-integrity-fix cache) that just
			// passed a live 304: adopt it by recording its hash now, so a
			// steady-state cache that only ever sees 304s still becomes
			// content-bound.
			if err := fsutil.RecordPayloadHash(payloadPath, cached); err != nil {
				s.logger.Warn().Err(err).Msg("adopt grandfathered payload hash")
			}
		}
		return cached, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "url", s.url)
	}

	// Cap the body so a compromised or MITM'd upstream can't OOM veto by
	// serving a multi-GB tarball. The +1 sentinel distinguishes "exactly at
	// limit" from "tried to exceed limit".
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, errors.With(err, "read body")
	}
	if len(body) > maxFeedBytes {
		return nil, errors.WithNew("gemnasium tarball exceeds size limit").
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
	// etag goes to a `.pending` sibling. The caller promotes it after
	// parseTarball succeeds, so a body that fails to parse never pins us into
	// a 304-loop on a broken cache.
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := fsutil.WriteAtomic(etagPath+".pending", []byte(etag)); err != nil {
			s.logger.Warn().Err(err).Msg("write etag.pending")
		}
	}
	return body, nil
}

// parseTarball walks a gzipped tar of the advisories-community repo and emits
// MalwareReports for every advisory matching the requested ecosystem.
//
// The expected layout is GitLab's archive shape:
//
//	advisories-community-main/
//	  npm/
//	    lodash/
//	      CVE-2019-10744.yml
//	  pypi/...
//	  go/...
//	  cargo/...
//
// Files outside `<eco>/<pkg>/*.yml` are skipped. One malformed advisory is
// logged and skipped — it must not abort the whole feed.
func parseTarball(payload []byte, eco intel.Ecosystem, logger zerolog.Logger) ([]intel.MalwareReport, error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, errors.With(err, "decompress tarball")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	wantPrefix := gemnasiumPrefix(eco)

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
		if !isAdvisoryYAMLForEcosystem(hdr.Name, wantPrefix) {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			logger.Warn().Err(err).Str("entry", hdr.Name).Msg("read entry; skipping")
			continue
		}
		if len(body) > maxAdvisoryBytes {
			logger.Warn().Str("entry", hdr.Name).Int("size", len(body)).Msg("advisory exceeds size cap; skipping")
			continue
		}
		adv, err := parseAdvisory(body)
		if err != nil {
			// Malformed individual advisory: log and continue. One bad file
			// must not stop the whole feed.
			logger.Debug().Err(err).Str("entry", hdr.Name).Msg("parse advisory; skipping")
			continue
		}
		out = append(out, reportsFromAdvisory(adv, eco, sourceID, logger)...)
	}
	return out, nil
}

// supportedEcosystem reports whether veto gates the given ecosystem AND
// gemnasium publishes advisories for it.
func supportedEcosystem(eco intel.Ecosystem) bool {
	return gemnasiumPrefix(eco) != ""
}

// gemnasiumPrefix maps an intel.Ecosystem to its gemnasium directory-name
// prefix (the first path segment in the tarball). Returns "" for ecosystems
// gemnasium does not cover or veto does not gate.
func gemnasiumPrefix(eco intel.Ecosystem) string {
	switch eco {
	case intel.EcosystemNPM:
		return "npm"
	case intel.EcosystemPyPI:
		return "pypi"
	case intel.EcosystemGo:
		return "go"
	case intel.EcosystemCrates:
		return "cargo"
	default:
		return ""
	}
}

// isAdvisoryYAMLForEcosystem matches `*/<eco-prefix>/<pkg...>/<id>.yml` paths
// inside the tarball. GitLab archives prefix every entry with a top-level
// project directory (`advisories-community-main/`) we deliberately do not pin —
// match the ecosystem segment by position after the first path component.
func isAdvisoryYAMLForEcosystem(name, wantPrefix string) bool {
	if wantPrefix == "" {
		return false
	}
	if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
		return false
	}
	// Strip the leading archive-root component (e.g. advisories-community-main/).
	slash := strings.IndexByte(name, '/')
	if slash < 0 {
		return false
	}
	rest := name[slash+1:]
	// rest must be `<eco-prefix>/<pkg>.../<id>.yml`.
	return strings.HasPrefix(rest, wantPrefix+"/")
}
