// Package ghsa implements intel.Source for GitHub Advisory Database.
//
// GitHub's advisory-database repository publishes reviewed GHSA/CVE advisories
// as OSV-shaped JSON files under advisories/github-reviewed/. Unlike the
// default veto sources, this feed is not malware-only: it includes ordinary
// vulnerable versions too. Keep it opt-in until the product has first-class
// vulnerability policy controls separate from malware blocking.
package ghsa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/gob"
	stderrors "errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/osvschema"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	defaultTarballURL = "https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz"
	sourceID          = "ghsa"
	reviewedPrefix    = "advisories/github-reviewed/"

	// maxFeedBytes caps the whole GitHub Advisory Database archive. The archive
	// is substantially larger than malware-only feeds, but this still bounds a
	// compromised upstream that streams a multi-GB payload.
	maxFeedBytes = 1024 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON file. Real GHSA documents
	// are usually a few KB; 5 MiB leaves room for long markdown details.
	maxAdvisoryBytes = 5 << 20
)

// Options configures the GitHub Advisory Database source.
type Options struct {
	// TarballURL overrides the upstream tarball location.
	TarballURL string

	// CacheDir is where the tarball and parsed gob blobs live.
	// Required; typically ~/.cache/veto/ghsa.
	CacheDir string

	// HTTPClient overrides the default 5-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the GitHub Advisory Database implementation of intel.Source.
type Source struct {
	tarballURL string
	cacheDir   string
	client     *http.Client
	logger     zerolog.Logger

	mu      sync.Mutex
	cached  []intel.MalwareReport
	loaded  bool
	cacheEt string
}

var _ intel.Source = (*Source)(nil)

// New builds a GitHub Advisory Database source.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("ghsa: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "ghsa: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "ghsa: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	tarballURL := opts.TarballURL
	if tarballURL == "" {
		tarballURL = defaultTarballURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}

	return &Source{
		tarballURL: tarballURL,
		cacheDir:   opts.CacheDir,
		client:     client,
		logger:     opts.Logger.With().Str("component", "intel.ghsa").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. The first call downloads or revalidates the
// shared tarball; later ecosystem fetches reuse the parsed report set.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if _, ok := ecosystemPath(eco); !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	reports, err := s.ensureLoaded(ctx)
	if err != nil {
		return nil, err
	}

	out := reports[:0:0]
	for _, r := range reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Source) ensureLoaded(ctx context.Context) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cache-integrity gate: both on-disk layers the cache-only directive
	// below might serve — the parsed gob and the raw tarball — must have
	// their verdicts computed BEFORE the directive. Serving from disk
	// without consulting them is the whole vulnerability. (The in-memory
	// cache needs no gate: it was fetched and parsed in this process, so
	// it is pre-verified.)
	gobVerdict := fsutil.PayloadHashVerdict(s.anyGobPath())
	tarballPath := filepath.Join(s.cacheDir, "main.tar.gz")
	tarballVerdict := fsutil.PayloadHashVerdict(tarballPath)

	// Cache-only directive: the caller's freshness window says the advisory
	// set was fetched moments ago, so skip the upstream HEAD etag probe and
	// serve whatever is in memory, on disk as a parsed gob, or in the cached
	// tarball. No usable local state falls through to the normal network
	// path — the directive is an optimization, never a correctness gate.
	//
	// Two rules make it safe, and both are easy to lose in a merge:
	//
	//  1. A HashMismatch on EITHER local layer does NOT short-circuit. The
	//     damaged layer is skipped (the gob load fails; the tarball fallback
	//     is not taken) and the fetch falls through to the network path,
	//     which re-downloads and re-records. A freshness window saying "we
	//     fetched recently" is not evidence that the bytes on disk are the
	//     bytes we fetched.
	//  2. HashUnrecorded (a pre-integrity-fix cache) is served but NEVER
	//     adopted. Adoption is justified only by upstream validation — a
	//     live HEAD probe confirming the etag — which the cache-only path
	//     has explicitly skipped. Adopting here would bless whatever happens
	//     to be on disk and permanently blind the gate. The persistent
	//     per-source baseline is the backstop for that case.
	if intel.CacheOnly(ctx) {
		if s.loaded {
			return s.cached, nil
		}
		if gobVerdict != fsutil.HashMismatch {
			if cached, ok := s.loadGobUnvalidated(""); ok {
				s.cached = cached
				s.loaded = true
				return s.cached, nil
			}
		}
		if tarballVerdict != fsutil.HashMismatch {
			if _, err := os.Stat(tarballPath); err == nil {
				if tarballVerdict == fsutil.HashUnrecorded {
					s.logger.Warn().
						Str("payload_path", tarballPath).
						Msg("serving pre-integrity cache under cache-only directive; not adopting its hash without upstream validation")
				}
				reports, err := s.parseTarball(tarballPath)
				if err == nil {
					s.cached = reports
					s.loaded = true
					return s.cached, nil
				}
				s.logger.Warn().Err(err).Msg("cache-only: cached tarball failed to parse; falling back to network")
			}
		}
	}

	upstreamEtag, err := s.headEtag(ctx)
	if err != nil {
		// A broken upstream must not stand in for an unreachable one. A
		// 304 answer to the unconditional HEAD carries ErrDamagedCache
		// (see headEtag); a genuine transport failure does not. Only the
		// latter may be answered from local layers — a hostile upstream
		// that 304s everything would otherwise be served the unrecorded
		// gob out of the availability arm, laundering garbage protocol
		// into a clean cache hit.
		if stderrors.Is(err, intel.ErrDamagedCache) {
			return nil, err
		}
		if s.loaded {
			s.logger.Warn().Err(err).Msg("etag check failed, using in-memory cache")
			return s.cached, nil
		}
		if cached, ok := s.loadGob(""); ok {
			s.logger.Warn().Err(err).Msg("etag check failed, using disk gob")
			s.cached = cached
			s.loaded = true
			return s.cached, nil
		}
		// No usable local layer survived its content-hash gate (or none
		// existed) and upstream is unreachable. When a local layer exists
		// but failed verification, this is cache damage with no repair
		// path — the same condition the payload+etag sources fail closed
		// on — so wrap ErrDamagedCache and let the store classify it.
		if gobVerdict == fsutil.HashMismatch || tarballVerdict == fsutil.HashMismatch {
			return nil, errors.With(intel.ErrDamagedCache, "ghsa: local cache is damaged and upstream is unreachable").
				Set("gob_hash", gobVerdict.String()).Set("tarball_hash", tarballVerdict.String())
		}
		return nil, errors.With(err, "ghsa: cannot reach upstream and no local cache")
	}

	if s.loaded && s.cacheEt == upstreamEtag {
		return s.cached, nil
	}

	// The HEAD probe confirmed this etag live upstream, so an Unrecorded
	// gob under it may be adopted (loadGobValidated with true).
	if cached, ok := s.loadGobValidated(upstreamEtag, true); ok {
		s.cached = cached
		s.cacheEt = upstreamEtag
		s.loaded = true
		return s.cached, nil
	}

	tarballPath, etag, err := s.downloadIfChanged(ctx, upstreamEtag)
	if err != nil {
		return nil, err
	}

	reports, err := s.parseTarball(tarballPath)
	etagPath := filepath.Join(s.cacheDir, "main.etag")
	if err != nil {
		if rmErr := os.Remove(etagPath + ".pending"); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag.pending after parse failure")
		}
		if rmErr := os.Remove(etagPath); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		return nil, errors.With(err, "ghsa: parse tarball")
	}
	// Phase 1.9: parse succeeded — promote the pending etag.
	if _, statErr := os.Stat(etagPath + ".pending"); statErr == nil {
		if mvErr := os.Rename(etagPath+".pending", etagPath); mvErr != nil {
			s.logger.Warn().Err(mvErr).Msg("commit etag")
		}
	}

	if err := s.writeGob(etag, reports); err != nil {
		s.logger.Warn().Err(err).Msg("write parsed gob")
	}

	s.cached = reports
	s.cacheEt = etag
	s.loaded = true
	s.logger.Info().Int("reports", len(reports)).Str("etag", etag).Msg("ghsa parsed")
	return s.cached, nil
}

func (s *Source) headEtag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.tarballURL, nil)
	if err != nil {
		return "", errors.With(err, "build head request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.With(err, "head request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A non-OK HEAD is upstream unavailability — EXCEPT a 304, which
		// answers a question nobody asked (an unconditional HEAD carries
		// no If-None-Match). A 304 here is protocol garbage from a broken
		// or hostile upstream, and the availability arms below must not
		// be able to launder it into a served cache hit. Carrying
		// ErrDamagedCache marks the upstream itself as unusable.
		if resp.StatusCode == http.StatusNotModified {
			return "", errors.With(intel.ErrDamagedCache, "upstream answered 304 to an unconditional HEAD").
				Set("status", resp.StatusCode).Set("url", s.tarballURL)
		}
		return "", errors.WithNew("unexpected head status").Set("status", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("upstream returned no etag")
	}
	return etag, nil
}

func (s *Source) downloadIfChanged(ctx context.Context, upstreamEtag string) (string, string, error) {
	tarballPath := filepath.Join(s.cacheDir, "main.tar.gz")
	etagPath := filepath.Join(s.cacheDir, "main.etag")

	if existing, err := os.ReadFile(etagPath); err == nil && string(existing) == upstreamEtag {
		if _, err := os.Stat(tarballPath); err == nil {
			// Cache-integrity gate: the etag matches, but the tarball's
			// bytes may have been damaged on disk. A mismatch falls
			// through to the download path (re-fetch + re-record).
			// FIX 1 extends the same rule to Unrecorded: a HEAD-confirmed
			// etag is not evidence about unbound disk bytes, so an unrecorded
			// tarball is re-downloaded and only the wire bytes get bound.
			if fsutil.PayloadHashVerdict(tarballPath) != fsutil.HashMatch {
				s.logger.Warn().
					Str("payload_path", tarballPath).
					Msg("cached tarball not content-verified (damaged or unrecorded); forcing re-download")
			} else {
				return tarballPath, upstreamEtag, nil
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.tarballURL, nil)
	if err != nil {
		return "", "", errors.With(err, "build get request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", errors.With(err, "get tarball")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotModified {
			// A 304 answer to an UNCONDITIONAL GET (no If-None-Match was set
			// on this request) is protocol garbage: the upstream confirms the
			// bytes are elsewhere while refusing to send them. A broken
			// upstream must not stand in for an unreachable one — the
			// availability arms would otherwise serve the unbound cache.
			return "", "", errors.With(intel.ErrDamagedCache, "upstream answered 304 to an unconditional request").
				Set("status", resp.StatusCode).Set("url", s.tarballURL)
		}
		return "", "", errors.WithNew("unexpected get status").Set("status", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(s.cacheDir, "main.tar.gz.tmp-")
	if err != nil {
		return "", "", errors.With(err, "create temp tarball")
	}
	tmpPath := tmp.Name()
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.With(err, "stream tarball")
	}
	if written > maxFeedBytes {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.WithNew("ghsa tarball exceeds size limit").
			Set("limit_bytes", maxFeedBytes)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", "", errors.With(err, "close temp tarball")
	}
	if err := os.Rename(tmpPath, tarballPath); err != nil {
		os.Remove(tmpPath)
		return "", "", errors.With(err, "rename tarball")
	}
	// Bind the tarball to its content hash so a later etag-reuse
	// revalidates the bytes on disk, not just the upstream etag.
	if body, readErr := os.ReadFile(tarballPath); readErr == nil {
		if hashErr := fsutil.RecordPayloadHash(tarballPath, body); hashErr != nil {
			s.logger.Warn().Err(hashErr).Msg("record payload hash")
		}
	}
	// Phase 1.9: write etag to a `.pending` sibling. Promoted by the
	// caller after parseTarball succeeds.
	if err := os.WriteFile(etagPath+".pending", []byte(upstreamEtag), 0o600); err != nil {
		s.logger.Warn().Err(err).Msg("write etag.pending")
	}
	return tarballPath, upstreamEtag, nil
}

func (s *Source) parseTarball(path string) ([]intel.MalwareReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.With(err, "open tarball")
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.With(err, "gzip reader")
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var reports []intel.MalwareReport
	for {
		hdr, err := tr.Next()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.With(err, "tar read")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if !isReviewedAdvisoryEntry(hdr.Name) {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return nil, errors.With(err, "read entry").Set("name", hdr.Name)
		}
		if len(payload) > maxAdvisoryBytes {
			s.logger.Warn().Str("entry", hdr.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("ghsa advisory exceeds size limit; skipping")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			s.logger.Debug().Err(err).Str("entry", hdr.Name).Msg("skip unparseable advisory")
			continue
		}
		reports = append(reports, osvschema.VulnerabilityReports(adv, sourceID)...)
	}
	return reports, nil
}

// isReviewedAdvisoryEntry returns true for GitHub-reviewed advisory JSON files
// inside GitHub archive tarballs. Tar entries include a repo-root prefix such
// as advisory-database-main/ that we deliberately do not pin.
func isReviewedAdvisoryEntry(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(parts[1], reviewedPrefix)
}

func ecosystemPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "npm", true
	case intel.EcosystemPyPI:
		return "pypi", true
	case intel.EcosystemGo:
		return "go", true
	case intel.EcosystemCrates:
		return "crates.io", true
	default:
		return "", false
	}
}

type gobBlob struct {
	Reports []intel.MalwareReport
}

func (s *Source) gobPath(etag string) string {
	clean := strings.NewReplacer(`"`, "", `/`, "_", `:`, "_", ` `, "_").Replace(etag)
	if clean == "" {
		clean = "no-etag"
	}
	return filepath.Join(s.cacheDir, "parsed-"+clean+".gob")
}

func (s *Source) loadGob(etag string) ([]intel.MalwareReport, bool) {
	return s.loadGobValidated(etag, false)
}

// loadGobValidated is loadGob with the upstream-validation flag threaded
// to readGobFileValidated. See that method for why adoption requires it.
func (s *Source) loadGobValidated(etag string, upstreamValidated bool) ([]intel.MalwareReport, bool) {
	if etag == "" {
		entries, err := os.ReadDir(s.cacheDir)
		if err != nil {
			return nil, false
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
				return s.readGobFileValidated(filepath.Join(s.cacheDir, e.Name()), upstreamValidated)
			}
		}
		return nil, false
	}
	return s.readGobFileValidated(s.gobPath(etag), upstreamValidated)
}

// anyGobPath returns the path of whichever parsed gob is on disk ("" when
// none), so the cache-only path can gate on its content hash before
// deciding to load it.
func (s *Source) anyGobPath() string {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
			return filepath.Join(s.cacheDir, e.Name())
		}
	}
	return ""
}

func (s *Source) readGobFile(path string) ([]intel.MalwareReport, bool) {
	return s.readGobFileValidated(path, false)
}

// loadGobUnvalidated is loadGob for paths that reached the gob without
// upstream confirming its etag (cache-only directive, HEAD failure). The
// mismatch gate still applies; adoption does not.
func (s *Source) loadGobUnvalidated(etag string) ([]intel.MalwareReport, bool) {
	return s.loadGobValidated(etag, false)
}

// readGobFileValidated loads a parsed gob. upstreamValidated reports
// whether upstream actually confirmed the etag naming this gob (a live
// HEAD probe whose etag matches, or the load happened right after a fresh
// download). ONLY then may an Unrecorded (pre-integrity-fix) gob have its
// hash adopted. Callers that reached the gob without upstream validation
// — the cache-only directive, which skips the HEAD probe entirely, and the
// HEAD-failure fallback — must pass false: adopting there would bless
// whatever bytes happen to be on disk, laundering existing damage into
// "verified" and permanently blinding the gate.
func (s *Source) readGobFileValidated(path string, upstreamValidated bool) ([]intel.MalwareReport, bool) {
	// Cache-integrity gate: the gob's filename is derived from the etag,
	// but anything with write access to the cache dir can damage its
	// bytes. A hash mismatch means the parsed-report cache cannot be
	// trusted — fail the load (return not-ok) so the caller falls through
	// to re-download and re-parse. Unrecorded (pre-integrity-fix cache)
	// loads normally and is adopted below, so a steady-state cache whose
	// etag never changes still becomes content-bound.
	switch fsutil.PayloadHashVerdict(path) {
	case fsutil.HashMismatch:
		s.logger.Warn().
			Str("path", path).
			Msg("parsed gob failed content-hash verification; ignoring cache")
		return nil, false
	case fsutil.HashUnrecorded:
		// FIX 1: never adopt on read-side evidence. Even a HEAD-confirmed
		// etag validates only the upstream REPRESENTATION, not the gob
		// bytes on disk; an Unrecorded sidecar means nothing binds them
		// (crash between WriteAtomic and RecordPayloadHash, a deleted
		// sidecar, or a pre-sidecar cache). Adopting now would bless
		// whatever happens to be on disk -- gutted bytes would read
		// HashMatch forever after. Serve the unbound gob only when the
		// caller cannot fall through to the wire (upstreamValidated is
		// false only on cache-only and dead-upstream paths); when the
		// wire IS reachable the caller must prefer re-downloading and
		// re-parsing so only bytes read off the wire get bound.
		if upstreamValidated {
			// Wire reachable: refuse the unbound gob so ensureLoaded falls
			// through to downloadIfChanged (which re-downloads the tarball
			// and re-records its hash) and writeGob re-binds the gob from
			// bytes this process produced.
			s.logger.Warn().
				Str("path", path).
				Msg("gob hash unrecorded; refusing to adopt on etag evidence alone; falling through to wire")
			return nil, false
		}
		s.logger.Warn().
			Str("path", path).
			Msg("serving pre-integrity gob without upstream validation; not adopting its hash")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var blob gobBlob
	if err := gob.NewDecoder(f).Decode(&blob); err != nil {
		s.logger.Warn().Err(err).Str("path", path).Msg("gob decode failed; ignoring cache")
		return nil, false
	}
	return blob.Reports, true
}

func (s *Source) writeGob(etag string, reports []intel.MalwareReport) error {
	path := s.gobPath(etag)
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(gobBlob{Reports: reports}); err != nil {
		return errors.With(err, "encode gob")
	}
	if err := fsutil.WriteAtomic(path, buf.Bytes()); err != nil {
		return errors.With(err, "write gob")
	}
	// Bind the gob to its content hash so a later load verifies the bytes
	// on disk, not just the etag-derived filename.
	if err := fsutil.RecordPayloadHash(path, buf.Bytes()); err != nil {
		s.logger.Warn().Err(err).Msg("record gob hash")
	}
	return nil
}
