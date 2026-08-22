// Package osv implements intel.Source for OSV's open vulnerability database
// at https://osv.dev. The bulk-download endpoint serves a per-ecosystem ZIP
// containing one JSON file per advisory:
//
//	https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip
//
// OSV mixes regular vulnerabilities with malware advisories. By default we
// filter to entries whose ID starts with "MAL-" (OSV's malware namespace)
// via osvschema.IsMalware. Set Options.IncludeVulnerabilities to also emit
// ordinary CVE/GHSA advisories (everything still-active) alongside the
// malware findings.
//
// OSV aggregates upstreams including OpenSSF's malicious-packages, so
// running both yields duplicate findings — that's intentional belt-and-
// suspenders coverage. The Store dedups by (source, ecosystem, name,
// version), which keeps each source's "I flagged it" signal distinct in
// the verdict.
package osv

import (
	"archive/zip"
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

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/osvschema"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	defaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	sourceID       = "osv"

	// maxFeedBytes caps the size of the per-ecosystem zip we download.
	// OSV's all.zip payloads currently sit around 30–60 MB across the
	// covered ecosystems; the 256 MiB ceiling leaves plenty of room for
	// growth while keeping a MITM'd or compromised upstream from OOMing
	// veto by streaming a multi-GB body.
	maxFeedBytes = 256 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON we read out of the
	// zip. Real advisories are typically a few KB; 5 MiB is generous.
	// A zip with a single huge entry can't exhaust memory under this cap.
	maxAdvisoryBytes = 5 << 20
)

// Options configures the OSV source.
type Options struct {
	// BaseURL overrides the upstream GCS bucket root.
	BaseURL string

	// CacheDir is where per-ecosystem zip payloads and etags live.
	// Required; typically ~/.cache/veto/osv.
	CacheDir string

	// HTTPClient overrides the default 2-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger

	// IncludeVulnerabilities widens the source beyond OSV's MAL-* malware
	// namespace: when true, every still-active advisory (CVE/GHSA/RustSec/…
	// that OSV.dev aggregates) is also emitted via
	// osvschema.VulnerabilityReports. When false (the default) the source
	// behaves exactly as before — malware-only, MAL-* filtered. The flag is
	// fixed for the lifetime of a Source instance.
	IncludeVulnerabilities bool
}

// Source is the OSV implementation of intel.Source.
type Source struct {
	baseURL     string
	cacheDir    string
	client      *http.Client
	logger      zerolog.Logger
	includeVuln bool

	mu     sync.Mutex
	cached map[intel.Ecosystem]ecosystemEntry
}

type ecosystemEntry struct {
	etag    string
	reports []intel.MalwareReport
}

var _ intel.Source = (*Source)(nil)

// New builds an OSV source.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("osv: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "osv: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "osv: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}

	return &Source{
		baseURL:     baseURL,
		cacheDir:    opts.CacheDir,
		client:      client,
		logger:      opts.Logger.With().Str("component", "intel.osv").Logger(),
		includeVuln: opts.IncludeVulnerabilities,
		cached:      make(map[intel.Ecosystem]ecosystemEntry),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if _, ok := ecosystemPath(eco); !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	// The 304 arms inside may retry once (etag dropped, unconditional
	// refetch). That retry must NOT re-enter Fetch: the mutex is held
	// here, and re-locking self-deadlocks (a latent bug in the Mismatch
	// arm that the FIX 1 Unrecorded arm made reachable). Retry goes to
	// fetchLocked directly.
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fetchLocked(ctx, eco)
}

// fetchLocked is Fetch with the mutex already held.
func (s *Source) fetchLocked(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	return s.fetchLockedBudget(ctx, eco, 1)
}

// fetchLockedBudget is fetchLocked with a retry budget: the 304
// arms may consume one retry (drop etag, unconditional refetch).
// An upstream that answers 304 to an UNCONDITIONAL GET is broken
// or hostile; fail closed instead of looping forever.
func (s *Source) fetchLockedBudget(ctx context.Context, eco intel.Ecosystem, retries int) ([]intel.MalwareReport, error) {
	ecoPath, ok := ecosystemPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	url := s.baseURL + "/" + ecoPath + "/all.zip"
	zipPath := filepath.Join(s.cacheDir, ecoPath+".zip")
	etagPath := filepath.Join(s.cacheDir, ecoPath+".etag")

	// Cache-integrity gate: the etag names the upstream representation,
	// not the bytes on disk. A hash mismatch downgrades this fetch to a
	// cache miss so the 200 path re-downloads and re-records. Unrecorded
	// (pre-integrity-fix cache) stays a conditional GET; the 200 path
	// writes the sidecar on the next body.
	//
	// This MUST be computed before the cache-only directive below. Serving
	// from disk without consulting it is the whole vulnerability.
	hashVerdict := fsutil.PayloadHashVerdict(zipPath)

	// Cache-only directive: the caller's freshness window says the advisory
	// set was fetched moments ago, so serve from memory or the on-disk zip
	// without a network round-trip. No usable cache falls through to the
	// normal path — the directive is an optimization, never a correctness
	// gate.
	//
	// Two rules make it safe, and both are easy to lose in a merge:
	//
	//  1. The in-memory cache short-circuits freely: it was fetched and
	//     parsed in this process, so it is pre-verified.
	//  2. The on-disk zip is gated on its content hash. A HashMismatch does
	//     NOT short-circuit — it falls through to the network path, which
	//     re-downloads and re-records — and HashUnrecorded (a
	//     pre-integrity-fix zip) serves but is NEVER adopted: adoption is
	//     justified only by a live 304, where upstream confirmed the etag
	//     names these bytes. Under cache-only nothing confirms anything, so
	//     adopting would bless whatever happens to be on disk. The
	//     persistent per-source baseline is the backstop for that case.
	if intel.CacheOnly(ctx) {
		if entry, ok := s.cached[eco]; ok {
			return entry.reports, nil
		}
		if hashVerdict != fsutil.HashMismatch {
			if _, statErr := os.Stat(zipPath); statErr == nil {
				if hashVerdict == fsutil.HashUnrecorded {
					s.logger.Warn().
						Str("payload_path", zipPath).
						Msg("serving pre-integrity cache under cache-only directive; not adopting its hash without upstream validation")
				}
				reports, parseErr := parseZip(zipPath, s.includeVuln, s.logger)
				if parseErr == nil {
					s.cached[eco] = ecosystemEntry{etag: "", reports: reports}
					return reports, nil
				}
				s.logger.Warn().Err(parseErr).Str("ecosystem", string(eco)).Msg("cache-only: cached zip failed to parse; falling back to network")
			}
		}
	}

	prevEtag, _ := os.ReadFile(etagPath)

	if hashVerdict == fsutil.HashMismatch && len(prevEtag) > 0 {
		s.logger.Warn().
			Str("payload_path", zipPath).
			Msg("cached zip failed content-hash verification; forcing full refetch")
		prevEtag = nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.With(err, "build request")
	}
	if len(prevEtag) > 0 {
		req.Header.Set("If-None-Match", string(prevEtag))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Network blip — use in-memory cache if we have one.
		if entry, ok := s.cached[eco]; ok {
			s.logger.Warn().Err(err).Str("ecosystem", string(eco)).Msg("osv unreachable, using in-memory")
			return entry.reports, nil
		}
		// Or fall back to on-disk zip if present (re-parse).
		//
		// The integrity gate applies to the disk path: with no network
		// there is no way to repair a damaged payload, and serving it
		// would silently reduce this source's coverage. Mismatch → fail
		// closed with ErrDamagedCache.
		if hashVerdict == fsutil.HashMismatch {
			return nil, errors.With(intel.ErrDamagedCache, "cached zip is damaged and upstream is unreachable").
				Set("url", url).Set("payload_path", zipPath)
		}
		if _, statErr := os.Stat(zipPath); statErr == nil {
			s.logger.Warn().Err(err).Str("ecosystem", string(eco)).Msg("osv unreachable, re-parsing cached zip")
			reports, parseErr := parseZip(zipPath, s.includeVuln, s.logger)
			if parseErr != nil {
				return nil, errors.With(parseErr, "parse cached zip after network failure")
			}
			s.cached[eco] = ecosystemEntry{etag: string(prevEtag), reports: reports}
			return reports, nil
		}
		return nil, errors.With(err, "osv request")
	}
	defer resp.Body.Close()

	upstreamEtag := resp.Header.Get("ETag")

	switch resp.StatusCode {
	case http.StatusNotModified:
		if entry, ok := s.cached[eco]; ok && entry.etag == string(prevEtag) {
			return entry.reports, nil
		}
		// The 304 validated the etag, but the etag only names the upstream
		// representation. Re-verify the payload hash NOW so damaged bytes
		// cannot ride a 304 into the index. Mismatch → drop the etag and
		// refetch (the retry loop terminates because the refetch carries
		// no If-None-Match).
		switch fsutil.PayloadHashVerdict(zipPath) {
		case fsutil.HashMismatch:
			s.logger.Warn().
				Str("payload_path", zipPath).
				Msg("304 validated etag but cached zip failed content-hash verification; forcing refetch")
			_ = os.Remove(etagPath)
			if retries <= 0 {
				return nil, errors.With(intel.ErrDamagedCache, "304 to an unconditional refetch; upstream is broken or hostile").Set("url", url)
			}
			return s.fetchLockedBudget(ctx, eco, retries-1)
		case fsutil.HashUnrecorded:
			// FIX 1: a live 304 validates the ETAG, not the bytes on
			// disk. An Unrecorded sidecar means nothing binds this zip
			// (crash between write and RecordPayloadHash, a deleted
			// sidecar, or a pre-sidecar cache), so adopting the on-disk
			// bytes now would bless whatever happens to be there --
			// gutted bytes would read HashMatch forever after. Treat
			// Unrecorded exactly like Mismatch: drop the etag and refetch,
			// so only bytes read off the wire in THIS request get bound.
			s.logger.Warn().
				Str("payload_path", zipPath).
				Msg("304 validated etag but zip hash is unrecorded; forcing refetch to bind wire bytes")
			_ = os.Remove(etagPath)
			if retries <= 0 {
				return nil, errors.With(intel.ErrDamagedCache, "304 to an unconditional refetch; upstream is broken or hostile").Set("url", url)
			}
			return s.fetchLockedBudget(ctx, eco, retries-1)
		}
		reports, err := parseZip(zipPath, s.includeVuln, s.logger)
		if err != nil {
			return nil, errors.With(err, "parse cached zip on 304")
		}
		s.cached[eco] = ecosystemEntry{etag: string(prevEtag), reports: reports}
		return reports, nil

	case http.StatusOK:
		// Stream to a temp file, then atomic rename.
		tmp, err := os.CreateTemp(s.cacheDir, ecoPath+".zip.tmp-")
		if err != nil {
			return nil, errors.With(err, "create temp zip")
		}
		tmpPath := tmp.Name()
		// LimitReader+1 so we can detect oversized payloads — a server
		// that streams maxFeedBytes+1 bytes is over the cap, and we
		// refuse the fetch rather than write a truncated zip to disk.
		written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
		if err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, errors.With(err, "stream zip")
		}
		if written > maxFeedBytes {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, errors.WithNew("osv zip exceeds size limit").
				Set("limit_bytes", maxFeedBytes).
				Set("url", url)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "close temp zip")
		}
		if err := os.Rename(tmpPath, zipPath); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "rename zip")
		}
		// Bind the zip to its content hash so a later 304 revalidates the
		// bytes on disk, not just the upstream representation.
		if body, readErr := os.ReadFile(zipPath); readErr == nil {
			if hashErr := fsutil.RecordPayloadHash(zipPath, body); hashErr != nil {
				s.logger.Warn().Err(hashErr).Msg("record payload hash")
			}
		}

		// Parse BEFORE persisting the etag so a malformed payload doesn't
		// pin us into 304-loop perma-failure: if parse fails here we leave
		// the previous etag in place (or no etag at all), and the next
		// refresh will re-download the body rather than re-parse the same
		// broken zip from disk.
		reports, err := parseZip(zipPath, s.includeVuln, s.logger)
		if err != nil {
			// Parse failed — the freshly downloaded bytes are unusable.
			// Drop the hash sidecar so the damaged zip is never treated
			// as validated (the etag was never written for it).
			fsutil.RemovePayloadHash(zipPath)
			return nil, errors.With(err, "parse fresh zip")
		}
		if upstreamEtag != "" {
			if err := os.WriteFile(etagPath, []byte(upstreamEtag), 0o644); err != nil {
				s.logger.Warn().Err(err).Msg("write etag")
			}
		}
		s.cached[eco] = ecosystemEntry{etag: upstreamEtag, reports: reports}
		s.logger.Info().Str("ecosystem", string(eco)).Int("reports", len(reports)).Msg("osv parsed")
		return reports, nil

	default:
		return nil, errors.WithNew("unexpected osv status").Set("status", resp.StatusCode, "url", url)
	}
}

// parseZip walks every advisory JSON in the on-disk zip and emits reports.
//
// When includeVuln is false it emits only MAL-* malware findings (the
// historical behavior). When true it additionally emits every still-active
// advisory via osvschema.VulnerabilityReports — ordinary CVE/GHSA/RustSec
// entries that OSV.dev aggregates. The MAL-* path is unchanged in both
// modes; includeVuln only widens, never narrows.
//
// Cache note: includeVuln is fixed per Source instance, so the in-memory
// `cached` map (parsed reports keyed by ecosystem) never mixes modes within
// one instance. The on-disk zip holds raw upstream bytes — no parse-mode
// state — so a cold-memory re-parse off disk (304 / network-fallback paths)
// always reflects the live instance's includeVuln via this argument. Two
// Source instances with different includeVuln safely share a CacheDir: each
// re-derives its own reports from the shared raw zip.
func parseZip(path string, includeVuln bool, logger zerolog.Logger) ([]intel.MalwareReport, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errors.With(err, "open zip")
	}
	defer zr.Close()

	// Entry COUNT is not capped here — we trust the per-feed entry total
	// (tens of thousands today) to stay bounded by the outer maxFeedBytes
	// zip-size cap plus the per-entry maxAdvisoryBytes below. Together
	// those keep worst-case memory well below GiB on adversarial inputs.
	var reports []intel.MalwareReport
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		// Per-advisory cap defends against a zip with one pathologically
		// large entry. Truncated reads are silently skipped — the next
		// advisory is independent.
		payload, err := io.ReadAll(io.LimitReader(rc, maxAdvisoryBytes+1))
		rc.Close()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		if len(payload) > maxAdvisoryBytes {
			logger.Warn().Str("entry", f.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("osv advisory exceeds size limit; skipping")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unparseable")
			continue
		}
		if osvschema.IsMalware(adv) {
			// MAL-* path — unchanged in both modes.
			reports = append(reports, osvschema.Reports(adv, sourceID)...)
			continue
		}
		// Non-MAL-* advisory. Default mode discards it; the widened mode
		// emits it as an ordinary vulnerability. The IsMalware short-circuit
		// above keeps the two emission paths disjoint, so a widened fetch
		// never double-counts a MAL-* entry.
		if includeVuln {
			reports = append(reports, osvschema.VulnerabilityReports(adv, sourceID)...)
		}
	}
	return reports, nil
}

// ecosystemPath translates intel.Ecosystem to OSV's URL path component.
// OSV is case-sensitive: npm is lowercase but PyPI is mixed-case.
func ecosystemPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "npm", true
	case intel.EcosystemPyPI:
		return "PyPI", true
	case intel.EcosystemGo:
		return "Go", true
	case intel.EcosystemCrates:
		return "crates.io", true
	default:
		return "", false
	}
}
