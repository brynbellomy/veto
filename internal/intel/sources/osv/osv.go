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
	ecoPath, ok := ecosystemPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	url := s.baseURL + "/" + ecoPath + "/all.zip"
	zipPath := filepath.Join(s.cacheDir, ecoPath+".zip")
	etagPath := filepath.Join(s.cacheDir, ecoPath+".etag")

	prevEtag, _ := os.ReadFile(etagPath)

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

		// Parse BEFORE persisting the etag so a malformed payload doesn't
		// pin us into 304-loop perma-failure: if parse fails here we leave
		// the previous etag in place (or no etag at all), and the next
		// refresh will re-download the body rather than re-parse the same
		// broken zip from disk.
		reports, err := parseZip(zipPath, s.includeVuln, s.logger)
		if err != nil {
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
