// Package govulndb implements intel.Source for the Go team's authoritative
// vulnerability database at https://vuln.go.dev.
//
// This is the database that powers govulncheck. It is the canonical Go
// vulnerability feed, distinct from osv.dev's Go/all.zip mirror: the osv
// source consumes the mirror, this source consumes the upstream. Running both
// yields overlapping findings, which the Store keeps distinct per source so a
// verdict shows every feed that flagged a package.
//
// The database publishes a single unauthenticated bulk artifact:
//
//	https://vuln.go.dev/vulndb.zip
//
// containing index/*.json plus one OSV document per advisory under ID/GO-*.json
// (~3k entries, ~2.4 MB compressed). We download the zip with an etag-revalidated
// cache (mirroring the osv source), parse every ID/*.json OSV document, and emit
// vulnerability reports. Entries always carry ecosystem "Go"; the affected
// package name is the module path (or the "stdlib"/"toolchain" pseudo-modules,
// which never match a real install ref and are therefore inert).
//
// Like the ghsa source, this feed is not malware-only — it reports ordinary
// vulnerable versions. Keep it opt-in until veto has vulnerability policy
// controls separate from malware blocking.
//
// Data is distributed under CC-BY-4.0 (https://github.com/golang/vulndb).
package govulndb

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
	defaultZipURL = "https://vuln.go.dev/vulndb.zip"
	sourceID      = "govulndb"

	// entryPrefix is the path prefix, inside the zip, under which the
	// per-advisory OSV documents live. The index/*.json files share the
	// archive but are summaries we don't parse — only ID/GO-*.json carry the
	// full OSV records.
	entryPrefix = "ID/"

	// maxFeedBytes caps the vulndb.zip download. The archive sits around
	// 2-3 MB today; the 64 MiB ceiling leaves generous headroom for years of
	// growth while keeping a MITM'd or compromised upstream from OOMing veto
	// by streaming a multi-GB body.
	maxFeedBytes = 64 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON read out of the zip. Real
	// Go advisories are 1-3 KB; 2 MiB is far more than any entry needs and
	// stops a zip with one pathologically large member from exhausting memory.
	maxAdvisoryBytes = 2 << 20
)

// Options configures the Go vulnerability database source.
type Options struct {
	// ZipURL overrides the upstream bulk-zip location.
	ZipURL string

	// CacheDir is where the zip payload and etag live.
	// Required; typically ~/.cache/veto/govulndb.
	CacheDir string

	// HTTPClient overrides the default 2-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the Go vulnerability database implementation of intel.Source.
//
// Fetch is safe for concurrent use: a single mutex serializes downloads and
// guards the in-memory cache.
type Source struct {
	zipURL   string
	cacheDir string
	client   *http.Client
	logger   zerolog.Logger

	mu      sync.Mutex
	cached  []intel.MalwareReport
	loaded  bool
	cacheEt string
}

var _ intel.Source = (*Source)(nil)

// New builds a Go vulnerability database source. CacheDir is required and is
// created (0700) if absent.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("govulndb: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "govulndb: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "govulndb: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	zipURL := opts.ZipURL
	if zipURL == "" {
		zipURL = defaultZipURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}

	return &Source{
		zipURL:   zipURL,
		cacheDir: opts.CacheDir,
		client:   client,
		logger:   opts.Logger.With().Str("component", "intel.govulndb").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. The database covers only the Go ecosystem;
// every other ecosystem returns ErrUnsupportedEcosystem. The first covered
// fetch downloads or revalidates the shared zip; subsequent calls reuse the
// parsed report set until the upstream etag changes.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemGo {
		return nil, intel.ErrUnsupportedEcosystem
	}
	return s.ensureLoaded(ctx)
}

func (s *Source) ensureLoaded(ctx context.Context) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	zipPath := filepath.Join(s.cacheDir, "vulndb.zip")
	etagPath := filepath.Join(s.cacheDir, "vulndb.etag")

	prevEtag, _ := os.ReadFile(etagPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.zipURL, nil)
	if err != nil {
		return nil, errors.With(err, "build request")
	}
	if len(prevEtag) > 0 {
		req.Header.Set("If-None-Match", string(prevEtag))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Network blip — fall back to in-memory cache, then on-disk zip.
		if s.loaded {
			s.logger.Warn().Err(err).Msg("govulndb unreachable, using in-memory cache")
			return s.cached, nil
		}
		if _, statErr := os.Stat(zipPath); statErr == nil {
			s.logger.Warn().Err(err).Msg("govulndb unreachable, re-parsing cached zip")
			reports, parseErr := parseZip(zipPath, s.logger)
			if parseErr != nil {
				return nil, errors.With(parseErr, "parse cached zip after network failure")
			}
			s.cached = reports
			s.cacheEt = string(prevEtag)
			s.loaded = true
			return reports, nil
		}
		return nil, errors.With(err, "govulndb request")
	}
	defer resp.Body.Close()

	upstreamEtag := resp.Header.Get("ETag")

	switch resp.StatusCode {
	case http.StatusNotModified:
		if s.loaded && s.cacheEt == string(prevEtag) {
			return s.cached, nil
		}
		reports, err := parseZip(zipPath, s.logger)
		if err != nil {
			return nil, errors.With(err, "parse cached zip on 304")
		}
		s.cached = reports
		s.cacheEt = string(prevEtag)
		s.loaded = true
		return reports, nil

	case http.StatusOK:
		// Stream to a temp file, then atomic rename.
		tmp, err := os.CreateTemp(s.cacheDir, "vulndb.zip.tmp-")
		if err != nil {
			return nil, errors.With(err, "create temp zip")
		}
		tmpPath := tmp.Name()
		// LimitReader+1 so we can detect oversized payloads — a server that
		// streams maxFeedBytes+1 bytes is over the cap, and we refuse the
		// fetch rather than persist a truncated zip.
		written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
		if err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, errors.With(err, "stream zip")
		}
		if written > maxFeedBytes {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, errors.WithNew("govulndb zip exceeds size limit").
				Set("limit_bytes", maxFeedBytes).
				Set("url", s.zipURL)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "close temp zip")
		}
		if err := os.Rename(tmpPath, zipPath); err != nil {
			os.Remove(tmpPath)
			return nil, errors.With(err, "rename zip")
		}

		// Parse BEFORE persisting the etag so a malformed payload doesn't pin
		// us into a 304-loop perma-failure: if parse fails here we leave the
		// previous etag in place, and the next refresh re-downloads the body
		// rather than re-parsing the same broken zip from disk.
		reports, err := parseZip(zipPath, s.logger)
		if err != nil {
			return nil, errors.With(err, "parse fresh zip")
		}
		if upstreamEtag != "" {
			if err := os.WriteFile(etagPath, []byte(upstreamEtag), 0o600); err != nil {
				s.logger.Warn().Err(err).Msg("write etag")
			}
		}
		s.cached = reports
		s.cacheEt = upstreamEtag
		s.loaded = true
		s.logger.Info().Int("reports", len(reports)).Msg("govulndb parsed")
		return reports, nil

	default:
		return nil, errors.WithNew("unexpected govulndb status").
			Set("status", resp.StatusCode, "url", s.zipURL)
	}
}

// parseZip reads every ID/GO-*.json OSV document out of the vulndb zip and
// converts active advisories into vulnerability reports. The index/*.json
// summary files in the same archive are skipped. Individual unreadable or
// unparseable entries are logged and dropped rather than failing the whole
// parse — one corrupt advisory must not blind the source to the rest.
func parseZip(path string, logger zerolog.Logger) ([]intel.MalwareReport, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errors.With(err, "open zip")
	}
	defer zr.Close()

	// Entry COUNT is not capped: the outer maxFeedBytes zip-size cap plus the
	// per-entry maxAdvisoryBytes cap together bound worst-case memory well
	// below a GiB even on an adversarial archive.
	var reports []intel.MalwareReport
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(f.Name, entryPrefix) || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		// Per-advisory cap defends against a zip with one pathologically large
		// entry. Truncated reads are skipped — the next advisory is independent.
		payload, err := io.ReadAll(io.LimitReader(rc, maxAdvisoryBytes+1))
		rc.Close()
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unreadable")
			continue
		}
		if len(payload) > maxAdvisoryBytes {
			logger.Warn().Str("entry", f.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("govulndb advisory exceeds size limit; skipping")
			continue
		}
		adv, err := osvschema.Parse(payload)
		if err != nil {
			logger.Debug().Err(err).Str("entry", f.Name).Msg("skip unparseable")
			continue
		}
		reports = append(reports, osvschema.VulnerabilityReports(adv, sourceID)...)
	}
	return reports, nil
}
