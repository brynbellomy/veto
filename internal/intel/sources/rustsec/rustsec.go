// Package rustsec implements intel.Source for the RustSec advisory-db, the
// authoritative security-advisory database for crates published on crates.io.
//
// RustSec maintains a dedicated `osv` branch that mirrors every advisory in
// OSV JSON format at crates/RUSTSEC-YYYY-NNNN.json. We download that branch as
// a tarball:
//
//	https://github.com/rustsec/advisory-db/archive/refs/heads/osv.tar.gz
//
// This is RustSec's own first-party export, distinct from osv.dev's
// crates.io/all.zip mirror (the separate `osv` source): consuming it directly
// keeps veto authoritative and avoids a dependency on a downstream aggregator's
// ingestion lag.
//
// These are ordinary vulnerabilities (RUSTSEC-*/CVE), not MAL-* malware, so we
// emit them via osvschema.VulnerabilityReports. Like the ghsa source, this is a
// broad CVE feed rather than malware-only — keep it opt-in until the product
// has first-class vulnerability policy controls separate from malware blocking.
//
// The repository is CC0-1.0 (public domain), with advisories imported from the
// GitHub Advisory Database carrying CC-BY-4.0 attribution.
package rustsec

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
	defaultTarballURL = "https://github.com/rustsec/advisory-db/archive/refs/heads/osv.tar.gz"
	sourceID          = "rustsec"

	// cratesDir is the path component (under the tarball's repo-root prefix)
	// that holds the OSV-format advisory JSON files. The osv branch lays them
	// out flat as crates/RUSTSEC-YYYY-NNNN.json.
	cratesDir = "crates/"

	// maxFeedBytes caps the whole RustSec osv-branch archive. The export is
	// small today (well under 1 MiB compressed), but this still bounds a
	// compromised upstream that streams a multi-GB payload.
	maxFeedBytes = 256 << 20

	// maxAdvisoryBytes bounds each per-advisory JSON file. Real RustSec
	// documents are a few KB; 5 MiB leaves room for long markdown details.
	maxAdvisoryBytes = 5 << 20
)

// Options configures the RustSec advisory-db source.
type Options struct {
	// TarballURL overrides the upstream osv-branch tarball location.
	TarballURL string

	// CacheDir is where the tarball and parsed gob blobs live.
	// Required; typically ~/.cache/veto/rustsec.
	CacheDir string

	// HTTPClient overrides the default 5-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the RustSec advisory-db implementation of intel.Source.
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

// New builds a RustSec advisory-db source. CacheDir is required; New fails if
// it cannot be created with 0700 permissions.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("rustsec: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "rustsec: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "rustsec: tighten cache dir perms").Set("path", opts.CacheDir)
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
		logger:     opts.Logger.With().Str("component", "intel.rustsec").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. RustSec covers only crates.io; every other
// ecosystem returns intel.ErrUnsupportedEcosystem so the Store skips it without
// treating it as a fetch failure. The first supported call downloads or
// revalidates the shared tarball; the parsed report set is reused thereafter.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemCrates {
		return nil, intel.ErrUnsupportedEcosystem
	}

	reports, err := s.ensureLoaded(ctx)
	if err != nil {
		return nil, err
	}

	// Every report is crates.io, but filter defensively in case a future
	// advisory carries a cross-ecosystem affected entry.
	out := reports[:0:0]
	for _, r := range reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

// ensureLoaded returns the parsed report set, revalidating the cached tarball
// against the upstream etag and re-parsing only when it has changed. Callers
// hold s.mu for the duration so the download/parse runs at most once per change.
func (s *Source) ensureLoaded(ctx context.Context) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	upstreamEtag, err := s.headEtag(ctx)
	if err != nil {
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
		return nil, errors.With(err, "rustsec: cannot reach upstream and no local cache")
	}

	if s.loaded && s.cacheEt == upstreamEtag {
		return s.cached, nil
	}

	if cached, ok := s.loadGob(upstreamEtag); ok {
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
	etagPath := filepath.Join(s.cacheDir, "osv.etag")
	if err != nil {
		// Parse failed — drop any pending/committed etag so the next refresh
		// re-downloads the body rather than trusting a tarball we couldn't read.
		if rmErr := os.Remove(etagPath + ".pending"); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag.pending after parse failure")
		}
		if rmErr := os.Remove(etagPath); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		return nil, errors.With(err, "rustsec: parse tarball")
	}
	// Parse succeeded — promote the pending etag.
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
	s.logger.Info().Int("reports", len(reports)).Str("etag", etag).Msg("rustsec parsed")
	return s.cached, nil
}

// headEtag fetches the upstream entity tag with a HEAD request so an unchanged
// tarball costs no body download. Returns an error when the upstream is
// unreachable or omits an ETag.
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
		return "", errors.WithNew("unexpected head status").Set("status", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("upstream returned no etag")
	}
	return etag, nil
}

// downloadIfChanged returns the on-disk tarball path, reusing the cached file
// when its committed etag already matches upstreamEtag and otherwise streaming
// a fresh copy to disk via temp-file-then-rename. The new etag is written to a
// `.pending` sibling and promoted by the caller only after a successful parse.
func (s *Source) downloadIfChanged(ctx context.Context, upstreamEtag string) (string, string, error) {
	tarballPath := filepath.Join(s.cacheDir, "osv.tar.gz")
	etagPath := filepath.Join(s.cacheDir, "osv.etag")

	if existing, err := os.ReadFile(etagPath); err == nil && string(existing) == upstreamEtag {
		if _, err := os.Stat(tarballPath); err == nil {
			// Cache-integrity gate: the etag matches, but the tarball's
			// bytes may have been damaged on disk. A mismatch falls
			// through to the download path (re-fetch + re-record).
			// Unrecorded (pre-integrity-fix cache) is served as-is and
			// self-heals on the next fresh download.
			if fsutil.PayloadHashVerdict(tarballPath) == fsutil.HashMismatch {
				s.logger.Warn().
					Str("payload_path", tarballPath).
					Msg("cached tarball failed content-hash verification; forcing re-download")
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
		return "", "", errors.WithNew("unexpected get status").Set("status", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(s.cacheDir, "osv.tar.gz.tmp-")
	if err != nil {
		return "", "", errors.With(err, "create temp tarball")
	}
	tmpPath := tmp.Name()
	// LimitReader+1 so we can detect oversized payloads: a server streaming
	// maxFeedBytes+1 bytes is over the cap and we refuse rather than persist a
	// truncated tarball.
	written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.With(err, "stream tarball")
	}
	if written > maxFeedBytes {
		tmp.Close()
		os.Remove(tmpPath)
		return "", "", errors.WithNew("rustsec tarball exceeds size limit").
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
	if err := os.WriteFile(etagPath+".pending", []byte(upstreamEtag), 0o600); err != nil {
		s.logger.Warn().Err(err).Msg("write etag.pending")
	}
	return tarballPath, upstreamEtag, nil
}

// parseTarball walks the gzipped tar and emits one set of reports per OSV
// advisory under crates/. Unparseable or oversized entries are skipped with a
// log line rather than failing the whole feed; a structural read error (corrupt
// gzip/tar) aborts.
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
		if !isAdvisoryEntry(hdr.Name) {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(tr, maxAdvisoryBytes+1))
		if err != nil {
			return nil, errors.With(err, "read entry").Set("name", hdr.Name)
		}
		if len(payload) > maxAdvisoryBytes {
			s.logger.Warn().Str("entry", hdr.Name).Int("limit_bytes", maxAdvisoryBytes).
				Msg("rustsec advisory exceeds size limit; skipping")
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

// isAdvisoryEntry returns true for OSV advisory JSON files in the osv-branch
// tarball. Tar entries carry a repo-root prefix such as advisory-db-osv/ that
// we deliberately do not pin (GitHub derives it from the branch name).
func isAdvisoryEntry(name string) bool {
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(parts[1], cratesDir)
}

// gobBlob is the on-disk shape of a parsed-report cache.
type gobBlob struct {
	Reports []intel.MalwareReport
}

// gobPath derives a filesystem-safe cache path from an etag.
func (s *Source) gobPath(etag string) string {
	clean := strings.NewReplacer(`"`, "", `/`, "_", `:`, "_", ` `, "_").Replace(etag)
	if clean == "" {
		clean = "no-etag"
	}
	return filepath.Join(s.cacheDir, "parsed-"+clean+".gob")
}

// loadGob reads a cached report set. An empty etag means "any parsed blob on
// disk" (used as a last resort when the upstream is unreachable on first load).
func (s *Source) loadGob(etag string) ([]intel.MalwareReport, bool) {
	if etag == "" {
		entries, err := os.ReadDir(s.cacheDir)
		if err != nil {
			return nil, false
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
				return s.readGobFile(filepath.Join(s.cacheDir, e.Name()))
			}
		}
		return nil, false
	}
	return s.readGobFile(s.gobPath(etag))
}

func (s *Source) readGobFile(path string) ([]intel.MalwareReport, bool) {
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
		// The etag matched upstream (the caller only reaches the gob when
		// it did), so the gob's bytes are upstream-consistent: adopt them
		// by recording the hash now.
		if body, readErr := os.ReadFile(path); readErr == nil {
			if hashErr := fsutil.RecordPayloadHash(path, body); hashErr != nil {
				s.logger.Warn().Err(hashErr).Msg("adopt grandfathered gob hash")
			}
		}
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

// writeGob persists a parsed report set via temp-file-then-rename so a crash
// mid-write never leaves a truncated cache, and records the content hash so
// a later load verifies the bytes on disk, not just the etag-derived
// filename.
func (s *Source) writeGob(etag string, reports []intel.MalwareReport) error {
	path := s.gobPath(etag)
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(gobBlob{Reports: reports}); err != nil {
		return errors.With(err, "encode gob")
	}
	if err := fsutil.WriteAtomic(path, buf.Bytes()); err != nil {
		return errors.With(err, "write gob")
	}
	if err := fsutil.RecordPayloadHash(path, buf.Bytes()); err != nil {
		s.logger.Warn().Err(err).Msg("record gob hash")
	}
	return nil
}
