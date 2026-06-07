// Package datadog implements intel.Source for Datadog's
// malicious-software-packages-dataset, a curated feed of malicious npm and
// PyPI packages published at
// https://github.com/DataDog/malicious-software-packages-dataset (Apache-2.0).
//
// The feed ships one raw manifest per ecosystem, fetched unauthenticated from
// raw.githubusercontent.com and served with etag headers so refreshes can be
// cheap. The malware SAMPLES in the repo are encrypted zips; this source
// ignores them entirely and parses only the manifest.
//
// Data shape (npm and pypi manifests share it): a flat JSON object mapping a
// package name to either null or a list of affected version strings.
//
//	{
//	  "000webhost-admin": null,                 // every version is malicious
//	  "@antv/a8": ["0.1.1", "0.2.1"],           // only these versions are
//	  "evil-pkg": ["1.0.0"]                      //   compromised
//	}
//
// A null value means the package is malicious in its entirety; a list means the
// package was a legitimate one that suffered a compromise and only the listed
// versions are bad. This source emits one MalwareReport per affected version,
// or a single version-less ("all versions") report when the value is null.
package datadog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	// defaultBaseURL points at the raw manifest tree on the repo's default
	// branch. Each ecosystem manifest lives at
	// <baseURL>/samples/<eco>/manifest.json.
	defaultBaseURL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main"
	sourceID       = "datadog"

	// maxManifestBytes caps how much we accept from a single manifest fetch.
	// Sized far above the current observed sizes (~1.5 MB npm, ~50 KB pypi as
	// of 2026-06) so legitimate growth doesn't trip it, but bounded so a
	// MITM'd or compromised upstream cannot OOM the veto process by serving a
	// multi-GB body. Pair with io.LimitReader(maxManifestBytes+1) and detect
	// truncation by checking len(body) > maxManifestBytes.
	maxManifestBytes = 256 << 20 // 256 MiB

	// staleCacheThreshold controls when the warning fires on the
	// network-fail-fallback-to-cache path. 24h means: if we fell back to a
	// cache file older than a day, the operator should know — the intel set
	// protecting their installs is at least that out of date.
	staleCacheThreshold = 24 * time.Hour
)

// Options configures the Datadog source.
type Options struct {
	// BaseURL overrides the upstream raw-manifest base URL. Defaults to the
	// repo's main-branch raw tree on raw.githubusercontent.com.
	BaseURL string

	// CacheDir is where fetched manifests and etags are persisted between
	// runs. Required; typically ~/.cache/veto/datadog.
	CacheDir string

	// HTTPClient is used for fetches. Defaults to a client with a 30s timeout.
	HTTPClient *http.Client

	// Logger receives structured log events. Defaults to zerolog.Nop().
	Logger zerolog.Logger
}

// Source is the Datadog implementation of intel.Source. Construct via New.
// It is safe to call Fetch concurrently; each call operates on per-ecosystem
// cache files and holds no shared mutable state across calls.
type Source struct {
	baseURL string
	cache   string
	client  *http.Client
	logger  zerolog.Logger
}

var _ intel.Source = (*Source)(nil)

// New builds a Datadog source. Returns an error if CacheDir is empty or cannot
// be created.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("datadog: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "datadog: create cache dir").Set("path", opts.CacheDir)
	}
	// Tighten perms even if the dir pre-existed with looser bits — MkdirAll
	// doesn't touch existing dirs. Cache files are internal to veto; a
	// world-readable ~/.cache/veto/ lets any local UID inspect the on-disk
	// shape of an attack surface, and a world-writable one is a poisoning
	// vector for same-host attackers across UIDs.
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "datadog: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	return &Source{
		baseURL: baseURL,
		cache:   opts.CacheDir,
		client:  client,
		logger:  opts.Logger.With().Str("component", "intel.datadog").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source. It returns intel.ErrUnsupportedEcosystem for
// any ecosystem other than npm and pypi.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	path, ok := manifestPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	url := s.baseURL + "/" + path
	cachedPayload := filepath.Join(s.cache, string(eco)+".json")
	cachedEtag := filepath.Join(s.cache, string(eco)+".etag")

	payload, err := s.fetchWithCache(ctx, url, cachedPayload, cachedEtag)
	if err != nil {
		return nil, errors.With(err, "datadog fetch").Set("ecosystem", string(eco), "url", url)
	}

	reports, err := parseManifest(eco, payload)
	if err != nil {
		// The etag on disk (if any) still points at a manifest we couldn't
		// parse. Drop it — and the .pending sibling — so the next refresh
		// re-downloads instead of 304-looping on the same bad bytes.
		if rmErr := os.Remove(cachedEtag); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		if rmErr := os.Remove(cachedEtag + ".pending"); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag.pending after parse failure")
		}
		return nil, err
	}
	// Parse succeeded — commit the pending etag atomically.
	s.commitEtagAfterParse(cachedEtag)
	return reports, nil
}

// fetchWithCache returns the latest manifest bytes for url. It honors
// etag-based conditional fetches: if the cached etag still matches upstream,
// the cached manifest is returned without re-downloading the body. On network
// failure, a previously-cached manifest is returned with a logged warning
// rather than failing the refresh.
//
// The 304-with-missing-cache edge case (upstream says "nothing changed" but our
// cache file vanished — disk wipe, manual cleanup) is recovered by dropping the
// etag and refetching ONCE. Bounded retry so a wedged filesystem (read-only,
// quota exhausted) can't loop indefinitely.
func (s *Source) fetchWithCache(ctx context.Context, url, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, url, payloadPath, etagPath, true)
}

// fetchOnce is fetchWithCache with retry forbidden — used internally when the
// function has already taken its one allowed retry.
func (s *Source) fetchOnce(ctx context.Context, url, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, url, payloadPath, etagPath, false)
}

func (s *Source) fetchWithCacheBounded(ctx context.Context, url, payloadPath, etagPath string, retryAllowed bool) ([]byte, error) {
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
		// Network failure — fall back to cached manifest if we have one. Emit
		// a louder warning when the cache is past staleCacheThreshold; a
		// long-running offline period silently keeping us on month-old intel
		// is exactly the kind of regression an operator should see.
		if cached, readErr := os.ReadFile(payloadPath); readErr == nil {
			logEvt := s.logger.Warn().Err(err).Str("url", url)
			if stat, statErr := os.Stat(payloadPath); statErr == nil {
				age := time.Since(stat.ModTime())
				logEvt = logEvt.Dur("cache_age", age)
				if age > staleCacheThreshold {
					logEvt = logEvt.Bool("cache_stale", true)
				}
			}
			logEvt.Msg("upstream unreachable, using cached manifest")
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
				// Already took our one allowed refetch and the cache is still
				// missing — give up rather than spin.
				return nil, errors.With(err, "304 with missing cache after retry").
					Set("url", url).Set("payload_path", payloadPath)
			}
			// Upstream told us nothing changed but we have no local copy.
			// Treat this as a cache invariant break — drop the etag and
			// refetch ONCE. Bounded retry so a filesystem in a wedged state
			// (read-only, quota exhausted, etc.) doesn't spin forever.
			s.logger.Warn().Err(err).Msg("304 received but cached manifest missing; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchOnce(ctx, url, payloadPath, etagPath)
		}
		return cached, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "url", url)
	}

	// Bound the manifest size so a compromised or MITM'd upstream cannot OOM
	// veto by serving a gigantic body. The +1 lets us detect truncation: if we
	// read more than maxManifestBytes we know upstream was over the limit and
	// the read was cut short.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, errors.With(err, "read body")
	}
	if len(body) > maxManifestBytes {
		return nil, errors.WithNew("manifest payload exceeds size limit").
			Set("limit_bytes", maxManifestBytes).
			Set("url", url)
	}

	if err := fsutil.WriteAtomic(payloadPath, body); err != nil {
		return nil, errors.With(err, "cache manifest")
	}
	// Write the etag to a `.pending` sibling. The caller's commitEtagAfterParse
	// promotes it to the canonical path only after the body parses cleanly.
	// Closes the race where a transient malformed manifest could persist an
	// etag pointing at unparseable bytes and 304-loop forever.
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := fsutil.WriteAtomic(etagPath+".pending", []byte(etag)); err != nil {
			s.logger.Warn().Err(err).Msg("write etag.pending")
		}
	}

	return body, nil
}

// commitEtagAfterParse promotes a `.pending` etag file to the canonical path.
// Called by Fetch after the body parses cleanly. The rename is atomic on POSIX.
func (s *Source) commitEtagAfterParse(etagPath string) {
	pending := etagPath + ".pending"
	if _, err := os.Stat(pending); err != nil {
		return
	}
	if err := os.Rename(pending, etagPath); err != nil {
		s.logger.Warn().Err(err).Str("from", pending).Str("to", etagPath).Msg("commit etag")
	}
}

// manifestPath returns the repo-relative path of the manifest for eco, and
// whether the ecosystem is covered. Datadog covers npm and pypi only.
func manifestPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "samples/npm/manifest.json", true
	case intel.EcosystemPyPI:
		return "samples/pypi/manifest.json", true
	default:
		return "", false
	}
}

// reasonAllVersions is the description attached to a report whose manifest
// entry was null (the whole package is malicious).
const reasonAllVersions = "Datadog malicious-software-packages-dataset: package is malicious (all versions)"

// reasonCompromisedVersion is the description attached to a report for a
// specific compromised version of an otherwise-legitimate package.
const reasonCompromisedVersion = "Datadog malicious-software-packages-dataset: compromised package version"

// parseManifest decodes a Datadog ecosystem manifest into MalwareReports.
//
// The manifest is a flat object mapping a package name to either null (every
// version is malicious → one version-less report) or a list of version strings
// (only those versions are compromised → one report each). An empty list is
// treated like null: nothing pins the badness to a version, so flag the package
// wholesale rather than silently dropping it.
func parseManifest(eco intel.Ecosystem, payload []byte) ([]intel.MalwareReport, error) {
	var raw map[string][]string
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.With(err, "parse datadog manifest").Set("ecosystem", string(eco))
	}

	out := make([]intel.MalwareReport, 0, len(raw))
	for name, versions := range raw {
		if name == "" {
			continue
		}
		if len(versions) == 0 {
			// null or [] → the entire package is malicious.
			out = append(out, intel.MalwareReport{
				PackageRef: intel.PackageRef{Ecosystem: eco, Name: name},
				SourceID:   sourceID,
				Reason:     reasonAllVersions,
			})
			continue
		}
		for _, v := range versions {
			if v == "" {
				continue
			}
			out = append(out, intel.MalwareReport{
				PackageRef: intel.PackageRef{Ecosystem: eco, Name: name, Version: v},
				SourceID:   sourceID,
				Reason:     reasonCompromisedVersion,
			})
		}
	}
	return out, nil
}
