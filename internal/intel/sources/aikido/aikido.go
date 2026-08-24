// Package aikido implements intel.Source for Aikido's open malware feed at
// https://malware-list.aikido.dev. The feed is a static JSON array per
// ecosystem, served with etag headers so refreshes can be cheap.
//
// Data shape (npm and pypi feeds share it):
//
//	[
//	  { "package_name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE" },
//	  ...
//	]
package aikido

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

const (
	defaultBaseURL = "https://malware-list.aikido.dev"
	sourceID       = "aikido"

	// maxFeedBytes caps how much we accept from the Aikido feed in a
	// single fetch. Sized generously above the current observed feed
	// size (~20 MB for npm, ~5 MB for pypi as of 2026-05) so legitimate
	// growth doesn't trip it, but bounded so a MITM'd or compromised
	// upstream cannot OOM the veto process by serving a multi-GB
	// body. Pair with io.LimitReader(maxFeedBytes+1) and detect the
	// truncation by checking len(body) > maxFeedBytes.
	maxFeedBytes = 256 << 20 // 256 MiB

	// staleCacheThreshold controls when the warning fires on the
	// network-fail-fallback-to-cache path. 24h means: if we fell back
	// to a cache file older than a day, the operator should know — the
	// intel set protecting their installs is at least that out of date.
	staleCacheThreshold = 24 * time.Hour
)

// Options configures the Aikido source.
type Options struct {
	// BaseURL overrides the upstream URL. Defaults to https://malware-list.aikido.dev.
	BaseURL string

	// CacheDir is where fetched payloads and etags are persisted between runs.
	// Required; typically ~/.cache/veto/aikido.
	CacheDir string

	// HTTPClient is used for fetches. Defaults to a client with a 30s timeout.
	HTTPClient *http.Client

	// Logger receives structured log events. Defaults to zerolog.Nop().
	Logger zerolog.Logger
}

// Source is the Aikido implementation of intel.Source. Construct via New.
type Source struct {
	baseURL string
	cache   string
	client  *http.Client
	logger  zerolog.Logger

	// sweepOnce bounds the orphan-temp sweep to one pass per process. This
	// is a COST guard, not a correctness lock: the sweep's safety comes
	// from the 24h age threshold (a live writer's temp can never be that
	// old), so concurrent processes sweeping the same directory are safe.
	sweepOnce sync.Once
}

var _ intel.Source = (*Source)(nil)

// New builds an Aikido source. Returns an error if CacheDir is empty or cannot
// be created.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("aikido: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "aikido: create cache dir").Set("path", opts.CacheDir)
	}
	// Tighten perms even if the dir pre-existed with looser bits — MkdirAll
	// doesn't touch existing dirs. Cache files are internal to veto; a
	// world-readable ~/.cache/veto/ lets any local UID inspect the on-disk
	// shape of an attack surface, and a world-writable one is a poisoning
	// vector for same-host attackers across UIDs.
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "aikido: tighten cache dir perms").Set("path", opts.CacheDir)
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
		logger:  opts.Logger.With().Str("component", "intel.aikido").Logger(),
	}, nil
}

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements intel.Source.
func (s *Source) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	path, ok := feedPath(eco)
	if !ok {
		return nil, intel.ErrUnsupportedEcosystem
	}

	// Hygiene, not a gate: drop download temps this source's own dead runs
	// left behind. Non-fatal by contract (see fsutil.SweepOrphanTemps);
	// once per process keeps it off the per-ecosystem hot path.
	s.sweepOnce.Do(s.sweepOrphanTemps)

	url := s.baseURL + "/" + path
	cachedPayload := filepath.Join(s.cache, string(eco)+".json")
	cachedEtag := filepath.Join(s.cache, string(eco)+".etag")

	payload, err := s.fetchWithCache(ctx, url, cachedPayload, cachedEtag)
	if err != nil {
		return nil, errors.With(err, "aikido fetch").Set("ecosystem", string(eco), "url", url)
	}

	reports, err := parsePayload(eco, payload)
	if err != nil {
		// Etag-on-disk (if any) still points to a payload we couldn't
		// parse. Drop it so the next refresh re-downloads. Phase 1.9:
		// also drop the .pending etag so it isn't promoted later. The
		// content-hash sidecar goes too — the bytes are what we stored,
		// but they're not parseable, and a future fetch must not treat
		// them as validated-good.
		if rmErr := os.Remove(cachedEtag); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag after parse failure")
		}
		if rmErr := os.Remove(cachedEtag + ".pending"); rmErr != nil && !os.IsNotExist(rmErr) {
			s.logger.Warn().Err(rmErr).Msg("remove etag.pending after parse failure")
		}
		fsutil.RemovePayloadHash(cachedPayload)
		return nil, err
	}
	// Phase 1.9: parse succeeded — commit the pending etag atomically.
	s.commitEtagAfterParse(cachedEtag)
	return reports, nil
}

// fetchWithCache returns the latest payload bytes for url. It honors etag-based
// conditional fetches: if the cached etag still matches upstream, the cached
// payload is returned without re-downloading the body. On network failure, a
// previously-cached payload is returned with a logged warning rather than
// failing the refresh.
//
// The 304-with-missing-cache edge case (upstream says "nothing changed" but
// our cache file vanished — disk wipe, manual cleanup) is recovered by
// dropping the etag and refetching ONCE. Bounded retry so a wedged
// filesystem (read-only, quota exhausted) can't loop indefinitely.
func (s *Source) fetchWithCache(ctx context.Context, url, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, url, payloadPath, etagPath, true)
}

// fetchOnce is fetchWithCache with retry forbidden — used internally when
// the function has already taken its one allowed retry.
func (s *Source) fetchOnce(ctx context.Context, url, payloadPath, etagPath string) ([]byte, error) {
	return s.fetchWithCacheBounded(ctx, url, payloadPath, etagPath, false)
}

func (s *Source) fetchWithCacheBounded(ctx context.Context, url, payloadPath, etagPath string, retryAllowed bool) ([]byte, error) {
	prevEtag, _ := os.ReadFile(etagPath)

	// Cache-integrity gate: the etag names the upstream representation,
	// not the bytes on disk. If the payload's content hash no longer
	// matches what we recorded, the 304 below would "validate" damaged
	// bytes. A mismatch downgrades this to a cache miss (no
	// If-None-Match) so the 200 path re-downloads and re-records.
	// Unrecorded (pre-integrity-fix cache) stays a conditional GET: the
	// 200 path writes the sidecar on the next body.
	//
	// This MUST be computed before the cache-only directive below. Serving
	// from disk without consulting it is the whole vulnerability.
	hashVerdict := fsutil.PayloadHashVerdict(payloadPath)

	// Cache-only directive: the caller's freshness window says the advisory
	// set was fetched moments ago, so serve the on-disk payload without a
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
			Msg("cached payload failed content-hash verification; forcing full refetch")
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
		// Network failure — fall back to cached payload if we have one.
		// Emit a louder warning when the cache is past staleCacheThreshold;
		// a long-running offline period silently keeping us on month-old
		// intel is exactly the kind of regression an operator should see.
		//
		// The integrity gate applies here too, more strictly: with no
		// network there is no way to repair a damaged payload, and serving
		// it would be the exact silent-coverage-loss the gate exists to
		// prevent. Mismatch → fail closed with ErrDamagedCache.
		if hashVerdict == fsutil.HashMismatch {
			return nil, errors.With(intel.ErrDamagedCache, "cached payload is damaged and upstream is unreachable").
				Set("url", url).Set("payload_path", payloadPath)
		}
		if cached, readErr := os.ReadFile(payloadPath); readErr == nil {
			logEvt := s.logger.Warn().Err(err).Str("url", url)
			if stat, statErr := os.Stat(payloadPath); statErr == nil {
				age := time.Since(stat.ModTime())
				logEvt = logEvt.Dur("cache_age", age)
				if age > staleCacheThreshold {
					logEvt = logEvt.Bool("cache_stale", true)
				}
			}
			logEvt.Msg("upstream unreachable, using cached payload")
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
				// Already took our one allowed refetch and the cache is
				// still missing — give up rather than spin.
				return nil, errors.With(err, "304 with missing cache after retry").
					Set("url", url).Set("payload_path", payloadPath)
			}
			// Upstream told us nothing changed but we have no local copy.
			// Treat this as a cache invariant break — drop the etag and refetch
			// ONCE. Bounded retry so a filesystem in a wedged state (read-only,
			// quota exhausted, etc.) doesn't spin forever.
			s.logger.Warn().Err(err).Msg("304 received but cached payload missing; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchOnce(ctx, url, payloadPath, etagPath)
		}
		// The 304 validated the etag, but the etag only names the upstream
		// representation. Re-verify the payload hash NOW (the pre-request
		// check and this check bracket the network call; an Unrecorded
		// sidecar or a concurrent swap must not slip through the 304 path).
		// Mismatch → drop the etag and refetch ONCE, exactly like the
		// missing-cache case above.
		switch fsutil.PayloadHashVerdict(payloadPath) {
		case fsutil.HashMismatch:
			if !retryAllowed {
				return nil, errors.With(intel.ErrDamagedCache, "304 validated etag but payload is damaged").
					Set("url", url).Set("payload_path", payloadPath)
			}
			s.logger.Warn().
				Str("payload_path", payloadPath).
				Msg("304 validated etag but cached payload failed content-hash verification; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchOnce(ctx, url, payloadPath, etagPath)
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
			return s.fetchOnce(ctx, url, payloadPath, etagPath)
		}
		return cached, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "url", url)
	}

	// Bound the payload size so a compromised or MITM'd upstream cannot
	// OOM veto by serving a gigantic body. The +1 lets us detect
	// truncation: if we read more than maxFeedBytes we know upstream was
	// over the limit and the read was cut short.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, errors.With(err, "read body")
	}
	if len(body) > maxFeedBytes {
		return nil, errors.WithNew("feed payload exceeds size limit").
			Set("limit_bytes", maxFeedBytes).
			Set("url", url)
	}

	if err := fsutil.WriteAtomic(payloadPath, body); err != nil {
		return nil, errors.With(err, "cache payload")
	}
	// Bind the payload to its content hash so a later 304 revalidates the
	// bytes on disk, not just the upstream representation. Written
	// immediately after the payload: the crash window between the two
	// writes leaves an Unrecorded payload, which self-heals on the next
	// fresh fetch (one extra download) and never falsely refuses.
	if err := fsutil.RecordPayloadHash(payloadPath, body); err != nil {
		s.logger.Warn().Err(err).Msg("record payload hash")
	}
	// Phase 1.9: write the etag to a `.pending` sibling. The caller's
	// commitEtagAfterParse promotes it to the canonical path only
	// after the body parses cleanly. Closes the race where a transient
	// malformed payload could persist an etag pointing at unparseable
	// bytes and 304-loop forever.
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := fsutil.WriteAtomic(etagPath+".pending", []byte(etag)); err != nil {
			s.logger.Warn().Err(err).Msg("write etag.pending")
		}
	}

	return body, nil
}

// commitEtagAfterParse promotes a `.pending` etag file to the canonical
// path. Called by Fetch() after the body parses cleanly. The rename is
// atomic on POSIX.
func (s *Source) commitEtagAfterParse(etagPath string) {
	pending := etagPath + ".pending"
	if _, err := os.Stat(pending); err != nil {
		return
	}
	if err := os.Rename(pending, etagPath); err != nil {
		s.logger.Warn().Err(err).Str("from", pending).Str("to", etagPath).Msg("commit etag")
	}
}

// sweepOrphanTemps removes abandoned download temps from this source's
// cache dir. Runs once per process (sweepOnce); failures are logged, never
// propagated — a cache that can't be cleaned must not fail a fetch.
func (s *Source) sweepOrphanTemps() {
	fsutil.SweepOrphanTemps(s.cache, s.logger)
}

func feedPath(eco intel.Ecosystem) (string, bool) {
	switch eco {
	case intel.EcosystemNPM:
		return "malware_predictions.json", true
	case intel.EcosystemPyPI:
		return "malware_pypi.json", true
	default:
		return "", false
	}
}

// rawEntry mirrors one element of Aikido's feed.
type rawEntry struct {
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Reason      string `json:"reason"`
}

func parsePayload(eco intel.Ecosystem, payload []byte) ([]intel.MalwareReport, error) {
	var raw []rawEntry
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.With(err, "parse aikido payload").Set("ecosystem", string(eco))
	}

	out := make([]intel.MalwareReport, 0, len(raw))
	for _, r := range raw {
		if r.PackageName == "" {
			continue
		}
		out = append(out, intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: eco,
				Name:      r.PackageName,
				Version:   r.Version,
			},
			SourceID: sourceID,
			Reason:   r.Reason,
		})
	}
	return out, nil
}
