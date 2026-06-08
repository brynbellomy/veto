// Package abusech implements ioc.Source for abuse.ch's family of host-level
// indicator feeds: MalwareBazaar (file hashes), Feodo Tracker (botnet C2 IPs),
// URLhaus (malicious URLs), and ThreatFox (mixed IOCs).
//
// abuse.ch now gates its bulk dumps and APIs behind a FREE Auth-Key obtained at
// https://auth.abuse.ch/. The key is supplied via Options.AuthKey (wired from
// VETO_ABUSECH_AUTH_KEY by the orchestrator) and sent as the documented
// "Auth-Key" HTTP header on every request. When no key is configured the feed
// degrades gracefully: Fetch logs a single WARN and returns (nil, nil) rather
// than erroring, because IOC refresh is non-fatal and this feed is opt-in.
//
// Each sub-feed contributes a slice of normalized ioc.Indicators:
//
//   - MalwareBazaar recent.csv  -> sha256/sha1/md5 file-hash indicators
//   - Feodo Tracker ipblocklist -> ipv4 botnet-C2 indicators
//   - URLhaus csv_recent        -> url indicators
//   - ThreatFox get_iocs        -> ipv4 / domain / url / sha256 indicators
//
// A failure in one sub-feed never sinks the others: Fetch fans out across all
// four, logs and skips any that error, and returns whatever it could collect.
// Sub-feed parsers live in malwarebazaar.go, feodo.go, urlhaus.go, and
// threatfox.go so each format's quirks stay isolated from the lifecycle and
// caching machinery here.
package abusech

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/ioc"
	"github.com/brynbellomy/veto/internal/ioc/sources/internal/fsutil"
)

const (
	sourceID = "abusech"

	// Default per-feed bulk-export endpoints. Each is overridable through
	// Options for tests; production uses these.
	defaultBazaarURL    = "https://mb-api.abuse.ch/downloads/csv_recent/"
	defaultFeodoURL     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
	defaultURLhausURL   = "https://urlhaus.abuse.ch/downloads/csv_recent/"
	defaultThreatFoxURL = "https://threatfox-api.abuse.ch/api/v1/"

	// maxFeedBytes caps how much we accept from any single sub-feed fetch.
	// Sized far above the observed sizes (URLhaus recent ~a few MB,
	// MalwareBazaar recent ~tens of MB, Feodo/ThreatFox under 5 MB as of
	// 2026-06) so legitimate growth doesn't trip it, but bounded so a MITM'd
	// or compromised upstream cannot OOM the veto process by serving a
	// multi-GB body. Pair with io.LimitReader(maxFeedBytes+1) and detect
	// truncation by checking len(body) > maxFeedBytes.
	maxFeedBytes = 128 << 20 // 128 MiB

	// staleCacheThreshold controls when the warning fires on the
	// network-fail-fallback-to-cache path. 24h means: if we fell back to a
	// cache file older than a day, the operator should know — the IOC set is
	// at least that out of date.
	staleCacheThreshold = 24 * time.Hour

	// authKeyHeader is the documented header abuse.ch reads the free Auth-Key
	// from across its API gateway.
	authKeyHeader = "Auth-Key"
)

// Options configures the abuse.ch source.
type Options struct {
	// CacheDir is where fetched payloads and etags are persisted between runs.
	// Required; typically ~/.cache/veto/abusech.
	CacheDir string

	// AuthKey is the free abuse.ch Auth-Key (https://auth.abuse.ch/). When
	// empty, Fetch logs one WARN and returns (nil, nil) — the feed is opt-in
	// and a missing key is not an error.
	AuthKey string

	// HTTPClient is used for fetches. Defaults to a client with a 60s timeout
	// (the recent bulk dumps can be sizable).
	HTTPClient *http.Client

	// Logger receives structured log events. Defaults to zerolog.Nop().
	Logger zerolog.Logger

	// BazaarURL, FeodoURL, URLhausURL, ThreatFoxURL override the per-feed
	// endpoints. Empty fields fall back to the abuse.ch defaults; tests set
	// them to httptest server URLs.
	BazaarURL    string
	FeodoURL     string
	URLhausURL   string
	ThreatFoxURL string
}

// Source is the abuse.ch implementation of ioc.Source. Construct via New.
//
// It is safe to call Fetch concurrently: each call fans out to the sub-feeds
// under an internal mutex that serializes access to the shared cache files, so
// two concurrent Fetches never race on the same payload/etag path.
type Source struct {
	cache   string
	authKey string
	client  *http.Client
	logger  zerolog.Logger

	bazaarURL    string
	feodoURL     string
	urlhausURL   string
	threatFoxURL string

	// mu serializes cache reads/writes across concurrent Fetch calls. The
	// per-feed cache files are the only shared mutable state; guarding them
	// keeps Fetch safe to call concurrently per the ioc.Source contract.
	mu sync.Mutex
}

var _ ioc.Source = (*Source)(nil)

// New builds an abuse.ch source. Returns an error if CacheDir is empty or
// cannot be created. A missing AuthKey is NOT an error here — it surfaces as a
// graceful no-op at Fetch time so an opt-in feed without a key stays quiet.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("abusech: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "abusech: create cache dir").Set("path", opts.CacheDir)
	}
	// Tighten perms even if the dir pre-existed with looser bits — MkdirAll
	// doesn't touch existing dirs. Cache files are internal to veto; a
	// world-readable ~/.cache/veto/ lets any local UID inspect the on-disk
	// shape of an attack surface, and a world-writable one is a poisoning
	// vector for same-host attackers across UIDs.
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "abusech: tighten cache dir perms").Set("path", opts.CacheDir)
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	return &Source{
		cache:        opts.CacheDir,
		authKey:      opts.AuthKey,
		client:       client,
		logger:       opts.Logger.With().Str("component", "ioc.abusech").Logger(),
		bazaarURL:    orDefault(opts.BazaarURL, defaultBazaarURL),
		feodoURL:     orDefault(opts.FeodoURL, defaultFeodoURL),
		urlhausURL:   orDefault(opts.URLhausURL, defaultURLhausURL),
		threatFoxURL: orDefault(opts.ThreatFoxURL, defaultThreatFoxURL),
	}, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ID implements ioc.Source.
func (s *Source) ID() string { return sourceID }

// subFeed names one abuse.ch sub-feed: its cache key, fetch URL, and the parser
// that turns its raw payload into normalized indicators.
type subFeed struct {
	name  string
	url   string
	fetch func(ctx context.Context, url string) ([]ioc.Indicator, error)
}

// Fetch implements ioc.Source. It fans out across all four abuse.ch sub-feeds
// and returns the union of their normalized indicators.
//
// When Options.AuthKey was empty, Fetch returns (nil, nil) after one WARN: the
// feed is opt-in and a missing free key is not a fault. A failure in any single
// sub-feed is logged and skipped — the surviving feeds' indicators are still
// returned — because a partial IOC refresh beats none.
func (s *Source) Fetch(ctx context.Context) ([]ioc.Indicator, error) {
	if s.authKey == "" {
		// Graceful degradation: this feed is opt-in and the free Auth-Key is
		// not configured. Skip quietly with a single structured warning rather
		// than failing the (non-fatal) IOC refresh.
		s.logger.Warn().Msg("abuse.ch auth key not set; skipping")
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	feeds := []subFeed{
		{name: "malwarebazaar", url: s.bazaarURL, fetch: s.fetchMalwareBazaar},
		{name: "feodo", url: s.feodoURL, fetch: s.fetchFeodo},
		{name: "urlhaus", url: s.urlhausURL, fetch: s.fetchURLhaus},
		{name: "threatfox", url: s.threatFoxURL, fetch: s.fetchThreatFox},
	}

	var out []ioc.Indicator
	for _, f := range feeds {
		indicators, err := f.fetch(ctx, f.url)
		if err != nil {
			// One sub-feed failing must not sink the rest: log and continue so
			// the union of the healthy feeds still reaches the store.
			s.logger.Warn().Err(err).
				Str("subfeed", f.name).
				Fields(errors.ListFields(err)).
				Msg("abuse.ch sub-feed fetch failed; skipping")
			continue
		}
		out = append(out, indicators...)
	}
	return out, nil
}

// cachePaths returns the payload and etag cache-file paths for a sub-feed.
func (s *Source) cachePaths(feed string) (payload, etag string) {
	return filepath.Join(s.cache, feed+".cache"), filepath.Join(s.cache, feed+".etag")
}

// fetchPayload performs an etag-aware GET (or POST when body != nil), returning
// the latest payload bytes for a sub-feed. It honors etag-based conditional
// fetches, falls back to a cached payload on network failure, and bounds the
// body size so a compromised upstream cannot OOM veto. The abuse.ch Auth-Key is
// attached as the documented header on every request.
//
// commit must be called by the caller once the payload parses cleanly; it
// promotes the pending etag so a transient malformed payload never persists an
// etag that would 304-loop on unparseable bytes.
func (s *Source) fetchPayload(ctx context.Context, feed, url string, method string, body io.Reader, contentType string) (payload []byte, commit func(), _ error) {
	payloadPath, etagPath := s.cachePaths(feed)
	return s.fetchPayloadBounded(ctx, feed, url, method, body, contentType, payloadPath, etagPath, true)
}

func (s *Source) fetchPayloadBounded(
	ctx context.Context,
	feed, url, method string,
	body io.Reader,
	contentType, payloadPath, etagPath string,
	retryAllowed bool,
) ([]byte, func(), error) {
	prevEtag, _ := os.ReadFile(etagPath)

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, nil, errors.With(err, "build request").Set("subfeed", feed)
	}
	req.Header.Set(authKeyHeader, s.authKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Conditional fetch is only meaningful for idempotent GETs; the ThreatFox
	// POST carries a request body that changes the response window, so skip it
	// there.
	if method == http.MethodGet && len(prevEtag) > 0 {
		req.Header.Set("If-None-Match", string(prevEtag))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		// Network failure — fall back to a cached payload if we have one. Emit
		// a louder warning when the cache is past staleCacheThreshold; a
		// long-running offline period silently keeping us on month-old intel is
		// exactly the kind of regression an operator should see.
		if cached, readErr := os.ReadFile(payloadPath); readErr == nil {
			logEvt := s.logger.Warn().Err(err).Str("subfeed", feed).Str("url", url)
			if stat, statErr := os.Stat(payloadPath); statErr == nil {
				age := time.Since(stat.ModTime())
				logEvt = logEvt.Dur("cache_age", age)
				if age > staleCacheThreshold {
					logEvt = logEvt.Bool("cache_stale", true)
				}
			}
			logEvt.Msg("upstream unreachable, using cached payload")
			return cached, func() {}, nil
		}
		return nil, nil, errors.With(err, "http request").Set("subfeed", feed, "url", url)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		cached, err := os.ReadFile(payloadPath)
		if err != nil {
			if !retryAllowed {
				return nil, nil, errors.With(err, "304 with missing cache after retry").
					Set("subfeed", feed, "url", url, "payload_path", payloadPath)
			}
			// Upstream told us nothing changed but we have no local copy. Treat
			// this as a cache invariant break — drop the etag and refetch ONCE.
			// Bounded retry so a wedged filesystem (read-only, quota exhausted)
			// doesn't spin forever.
			s.logger.Warn().Str("subfeed", feed).Err(err).
				Msg("304 received but cached payload missing; forcing refetch")
			_ = os.Remove(etagPath)
			return s.fetchPayloadBounded(ctx, feed, url, method, body, contentType, payloadPath, etagPath, false)
		}
		return cached, func() {}, nil
	case http.StatusOK:
		// fall through
	default:
		return nil, nil, errors.WithNew("unexpected status").Set("status", resp.StatusCode, "subfeed", feed, "url", url)
	}

	// Bound the payload size so a compromised or MITM'd upstream cannot OOM
	// veto by serving a gigantic body. The +1 lets us detect truncation: if we
	// read more than maxFeedBytes we know upstream was over the limit and the
	// read was cut short.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, nil, errors.With(err, "read body").Set("subfeed", feed)
	}
	if len(payload) > maxFeedBytes {
		return nil, nil, errors.WithNew("feed payload exceeds size limit").
			Set("limit_bytes", maxFeedBytes, "subfeed", feed, "url", url)
	}

	if err := fsutil.WriteAtomic(payloadPath, payload); err != nil {
		return nil, nil, errors.With(err, "cache payload").Set("subfeed", feed)
	}
	// Stage the etag in a `.pending` sibling. The returned commit closure
	// promotes it only after the body parses cleanly, closing the race where a
	// transient malformed payload could persist an etag pointing at unparseable
	// bytes and 304-loop forever.
	if etag := resp.Header.Get("ETag"); etag != "" {
		if err := fsutil.WriteAtomic(etagPath+".pending", []byte(etag)); err != nil {
			s.logger.Warn().Str("subfeed", feed).Err(err).Msg("write etag.pending")
		}
	}

	commit := func() { s.commitEtag(etagPath) }
	return payload, commit, nil
}

// commitEtag promotes a `.pending` etag file to the canonical path. Called by a
// sub-feed parser after its body parses cleanly. The rename is atomic on POSIX.
func (s *Source) commitEtag(etagPath string) {
	pending := etagPath + ".pending"
	if _, err := os.Stat(pending); err != nil {
		return
	}
	if err := os.Rename(pending, etagPath); err != nil {
		s.logger.Warn().Err(err).Str("from", pending).Str("to", etagPath).Msg("commit etag")
	}
}

// dropEtag removes the canonical and pending etag files for a sub-feed after a
// parse failure, so the next refresh re-downloads instead of 304-looping on the
// same unparseable bytes.
func (s *Source) dropEtag(feed string) {
	_, etagPath := s.cachePaths(feed)
	if err := os.Remove(etagPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn().Str("subfeed", feed).Err(err).Msg("remove etag after parse failure")
	}
	if err := os.Remove(etagPath + ".pending"); err != nil && !os.IsNotExist(err) {
		s.logger.Warn().Str("subfeed", feed).Err(err).Msg("remove etag.pending after parse failure")
	}
}
