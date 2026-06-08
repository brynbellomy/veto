// Package misp implements ioc.Source for a MISP feed, defaulting to CIRCL's
// public OSINT feed at https://www.circl.lu/doc/misp/feed-osint/.
//
// A MISP feed is a flat directory served over HTTP:
//
//	manifest.json   — map of event UUID -> event metadata (info, timestamp, ...)
//	<uuid>.json     — one MISP Event document per manifest entry
//
// The CIRCL OSINT feed is unauthenticated; no API key is required. We read the
// manifest, then fetch each event document and extract its indicator
// attributes. Because the feed holds thousands of events but only a handful
// change between refreshes, the manifest's per-event Unix `timestamp` drives an
// aggressive cache: an event whose manifest timestamp is unchanged since the
// last fetch is served from its on-disk extraction and never re-downloaded.
//
// Attribute mapping (MISP attribute `type` -> ioc.IndicatorType):
//
//	md5 / sha1 / sha256              -> IndicatorMD5 / SHA1 / SHA256
//	filename|md5 / |sha1 / |sha256   -> same, taking the hash half of the composite
//	domain / hostname                -> IndicatorDomain
//	ip-src / ip-dst                  -> IndicatorIPv4 (IPv6 and CIDR are skipped)
//	url                              -> IndicatorURL
//
// Every emitted Indicator.Value is normalized: lowercase hex for hashes,
// lowercase host for domains/URLs, canonical dotted-quad for IPv4.
//
// CIRCL distributes the OSINT feed publicly for use in MISP instances; it
// carries no machine-readable per-event license, and the feed as a whole is
// published by CIRCL (Computer Incident Response Center Luxembourg) for open
// consumption. Individual events may carry their own TLP tags in the data;
// veto treats the indicators as display-and-match data only.
package misp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/ioc"
)

const (
	// defaultFeedURL is CIRCL's public OSINT MISP feed root. The trailing
	// slash matters: manifest and event paths are resolved relative to it.
	defaultFeedURL = "https://www.circl.lu/doc/misp/feed-osint/"

	sourceID = "misp"

	// maxConcurrency bounds the number of in-flight per-event downloads inside
	// a single Fetch. The CIRCL host serves many small files; a handful of
	// parallel requests keeps a full cold sync brisk without hammering the
	// upstream or exhausting local sockets.
	maxConcurrency = 8

	// maxManifestBytes caps the manifest.json download. The CIRCL manifest is
	// a few MB of UUID->metadata entries; 64 MiB is far more than it will ever
	// need and stops a MITM'd or compromised upstream from OOMing veto by
	// streaming a multi-GB body.
	maxManifestBytes = 64 << 20

	// maxEventBytes bounds each per-event JSON document. Real MISP events run
	// from a few KB to a few MB (large hash dumps); 32 MiB is generous and
	// stops one pathological event from exhausting memory.
	maxEventBytes = 32 << 20

	// maxTotalEventBytes caps the cumulative bytes pulled across all per-event
	// downloads in a single Fetch, independent of the per-event cap. Without
	// it a feed that grew to millions of small events could still stream an
	// unbounded total. 512 MiB covers the entire CIRCL OSINT corpus with room
	// to spare; exceeding it aborts the fetch rather than persisting a partial
	// set silently.
	maxTotalEventBytes = 512 << 20
)

// Options configures the MISP feed source.
type Options struct {
	// FeedURL overrides the feed root (the directory holding manifest.json and
	// the per-event <uuid>.json files). Defaults to the CIRCL OSINT feed. A
	// trailing slash is added if absent.
	FeedURL string

	// CacheDir is where the manifest copy and per-event extractions live.
	// Required; typically ~/.cache/veto/misp.
	CacheDir string

	// HTTPClient overrides the default 2-minute-timeout client.
	HTTPClient *http.Client

	// Logger receives structured log events.
	Logger zerolog.Logger
}

// Source is the MISP-feed implementation of ioc.Source.
//
// Fetch is safe for concurrent use: a single mutex serializes manifest
// refreshes and guards the in-memory cache, and the per-event fan-out it spawns
// is bounded and joined before Fetch returns.
type Source struct {
	feedURL  *url.URL
	cacheDir string
	client   *http.Client
	logger   zerolog.Logger

	mu     sync.Mutex
	cached []ioc.Indicator
	loaded bool
}

var _ ioc.Source = (*Source)(nil)

// New builds a MISP feed source. CacheDir is required and is created (0700) if
// absent. An invalid FeedURL is a caller fault and fails construction.
func New(opts Options) (*Source, error) {
	if opts.CacheDir == "" {
		return nil, errors.New("misp: CacheDir is required")
	}
	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "misp: create cache dir").Set("path", opts.CacheDir)
	}
	if err := os.Chmod(opts.CacheDir, 0o700); err != nil {
		return nil, errors.With(err, "misp: tighten cache dir perms").Set("path", opts.CacheDir)
	}
	if err := os.MkdirAll(filepath.Join(opts.CacheDir, "events"), 0o700); err != nil {
		return nil, errors.With(err, "misp: create event cache dir").Set("path", opts.CacheDir)
	}

	raw := opts.FeedURL
	if raw == "" {
		raw = defaultFeedURL
	}
	if !strings.HasSuffix(raw, "/") {
		raw += "/"
	}
	feedURL, err := url.Parse(raw)
	if err != nil {
		return nil, errors.With(err, "misp: invalid FeedURL").Set(errors.FaultCaller, "url", raw)
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}

	return &Source{
		feedURL:  feedURL,
		cacheDir: opts.CacheDir,
		client:   client,
		logger:   opts.Logger.With().Str("component", "ioc.misp").Logger(),
	}, nil
}

// ID implements ioc.Source.
func (s *Source) ID() string { return sourceID }

// Fetch implements ioc.Source. It downloads the feed manifest, fetches the
// per-event documents that changed since the last call (reusing on-disk
// extractions for the rest), and returns every indicator the feed currently
// reports. The per-event fan-out respects ctx cancellation and is bounded to
// maxConcurrency in-flight requests.
func (s *Source) Fetch(ctx context.Context) ([]ioc.Indicator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	manifest, err := s.fetchManifest(ctx)
	if err != nil {
		// Manifest unreachable: fall back to the in-memory cache from a prior
		// successful fetch so a transient upstream blip doesn't blind the store.
		if s.loaded {
			s.logger.Warn().Err(err).Msg("misp manifest unreachable, using in-memory cache")
			return s.cached, nil
		}
		return nil, errors.With(err, "misp fetch manifest")
	}

	indicators, err := s.collectEvents(ctx, manifest)
	if err != nil {
		return nil, err
	}

	s.cached = indicators
	s.loaded = true
	s.logger.Info().
		Int("events", len(manifest)).
		Int("indicators", len(indicators)).
		Msg("misp feed parsed")
	return indicators, nil
}

// fetchManifest downloads and parses manifest.json. The manifest is small
// relative to the event corpus and changes on every feed update, so it is
// fetched unconditionally (no etag) and capped at maxManifestBytes.
func (s *Source) fetchManifest(ctx context.Context) (manifest, error) {
	manifestURL := s.feedURL.JoinPath("manifest.json").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, errors.With(err, "build manifest request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.With(err, "manifest request").Set("url", manifestURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithNew("unexpected misp manifest status").
			Set("status", resp.StatusCode, "url", manifestURL)
	}

	body, err := readCapped(resp.Body, maxManifestBytes)
	if err != nil {
		return nil, errors.With(err, "read manifest").Set("url", manifestURL)
	}

	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, errors.With(err, "parse manifest").Set("url", manifestURL)
	}
	return m, nil
}

// collectEvents resolves the manifest to a flat indicator set. For each event
// it serves from the on-disk extraction when the manifest timestamp is
// unchanged, otherwise it downloads and re-parses the event. Downloads are
// fanned out with bounded concurrency and joined before returning; an
// individual event that fails to download or parse is logged and skipped so one
// bad event never blinds the source to the rest.
func (s *Source) collectEvents(ctx context.Context, m manifest) ([]ioc.Indicator, error) {
	type result struct {
		uuid       string
		indicators []ioc.Indicator
	}

	var (
		mu         sync.Mutex
		results    = make([]result, 0, len(m))
		totalBytes int64
		overCap    bool
	)

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

loop:
	for uuid, meta := range m {
		// Cache short-circuit: a cached extraction whose recorded manifest
		// timestamp matches the current one is authoritative — skip the
		// network entirely.
		if cached, ok := s.readEventCache(uuid, meta.Timestamp.Unix()); ok {
			// A worker launched in a prior iteration may be appending
			// concurrently, so guard this append with the same mutex.
			mu.Lock()
			results = append(results, result{uuid: uuid, indicators: cached})
			mu.Unlock()
			continue
		}

		// Acquire a concurrency slot, or stop launching new downloads once the
		// caller cancels. Acquire and release are balanced: a slot is only
		// drained by a goroutine that successfully sent into sem.
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(uuid string, meta eventMeta) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			indicators, n, err := s.fetchEvent(ctx, uuid, meta)
			if err != nil {
				s.logger.Debug().Err(err).Str("event", uuid).Msg("skip misp event")
				return
			}

			mu.Lock()
			defer mu.Unlock()
			totalBytes += n
			if totalBytes > maxTotalEventBytes {
				overCap = true
				return
			}
			results = append(results, result{uuid: uuid, indicators: indicators})
		}(uuid, meta)
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, errors.With(err, "misp fetch cancelled")
	}
	if overCap {
		return nil, errors.WithNew("misp event downloads exceed total size limit").
			Set("limit_bytes", maxTotalEventBytes)
	}

	var indicators []ioc.Indicator
	for _, r := range results {
		indicators = append(indicators, r.indicators...)
	}
	return indicators, nil
}

// fetchEvent downloads one per-event document, extracts its indicators, and
// persists the extraction to the on-disk cache keyed by the manifest timestamp.
// It returns the extracted indicators and the number of bytes downloaded.
func (s *Source) fetchEvent(ctx context.Context, uuid string, meta eventMeta) ([]ioc.Indicator, int64, error) {
	eventURL := s.feedURL.JoinPath(uuid + ".json").String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, eventURL, nil)
	if err != nil {
		return nil, 0, errors.With(err, "build event request")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, errors.With(err, "event request").Set("url", eventURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, errors.WithNew("unexpected misp event status").
			Set("status", resp.StatusCode, "url", eventURL)
	}

	body, err := readCapped(resp.Body, maxEventBytes)
	if err != nil {
		return nil, 0, errors.With(err, "read event").Set("url", eventURL)
	}

	indicators, err := extractEvent(body, sourceID)
	if err != nil {
		return nil, int64(len(body)), errors.With(err, "parse event").Set("url", eventURL)
	}

	s.writeEventCache(uuid, meta.Timestamp.Unix(), indicators)
	return indicators, int64(len(body)), nil
}

// readCapped reads up to limit bytes from r, returning an error if the body
// would exceed the cap. Reading limit+1 lets us distinguish "exactly at the
// cap" from "over the cap" without trusting Content-Length.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, errors.With(err, "read body")
	}
	if int64(len(body)) > limit {
		return nil, errors.WithNew("response exceeds size limit").Set("limit_bytes", limit)
	}
	return body, nil
}
