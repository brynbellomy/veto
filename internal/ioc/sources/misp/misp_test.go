package misp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/ioc"
)

// feedServer serves the testdata/ fixtures as a MISP feed and counts the GETs
// per path, so tests can assert which events were (re)downloaded. The manifest
// is held in memory so a test can mutate per-event timestamps to simulate a
// feed update; event documents are read from disk on each request.
type feedServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	gets     map[string]int
	manifest []byte
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join("testdata", "manifest.json"))
	require.NoError(t, err)

	fs := &feedServer{gets: map[string]int{}, manifest: manifest}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		fs.mu.Lock()
		fs.gets[name]++
		manifestCopy := fs.manifest
		fs.mu.Unlock()

		if name == "manifest.json" {
			_, _ = w.Write(manifestCopy)
			return
		}

		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) getCount(name string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.gets[name]
}

// bumpManifestTimestamp rewrites the in-memory manifest so the given event's
// timestamp becomes newTS, simulating an upstream feed update for that event.
func bumpManifestTimestamp(t *testing.T, fs *feedServer, uuid, newTS string) {
	t.Helper()
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var m map[string]map[string]any
	require.NoError(t, json.Unmarshal(fs.manifest, &m))
	entry, ok := m[uuid]
	require.True(t, ok, "event %s not in manifest", uuid)
	entry["timestamp"] = newTS

	updated, err := json.Marshal(m)
	require.NoError(t, err)
	fs.manifest = updated
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func newSource(t *testing.T, feedURL string) *Source {
	t.Helper()
	src, err := New(Options{
		FeedURL:  feedURL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)
	return src
}

// indexByTypeValue keys indicators by (type, value) for assertion lookups.
func indexByTypeValue(inds []ioc.Indicator) map[string]ioc.Indicator {
	m := make(map[string]ioc.Indicator, len(inds))
	for _, in := range inds {
		m[string(in.Type)+"|"+in.Value] = in
	}
	return m
}

func TestFetchExtractsAllTypesNormalized(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)
	src := newSource(t, fs.srv.URL)

	inds, err := src.Fetch(context.Background())
	require.NoError(t, err)

	by := indexByTypeValue(inds)

	// Event 1: every mapped type, each value normalized.
	require.Contains(t, by, "sha256|abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd",
		"sha256 lowercased")
	require.Contains(t, by, "sha1|da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1 lowercased")
	require.Contains(t, by, "md5|d41d8cd98f00b204e9800998ecf8427e", "md5 passthrough")
	require.Contains(t, by, "domain|evil.example.com", "domain lowercased + trailing dot stripped")
	require.Contains(t, by, "domain|host.bad.example", "hostname mapped to domain")
	require.Contains(t, by, "ipv4|203.0.113.7", "ip-src dotted-quad")
	require.Contains(t, by, "ipv4|198.51.100.22", "ip-dst dotted-quad")
	require.Contains(t, by, "url|http://bad.example.com/Path/To?q=1",
		"url scheme+host lowercased, path preserved")

	// Skipped: IPv6, CIDR, and the unmapped "link" type must not appear.
	require.NotContains(t, by, "ipv4|2001:db8::1")
	for k := range by {
		require.NotContains(t, k, "10.0.0.0", "CIDR must be skipped")
		require.NotContains(t, k, "blog.example.com", "unmapped link type must be skipped")
	}

	// SourceID, Reference (event UUID), and a display-only ThreatLabel are set.
	sha := by["sha256|abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"]
	require.Equal(t, sourceID, sha.SourceID)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", sha.Reference)
	require.Equal(t, "Payload delivery", sha.ThreatLabel)
	require.False(t, sha.PublishedAt.IsZero(), "attribute timestamp populates PublishedAt")
}

func TestFetchCompositeHashesAndNestedObjects(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)
	src := newSource(t, fs.srv.URL)

	inds, err := src.Fetch(context.Background())
	require.NoError(t, err)

	by := indexByTypeValue(inds)

	// Event 2: composite types contribute only their hash half, lowercased.
	require.Contains(t, by, "md5|5d41402abc4b2a76b9719d911017c592", "filename|md5 -> md5 hash half")
	require.Contains(t, by,
		"sha256|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"filename|sha256 -> sha256 hash half")

	// The filename half must never leak in as a value.
	for k := range by {
		require.NotContains(t, k, "evil.exe")
		require.NotContains(t, k, "dropper.bin")
	}

	// Nested MISP Object attributes are harvested too.
	require.Contains(t, by, "sha1|356a192b7913b04c54574d18c28d46e6395428ab", "nested object sha1")
	require.Contains(t, by, "domain|nested.example.org", "nested object domain")
}

func TestFetchSkipsMalformedEventNotFatal(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)
	src := newSource(t, fs.srv.URL)

	// The malformed event (33333333…) is in the manifest, but its broken JSON
	// must be dropped without failing the whole fetch — events 1 and 2 still
	// produce indicators.
	inds, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, inds)

	by := indexByTypeValue(inds)
	require.Contains(t, by, "md5|d41d8cd98f00b204e9800998ecf8427e")
	require.Contains(t, by, "sha1|356a192b7913b04c54574d18c28d46e6395428ab")
}

func TestFetchUnchangedManifestShortCircuitsEventDownloads(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)
	src := newSource(t, fs.srv.URL)

	first, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first)

	// Each well-formed event was fetched exactly once on the cold pass.
	require.Equal(t, 1, fs.getCount("11111111-1111-1111-1111-111111111111.json"))
	require.Equal(t, 1, fs.getCount("22222222-2222-2222-2222-222222222222.json"))

	second, err := src.Fetch(context.Background())
	require.NoError(t, err)

	// Same indicator set, served from the per-event on-disk cache: the manifest
	// is re-fetched but no event JSON is re-downloaded because the manifest
	// timestamps are unchanged.
	require.ElementsMatch(t, first, second)
	require.Equal(t, 2, fs.getCount("manifest.json"), "manifest re-fetched each call")
	require.Equal(t, 1, fs.getCount("11111111-1111-1111-1111-111111111111.json"),
		"unchanged event served from cache, not re-downloaded")
	require.Equal(t, 1, fs.getCount("22222222-2222-2222-2222-222222222222.json"),
		"unchanged event served from cache, not re-downloaded")
}

func TestFetchChangedManifestTimestampReDownloads(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)

	// Share a cache dir across two sources so the second sees the first's
	// on-disk extractions but a bumped manifest timestamp forces a re-download.
	cacheDir := t.TempDir()
	mk := func() *Source {
		s, err := New(Options{FeedURL: fs.srv.URL, CacheDir: cacheDir, Logger: zerolog.Nop()})
		require.NoError(t, err)
		return s
	}

	_, err := mk().Fetch(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, fs.getCount("11111111-1111-1111-1111-111111111111.json"))

	// Bump event 1's manifest timestamp; its cached extraction is now stale.
	bumpManifestTimestamp(t, fs, "11111111-1111-1111-1111-111111111111", "1700000000")

	_, err = mk().Fetch(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, fs.getCount("11111111-1111-1111-1111-111111111111.json"),
		"changed timestamp re-downloads the event")
	require.Equal(t, 1, fs.getCount("22222222-2222-2222-2222-222222222222.json"),
		"unchanged sibling event still served from cache")
}

func TestFetchHTTPErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	src := newSource(t, srv.URL)
	_, err := src.Fetch(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected misp manifest status")
}

func TestFetchManifestUnreachableUsesInMemoryCache(t *testing.T) {
	t.Parallel()

	fs := newFeedServer(t)
	src := newSource(t, fs.srv.URL)

	first, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first)

	// Point the source at a dead URL; a prior successful fetch means the
	// in-memory cache answers rather than failing the fetch.
	src.feedURL = mustParseURL(t, "http://127.0.0.1:1/dead/")
	second, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, first, second)
}

func TestNewRequiresCacheDir(t *testing.T) {
	t.Parallel()

	_, err := New(Options{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "CacheDir is required")
}

func TestNewDefaultsToCIRCLFeed(t *testing.T) {
	t.Parallel()

	src, err := New(Options{CacheDir: t.TempDir(), Logger: zerolog.Nop()})
	require.NoError(t, err)
	require.Equal(t, defaultFeedURL, src.feedURL.String())
	require.Equal(t, "misp", src.ID())
}
