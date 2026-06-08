package abusech_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/ioc/sources/abusech"
)

// malformedJSON returns a body that parses cleanly as CSV (so the CSV feeds
// don't error) but is invalid JSON, used to fail a single JSON sub-feed in
// isolation.
const malformedJSON = "{ this is not valid json"

// servePerFeed builds a server where each feed path returns the body chosen for
// it, so a test can selectively corrupt one sub-feed.
func servePerFeed(t *testing.T, bodies map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := bodies[r.URL.Path]; ok {
			w.Header().Set("ETag", `"x"`)
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
}

// TestFeodoMalformedJSONDropsEtag confirms a malformed Feodo payload is skipped
// (the whole Fetch still succeeds via isolation) and that no etag persists for
// the unparseable body, so the next refresh re-downloads instead of 304-looping.
func TestFeodoMalformedJSONDropsEtag(t *testing.T) {
	bodies := map[string][]byte{
		"/bazaar":    []byte("# header\n"),
		"/feodo":     []byte(malformedJSON),
		"/urlhaus":   []byte("# header\n"),
		"/threatfox": []byte(`{"query_status":"ok","data":[]}`),
	}
	srv := servePerFeed(t, bodies)
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := abusech.New(abusech.Options{
		CacheDir:     cacheDir,
		AuthKey:      testAuthKey,
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL + "/bazaar",
		FeodoURL:     srv.URL + "/feodo",
		URLhausURL:   srv.URL + "/urlhaus",
		ThreatFoxURL: srv.URL + "/threatfox",
	})
	require.NoError(t, err)

	// Isolation: the malformed sub-feed is skipped, so Fetch itself succeeds.
	_, err = src.Fetch(context.Background())
	require.NoError(t, err)

	// The etag for the malformed feed must NOT persist.
	_, statErr := os.Stat(filepath.Join(cacheDir, "feodo.etag"))
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable feodo payload (stat err: %v)", statErr)
}

// TestThreatFoxMalformedJSONDropsEtag is the ThreatFox analogue of the Feodo
// malformed-payload case.
func TestThreatFoxMalformedJSONDropsEtag(t *testing.T) {
	bodies := map[string][]byte{
		"/bazaar":    []byte("# header\n"),
		"/feodo":     []byte("[]"),
		"/urlhaus":   []byte("# header\n"),
		"/threatfox": []byte(malformedJSON),
	}
	srv := servePerFeed(t, bodies)
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := abusech.New(abusech.Options{
		CacheDir:     cacheDir,
		AuthKey:      testAuthKey,
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL + "/bazaar",
		FeodoURL:     srv.URL + "/feodo",
		URLhausURL:   srv.URL + "/urlhaus",
		ThreatFoxURL: srv.URL + "/threatfox",
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background())
	require.NoError(t, err)

	_, statErr := os.Stat(filepath.Join(cacheDir, "threatfox.etag"))
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable threatfox payload (stat err: %v)", statErr)
}

// TestFetchNetworkFailureFallsBackToCache confirms a cached payload still
// satisfies a sub-feed when upstream is unreachable on a later refresh.
func TestFetchNetworkFailureFallsBackToCache(t *testing.T) {
	bodies := map[string][]byte{
		"/bazaar":    loadFixture(t, "malwarebazaar_recent.csv"),
		"/feodo":     loadFixture(t, "feodo_ipblocklist.json"),
		"/urlhaus":   loadFixture(t, "urlhaus_recent.csv"),
		"/threatfox": loadFixture(t, "threatfox_get_iocs.json"),
	}
	srv := servePerFeed(t, bodies)

	cacheDir := t.TempDir()
	src, err := abusech.New(abusech.Options{
		CacheDir:     cacheDir,
		AuthKey:      testAuthKey,
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL + "/bazaar",
		FeodoURL:     srv.URL + "/feodo",
		URLhausURL:   srv.URL + "/urlhaus",
		ThreatFoxURL: srv.URL + "/threatfox",
	})
	require.NoError(t, err)

	first, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first)

	// Simulate a total outage; cached payloads must keep Fetch working.
	srv.Close()

	second, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.Equal(t, len(first), len(second),
		"cached payloads must reproduce the same indicator set offline")
}
