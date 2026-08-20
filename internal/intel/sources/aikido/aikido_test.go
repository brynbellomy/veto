package aikido_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
)

const samplePayload = `[
  {"package_name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE"},
  {"package_name": "evil-pkg", "version": "1.0.1", "reason": "MALWARE"},
  {"package_name": "rogue", "version": "9.9.9", "reason": "MALWARE"}
]`

func TestFetchParsesPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/malware_predictions.json", r.URL.Path)
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))
	defer srv.Close()

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	require.Equal(t, "aikido", reports[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "evil-pkg", reports[0].Name)
	require.Equal(t, "1.0.0", reports[0].Version)
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	src, err := aikido.New(aikido.Options{
		BaseURL:  "https://example.invalid",
		CacheDir: t.TempDir(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.Ecosystem("maven"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

func TestFetchEtagShortCircuit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 3)

	second, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, second, 3)

	require.Equal(t, int32(2), hits.Load(), "expected two upstream calls")

	// Cache files exist after both fetches.
	require.FileExists(t, filepath.Join(cacheDir, "npm.json"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"abc123"`, string(etag))
}

// TestFetchCacheOnlyServesFromDiskWithoutNetwork: when the context carries
// the cache-only directive (the CLI's freshness window says the advisory
// set was fetched moments ago), Fetch must serve the on-disk payload
// without any upstream round-trip. A second fetch with a wiped cache must
// fall through to the network — the directive is an optimization, never a
// correctness gate.
func TestFetchCacheOnlyServesFromDiskWithoutNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	// Prime the on-disk cache with a normal (network) fetch.
	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 3)
	require.Equal(t, int32(1), hits.Load())

	// Cache-only fetch: zero upstream hits, same reports.
	reports, err := src.Fetch(intel.WithCacheOnly(context.Background()), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	require.Equal(t, int32(1), hits.Load(), "cache-only fetch must not contact upstream")

	// Wipe the on-disk cache: cache-only must fall back to network.
	require.NoError(t, os.Remove(filepath.Join(cacheDir, "npm.json")))
	reports, err = src.Fetch(intel.WithCacheOnly(context.Background()), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	require.Equal(t, int32(2), hits.Load(), "cache-only with missing cache must fall back to network")
}

// TestFetchRejectsOversizedPayload: a MITM'd or compromised upstream
// cannot OOM veto by serving a multi-GB body. The fetcher caps
// payloads with io.LimitReader; reads past the cap are an error.
//
// Defends against C2 from the audit. The handler streams JSON-shaped
// bytes past the cap; if the cap is honored the fetch errors before
// completion, otherwise the handler would happily write the whole thing.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		const oversize = (256 << 20) + 1024 // 1 KB past the 256 MiB cap
		_, _ = w.Write([]byte("["))
		buf := make([]byte, 1<<20) // 1 MiB chunks
		written := 1
		for written < oversize {
			n, err := w.Write(buf)
			if err != nil {
				return // client closed — expected once we hit the cap
			}
			written += n
		}
	}))
	defer srv.Close()

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "oversized payload must be rejected, not buffered into memory")
	require.Contains(t, err.Error(), "size limit")
}

// TestFetch304WithMissingCacheRetriesOnce verifies S3: if upstream returns
// 304 but our cache is gone, we drop the etag and refetch ONCE — and if
// the refetch ALSO returns 304 (server bug — should never happen without
// If-None-Match, but defensive bound), we surface an error rather than
// spinning. The bounded retry replaces the previous unbounded recursion.
func TestFetch304WithMissingCacheRetriesOnce(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Pre-seed an etag file so the first request includes If-None-Match.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"abc123"`), 0o644))

	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "304 with no cache after retry must surface an error")
	require.LessOrEqual(t, hits.Load(), int64(2),
		"bounded retry must not spin — at most 2 hits (initial + 1 retry)")
}

// TestFetchParseFailureDropsEtag verifies H3: when the body cannot be
// parsed (transient malformed payload, partial upload, etc.), the etag
// must NOT persist to disk pointing at the bad cache. Otherwise the next
// refresh sends If-None-Match, gets 304, re-parses the same bad payload,
// and fails again — perma-failure until the operator wipes the cache.
//
// We simulate this by first serving non-JSON garbage with an etag, then
// flipping the server to serve a valid payload on a second hit. If the
// fix is in place the second fetch hits the server (no 304) and succeeds.
func TestFetchParseFailureDropsEtag(t *testing.T) {
	var hits atomic.Int32
	var serveValid atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// If the client honors a 304-from-cache for the broken payload, we
		// will see If-None-Match on the second hit. Fail loudly in that
		// case rather than silently 304ing — the test wants to assert
		// the etag was dropped after parse failure.
		if r.Header.Get("If-None-Match") == `"broken"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if serveValid.Load() {
			w.Header().Set("ETag", `"good"`)
			_, _ = w.Write([]byte(samplePayload))
			return
		}
		w.Header().Set("ETag", `"broken"`)
		// Non-JSON body — survives the size cap (small) but fails parsePayload.
		_, _ = w.Write([]byte("not valid json at all"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	// First fetch: parse must fail.
	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "garbage payload must fail to parse")

	// Etag file must NOT be present (was either never written or removed
	// after parse failed). If it is present, the next refresh will 304-loop.
	_, statErr := os.Stat(filepath.Join(cacheDir, "npm.etag"))
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable payload (got stat err: %v)", statErr)

	// Flip the server to serve a valid payload and refetch. Without the
	// fix this would send If-None-Match: "broken" and get a 304, then
	// re-parse the same garbage from disk and fail again.
	serveValid.Store(true)
	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "second fetch must succeed after parse-failure recovery")
	require.Len(t, reports, 3)

	// Etag for the GOOD payload should now be persisted.
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"good"`, string(etag))

	require.Equal(t, int32(2), hits.Load(), "exactly two upstream hits expected")
}

func TestFetchNetworkFailureFallsBackToCache(t *testing.T) {
	// First serve the payload to populate the cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write([]byte(samplePayload))
	}))

	cacheDir := t.TempDir()
	src, err := aikido.New(aikido.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Kill the server to simulate network outage.
	srv.Close()

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 3)
}
