package aikido_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
)

// guttedPayload is the parseable-but-gutted damage shape: valid feed JSON
// carrying a single unrelated entry where the intact feed carried three.
const guttedPayload = `[{"package_name": "someone-else", "version": "1.0.0", "reason": "MALWARE"}]`

// TestFetchGuttedCacheMustNotSilentlyShrink: warm cache, upstream answers
// 304 against the intact etag, and the on-disk payload has been replaced
// with a parseable-but-gutted variant. The damaged bytes must never be
// served — either the source re-fetches (network path) or fails closed
// with intel.ErrDamagedCache.
func TestFetchGuttedCacheMustNotSilentlyShrink(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
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

	warm, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warm, 3)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), []byte(guttedPayload), 0o600))

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	if err != nil {
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache payload must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	require.Greater(t, len(reports), 1,
		"serving the gutted payload is the vulnerability; expected a re-fetch or an error")
}

// TestFetchGuttedCacheOfflineMustFailClosed: same damage, upstream dead.
// Serving the damaged bytes offline is the worst variant of the bug.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), []byte(guttedPayload), 0o600))

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged payload must fail closed, not serve the gutted payload")
}
