package osv_test

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
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
)

// TestFetchGuttedCacheMustNotSilentlyShrink: warm on-disk zip + etag,
// upstream answers 304, and the zip bytes were replaced with a valid but
// gutted zip (one advisory instead of several). The 304 validated only
// the etag; the bytes on disk must be verified separately. Fresh Source
// instance so the in-memory cache cannot short-circuit the disk path —
// the CLI's cold-start shape.
func TestFetchGuttedCacheMustNotSilentlyShrink(t *testing.T) {
	intact := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0", "1.0.1"})
	gutted := makeOSVZip(t, "MAL-2026-2", "someone-else", "npm", []string{"1.0.0"})

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	warm, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	warmReports, err := warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warmReports, 2)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.zip"), gutted, 0o600))

	cold, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	if err != nil {
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache zip must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	require.Len(t, reports, 2,
		"serving the gutted zip is the vulnerability; expected a re-fetch or an error")
	// The re-fetch must have actually happened: at least the warm-up 200
	// plus the 304-then-200 recovery, never just one 304-and-serve.
	require.Greater(t, hits, 1, "the gutted zip must trigger a real re-fetch")
}

// TestFetchGuttedCacheOfflineMustFailClosed: same damage, upstream dead.
// Uses a fresh Source instance so the in-memory cache cannot short-circuit
// the disk path — the CLI's cold-start shape.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	intact := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})
	gutted := makeOSVZip(t, "MAL-2026-2", "someone-else", "npm", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))

	cacheDir := t.TempDir()
	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.zip"), gutted, 0o600))

	cold, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged zip must fail closed, not serve the gutted zip")
}
