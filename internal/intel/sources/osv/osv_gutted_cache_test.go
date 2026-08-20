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

// TestFetchCacheOnlyGuttedZipMustNotServe is the merged-configuration
// regression for the zip shape: freshness window active (CacheOnly
// directive) + gutted on-disk zip. The cache-only early return must
// consult the zip's content hash; a mismatch falls through to the network
// path, which re-downloads and re-records. Fresh Source instance so the
// in-memory cache cannot short-circuit the disk path.
func TestFetchCacheOnlyGuttedZipMustNotServe(t *testing.T) {
	intact := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0", "1.0.1"})
	gutted := makeOSVZip(t, "MAL-2026-2", "someone-else", "npm", []string{"1.0.0"})

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
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
	_, err = warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Gut the on-disk zip.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.zip"), gutted, 0o600))

	// Cold source (fresh in-memory state) + cache-only directive.
	cold, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "mismatch under cache-only falls through to network, which heals")
	require.Len(t, reports, 2,
		"the gutted zip must not be served under the cache-only directive")
	require.Greater(t, hits, 1, "the mismatch must trigger a real re-fetch")
	for _, r := range reports {
		require.Equal(t, "evil-pkg", r.Name,
			"no report may come from the gutted zip")
	}
}

// TestFetchCacheOnlyUnrecordedZipServesButDoesNotAdopt pins rule 3 for
// the zip shape: a pre-integrity-fix zip serves under cache-only but its
// hash is never adopted without upstream validation.
func TestFetchCacheOnlyUnrecordedZipServesButDoesNotAdopt(t *testing.T) {
	intact := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Pre-integrity-fix cache: zip + etag, no sidecar.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.zip"), intact, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"v1"`), 0o600))

	src, err := osv.New(osv.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := src.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "an unrecorded zip must still serve under cache-only")
	require.Len(t, reports, 1)

	_, statErr := os.Stat(filepath.Join(cacheDir, "npm.zip.sha256"))
	require.True(t, os.IsNotExist(statErr),
		"cache-only must NOT adopt (record) the hash of an unvalidated zip")
}
