package govulndb

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
)

// TestFetchGuttedCacheMustNotSilentlyShrink: warm zip + etag, upstream
// answers 304, zip bytes replaced with a valid-but-gutted zip (unrelated
// advisory). Fresh Source instance so the in-memory cache cannot
// short-circuit the disk path — the CLI's cold-start shape.
func TestFetchGuttedCacheMustNotSilentlyShrink(t *testing.T) {
	intact := writeZipBytes(t, realFixtureFiles)
	gutted := writeZipBytes(t, map[string]string{
		"ID/GO-2099-0001.json": fixtureVersions(
			"GO-2099-0001",
			"someone else's advisory",
			"example.com/someone-else",
			[]string{"1.0.0"},
		),
	})

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
	warm, err := New(Options{
		ZipURL:   srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	warmReports, err := warm.Fetch(context.Background(), intel.EcosystemGo)
	require.NoError(t, err)
	require.Len(t, warmReports, 2)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "vulndb.zip"), gutted, 0o600))

	cold, err := New(Options{
		ZipURL:   srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemGo)
	if err != nil {
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache zip must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	require.Len(t, reports, 2, "expected a re-fetch")
	require.Greater(t, hits, 1, "the gutted zip must trigger a real re-fetch")
}

// TestFetchGuttedCacheOfflineMustFailClosed: same damage, upstream dead.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	intact := writeZipBytes(t, realFixtureFiles)
	gutted := writeZipBytes(t, map[string]string{
		"ID/GO-2099-0001.json": fixtureVersions(
			"GO-2099-0001",
			"someone else's advisory",
			"example.com/someone-else",
			[]string{"1.0.0"},
		),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))

	cacheDir := t.TempDir()
	warm, err := New(Options{
		ZipURL:   srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = warm.Fetch(context.Background(), intel.EcosystemGo)
	require.NoError(t, err)

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "vulndb.zip"), gutted, 0o600))

	cold, err := New(Options{
		ZipURL:   srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = cold.Fetch(context.Background(), intel.EcosystemGo)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged zip must fail closed, not serve the gutted payload")
}
