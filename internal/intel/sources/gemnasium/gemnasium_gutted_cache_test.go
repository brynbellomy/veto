package gemnasium

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

// TestFetchGuttedCacheMustNotSilentlyShrink: warm tarball + etag, upstream
// answers 304, tarball bytes replaced with a valid-but-gutted tarball
// (advisory for a different package). The damaged bytes must not be
// served as validated.
func TestFetchGuttedCacheMustNotSilentlyShrink(t *testing.T) {
	intact := makeTarball(t, map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml": readFixture(t, "npm_lodash.yml"),
	})
	gutted := makeTarball(t, map[string]string{
		"advisories-community-main/npm/someone-else/CVE-2020-0001.yml": readFixture(t, "npm_lodash.yml"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	warm, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warm, 1)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "advisories-community.tar.gz"), gutted, 0o600))

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	if err != nil {
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache tarball must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	require.Len(t, reports, 1, "expected a re-fetch")
	require.Equal(t, "lodash", reports[0].Name,
		"serving the gutted tarball is the vulnerability")
}

// TestFetchGuttedCacheOfflineMustFailClosed: same damage, upstream dead.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	intact := makeTarball(t, map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml": readFixture(t, "npm_lodash.yml"),
	})
	gutted := makeTarball(t, map[string]string{
		"advisories-community-main/npm/someone-else/CVE-2020-0001.yml": readFixture(t, "npm_lodash.yml"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))

	cacheDir := t.TempDir()
	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "advisories-community.tar.gz"), gutted, 0o600))

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged tarball must fail closed, not serve the gutted payload")
}
