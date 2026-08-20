package pypa_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/pypa"
)

// makePypaTarball builds a small advisory-database-shaped tarball with one
// malware advisory.
func makePypaTarball(t *testing.T, pkg string) []byte {
	t.Helper()
	advisory := `{
  "id": "MAL-2026-1",
  "summary": "malware",
  "affected": [
    {"package": {"ecosystem": "PyPI", "name": "` + pkg + `"}, "versions": ["1.0.0"]}
  ]
}`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "advisory-database-main/vulns/pypi/" + pkg + "/MAL-2026-1/MAL-2026-1.yaml",
		Mode:     0o644,
		Size:     int64(len(advisory)),
		Typeflag: tar.TypeReg,
	}))
	_, err := tw.Write([]byte(advisory))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// TestFetchGuttedCacheMustNotSilentlyShrink: warm tarball + etag,
// upstream answers 304, tarball bytes replaced with a valid-but-gutted
// tarball (different, unrelated advisory). The damaged bytes must not be
// served as validated.
func TestFetchGuttedCacheMustNotSilentlyShrink(t *testing.T) {
	intact := makePypaTarball(t, "evil-pkg")
	gutted := makePypaTarball(t, "someone-else")

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
	src, err := pypa.New(pypa.Options{
		URL:      srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	warm, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.Len(t, warm, 1)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "advisory-database.tar.gz"), gutted, 0o600))

	reports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	if err != nil {
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache tarball must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	require.Len(t, reports, 1, "expected a re-fetch")
	require.Equal(t, "evil-pkg", reports[0].Name,
		"serving the gutted tarball is the vulnerability")
}

// TestFetchGuttedCacheOfflineMustFailClosed: same damage, upstream dead.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	intact := makePypaTarball(t, "evil-pkg")
	gutted := makePypaTarball(t, "someone-else")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(intact)
	}))

	cacheDir := t.TempDir()
	src, err := pypa.New(pypa.Options{
		URL:      srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "advisory-database.tar.gz"), gutted, 0o600))

	_, err = src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged tarball must fail closed, not serve the gutted payload")
}
