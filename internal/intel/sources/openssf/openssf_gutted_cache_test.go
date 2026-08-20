package openssf_test

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
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
)

// TestFetchGuttedGobMustNotSilentlyShrink: the parsed-report gob is the
// cache layer the etag short-circuit actually serves from. Damaging its
// bytes (truncating the gob mid-stream so it decodes to a smaller report
// set, or overwriting it entirely) must not silently reduce coverage:
// the gob load fails its content-hash check and the source falls through
// to re-download and re-parse.
func TestFetchGuttedGobMustNotSilentlyShrink(t *testing.T) {
	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(tarball)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	warm, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warm, 1)
	require.True(t, hasGobFile(t, cacheDir), "warm-up must leave a parsed gob on disk")

	// Damage every gob on disk: overwrite with arbitrary bytes. The next
	// fetch must NOT decode those bytes into reports — it must fall
	// through to the tarball path. Fresh Source instance so the
	// in-memory cache cannot short-circuit the disk path (the CLI's
	// cold-start shape).
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".gob" {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, e.Name()), []byte("damaged gob bytes"), 0o600))
		}
	}

	cold, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "a damaged gob must fall through to re-parse, not error")
	require.Len(t, reports, 1,
		"a damaged gob must not silently reduce the report set")
	require.Equal(t, "evil-pkg", reports[0].Name)
}

// TestFetchGuttedTarballMustNotSilentlyShrink: damage the tarball payload
// itself while leaving the etag intact. The etag-reuse path must verify
// the tarball's content hash and re-download instead of re-parsing the
// damaged bytes. Uses a fresh Source instance so the in-memory cache
// cannot short-circuit the disk path (the CLI's cold-start shape).
func TestFetchGuttedTarballMustNotSilentlyShrink(t *testing.T) {
	tarball := makeMaliciousPackagesTarball(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})

	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			gets++
			_, _ = w.Write(tarball)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	warm, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Damage the tarball. Also remove the gob so the fetch must go
	// through the tarball path rather than the (still-valid) gob layer.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "main.tar.gz"), []byte("gutted tarball"), 0o600))
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".gob" {
			require.NoError(t, os.Remove(filepath.Join(cacheDir, e.Name())))
		}
	}

	// Cold start against the damaged tarball.
	cold, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1, "damaged tarball must be re-downloaded and re-parsed")
	require.Equal(t, "evil-pkg", reports[0].Name)
	require.Equal(t, 2, gets, "the damaged tarball must trigger exactly one re-download")
}
