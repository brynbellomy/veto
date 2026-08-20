package ghsa

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

// ghsaAdvisoryJSON renders one OSV-shaped GHSA advisory for pkg.
func ghsaAdvisoryJSON(pkg string) string {
	return `{
  "id": "GHSA-test-test-test",
  "summary": "known vulnerable",
  "affected": [
    {"package": {"ecosystem": "npm", "name": "` + pkg + `"}, "versions": ["9.9.9"]}
  ]
}`
}

// TestFetchGuttedGobMustNotSilentlyShrink: the gob is the layer the etag
// short-circuit serves from. Damaged gob bytes must fail the content-hash
// check and fall through to re-parse — never silently decode into a
// smaller report set.
func TestFetchGuttedGobMustNotSilentlyShrink(t *testing.T) {
	tarball := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-test/GHSA-test.json": ghsaAdvisoryJSON("vulnerable"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(tarball)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	warm, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	warmReports, err := warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warmReports, 1)

	// Damage every gob on disk. Fresh Source instance so the in-memory
	// cache cannot short-circuit the disk path — the CLI's cold-start
	// shape.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".gob" {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, e.Name()), []byte("damaged gob bytes"), 0o600))
		}
	}

	cold, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "a damaged gob must fall through to re-parse, not error")
	require.Len(t, reports, 1)
	require.Equal(t, "vulnerable", reports[0].Name,
		"a damaged gob must not silently reduce the report set")
}

// TestFetchGuttedTarballMustNotSilentlyShrink: damage the tarball while
// leaving the etag intact and remove the gob so the fetch must go through
// the tarball path. The etag-reuse must verify the tarball's content hash
// and re-download.
func TestFetchGuttedTarballMustNotSilentlyShrink(t *testing.T) {
	tarball := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-test/GHSA-test.json": ghsaAdvisoryJSON("vulnerable"),
	})

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
	warm, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "main.tar.gz"), []byte("gutted tarball"), 0o600))
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".gob" {
			require.NoError(t, os.Remove(filepath.Join(cacheDir, e.Name())))
		}
	}

	cold, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := cold.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "vulnerable", reports[0].Name)
	require.Equal(t, 2, gets, "the damaged tarball must trigger exactly one re-download")
}
