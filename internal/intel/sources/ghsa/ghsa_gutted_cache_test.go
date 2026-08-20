package ghsa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestFetchCacheOnlyGuttedTarballMustNotServe is the merged-configuration
// regression for the gob/tarball shape: freshness window active (CacheOnly
// directive, which skips the upstream HEAD probe entirely) + gutted
// on-disk tarball. The cache-only early return must gate BOTH local
// layers — the parsed gob AND the raw tarball fallback — on their content
// hashes. A mismatch on either falls through to the network path.
func TestFetchCacheOnlyGuttedTarballMustNotServe(t *testing.T) {
	tarball := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-test/GHSA-test.json": ghsaAdvisoryJSON("vulnerable"),
	})
	gutted := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-other/GHSA-other.json": ghsaAdvisoryJSON("someone-else"),
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

	// Gut the tarball AND remove the gob so the cache-only path must go
	// through the raw-tarball fallback — the layer with no gate today.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "main.tar.gz"), gutted, 0o600))
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gob") {
			require.NoError(t, os.Remove(filepath.Join(cacheDir, e.Name())))
		}
	}

	// Cold source (fresh in-memory state) + cache-only directive.
	cold, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "mismatch under cache-only falls through to network, which heals")
	require.Len(t, reports, 1,
		"the gutted tarball must not be served under the cache-only directive")
	require.Equal(t, "vulnerable", reports[0].Name,
		"no report may come from the gutted tarball")
	require.Greater(t, gets, 0, "the mismatch must trigger a real re-download")
}

// TestFetchCacheOnlyGuttedGobMustNotServe: same scenario but the gob layer
// is the damaged one (tarball removed). The gob's content-hash gate must
// reject it and the fetch must fall through to the network path.
func TestFetchCacheOnlyGuttedGobMustNotServe(t *testing.T) {
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

	// Damage the gob; remove the tarball so the gob is the only local layer.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gob") {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, e.Name()), []byte("damaged gob bytes"), 0o600))
		}
	}
	require.NoError(t, os.Remove(filepath.Join(cacheDir, "main.tar.gz")))

	cold, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "a damaged gob must fall through to the network path, which re-parses")
	require.Len(t, reports, 1)
	require.Equal(t, "vulnerable", reports[0].Name,
		"no report may come from the damaged gob")
}

// TestFetchCacheOnlyUnrecordedGobServesButDoesNotAdopt pins rule 3 for the
// gob shape — and is the regression for the hazard where readGobFile's
// Unrecorded branch adopted on the justification "the caller only reaches
// the gob when the etag matched upstream." Under CacheOnly that
// precondition is false: ensureLoaded's cache-only path calls loadGob("")
// having skipped the HEAD probe entirely. Serving is correct; adopting
// is not.
func TestFetchCacheOnlyUnrecordedGobServesButDoesNotAdopt(t *testing.T) {
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
	_, err = warm.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Strip the gob's sidecar, simulating a pre-integrity-fix gob.
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	var gobName string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gob") {
			gobName = e.Name()
			require.NoError(t, os.Remove(filepath.Join(cacheDir, e.Name()+".sha256")))
		}
	}
	require.NotEmpty(t, gobName, "warm-up must leave a parsed gob on disk")

	// Remove the tarball too so the gob is the layer that serves.
	require.NoError(t, os.Remove(filepath.Join(cacheDir, "main.tar.gz")))

	cold, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "an unrecorded gob must still serve under cache-only")
	require.Len(t, reports, 1)
	require.Equal(t, "vulnerable", reports[0].Name)

	_, statErr := os.Stat(filepath.Join(cacheDir, gobName+".sha256"))
	require.True(t, os.IsNotExist(statErr),
		"cache-only must NOT adopt (record) the hash of an unvalidated gob")
}
