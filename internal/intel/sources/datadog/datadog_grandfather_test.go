package datadog_test

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
	"github.com/brynbellomy/veto/internal/intel/sources/datadog"
)

// TestFetchGrandfatheredCacheAdoptsHashOn304 pins the steady-state
// adoption path: a cache written before content binding (no .sha256
// sidecar) that passes a live 304 must get its hash recorded on that
// very fetch. Without this, a cache whose etag never changes would stay
// permanently grandfathered and the content-binding layer would never
// engage for it.
func TestFetchGrandfatheredCacheAdoptsHashOn304(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"npm-1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"npm-1"`)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Simulate a pre-integrity-fix cache: payload + etag on disk, no
	// sidecar.
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.json"), fixture, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "npm.etag"), []byte(`"npm-1"`), 0o600))
	_, statErr := os.Stat(filepath.Join(cacheDir, "npm.json.sha256"))
	require.True(t, os.IsNotExist(statErr), "test setup: cache must start without a sidecar")

	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "a grandfathered cache serving a live 304 must load")
	require.Len(t, reports, 7)

	// The sidecar must now exist — the 304-adopted payload is bound from
	// here on.
	require.FileExists(t, filepath.Join(cacheDir, "npm.json.sha256"),
		"a grandfathered payload that passes a live 304 must have its hash adopted")

	// And damage after adoption must be caught by the hash gate: same
	// fetch sequence, gutted payload, 304-answering upstream → re-fetch.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), []byte(guttedManifest), 0o600))

	recovered, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "post-adoption damage must be repaired by re-fetch")
	require.Len(t, recovered, 7, "the re-fetched manifest must be the intact one")
	// Hit 1: the adopting 304. Hit 2: the damage is caught by the
	// pre-request hash gate (etag present, hash mismatch → conditional
	// header dropped), so the upstream sees a bare GET and serves the
	// intact body.
	require.Equal(t, 2, hits, "one 304-adopt, then one bare GET re-fetch")
}
