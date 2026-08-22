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

// TestFetchGrandfatheredCacheAdoptsHashOn304 pins the steady-state path
// for a cache written before content binding (no .sha256 sidecar): FIX 1
// forbids adopting disk bytes on a 304 alone, so the fetch must rebind
// from the WIRE — one unconditional GET, then the sidecar exists and the
// cache is content-bound from here on. A cache whose etag never changes
// still becomes bound (via that one GET), just never via read-side
// adoption.
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

	// FIX 1 changed this contract: a 304 on an UNRECORDED payload no
	// longer adopts the disk bytes (the etag names the upstream
	// representation, not what is on disk). The fetch must instead drop
	// the etag and re-fetch unconditionally, binding the wire bytes.
	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "a grandfathered cache must heal via the wire")
	require.Len(t, reports, 7)

	// The sidecar must now exist — bound from the WIRE bytes this
	// process read, not from what was on disk.
	require.FileExists(t, filepath.Join(cacheDir, "npm.json.sha256"),
		"the wire-refetched payload must be bound on this very fetch")

	// And damage after binding must be caught by the hash gate: same
	// fetch sequence, gutted payload, 304-answering upstream → re-fetch.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), []byte(guttedManifest), 0o600))

	recovered, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "post-binding damage must be repaired by re-fetch")
	require.Len(t, recovered, 7, "the re-fetched manifest must be the intact one")
	// Hit 1: the 304 that refused adoption. Hit 2: the unconditional
	// refetch that bound the wire bytes. Hit 3: the damage is caught by
	// the pre-request hash gate (etag present, hash mismatch →
	// conditional header dropped), so the upstream sees a bare GET and
	// serves the intact body.
	require.Equal(t, 3, hits, "one refused-adoption 304, one wire-binding GET, one damage-repair GET")
}
