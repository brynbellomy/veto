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

// guttedManifest is the exact damage shape from the live reproduction: a
// syntactically valid manifest that parses cleanly but carries only two
// unrelated entries, replacing one carrying ~47k packages. The parse layer
// cannot catch this — the bytes are well-formed JSON in the correct shape —
// so the only defenses are content-binding (the payload no longer matches
// the bytes the etag validated) and the per-source baseline.
const guttedManifest = `{"000webhost-admin": null, "@0xengine/meow": null}`

// TestFetchGuttedCacheManifestMustNotSilentlyShrink is the regression for
// the live vulnerability: a single source's on-disk payload was replaced
// with a parseable-but-gutted manifest while its etag stayed intact, and
// veto kept reporting a healthy store (aggregate count still above the
// sanity floor) while serving 69k fewer reports. The fetch under test is
// the exact scenario: warm cache, upstream answers 304 against the intact
// etag, the on-disk payload has been swapped underneath.
//
// Required outcome: the damaged payload must NOT be served as-is. Either
// the source re-fetches the real body (network path) or it fails closed
// with intel.ErrDamagedCache (no-network path). A fetch that silently
// returns two reports is the vulnerability.
func TestFetchGuttedCacheManifestMustNotSilentlyShrink(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")

	var hits int
	// Upstream is alive and answers 304 for the cached etag — the normal
	// network path from the live repro.
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
	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	// Warm the cache with a real fetch.
	warm, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warm, 7, "fixture manifest must produce 7 reports")

	// Damage the on-disk payload exactly as the live repro did, leaving
	// the etag (and any integrity sidecar) in place.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"),
		[]byte(guttedManifest), 0o600))

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	if err != nil {
		// Fail-closed is acceptable: the source detected the damage and
		// refused to serve it. It must specifically be a damaged-cache
		// error, not a generic network complaint.
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"a gutted cache payload must fail closed with ErrDamagedCache, not serve silently")
		return
	}
	// No error → the only acceptable path is a full re-fetch of the real
	// body (cache miss), never the damaged bytes.
	require.Greater(t, len(reports), 2,
		"serving the 2-entry gutted manifest is the vulnerability; expected a re-fetch or an error")
}

// guttedReportsOnly counts reports for the two names present in
// guttedManifest. Retained for the store-level regression below; a fetch
// that serves ONLY these two names is the vulnerability.
func guttedReportsOnly(reports []intel.MalwareReport) int {
	n := 0
	for _, r := range reports {
		if r.Name == "000webhost-admin" || r.Name == "@0xengine/meow" {
			n++
		}
	}
	return n
}

// TestFetchGuttedCacheOfflineMustFailClosed: the same damage, but upstream
// is unreachable. The live repro's most dangerous property is that it
// "works" without network cooperation; the offline variant must not serve
// the damaged bytes either.
func TestFetchGuttedCacheOfflineMustFailClosed(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"npm-1"`)
		_, _ = w.Write(fixture)
	}))

	cacheDir := t.TempDir()
	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	srv.Close()

	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"),
		[]byte(guttedManifest), 0o600))

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrDamagedCache,
		"offline with a damaged payload must fail closed, not serve the gutted manifest")
}

// TestFetchIntactCacheServesWithoutRefetch pins the happy path: a healthy
// cache with an unchanged etag must still serve from disk without paying
// a full re-download. The integrity fix must not make every invocation
// an 8-second cold sync.
func TestFetchIntactCacheServesWithoutRefetch(t *testing.T) {
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
	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 7, "intact cache must serve the full manifest")
	require.Equal(t, 2, hits, "intact cache must serve from disk — exactly one 200 and one 304")
}

// TestFetchDamagedCacheShapes exercises the other damage shapes against a
// 304-answering upstream: truncated (parse error), empty, and syntactically
// corrupt. Every shape must either recover by re-fetching or fail closed —
// never serve the damaged bytes.
func TestFetchDamagedCacheShapes(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")

	shapes := []struct {
		name    string
		payload []byte
	}{
		{"truncated", fixture[:len(fixture)/2]},
		{"empty", []byte{}},
		{"corrupt", []byte("}{ this is not json")},
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
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
			src, err := datadog.New(datadog.Options{
				BaseURL:  srv.URL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)

			_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
			require.NoError(t, err)

			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "npm.json"), tc.payload, 0o600))

			reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
			if err != nil {
				// Fail-closed with the sentinel is fine; a generic parse
				// error is also acceptable for unparseable bytes (the
				// existing parse-failure path already drops the etag).
				return
			}
			require.Greater(t, len(reports), 2,
				"damaged payload must be re-fetched or refused, never served (%d reports)", len(reports))
		})
	}
}

// TestFetchCacheOnlyGuttedCacheMustNotServe is the merged-configuration
// regression: the freshness window says "we fetched moments ago" (context
// carries the CacheOnly directive) AND the on-disk payload has been
// gutted. This is the state neither branch could test alone — the
// freshness window removes the network round-trip whose 304 handler
// carried the integrity gate, so the cache-only early return must consult
// the content hash itself. Serving the gutted bytes here is the original
// vulnerability reinstated on the one path that never touches the
// network.
//
// Rules being pinned (see the cache-only block in fetchWithCacheBounded):
// the verdict is computed BEFORE the directive; HashMismatch never
// short-circuits under the directive (falls through to network, which
// re-downloads and re-records); HashUnrecorded serves but never adopts.
func TestFetchCacheOnlyGuttedCacheMustNotServe(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("ETag", `"npm-1"`)
		_, _ = w.Write(loadFixture(t, "npm_manifest.json"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	// Prime the cache with a network fetch (records the hash sidecar).
	warm, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, warm, 7)

	// Gut the on-disk payload.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), []byte(guttedManifest), 0o600))

	// Cache-only fetch against the gutted payload: must NOT serve it.
	ctx := intel.WithCacheOnly(context.Background())
	reports, err := src.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "mismatch under cache-only falls through to network, which heals")
	require.Len(t, reports, 7,
		"the gutted payload must not be served under the cache-only directive")
	require.Greater(t, hits, 1, "the mismatch must trigger a real re-fetch")
	for _, r := range reports {
		require.NotEqual(t, "@0xengine/meow", r.Name,
			"no report may come from the gutted manifest")
	}
}

// TestFetchCacheOnlyUnrecordedServesButDoesNotAdopt pins rule 3 for this
// source: a pre-integrity-fix payload (no .sha256 sidecar) under the
// cache-only directive is SERVED — refusing would brick every upgraded
// installation inside the freshness window — but its hash must NOT be
// adopted, because nothing upstream confirms the bytes. Adoption under
// cache-only would bless whatever is on disk and permanently blind the
// binding layer.
func TestFetchCacheOnlyUnrecordedServesButDoesNotAdopt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"npm-1"`)
		_, _ = w.Write(loadFixture(t, "npm_manifest.json"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	// Simulate a pre-integrity-fix cache: payload + etag, no sidecar.
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.json"), loadFixture(t, "npm_manifest.json"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(cacheDir, "npm.etag"), []byte(`"npm-1"`), 0o600))

	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	ctx := intel.WithCacheOnly(context.Background())
	reports, err := src.Fetch(ctx, intel.EcosystemNPM)
	require.NoError(t, err, "an unrecorded payload must still serve under cache-only")
	require.Len(t, reports, 7)

	_, statErr := os.Stat(filepath.Join(cacheDir, "npm.json.sha256"))
	require.True(t, os.IsNotExist(statErr),
		"cache-only must NOT adopt (record) the hash of an unvalidated payload")
}
