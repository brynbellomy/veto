package datadog_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/datadog"
)

// loadFixture reads a trimmed real manifest sample from testdata/.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// reportByName indexes reports by package name for order-independent
// assertions (parseManifest iterates a map, so output order is unstable).
func reportsByName(reports []intel.MalwareReport) map[string][]intel.MalwareReport {
	out := map[string][]intel.MalwareReport{}
	for _, r := range reports {
		out[r.Name] = append(out[r.Name], r)
	}
	return out
}

func TestFetchParsesNPMManifest(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/samples/npm/manifest.json", r.URL.Path)
		w.Header().Set("ETag", `"npm-1"`)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)

	// Fixture has 5 packages: 2 null (all-versions) + @antv/a8 (2 versions) +
	// @asyncapi/modelina (2 versions) + evil-pkg (1 version) = 2 + 2 + 2 + 1 = 7.
	require.Len(t, reports, 7)

	for _, r := range reports {
		require.Equal(t, "datadog", r.SourceID)
		require.Equal(t, intel.EcosystemNPM, r.Ecosystem)
	}

	byName := reportsByName(reports)

	// null entry → one version-less report flagging every version.
	require.Len(t, byName["000webhost-admin"], 1)
	require.Equal(t, "", byName["000webhost-admin"][0].Version)
	require.Contains(t, byName["000webhost-admin"][0].Reason, "all versions")

	require.Len(t, byName["fully-malicious"], 1)
	require.Equal(t, "", byName["fully-malicious"][0].Version)

	// version-list entry → one report per version, each pinned to its version.
	require.Len(t, byName["@antv/a8"], 2)
	versions := map[string]bool{}
	for _, r := range byName["@antv/a8"] {
		versions[r.Version] = true
		require.Contains(t, r.Reason, "compromised")
	}
	require.True(t, versions["0.1.1"])
	require.True(t, versions["0.2.1"])

	require.Len(t, byName["evil-pkg"], 1)
	require.Equal(t, "1.0.0", byName["evil-pkg"][0].Version)
}

func TestFetchParsesPyPIManifest(t *testing.T) {
	fixture := loadFixture(t, "pypi_manifest.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/samples/pypi/manifest.json", r.URL.Path)
		w.Header().Set("ETag", `"pypi-1"`)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)

	// 2 null packages + 1 single-version package = 3 reports.
	require.Len(t, reports, 3)
	byName := reportsByName(reports)
	require.Len(t, byName["0wneg"], 1)
	require.Equal(t, "", byName["0wneg"][0].Version)
	require.Len(t, byName["compromised-lib"], 1)
	require.Equal(t, "2.3.4", byName["compromised-lib"][0].Version)
	require.Equal(t, intel.EcosystemPyPI, byName["compromised-lib"][0].Ecosystem)
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	src, err := datadog.New(datadog.Options{
		BaseURL:  "https://example.invalid",
		CacheDir: t.TempDir(),
	})
	require.NoError(t, err)

	for _, eco := range []intel.Ecosystem{intel.EcosystemGo, intel.EcosystemCrates, intel.Ecosystem("maven")} {
		_, err = src.Fetch(context.Background(), eco)
		require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem, "ecosystem %q must be unsupported", eco)
	}
}

func TestFetchMalformedManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"bad"`)
		_, _ = w.Write([]byte("this is not valid json"))
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
	require.Error(t, err, "malformed manifest must surface a parse error")

	// The etag must NOT persist for an unparseable manifest, otherwise the
	// next refresh sends If-None-Match, gets 304, and re-parses the same bad
	// bytes forever.
	_, statErr := os.Stat(filepath.Join(cacheDir, "npm.etag"))
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable manifest (got stat err: %v)", statErr)
}

func TestFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := datadog.New(datadog.Options{
		BaseURL:  srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "a 5xx response must surface an error")
	require.Contains(t, err.Error(), "unexpected status")
}

func TestFetchEtagShortCircuit(t *testing.T) {
	fixture := loadFixture(t, "npm_manifest.json")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
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

	first, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, first, 7)

	second, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, second, 7)

	require.Equal(t, int32(2), hits.Load(), "expected two upstream calls")
	require.FileExists(t, filepath.Join(cacheDir, "npm.json"))
	etag, err := os.ReadFile(filepath.Join(cacheDir, "npm.etag"))
	require.NoError(t, err)
	require.Equal(t, `"npm-1"`, string(etag))
}

func TestFetchNetworkFailureFallsBackToCache(t *testing.T) {
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

	// Kill the server to simulate a network outage; the cached manifest
	// should still satisfy the fetch.
	srv.Close()

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 7)
}

func TestNewRequiresCacheDir(t *testing.T) {
	_, err := datadog.New(datadog.Options{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "CacheDir")
}
