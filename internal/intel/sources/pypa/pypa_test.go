package pypa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestParseTarball_ExtractsMalwareOnly is the core unit test: feed the
// tarball-walker a synthetic archive containing one malware entry, one
// regular CVE, and one non-vulns file. Only the MAL-* entry should
// produce reports.
func TestParseTarball_ExtractsMalwareOnly(t *testing.T) {
	malware := `id: MAL-2026-1
summary: Malicious code in evil-pkg
published: 2026-05-01T00:00:00Z
affected:
  - package:
      ecosystem: PyPI
      name: evil-pkg
    versions: ["1.0.0", "1.0.1"]
`
	regularCVE := `id: PYSEC-2024-1234
summary: Buffer overflow in normal-pkg
affected:
  - package:
      ecosystem: PyPI
      name: normal-pkg
    versions: ["2.0.0"]
`
	readme := "# advisory-database\nNot a vuln entry.\n"

	tarball := makeTarball(t, map[string]string{
		"advisory-database-main/README.md":                             readme,
		"advisory-database-main/vulns/evil-pkg/MAL-2026-1.yaml":        malware,
		"advisory-database-main/vulns/normal-pkg/PYSEC-2024-1234.yaml": regularCVE,
	})

	reports, err := parseTarball(tarball, zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, reports, 2, "should yield two reports (one per malware version)")
	for _, r := range reports {
		require.Equal(t, "evil-pkg", r.Name)
		require.Equal(t, intel.EcosystemPyPI, r.Ecosystem)
		require.Equal(t, "pypa", r.SourceID)
		require.Equal(t, "MAL-2026-1", r.AdvisoryID)
	}
}

// TestFetchAndParse_EndToEnd spins up an httptest server that serves a
// canned tarball; Source.Fetch must download it, parse it, and emit
// reports. This exercises the etag-on-first-request path (the response
// has an ETag header so cache files are written) without hitting the
// real GitHub.
func TestFetchAndParse_EndToEnd(t *testing.T) {
	malware := `id: MAL-2026-99
summary: Malicious
published: 2026-05-21T00:00:00Z
affected:
  - package:
      ecosystem: PyPI
      name: evil-pkg
    versions: ["9.9.9"]
`
	tarball := makeTarball(t, map[string]string{
		"advisory-database-main/vulns/evil-pkg/MAL-2026-99.yaml": malware,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Honor If-None-Match so the caching path can be exercised in
		// follow-up tests too.
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "evil-pkg", reports[0].Name)
	require.Equal(t, "9.9.9", reports[0].Version)

	// Second fetch hits the 304 path — must still return the same data
	// from the on-disk cache.
	reports2, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.Equal(t, reports, reports2, "304 path must return identical reports from cache")
}

// TestFetchParseFailureDropsEtag verifies H3: a body that survives the
// size cap but fails parseTarball (corrupt gzip, truncated tar, etc.)
// must NOT leave the etag on disk. Otherwise the next refresh sends
// If-None-Match, upstream returns 304, we re-parse the same broken cache,
// and fail forever.
func TestFetchParseFailureDropsEtag(t *testing.T) {
	var hits atomic.Int32
	var serveValid atomic.Bool
	validTarball := makeTarball(t, map[string]string{
		"advisory-database-main/vulns/evil-pkg/MAL-2026-X.yaml": `id: MAL-2026-X
summary: Malicious
affected:
  - package:
      ecosystem: PyPI
      name: evil-pkg
    versions: ["1.0.0"]
`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"broken"` {
			// Defensive: if the client tries to 304 against a known-bad
			// etag, fail loudly via a real 304 — the test will catch it
			// by observing the wrong number of reports / cached payload.
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if serveValid.Load() {
			w.Header().Set("ETag", `"good"`)
			_, _ = w.Write(validTarball)
			return
		}
		w.Header().Set("ETag", `"broken"`)
		// Not a valid gzip stream — small enough to pass the size cap,
		// fails gzip.NewReader inside parseTarball.
		_, _ = w.Write([]byte("definitely not a gzipped tarball"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: cacheDir,
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.Error(t, err, "corrupt tarball must fail to parse")

	_, statErr := os.Stat(filepath.Join(cacheDir, "advisory-database.etag"))
	require.True(t, os.IsNotExist(statErr),
		"etag must not persist for an unparseable tarball")

	serveValid.Store(true)
	reports, err := src.Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err, "next fetch must succeed without 304-looping on broken cache")
	require.Len(t, reports, 1)
	require.Equal(t, "evil-pkg", reports[0].Name)

	etag, err := os.ReadFile(filepath.Join(cacheDir, "advisory-database.etag"))
	require.NoError(t, err)
	require.Equal(t, `"good"`, string(etag))

	require.Equal(t, int32(2), hits.Load(), "exactly two upstream hits expected")
}

// TestFetch_NonPyPIEcosystem_ReturnsUnsupported: PyPA covers PyPI only.
// Other ecosystems must short-circuit cleanly so the Store treats it as
// a benign skip.
func TestFetch_NonPyPIEcosystem_ReturnsUnsupported(t *testing.T) {
	src, err := New(Options{
		CacheDir: t.TempDir(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

// TestIsVulnYAML covers the path-pattern recognizer. Tarball walks must
// skip non-advisory files (README, LICENSE, CI config) without trying
// to parse them as advisories.
func TestIsVulnYAML(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"advisory-database-main/vulns/foo/PYSEC-1.yaml", true},
		{"advisory-database-main/vulns/foo/PYSEC-1.yml", true},
		{"advisory-database-main/vulns/foo/MAL-2026-1.yaml", true},
		{"advisory-database-main/README.md", false},
		{"advisory-database-main/LICENSE", false},
		{"advisory-database-main/.github/workflows/ci.yml", false},
		{"some-other-dir/vulns/foo/PYSEC-1.yaml", true}, // suffix-match keeps us robust to tarball renames
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, isVulnYAML(c.name))
		})
	}
}

// makeTarball builds a gzipped tar with the given file map (relative
// path → contents). The order is non-deterministic but parseTarball
// doesn't depend on order.
func makeTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// unused but kept so future tests can introspect strings.Reader usage.
var _ = strings.NewReader
