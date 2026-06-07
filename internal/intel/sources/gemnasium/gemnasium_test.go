package gemnasium

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// readFixture loads a testdata advisory YAML file.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

// TestReportsFromAdvisory_RealFixtures parses every "happy path" fixture and
// asserts the emitted reports match the advisory's affected_range.
func TestReportsFromAdvisory_RealFixtures(t *testing.T) {
	t.Run("npm lodash exclusive upper", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "npm_lodash.yml")))
		require.NoError(t, err)
		reports := reportsFromAdvisory(adv, intel.EcosystemNPM, sourceID, zerolog.Nop())
		require.Len(t, reports, 1)
		r := reports[0]
		require.Equal(t, intel.EcosystemNPM, r.Ecosystem)
		require.Equal(t, "lodash", r.Name)
		require.Empty(t, r.Version)
		require.Equal(t, sourceID, r.SourceID)
		require.Equal(t, "CVE-2019-10744", r.AdvisoryID)
		require.NotNil(t, r.Range)
		require.Equal(t, "4.17.12", r.Range.Fixed)
		require.False(t, r.PublishedAt.IsZero(), "pubdate must parse")
	})

	t.Run("pypi django three OR ranges", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "pypi_django.yml")))
		require.NoError(t, err)
		reports := reportsFromAdvisory(adv, intel.EcosystemPyPI, sourceID, zerolog.Nop())
		require.Len(t, reports, 3, "one report per OR-alternative")
		for _, r := range reports {
			require.Equal(t, intel.EcosystemPyPI, r.Ecosystem)
			require.Equal(t, "Django", r.Name)
			require.NotNil(t, r.Range)
		}
		// The middle alternative bridges 3.0a1..3.1.14.
		require.Equal(t, "3.0a1", reports[1].Range.Introduced)
		require.Equal(t, "3.1.14", reports[1].Range.Fixed)
	})

	t.Run("go gin v-prefixed name with slashes", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "go_gin.yml")))
		require.NoError(t, err)
		reports := reportsFromAdvisory(adv, intel.EcosystemGo, sourceID, zerolog.Nop())
		require.Len(t, reports, 1)
		require.Equal(t, "github.com/gin-gonic/gin", reports[0].Name,
			"package name keeps its slashes; only the eco prefix is split off")
		require.NotNil(t, reports[0].Range)
		require.Equal(t, "1.7.0", reports[0].Range.Fixed, "v-prefix normalized away")
	})

	t.Run("cargo buttplug bounded interval", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "cargo_buttplug.yml")))
		require.NoError(t, err)
		reports := reportsFromAdvisory(adv, intel.EcosystemCrates, sourceID, zerolog.Nop())
		require.Len(t, reports, 1)
		require.Equal(t, "buttplug", reports[0].Name)
		require.Equal(t, "0.5.0", reports[0].Range.Introduced)
		require.Equal(t, "1.0.4", reports[0].Range.Fixed)
	})

	t.Run("strict lower bound drops one alternative, keeps the other", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "npm_strictlower.yml")))
		require.NoError(t, err)
		reports := reportsFromAdvisory(adv, intel.EcosystemNPM, sourceID, zerolog.Nop())
		require.Len(t, reports, 1, "the >1.0.0 alternative is dropped; >=3.0.0,<3.5.0 survives")
		require.Equal(t, "3.0.0", reports[0].Range.Introduced)
		require.Equal(t, "3.5.0", reports[0].Range.Fixed)
	})

	t.Run("maven advisory yields nothing for any covered ecosystem", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "maven_unsupported.yml")))
		require.NoError(t, err)
		for _, eco := range intel.AllEcosystems {
			require.Empty(t, reportsFromAdvisory(adv, eco, sourceID, zerolog.Nop()),
				"maven is not gated by veto: %s", eco)
		}
	})

	t.Run("ecosystem filter: npm advisory requested as pypi yields nothing", func(t *testing.T) {
		adv, err := parseAdvisory([]byte(readFixture(t, "npm_lodash.yml")))
		require.NoError(t, err)
		require.Empty(t, reportsFromAdvisory(adv, intel.EcosystemPyPI, sourceID, zerolog.Nop()))
	})
}

// TestParseAdvisory_Malformed confirms structurally invalid YAML surfaces as
// an error so the tarball walker can log-and-skip it.
func TestParseAdvisory_Malformed(t *testing.T) {
	_, err := parseAdvisory([]byte(readFixture(t, "malformed.yml")))
	require.Error(t, err)
}

// TestParseTarball_FiltersByEcosystem builds a tarball holding fixtures from
// all four ecosystems plus an unsupported one, then asserts each ecosystem
// fetch only sees its own advisories. A malformed entry is included to prove
// it is skipped rather than aborting the walk.
func TestParseTarball_FiltersByEcosystem(t *testing.T) {
	files := map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml":       readFixture(t, "npm_lodash.yml"),
		"advisories-community-main/npm/example-strict/GMS-2099-1.yml":   readFixture(t, "npm_strictlower.yml"),
		"advisories-community-main/pypi/Django/CVE-2021-44420.yml":      readFixture(t, "pypi_django.yml"),
		"advisories-community-main/go/github.com/gin-gonic/gin/CVE.yml": readFixture(t, "go_gin.yml"),
		"advisories-community-main/cargo/buttplug/CVE-2020-36218.yml":   readFixture(t, "cargo_buttplug.yml"),
		"advisories-community-main/maven/org.example/widget/CVE.yml":    readFixture(t, "maven_unsupported.yml"),
		"advisories-community-main/npm/broken/CVE-BROKEN.yml":           readFixture(t, "malformed.yml"),
		"advisories-community-main/README.md":                           "# not an advisory",
	}
	tarball := makeTarball(t, files)

	npm, err := parseTarball(tarball, intel.EcosystemNPM, zerolog.Nop())
	require.NoError(t, err)
	// lodash (1) + strictlower-surviving-alternative (1); broken yaml skipped.
	require.Len(t, npm, 2)

	py, err := parseTarball(tarball, intel.EcosystemPyPI, zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, py, 3)

	goReports, err := parseTarball(tarball, intel.EcosystemGo, zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, goReports, 1)
	require.Equal(t, "github.com/gin-gonic/gin", goReports[0].Name)

	crates, err := parseTarball(tarball, intel.EcosystemCrates, zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, crates, 1)
}

// TestFetchAndParse_EndToEnd serves a canned tarball over httptest and drives
// the full Fetch path including the 304-revalidation branch.
func TestFetchAndParse_EndToEnd(t *testing.T) {
	tarball := makeTarball(t, map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml": readFixture(t, "npm_lodash.yml"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(tarball)
	}))
	defer srv.Close()

	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "lodash", reports[0].Name)

	// Second fetch hits the 304 path and must return identical data from cache.
	reports2, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err)
	require.Equal(t, reports, reports2)
}

// TestFetch_UnsupportedEcosystem: ecosystems veto doesn't gate must short
// circuit to ErrUnsupportedEcosystem without any network access.
func TestFetch_UnsupportedEcosystem(t *testing.T) {
	src, err := New(Options{
		URL:      "http://127.0.0.1:0/should-never-be-called",
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	// "crates.io" IS covered; pick an ecosystem string veto knows but
	// gemnasium-via-veto maps... actually every intel ecosystem is covered.
	// Use a synthetic unknown ecosystem to exercise the unsupported branch.
	_, err = src.Fetch(context.Background(), intel.Ecosystem("rubygems"))
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

// TestFetch_HTTPError surfaces an upstream 500 (with no cache present) as an
// error rather than an empty success.
func TestFetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := New(Options{
		URL:      srv.URL,
		CacheDir: t.TempDir(),
		Logger:   zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err)
}

// TestFetchParseFailureDropsEtag: a body that passes the size cap but fails to
// decompress must not leave an etag on disk, or the next refresh would 304-loop
// on the broken cache forever.
func TestFetchParseFailureDropsEtag(t *testing.T) {
	var serveValid atomic.Bool
	var hits atomic.Int32
	valid := makeTarball(t, map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml": readFixture(t, "npm_lodash.yml"),
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if serveValid.Load() {
			w.Header().Set("ETag", `"good"`)
			_, _ = w.Write(valid)
			return
		}
		w.Header().Set("ETag", `"broken"`)
		_, _ = w.Write([]byte("not a gzip stream"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{URL: srv.URL, CacheDir: cacheDir, Logger: zerolog.Nop()})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err, "corrupt tarball must fail to parse")

	_, statErr := os.Stat(filepath.Join(cacheDir, "advisories-community.etag"))
	require.True(t, os.IsNotExist(statErr), "etag must not persist for an unparseable tarball")

	serveValid.Store(true)
	reports, err := src.Fetch(context.Background(), intel.EcosystemNPM)
	require.NoError(t, err, "next fetch must succeed without 304-looping")
	require.Len(t, reports, 1)

	etag, err := os.ReadFile(filepath.Join(cacheDir, "advisories-community.etag"))
	require.NoError(t, err)
	require.Equal(t, `"good"`, string(etag))
	require.Equal(t, int32(2), hits.Load(), "exactly two upstream hits")
}

// TestNew_RequiresCacheDir guards the constructor contract.
func TestNew_RequiresCacheDir(t *testing.T) {
	_, err := New(Options{})
	require.Error(t, err)
}

// TestID pins the source identifier used for store dedup and wiring.
func TestID(t *testing.T) {
	src, err := New(Options{CacheDir: t.TempDir()})
	require.NoError(t, err)
	require.Equal(t, "gemnasium", src.ID())
}

// makeTarball builds a gzipped tar from a path→contents map.
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
			ModTime:  time.Unix(0, 0),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
