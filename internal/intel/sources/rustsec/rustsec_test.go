package rustsec

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
)

// readFixture loads a real RustSec OSV advisory saved under testdata/.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

func TestParseTarballEmitsCratesAdvisories(t *testing.T) {
	t.Parallel()

	openssl := readFixture(t, "RUSTSEC-2016-0001.json")
	smallvec := readFixture(t, "RUSTSEC-2018-0003.json")

	// A non-advisory file under crates/ and a file outside crates/ must both
	// be ignored. The repo-root prefix (advisory-db-osv/) is intentionally not
	// pinned by the matcher.
	tarballPath := makeTarballFile(t, map[string]string{
		"advisory-db-osv/README.md":                        "# rustsec osv export\n",
		"advisory-db-osv/crates/RUSTSEC-2016-0001.json":    openssl,
		"advisory-db-osv/crates/RUSTSEC-2018-0003.json":    smallvec,
		"advisory-db-osv/crates/NOTES.md":                  "not an advisory\n",
		"advisory-db-osv/elsewhere/RUSTSEC-9999-9999.json": openssl,
	})

	src := &Source{logger: zerolog.Nop()}
	reports, err := src.parseTarball(tarballPath)
	require.NoError(t, err)

	// openssl: one bounded range [0.0.0-0, 0.9.0).
	// smallvec: four bounded ranges. So 5 reports total.
	require.Len(t, reports, 5)

	byAdvisory := map[string][]intel.MalwareReport{}
	for _, r := range reports {
		require.Equal(t, "rustsec", r.SourceID)
		require.Equal(t, intel.EcosystemCrates, r.Ecosystem)
		byAdvisory[r.AdvisoryID] = append(byAdvisory[r.AdvisoryID], r)
	}

	openSSLReports := byAdvisory["RUSTSEC-2016-0001"]
	require.Len(t, openSSLReports, 1)
	r := openSSLReports[0]
	require.Equal(t, "openssl", r.Name)
	require.Empty(t, r.Version, "range advisories leave Version empty")
	require.NotNil(t, r.Range)
	require.Equal(t, "0.0.0-0", r.Range.Introduced)
	require.Equal(t, "0.9.0", r.Range.Fixed)
	require.False(t, r.PublishedAt.IsZero())

	smallvecReports := byAdvisory["RUSTSEC-2018-0003"]
	require.Len(t, smallvecReports, 4)
	for _, sr := range smallvecReports {
		require.Equal(t, "smallvec", sr.Name)
		require.NotNil(t, sr.Range)
		require.Equal(t, "0.3.4", smallvecReports[0].Range.Fixed)
	}
}

func TestParseTarballSkipsMalformedJSON(t *testing.T) {
	t.Parallel()

	good := readFixture(t, "RUSTSEC-2016-0001.json")
	tarballPath := makeTarballFile(t, map[string]string{
		"advisory-db-osv/crates/RUSTSEC-2016-0001.json": good,
		"advisory-db-osv/crates/RUSTSEC-BROKEN.json":    `{"id": "RUSTSEC-BROKEN", "affected": [`, // truncated JSON
	})

	src := &Source{logger: zerolog.Nop()}
	reports, err := src.parseTarball(tarballPath)
	require.NoError(t, err, "a single malformed advisory must not fail the whole feed")
	require.Len(t, reports, 1)
	require.Equal(t, "RUSTSEC-2016-0001", reports[0].AdvisoryID)
}

func TestFetchEndToEndUsesTarballCache(t *testing.T) {
	t.Parallel()

	tarball := makeTarballBytes(t, map[string]string{
		"advisory-db-osv/crates/RUSTSEC-2016-0001.json": readFixture(t, "RUSTSEC-2016-0001.json"),
	})

	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		switch r.Method {
		case http.MethodHead:
			return
		case http.MethodGet:
			gets++
			_, _ = w.Write(tarball)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   cacheDir,
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemCrates)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, "openssl", reports[0].Name)
	require.Equal(t, intel.EcosystemCrates, reports[0].Ecosystem)

	// Second fetch: unchanged etag → no re-download, identical result.
	reports2, err := src.Fetch(context.Background(), intel.EcosystemCrates)
	require.NoError(t, err)
	require.Equal(t, reports, reports2)
	require.Equal(t, 1, gets, "unchanged etag must not re-download the tarball")
	require.FileExists(t, filepath.Join(cacheDir, "osv.tar.gz"))
	require.FileExists(t, filepath.Join(cacheDir, "osv.etag"))
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	src, err := New(Options{CacheDir: t.TempDir()})
	require.NoError(t, err)

	for _, eco := range []intel.Ecosystem{intel.EcosystemNPM, intel.EcosystemPyPI, intel.EcosystemGo, intel.Ecosystem("maven")} {
		_, err := src.Fetch(context.Background(), eco)
		require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem, "ecosystem %q must be unsupported", eco)
	}
}

func TestFetchHTTPErrorNoCache(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := New(Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemCrates)
	require.Error(t, err, "an unreachable upstream with no local cache must surface an error")
}

func TestRangeMembershipResolvesAcrossIntervals(t *testing.T) {
	t.Parallel()

	// smallvec is flagged on four disjoint intervals; assert the parsed ranges
	// resolve membership the way the Store's Lookup will: a version inside an
	// interval is in range, one in a patched gap is not.
	reports, err := (&Source{logger: zerolog.Nop()}).parseTarball(makeTarballFile(t, map[string]string{
		"advisory-db-osv/crates/RUSTSEC-2018-0003.json": readFixture(t, "RUSTSEC-2018-0003.json"),
	}))
	require.NoError(t, err)
	require.Len(t, reports, 4)

	inRange := func(v string) bool {
		for _, r := range reports {
			require.NotNil(t, r.Range)
			if intel.InRange(intel.EcosystemCrates, v, *r.Range) {
				return true
			}
		}
		return false
	}

	require.True(t, inRange("0.3.3"), "0.3.3 is within [0.3.2, 0.3.4)")
	require.True(t, inRange("0.6.2"), "0.6.2 is within [0.6.0-0, 0.6.3)")
	require.False(t, inRange("0.3.4"), "0.3.4 is the fixed (exclusive) bound")
	require.False(t, inRange("0.6.3"), "0.6.3 is patched")
}

func TestIsAdvisoryEntry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want bool
	}{
		{"advisory-db-osv/crates/RUSTSEC-2016-0001.json", true},
		{"renamed-root/crates/RUSTSEC-2016-0001.json", true},
		{"advisory-db-osv/crates/NOTES.md", false},
		{"advisory-db-osv/README.md", false},
		{"advisory-db-osv/elsewhere/RUSTSEC-2016-0001.json", false},
		{"crates/RUSTSEC-2016-0001.json", false}, // missing repo-root prefix
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, isAdvisoryEntry(c.name))
		})
	}
}

func makeTarballFile(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisory-db-osv.tar.gz")
	require.NoError(t, os.WriteFile(path, makeTarballBytes(t, files), 0o644))
	return path
}

func makeTarballBytes(t *testing.T, files map[string]string) []byte {
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
