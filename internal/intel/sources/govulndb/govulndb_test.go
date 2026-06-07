package govulndb

import (
	"archive/zip"
	"bytes"
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

// realFixtureFiles is the in-zip layout we exercise, mirroring vulndb.zip:
// index/*.json summaries (which the source must ignore) and ID/GO-*.json OSV
// documents (which it must parse).
var realFixtureFiles = map[string]string{
	"index/db.json":      `{"modified":"2026-06-02T21:39:47Z"}`,
	"index/modules.json": `[{"path":"gopkg.in/yaml.v2","vulns":[{"id":"GO-2021-0061","fixed":"2.2.3"}]}]`,
	// Bounded advisory: introduced 0 → fixed 2.2.3 (range membership tested below).
	"ID/GO-2021-0061.json": fixture(t1{
		ID:      "GO-2021-0061",
		Summary: "Denial of service in gopkg.in/yaml.v2",
		Module:  "gopkg.in/yaml.v2",
		Fixed:   "2.2.3",
	}),
	// Explicit-version stdlib advisory: an inert pseudo-module, kept to prove
	// we don't choke on it and that its concrete version survives parsing.
	"ID/GO-2022-0191.json": fixtureVersions(
		"GO-2022-0191",
		"Denial of service in crypto/x509",
		"stdlib",
		[]string{"1.10.6"},
	),
	// A withdrawn advisory must be dropped by VulnerabilityReports.
	"ID/GO-2099-9999.json": fixtureWithdrawn(
		"GO-2099-9999",
		"withdrawn advisory",
		"example.com/withdrawn",
	),
	// A malformed entry inside ID/ must be skipped, not fail the whole parse.
	"ID/GO-2099-0000.json": `{ this is not valid json `,
	// A non-ID file with a Go advisory body must be ignored entirely.
	"README.md": `# vulndb`,
}

func TestParseZipExtractsGoVulnerabilities(t *testing.T) {
	t.Parallel()

	zipPath := writeZipFile(t, realFixtureFiles)

	reports, err := parseZip(zipPath, zerolog.Nop())
	require.NoError(t, err)

	// One range report (yaml.v2) + one explicit-version report (stdlib).
	// The withdrawn entry, the malformed entry, the index/* files, and the
	// README are all excluded.
	require.Len(t, reports, 2)

	byName := map[string]intel.MalwareReport{}
	for _, r := range reports {
		byName[r.Name] = r
		require.Equal(t, sourceID, r.SourceID)
		require.Equal(t, intel.EcosystemGo, r.Ecosystem)
	}

	yaml := byName["gopkg.in/yaml.v2"]
	require.Equal(t, "GO-2021-0061", yaml.AdvisoryID)
	require.Empty(t, yaml.Version)
	require.NotNil(t, yaml.Range)
	require.Equal(t, "0", yaml.Range.Introduced)
	require.Equal(t, "2.2.3", yaml.Range.Fixed)

	stdlib := byName["stdlib"]
	require.Equal(t, "GO-2022-0191", stdlib.AdvisoryID)
	require.Equal(t, "1.10.6", stdlib.Version)
	require.Nil(t, stdlib.Range)
}

// TestRangeMembership confirms the emitted Range is comparable by the Go
// comparator: yaml.v2 < 2.2.3 is in range, >= 2.2.3 is not.
func TestRangeMembership(t *testing.T) {
	t.Parallel()

	zipPath := writeZipFile(t, realFixtureFiles)
	reports, err := parseZip(zipPath, zerolog.Nop())
	require.NoError(t, err)

	var rng *intel.VersionRange
	for _, r := range reports {
		if r.Name == "gopkg.in/yaml.v2" {
			rng = r.Range
		}
	}
	require.NotNil(t, rng)

	require.True(t, intel.InRange(intel.EcosystemGo, "v2.2.2", *rng), "below fixed is affected")
	require.True(t, intel.InRange(intel.EcosystemGo, "2.2.2", *rng), "bare-version below fixed is affected")
	require.False(t, intel.InRange(intel.EcosystemGo, "v2.2.3", *rng), "at fixed is not affected")
	require.False(t, intel.InRange(intel.EcosystemGo, "v2.3.0", *rng), "above fixed is not affected")
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	t.Parallel()

	src, err := New(Options{CacheDir: t.TempDir(), Logger: zerolog.Nop()})
	require.NoError(t, err)

	for _, eco := range []intel.Ecosystem{
		intel.EcosystemNPM,
		intel.EcosystemPyPI,
		intel.EcosystemCrates,
		intel.Ecosystem("maven"),
	} {
		_, err := src.Fetch(context.Background(), eco)
		require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem, "ecosystem %q", eco)
	}
}

func TestFetchEndToEndUsesZipCache(t *testing.T) {
	t.Parallel()

	zipBytes := writeZipBytes(t, realFixtureFiles)

	var getCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("ETag", `"v1"`)
		// Honor conditional revalidation: once the client has the etag it
		// sends If-None-Match and we answer 304 with no body.
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		getCount++
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{ZipURL: srv.URL, CacheDir: cacheDir, Logger: zerolog.Nop()})
	require.NoError(t, err)

	reports, err := src.Fetch(context.Background(), intel.EcosystemGo)
	require.NoError(t, err)
	require.Len(t, reports, 2)
	require.Equal(t, 1, getCount, "first fetch downloads the body")

	require.FileExists(t, filepath.Join(cacheDir, "vulndb.zip"))
	require.FileExists(t, filepath.Join(cacheDir, "vulndb.etag"))

	reports2, err := src.Fetch(context.Background(), intel.EcosystemGo)
	require.NoError(t, err)
	require.Equal(t, reports, reports2)
	require.Equal(t, 1, getCount, "revalidated fetch is served from cache, not re-downloaded")
}

func TestFetchHTTPErrorStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := New(Options{ZipURL: srv.URL, CacheDir: t.TempDir(), Logger: zerolog.Nop()})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemGo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected govulndb status")
}

func TestFetchMalformedZipPayload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"bad"`)
		_, _ = w.Write([]byte("this is not a zip archive"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := New(Options{ZipURL: srv.URL, CacheDir: cacheDir, Logger: zerolog.Nop()})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemGo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse fresh zip")

	// The etag must NOT be persisted on a parse failure, so the next refresh
	// re-downloads rather than 304-looping on a broken zip.
	require.NoFileExists(t, filepath.Join(cacheDir, "vulndb.etag"))
}

func TestFetchOversizedZipRejected(t *testing.T) {
	t.Parallel()

	// Stream more than maxFeedBytes so the LimitReader trips the cap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"big"`)
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for written := 0; written <= maxFeedBytes; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	src, err := New(Options{ZipURL: srv.URL, CacheDir: t.TempDir(), Logger: zerolog.Nop()})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemGo)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds size limit")
}

func TestNewRequiresCacheDir(t *testing.T) {
	t.Parallel()

	_, err := New(Options{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "CacheDir is required")
}

// --- fixture helpers ---

// writeZipFile materializes the given in-zip files to a zip on disk and returns
// its path.
func writeZipFile(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulndb.zip")
	require.NoError(t, os.WriteFile(path, writeZipBytes(t, files), 0o644))
	return path
}

// writeZipBytes builds an in-memory zip from a name→body map.
func writeZipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// t1 describes a bounded (introduced 0 → fixed) OSV advisory fixture.
type t1 struct {
	ID      string
	Summary string
	Module  string
	Fixed   string
}

func fixture(a t1) string {
	return `{
  "schema_version": "1.3.1",
  "id": "` + a.ID + `",
  "summary": "` + a.Summary + `",
  "published": "2021-04-14T20:04:52Z",
  "affected": [
    {
      "package": {"name": "` + a.Module + `", "ecosystem": "Go"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "` + a.Fixed + `"}]}]
    }
  ]
}`
}

func fixtureVersions(id, summary, module string, versions []string) string {
	var vs bytes.Buffer
	for i, v := range versions {
		if i > 0 {
			vs.WriteString(", ")
		}
		vs.WriteString(`"` + v + `"`)
	}
	return `{
  "schema_version": "1.3.1",
  "id": "` + id + `",
  "summary": "` + summary + `",
  "affected": [
    {
      "package": {"name": "` + module + `", "ecosystem": "Go"},
      "versions": [` + vs.String() + `]
    }
  ]
}`
}

func fixtureWithdrawn(id, summary, module string) string {
	return `{
  "schema_version": "1.3.1",
  "id": "` + id + `",
  "summary": "` + summary + `",
  "withdrawn": "2099-01-02T00:00:00Z",
  "affected": [
    {
      "package": {"name": "` + module + `", "ecosystem": "Go"},
      "versions": ["1.0.0"]
    }
  ]
}`
}
