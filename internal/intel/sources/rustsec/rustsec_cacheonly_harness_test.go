package rustsec

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// Plug rustsec into the shared cache-only integrity harness. rustsec is a
// gob/tarball source: the damage step guts BOTH local layers so whichever
// the directive tries, the verdict must reject it and the fetch heals.
func rustsecCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makeTarballBytes(t, map[string]string{
		"advisory-db-osv/crates/RUSTSEC-2016-0001.json": readFixture(t, "RUSTSEC-2016-0001.json"),
	})
	guttedTarball := makeTarballBytes(t, map[string]string{
		"advisory-db-osv/crates/RUSTSEC-2099-9999.json": rustsecAdvisoryJSONFor("someone-else"),
	})
	return cacheonlytest.Case{
		Name:      "rustsec",
		Ecosystem: intel.EcosystemCrates,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				if r.Method == http.MethodGet {
					_, _ = w.Write(intact)
				}
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := New(Options{
				TarballURL: srvURL,
				CacheDir:   cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 1,
		GuttedName:  "someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "osv.tar.gz"), guttedTarball, 0o600))
			guttedGob := encodeRustsecGobForTest(t, []intel.MalwareReport{{
				PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "someone-else"},
				SourceID:   "rustsec",
			}})
			entries, err := os.ReadDir(cacheDir)
			require.NoError(t, err)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
				require.NoError(t, os.WriteFile(
					filepath.Join(cacheDir, e.Name()), guttedGob, 0o600))
			}
		}
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
		HeadValidated:     true,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, rustsecCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, rustsecCacheOnlyCase(t))
}

func encodeRustsecGobForTest(t *testing.T, reports []intel.MalwareReport) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(gobBlob{Reports: reports}))
	return buf.Bytes()
}

// rustsecAdvisoryJSONFor renders a minimal OSV-shaped advisory for the
// gutted tarball; the real fixture stays the intact payload.
func rustsecAdvisoryJSONFor(pkg string) string {
	return `{
  "id": "RUSTSEC-2099-9999",
  "summary": "gutted",
  "affected": [
    {"package": {"ecosystem": "crates.io", "name": "` + pkg + `"}, "versions": ["1.0.0"]}
  ]
}`
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, rustsecCacheOnlyCase(t))
}
