package govulndb

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// Plug govulndb into the shared cache-only integrity harness. govulndb is
// a zip+etag source: the gutted damage swaps the on-disk zip for one
// carrying an unrelated advisory.
func govulndbCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := writeZipBytes(t, realFixtureFiles)
	gutted := writeZipBytes(t, map[string]string{
		"ID/GO-2099-0001.json": fixtureVersions(
			"GO-2099-0001",
			"someone else's advisory",
			"example.com/someone-else",
			[]string{"1.0.0"},
		),
	})
	return cacheonlytest.Case{
		Name:      "govulndb",
		Ecosystem: intel.EcosystemGo,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(intact)
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := New(Options{
				ZipURL:   srvURL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 2,
		GuttedName:  "example.com/someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "vulndb.zip"), gutted, 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, govulndbCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, govulndbCacheOnlyCase(t))
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, govulndbCacheOnlyCase(t))
}

func TestCacheOnlyHarness304LoopMustFailClosed(t *testing.T) {
	cacheonlytest.Run304LoopMustFailClosed(t, govulndbCacheOnlyCase(t))
}

func TestCacheOnlyHarnessHead304WithUnrecordedLayerFailsClosed(t *testing.T) {
	cacheonlytest.RunHead304WithUnrecordedLayerFailsClosed(t, govulndbCacheOnlyCase(t))
}
