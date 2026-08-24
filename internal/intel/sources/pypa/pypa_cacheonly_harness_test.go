package pypa_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
	"github.com/brynbellomy/veto/internal/intel/sources/pypa"
)

// Plug pypa into the shared cache-only integrity harness. pypa is a
// tarball+etag source; the gutted damage swaps the cached tarball for a
// valid-but-unrelated one.
func pypaCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makePypaTarball(t, "evil-pkg")
	gutted := makePypaTarball(t, "someone-else")
	return cacheonlytest.Case{
		Name:      "pypa",
		Ecosystem: intel.EcosystemPyPI,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(intact)
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := pypa.New(pypa.Options{
				URL:      srvURL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 1,
		GuttedName:  "someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "advisory-database.tar.gz"), gutted, 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, pypaCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, pypaCacheOnlyCase(t))
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, pypaCacheOnlyCase(t))
}

func TestCacheOnlyHarness304LoopMustFailClosed(t *testing.T) {
	cacheonlytest.Run304LoopMustFailClosed(t, pypaCacheOnlyCase(t))
}
