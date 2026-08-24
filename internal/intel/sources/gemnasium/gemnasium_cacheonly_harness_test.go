package gemnasium

import (
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

// Plug gemnasium into the shared cache-only integrity harness. gemnasium
// is a tarball+etag source (like pypa) whose cache payload is a tar.gz —
// the gutted damage swaps it for a valid-but-unrelated tarball.
func gemnasiumCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makeTarball(t, map[string]string{
		"advisories-community-main/npm/lodash/CVE-2019-10744.yml": readFixture(t, "npm_lodash.yml"),
	})
	gutted := makeTarball(t, map[string]string{
		// The gutted tarball must carry a DIFFERENT report: the report name
		// comes from package_slug inside the yml, not the tarball path, so a
		// gutted fixture that only renames the path still reports lodash and
		// a "no someone-else report" assertion passes even when the gutted
		// bytes ARE served -- the fixture lies.
		"advisories-community-main/npm/someone-else/CVE-2020-0001.yml": strings.Replace(
			readFixture(t, "npm_lodash.yml"), "npm/lodash", "npm/someone-else", 1),
	})
	return cacheonlytest.Case{
		Name:      "gemnasium",
		Ecosystem: intel.EcosystemNPM,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(intact)
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := New(Options{
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
				filepath.Join(cacheDir, "advisories-community.tar.gz"), gutted, 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, gemnasiumCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, gemnasiumCacheOnlyCase(t))
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, gemnasiumCacheOnlyCase(t))
}

func TestCacheOnlyHarness304LoopMustFailClosed(t *testing.T) {
	cacheonlytest.Run304LoopMustFailClosed(t, gemnasiumCacheOnlyCase(t))
}

func TestCacheOnlyHarnessHead304WithUnrecordedLayerFailsClosed(t *testing.T) {
	cacheonlytest.RunHead304WithUnrecordedLayerFailsClosed(t, gemnasiumCacheOnlyCase(t))
}
