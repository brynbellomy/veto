package datadog_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/datadog"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// Plug datadog into the shared cache-only integrity harness.
func datadogCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	return cacheonlytest.Case{
		Name:      "datadog",
		Ecosystem: intel.EcosystemNPM,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"npm-1"`)
				_, _ = w.Write(loadFixture(t, "npm_manifest.json"))
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := datadog.New(datadog.Options{
				BaseURL:  srvURL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 7,
		GuttedName:  "@0xengine/meow",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "npm.json"), []byte(guttedManifest), 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, datadogCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, datadogCacheOnlyCase(t))
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, datadogCacheOnlyCase(t))
}
