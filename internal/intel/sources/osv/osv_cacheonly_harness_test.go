package osv_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
)

// Plug osv into the shared cache-only integrity harness. osv is a
// zip+etag source: the gutted damage swaps the on-disk zip for a
// valid-but-unrelated one.
func osvCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makeOSVZip(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0", "1.0.1"})
	gutted := makeOSVZip(t, "MAL-2026-2", "someone-else", "npm", []string{"1.0.0"})
	return cacheonlytest.Case{
		Name:      "osv",
		Ecosystem: intel.EcosystemNPM,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(intact)
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := osv.New(osv.Options{
				BaseURL:  srvURL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 2,
		GuttedName:  "someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "npm.zip"), gutted, 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, osvCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, osvCacheOnlyCase(t))
}
