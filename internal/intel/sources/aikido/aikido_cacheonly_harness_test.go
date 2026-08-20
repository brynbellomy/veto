package aikido_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// Plug aikido into the shared cache-only integrity harness. The scenario
// (gutted payload under CacheOnly must not serve; unrecorded must not
// adopt) is defined once in the harness and exercised against every
// network source; if this file ever stops compiling or its Case
// disappears, cmd/veto's registry test fails loudly.
func aikidoCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	return cacheonlytest.Case{
		Name:      "aikido",
		Ecosystem: intel.EcosystemNPM,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", `"abc123"`)
				_, _ = w.Write([]byte(samplePayload))
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := aikido.New(aikido.Options{
				BaseURL:  srvURL,
				CacheDir: cacheDir,
				Logger:   zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 3,
		GuttedName:  "someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "npm.json"), []byte(guttedPayload), 0o600))
		},
		StripHashSidecars: cacheonlytest.StripSidecarsInRoot,
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, aikidoCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, aikidoCacheOnlyCase(t))
}
