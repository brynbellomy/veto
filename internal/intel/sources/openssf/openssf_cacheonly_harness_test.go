package openssf_test

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
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
)

// Plug openssf into the shared cache-only integrity harness. openssf is a
// gob/tarball source: the damage step guts BOTH local layers so whichever
// the directive tries, the verdict must reject it and the fetch heals.
func openssfCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makeMaliciousPackagesTarball(t, "MAL-2026-1", "evil-pkg", "npm", []string{"1.0.0"})
	guttedTarball := makeMaliciousPackagesTarball(t, "MAL-2026-2", "someone-else", "npm", []string{"1.0.0"})
	return cacheonlytest.Case{
		Name:      "openssf",
		Ecosystem: intel.EcosystemNPM,
		Serve: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				if r.Method == http.MethodGet {
					_, _ = w.Write(intact)
				}
			}
		},
		NewSource: func(t *testing.T, srvURL, cacheDir string) intel.Source {
			src, err := openssf.New(openssf.Options{
				TarballURL: srvURL,
				CacheDir:   cacheDir,
				Logger:     zerolog.Nop(),
			})
			require.NoError(t, err)
			return src
		},
		WarmReports: 1,
		GuttedName:  "someone-else",
		Damage: func(t *testing.T, cacheDir string) {
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "main.tar.gz"), guttedTarball, 0o600))
			guttedGob := encodeOpenssfGobForTest(t, []intel.MalwareReport{{
				PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "someone-else"},
				SourceID:   "openssf",
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
	}
}

func TestCacheOnlyHarnessGuttedCacheMustNotServe(t *testing.T) {
	cacheonlytest.RunGuttedUnderCacheOnly(t, openssfCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, openssfCacheOnlyCase(t))
}

func encodeOpenssfGobForTest(t *testing.T, reports []intel.MalwareReport) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(openssfGobBlob{Reports: reports}))
	return buf.Bytes()
}

// openssfGobBlob mirrors the source package's private gobBlob for damage
// construction in tests. gob field encoding is structural, so a type with
// identical shape encodes identically.
type openssfGobBlob struct {
	Reports []intel.MalwareReport
}
