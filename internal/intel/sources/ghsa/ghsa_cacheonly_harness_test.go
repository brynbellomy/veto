package ghsa

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

// Plug ghsa into the shared cache-only integrity harness. ghsa is a
// gob/tarball source with TWO local layers the cache-only directive can
// serve — the parsed gob and the raw tarball — so the damage step guts
// BOTH: whichever layer the directive tries, the verdict must reject it
// and the fetch must heal via network. (Layer-by-layer variants are
// pinned by ghsa_gutted_cache_test.go; this harness pins the guard as a
// whole, which is what a merge reverts.)
func ghsaCacheOnlyCase(t *testing.T) cacheonlytest.Case {
	t.Helper()
	intact := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-test/GHSA-test.json": ghsaAdvisoryJSON("vulnerable"),
	})
	guttedTarball := makeTarballBytes(t, map[string]string{
		"advisory-database-main/advisories/github-reviewed/2026/05/GHSA-other/GHSA-other.json": ghsaAdvisoryJSON("someone-else"),
	})
	return cacheonlytest.Case{
		Name:      "ghsa",
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
			src, err := New(Options{
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
			// Gut the tarball payload.
			require.NoError(t, os.WriteFile(
				filepath.Join(cacheDir, "main.tar.gz"), guttedTarball, 0o600))
			// And damage every gob: a parseable-but-different gob whose
			// recorded sidecar no longer matches. Encoding a real gob with
			// the gutted report set keeps it decodable (so a reverted guard
			// would serve it) while the hash mismatch marks it damaged.
			guttedGob := encodeGobForTest(t, []intel.MalwareReport{{
				PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "someone-else"},
				SourceID:   "ghsa",
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
	cacheonlytest.RunGuttedUnderCacheOnly(t, ghsaCacheOnlyCase(t))
}

func TestCacheOnlyHarnessUnrecordedServesButDoesNotAdopt(t *testing.T) {
	cacheonlytest.RunUnrecordedMustNotAdopt(t, ghsaCacheOnlyCase(t))
}

// encodeGobForTest renders a gobBlob the same way writeGob does, for
// damaging the gob layer with decodable-but-unrelated bytes.
func encodeGobForTest(t *testing.T, reports []intel.MalwareReport) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(gobBlob{Reports: reports}))
	return buf.Bytes()
}

func TestCacheOnlyHarness304UnrecordedGuttedMustRebindFromWire(t *testing.T) {
	cacheonlytest.Run304UnrecordedGuttedMustRebindFromWire(t, ghsaCacheOnlyCase(t))
}

func TestCacheOnlyHarness304LoopMustFailClosed(t *testing.T) {
	cacheonlytest.Run304LoopMustFailClosed(t, ghsaCacheOnlyCase(t))
}

func TestCacheOnlyHarnessHead304WithUnrecordedLayerFailsClosed(t *testing.T) {
	cacheonlytest.RunHead304WithUnrecordedLayerFailsClosed(t, ghsaCacheOnlyCase(t))
}
