// Package tmpsweeptest is a shared harness for the orphan-temp sweep
// contract: every NETWORK source must, on its first Fetch, sweep abandoned
// *.tmp-* download temps from its own cache directory — and that sweep
// must never be able to fail the fetch.
//
// Like cacheonlytest, this exists because the hook is duplicated per
// source (nine copies) and each copy can be reverted independently — a
// guard that nothing tests is a guard on a timer. Every network source
// MUST plug into this harness; sweep_registry_test.go fails loudly when a
// source is added without one. hades is static embedded data with no
// cache dir and is exempt.
//
// The harness deliberately reuses cacheonlytest.Case rather than defining
// its own fixture shape: each source's <name>CacheOnlyCase constructor
// already builds the real source against a real cache dir, and reusing it
// means the sweep is exercised through the exact construction the
// CLI-shaped tests use. Only NewSource and Ecosystem are consumed.
package tmpsweeptest

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// plantedAge is how old a planted orphan must be to be past the sweep
// threshold. It deliberately exceeds fsutil's 24h threshold by a wide
// margin so the harness stays correct even if the threshold is retuned
// upward within reason.
const plantedAge = 48 * time.Hour

// realCacheFiles is the set of REAL cache file shapes planted alongside
// the orphan. It is a deliberate superset across sources (osv's npm.zip,
// gemnasium's advisories-community.tar.gz, gob layers, sidecars, markers):
// the sweep matches only the *.tmp-<digits> name shape, never a payload
// registry, so every one of these must survive in every source's dir.
var realCacheFiles = []string{
	"npm.zip",
	"npm.zip.sha256",
	"npm.etag",
	"npm.etag.pending",
	"parsed-abcdef.gob",
	"advisories-community.tar.gz",
	"intel-baseline.json",
	"last-refresh",
}

// RunSweepsOrphansOnFirstFetch is the core scenario: construct a COLD
// source over a cache dir holding an orphaned download temp plus the full
// set of real cache files, run one Fetch, and assert the orphan is gone,
// every real file survived, and the fetch did not fail because of the
// sweep. A network error from the Fetch itself is acceptable — the sweep
// runs before any network I/O, so its effect on the cache dir is
// observable regardless of what the network did.
func RunSweepsOrphansOnFirstFetch(t *testing.T, c cacheonlytest.Case) {
	t.Helper()

	// The upstream can be a do-nothing server: the sweep happens before
	// any network I/O, and a 404 or empty body is a perfectly good
	// "network said no" outcome for the fetch to handle.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	orphan := plant(t, cacheDir, "planted-orphan.bin.tmp-1877699234")

	var real []string
	for _, name := range realCacheFiles {
		real = append(real, plant(t, cacheDir, name))
	}

	src := c.NewSource(t, srv.URL, cacheDir)
	_, _ = src.Fetch(t.Context(), c.Ecosystem) //nolint:errcheck // network errors are out of scope here

	require.NoFileExists(t, orphan,
		"%s: first Fetch must sweep the orphaned *.tmp-* download temp from its own cache dir", c.Name)
	for _, p := range real {
		require.FileExists(t, p,
			"%s: the sweep must never remove a real cache file: %q", c.Name, filepath.Base(p))
	}
}

// RunSweepFailureNeverFailsFetch pins the non-fatality half of the
// contract at the hook level: a cache dir the sweep can neither list nor
// write must not fail the fetch, and must not leave the sweep wedged —
// once the obstruction clears, the next Fetch's sweep still works.
func RunSweepFailureNeverFailsFetch(t *testing.T, c cacheonlytest.Case) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based unreadable-dir fixture is meaningless")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	orphan := plant(t, cacheDir, "planted-orphan.bin.tmp-1877699234")

	// Construct FIRST: every source's New() chmods its cache dir to 0700,
	// which would undo the obstruction below.
	src := c.NewSource(t, srv.URL, cacheDir)

	require.NoError(t, os.Chmod(cacheDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(cacheDir, 0o700) })

	// The fetch may error (network, cache unreadable) but must not panic
	// and must not error BECAUSE of the sweep — the sweep has no error
	// return to misuse, which is the point.
	_, _ = src.Fetch(t.Context(), c.Ecosystem) //nolint:errcheck // the fetch's own error is out of scope

	require.NoError(t, os.Chmod(cacheDir, 0o700))
	require.FileExists(t, orphan,
		"%s: a sweep that cannot proceed must leave the orphan untouched (skip, not half-run)", c.Name)

	// A second Fetch on a FRESH source (the once-per-process guard is per
	// Source instance, and a new process would sweep again) proves the
	// obstruction was skipped rather than latching: with the dir readable
	// again, the sweep completes.
	fresh := c.NewSource(t, srv.URL, cacheDir)
	_, _ = fresh.Fetch(t.Context(), c.Ecosystem) //nolint:errcheck
	require.NoFileExists(t, orphan,
		"%s: once the cache dir is readable again, the next Fetch's sweep must remove the orphan", c.Name)
}

// plant writes a small fixture into dir with a controlled mtime. Synthetic
// files (a few KB, exact ages) are a better test of an mtime-based sweep
// than any copy of a real cache: the ages are precise, and nobody's 4.7 GB
// of actual garbage gets duplicated.
func plant(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	require.NoError(t, os.Chtimes(path, time.Now().Add(-plantedAge), time.Now().Add(-plantedAge)))
	return path
}
