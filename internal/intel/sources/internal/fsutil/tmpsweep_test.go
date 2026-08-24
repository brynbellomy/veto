package fsutil_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

// plant writes a small file into dir with a controlled mtime, returning its
// full path. Synthetic fixtures (a few KB, exact ages) are a better test of a
// mtime-based sweep than any copy of a real cache: the ages are precise.
func plant(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	require.NoError(t, os.Chtimes(path, time.Now().Add(-age), time.Now().Add(-age)))
	return path
}

// TestSweepOrphanTempsRemovesOldTemps pins direction 1: an orphaned
// os.CreateTemp sibling whose mtime is past the threshold IS removed.
func TestSweepOrphanTempsRemovesOldTemps(t *testing.T) {
	dir := t.TempDir()
	old := plant(t, dir, "npm.zip.tmp-1877699234", 25*time.Hour)

	fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	require.NoFileExists(t, old, "a *.tmp-* file older than the threshold must be removed")
}

// TestSweepOrphanTempsSparesYoungTemps pins direction 2 — the one that
// protects an in-flight download. A live writer's temp file was created
// moments ago by os.CreateTemp; it must NOT be removed, at any threshold
// short of its real age.
func TestSweepOrphanTempsSparesYoungTemps(t *testing.T) {
	dir := t.TempDir()

	// A real os.CreateTemp-shaped name, young — the in-flight download shape.
	youngLive, err := os.CreateTemp(dir, "npm.zip.tmp-")
	require.NoError(t, err)
	require.NoError(t, youngLive.Close())
	t.Cleanup(func() { _ = os.Remove(youngLive.Name()) })

	// Same name shape but explicitly one hour old: still far inside the
	// 24h window, so it must survive even though it looks exactly like an
	// orphan to any purely name-based check.
	youngAged := plant(t, dir, "npm.zip.tmp-0000000001", time.Hour)

	fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	require.FileExists(t, youngLive.Name(), "a live writer's temp file must never be swept")
	require.FileExists(t, youngAged, "a *.tmp-* file newer than the threshold must NOT be removed")
}

// TestSweepOrphanTempsNeverTouchesRealCacheFiles pins direction 3: real
// cache files — payloads, sidecars, etags, gobs, baseline and refresh
// markers — are NEVER removed, at any age, however old. These are the
// files veto serves from; deleting one would turn hygiene into an outage.
func TestSweepOrphanTempsNeverTouchesRealCacheFiles(t *testing.T) {
	dir := t.TempDir()
	ancient := 500 * time.Hour // far past any threshold

	// Every real file shape a source's cache dir can hold.
	kept := []string{
		"npm.zip",                        // payload
		"npm.zip.sha256",                 // content-hash sidecar
		"npm.etag",                       // etag
		"npm.etag.pending",               // etag pending sibling
		"parsed-abc123.gob",              // parsed gob layer
		"main.tar.gz",                    // streaming payload
		"advisories-community.tar.gz",    // gemnasium payload
		"intel-baseline.json",            // per-source baseline
		"last-refresh",                   // freshness marker
		"npm.zip.tmp-123.gob",            // NOT a temp: digits not terminal
		"npm.zip.tmp-12a4",               // NOT a temp: suffix not all digits
		"npm.zip.tmp-",                   // NOT a temp: empty suffix
		"parsed-x.tmp-999.gob",           // NOT a temp: gob with tmp- inside
	}
	var planted []string
	for _, name := range kept {
		planted = append(planted, plant(t, dir, name, ancient))
	}

	// A temp-shaped file whose prefix is NOT any known payload name must
	// still be swept: the predicate is the os.CreateTemp NAME SHAPE, not a
	// registry of payload prefixes. That is what makes the primitive safe
	// to point at a new source's cache dir without enumerating its files.
	unrelated := plant(t, dir, "brand-new-source.bin.tmp-42", ancient)

	fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	for _, p := range planted {
		require.FileExists(t, p, "real cache file %q must never be swept, at any age", filepath.Base(p))
	}
	require.NoFileExists(t, unrelated, "any <name>.tmp-<digits> file past the threshold is an orphan, whatever its prefix")
}

// TestSweepOrphanTempsAgeBoundary pins the exact boundary semantics: the
// threshold is inclusive — a file exactly 24h old is swept, a file just
// under it is not.
func TestSweepOrphanTempsAgeBoundary(t *testing.T) {
	dir := t.TempDir()
	exactly := plant(t, dir, "npm.zip.tmp-2000000000", 24*time.Hour)
	justUnder := plant(t, dir, "npm.zip.tmp-2000000001", 24*time.Hour-time.Second)

	fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	require.NoFileExists(t, exactly, "a file at exactly the threshold has failed every reasonable retry window; sweep it")
	require.FileExists(t, justUnder, "a file just inside the window is potentially a slow live writer; spare it")
}

// TestSweepOrphanTempsSubdirectoriesIgnored pins that the sweep never
// descends and never removes a directory, even a temp-shaped one: the
// per-source scope is one flat directory listing.
func TestSweepOrphanTempsSubdirectoriesIgnored(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested.tmp-123")
	require.NoError(t, os.Mkdir(sub, 0o700))

	fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	info, err := os.Stat(sub)
	require.NoError(t, err)
	require.True(t, info.IsDir(), "a directory must never be removed by the sweep")
}

// TestSweepOrphanTempsMissingDirIsNonFatal pins the non-fatality contract:
// a cache dir that cannot be listed (missing, unreadable) is logged and
// skipped. Hygiene must never fail a fetch.
func TestSweepOrphanTempsMissingDirIsNonFatal(t *testing.T) {
	require.NotPanics(t, func() {
		fsutil.SweepOrphanTemps(filepath.Join(t.TempDir(), "does-not-exist"), zerolog.Nop())
	})
}

// TestSweepOrphanTempsUnremovableFileIsNonFatal pins the other half of the
// non-fatality contract: a file that matches the pattern but cannot be
// removed must be logged and skipped without aborting the sweep — the
// removable one next to it still goes.
func TestSweepOrphanTempsUnremovableFileIsNonFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based unremovable-file fixture is meaningless")
	}

	dir := t.TempDir()
	stuck := plant(t, dir, "npm.zip.tmp-1111111111", 30*time.Hour)
	gone := plant(t, dir, "npm.zip.tmp-2222222222", 30*time.Hour)

	// Make the directory non-writable: unlink needs write permission on
	// the parent dir, not the file itself. Both files are now unremovable.
	require.NoError(t, os.Chmod(dir, 0o500))
	fsutil.SweepOrphanTemps(dir, zerolog.Nop())
	require.FileExists(t, stuck, "an unremovable file must be logged and skipped, not fatal")

	// Restore writability: the same sweep must now succeed — proving the
	// earlier return was a skip, not a wedged state.
	require.NoError(t, os.Chmod(dir, 0o700))
	fsutil.SweepOrphanTemps(dir, zerolog.Nop())
	require.NoFileExists(t, gone, "once removable, the same file must go")
}

// TestSweepOrphanTempsOnlySweepsItsOwnDirectory pins the per-source scope
// requirement: a sweep of dir A must not reach a sibling directory B. A bug
// in one source's cleanup must not be able to touch another source's cache.
func TestSweepOrphanTempsOnlySweepsItsOwnDirectory(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()

	inB := plant(t, b, "npm.zip.tmp-3333333333", 48*time.Hour)

	fsutil.SweepOrphanTemps(a, zerolog.Nop())

	require.FileExists(t, inB, "sweeping directory A must not touch directory B")
}

// TestSweepOrphanTempsReportsRemovedCount pins the return value so callers
// can log one structured line per sweep instead of one per file.
func TestSweepOrphanTempsReportsRemovedCount(t *testing.T) {
	dir := t.TempDir()
	plant(t, dir, "npm.zip.tmp-1", 30*time.Hour)
	plant(t, dir, "npm.zip.tmp-2", 48*time.Hour)
	plant(t, dir, "PyPI.zip.tmp-3", 40*time.Hour)
	plant(t, dir, "npm.zip", 48*time.Hour)

	removed := fsutil.SweepOrphanTemps(dir, zerolog.Nop())

	require.Equal(t, 3, removed)
}

// TestSweepOrphanTempsReturnsZeroForRealFilesOnly pins that a healthy cache
// directory reports zero and leaves everything in place — the common case,
// run on every single Fetch across nine sources, must be a cheap no-op.
func TestSweepOrphanTempsReturnsZeroForRealFilesOnly(t *testing.T) {
	dir := t.TempDir()
	plant(t, dir, "npm.zip", 48*time.Hour)
	plant(t, dir, "npm.zip.sha256", 48*time.Hour)
	plant(t, dir, "npm.etag", 48*time.Hour)

	require.Zero(t, fsutil.SweepOrphanTemps(dir, zerolog.Nop()))
}
