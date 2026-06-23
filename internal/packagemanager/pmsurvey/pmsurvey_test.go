package pmsurvey_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

func writeExec(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
}

func writeSymlink(t *testing.T, link, target string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	require.NoError(t, os.Symlink(target, link))
}

func TestIsShimDirMatchesVersionManagerShimPaths(t *testing.T) {
	require.True(t, pmsurvey.IsShimDir("/Users/x/.local/share/mise/shims"))
	require.True(t, pmsurvey.IsShimDir("/home/x/.asdf/shims"))
	require.True(t, pmsurvey.IsShimDir("/home/x/.pyenv/shims"))
	require.True(t, pmsurvey.IsShimDir("/home/x/.nvm/versions/node/v20/bin"))
}

// TestIsShimDirRejectsDirWithVetoWrappers proves a normal bin dir that
// contains veto wrappers alongside unrelated content is NOT a shim dir.
// The veto-symlink heuristic was dropped because it was a false-positive
// magnet: every dir where veto had previously wrapped one binary (e.g.
// ~/.cargo/bin with a uvx→veto wrapper) was skipped entirely, hiding
// real wrap candidates like cargo from PathsFor.
func TestIsShimDirRejectsDirWithVetoWrappers(t *testing.T) {
	dir := t.TempDir()
	// Simulate ~/.cargo/bin after install-wrappers: uvx is a veto
	// wrapper, uvx.veto-original is the real binary, and cargo is an
	// unrelated (unwrapped) binary.
	vetoBin := filepath.Join(t.TempDir(), "bin", "veto")
	writeExec(t, vetoBin)
	writeSymlink(t, filepath.Join(dir, "uvx"), vetoBin)
	writeExec(t, filepath.Join(dir, "uvx.veto-original"))
	writeExec(t, filepath.Join(dir, "cargo"))
	require.False(t, pmsurvey.IsShimDir(dir),
		"dir containing veto wrappers AND unrelated binaries must not be a shim dir")
}

func TestIsShimDirRejectsRegularBinDir(t *testing.T) {
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "npm"))
	require.False(t, pmsurvey.IsShimDir(dir))
}

func TestPathsForFindsWellKnownAndPathEntries(t *testing.T) {
	// Use a fake $HOME so mise/asdf/etc. don't pick up the test runner's
	// real installs.
	home := t.TempDir()
	t.Setenv("HOME", home)

	miseBin := filepath.Join(home, ".local", "share", "mise", "installs", "node", "20.0.0", "bin")
	writeExec(t, filepath.Join(miseBin, "npm"))

	pathDir := t.TempDir()
	writeExec(t, filepath.Join(pathDir, "npm"))
	t.Setenv("PATH", pathDir)

	got := pmsurvey.PathsFor("npm")
	require.Contains(t, got, filepath.Join(miseBin, "npm"))
	require.Contains(t, got, filepath.Join(pathDir, "npm"))
}

func TestPathsForIncludesBrokenSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Plant a broken symlink at the mise bin location.
	miseBin := filepath.Join(home, ".local", "share", "mise", "installs", "bun", "1.0.0", "bin")
	writeSymlink(t, filepath.Join(miseBin, "bun"), filepath.Join(t.TempDir(), "vanished-target"))
	t.Setenv("PATH", "")

	got := pmsurvey.PathsFor("bun")
	require.Contains(t, got, filepath.Join(miseBin, "bun"),
		"broken symlinks must be included in PathsFor — install-wrappers and doctor both need to see them")
}

func TestPathsForSkipsShimDirsOnPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shim := filepath.Join(home, ".local", "share", "mise", "shims")
	writeExec(t, filepath.Join(shim, "npm"))
	t.Setenv("PATH", shim)

	got := pmsurvey.PathsFor("npm")
	for _, p := range got {
		require.False(t, strings.Contains(p, "/mise/shims/"),
			"PathsFor must skip mise shim dirs; got %s", p)
	}
}

func TestPathsForExcludesDirs(t *testing.T) {
	// A bare directory at a candidate path must not be returned.
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, ".bun", "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(bin, "bun"), 0o755)) // bun is a dir, not a file
	t.Setenv("PATH", "")

	got := pmsurvey.PathsFor("bun")
	for _, p := range got {
		info, err := os.Lstat(p)
		require.NoError(t, err)
		require.False(t, info.IsDir(), "PathsFor returned a directory: %s", p)
	}
}

func TestWellKnownBinDirsIncludesHomebrew(t *testing.T) {
	got := pmsurvey.WellKnownBinDirs()
	require.Contains(t, got, "/opt/homebrew/bin")
	require.Contains(t, got, "/usr/local/bin")
}

func TestPathsForDeduplicates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".bun", "bin")
	writeExec(t, filepath.Join(dir, "bun"))
	t.Setenv("PATH", dir) // same dir reachable via PATH too

	got := pmsurvey.PathsFor("bun")
	count := 0
	for _, p := range got {
		if p == filepath.Join(dir, "bun") {
			count++
		}
	}
	require.Equal(t, 1, count, "PathsFor must dedupe paths reachable via two roots")
}

// macOSOnly fences a test that depends on /opt/homebrew layout. Linux
// CI has /usr/local/bin but not /opt/homebrew; the assertion above
// would still pass on Linux because /opt/homebrew/bin doesn't have to
// exist for the slice to contain it.
func macOSOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only test")
	}
}

// TestPathsForIncludesUVCanonicalPython proves PathsFor walks the
// uv-managed cpython store and surfaces the canonical python3.X
// regular file living there, NOT on $PATH. Closes the uv-venv bypass
// at the source: a venv that symlinks the canonical binary now
// resolves through veto.
func TestPathsForIncludesUVCanonicalPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // isolate from the runner's PATH

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	writeExec(t, filepath.Join(uvBin, "python3.12"))

	got312 := pmsurvey.PathsFor("python3.12")
	require.Contains(t, got312, filepath.Join(uvBin, "python3.12"),
		"uv canonical python3.X must be surfaced as a wrap candidate")
}

// TestPathsForSkipsUVStoreForNonPython confirms the uv-store walk is
// gated on the versioned-python shape. A `PathsFor("npm")` must NOT
// poke the uv store on every call — it's a cold path that doesn't
// earn its keep for non-python requests.
func TestPathsForSkipsUVStoreForNonPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	// Plant an npm file inside the uv store path so any walker would
	// find it. PathsFor must NOT surface it because the name isn't a
	// versioned-python alias.
	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	writeExec(t, filepath.Join(uvBin, "npm"))

	got := pmsurvey.PathsFor("npm")
	require.NotContains(t, got, filepath.Join(uvBin, "npm"),
		"uv-store dirs must only contribute candidates for versioned python aliases")
}

// TestPathsForUVStoreFiltersAliasSymlinks proves that `python` and
// `python3` aliases inside a uv cpython bin dir are NOT surfaced as
// wrap candidates, but the canonical `python3.X` IS. This is the
// regression test for the chain-corruption bug: if the aliases were
// wrapped independently, `python.veto-original` would remain a symlink
// to the now-wrapped `python3.X`, looping veto back into itself on
// every `python` invocation. The aliases inherit the wrap for free
// via the existing symlink chain (python → python3.X → veto), so they
// must be omitted from uv-store discovery entirely (the uv-store walk
// is gated on the versioned-python shape).
func TestPathsForUVStoreFiltersAliasSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // isolate from the runner's PATH

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.11.13-macos-aarch64-none", "bin")
	// Real uv layout: python3.11 is the canonical regular file;
	// python and python3 are symlinks pointing at it.
	canonical := filepath.Join(uvBin, "python3.11")
	writeExec(t, canonical)
	writeSymlink(t, filepath.Join(uvBin, "python"), "python3.11")
	writeSymlink(t, filepath.Join(uvBin, "python3"), "python3.11")

	got311 := pmsurvey.PathsFor("python3.11")
	require.Contains(t, got311, canonical,
		"canonical python3.X must be surfaced as a wrap candidate")

	gotPython := pmsurvey.PathsFor("python")
	require.NotContains(t, gotPython, filepath.Join(uvBin, "python"),
		"uv-store python alias must not surface — would corrupt the exec chain after wrap")

	gotPython3 := pmsurvey.PathsFor("python3")
	require.NotContains(t, gotPython3, filepath.Join(uvBin, "python3"),
		"uv-store python3 alias must not surface — would corrupt the exec chain after wrap")
}

// TestPathsForUVStoreReentrantOnWrappedCanonical proves the uv-store
// walk surfaces an already-wrapped python3.X (now a symlink to veto)
// on a re-run, so the reconciler can classify it as already-ours
// instead of silently dropping it. Belt-and-suspenders against an
// over-eager regular-file filter: the gating is on the versioned-name
// shape only, not on the candidate's file type.
func TestPathsForUVStoreReentrantOnWrappedCanonical(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // isolate from the runner's PATH

	// Simulate an already-wrapped layout: python3.11 is a symlink to
	// some `veto` binary, and python3.11.veto-original holds the real
	// bytes.
	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.11.13-macos-aarch64-none", "bin")
	canonical := filepath.Join(uvBin, "python3.11")
	fakeVeto := filepath.Join(home, ".local", "bin", "veto")
	writeExec(t, fakeVeto)
	writeSymlink(t, canonical, fakeVeto)
	writeExec(t, canonical+".veto-original")

	got := pmsurvey.PathsFor("python3.11")
	require.Contains(t, got, canonical,
		"already-wrapped python3.X (symlink to veto) must still surface for reconciliation")
}

// TestPathsForUVStoreFiltersNonCPythonDirs proves only `cpython-*`
// dirs in the uv store contribute candidates. A future pypy/cython/etc.
// dir alongside cpython must not get picked up — the prefix filter is
// load-bearing for the python-family gating.
func TestPathsForUVStoreFiltersNonCPythonDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	pypyBin := filepath.Join(home, ".local", "share", "uv", "python",
		"pypy-3.10-macos-aarch64", "bin")
	writeExec(t, filepath.Join(pypyBin, "python3.10"))
	cpyBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.10.14-macos-aarch64-none", "bin")
	writeExec(t, filepath.Join(cpyBin, "python3.10"))

	got := pmsurvey.PathsFor("python3.10")
	require.Contains(t, got, filepath.Join(cpyBin, "python3.10"))
	require.NotContains(t, got, filepath.Join(pypyBin, "python3.10"),
		"only cpython-* dirs in the uv store should contribute candidates")
}
