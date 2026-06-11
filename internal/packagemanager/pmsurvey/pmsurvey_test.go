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

func TestIsShimDirDetectsVetoLayer2ShimDir(t *testing.T) {
	dir := t.TempDir()
	// Plant a fake "veto" binary somewhere and symlink an "npm" entry to it.
	vetoBin := filepath.Join(dir, "..", "bin", "veto")
	writeExec(t, vetoBin)
	writeSymlink(t, filepath.Join(dir, "npm"), vetoBin)
	require.True(t, pmsurvey.IsShimDir(dir), "veto-named symlink target should mark dir as a shim dir")
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
