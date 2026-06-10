package wsglob

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeDirs creates each path under root (as dirs), creating parents
// as needed. Empty subpath creates only root.
func makeDirs(t *testing.T, root string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		require.NoError(t, os.MkdirAll(filepath.Join(root, s), 0o755))
	}
}

// makeFile creates a touch-style file under root/path.
func makeFile(t *testing.T, root, path string) {
	t.Helper()
	full := filepath.Join(root, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte("x"), 0o644))
}

func sortedMatches(t *testing.T, pattern string) []string {
	t.Helper()
	got, err := Match(pattern)
	require.NoError(t, err)
	sort.Strings(got)
	return got
}

func TestMatch_NoDoubleStar_DelegatesToFilepathGlob(t *testing.T) {
	root := t.TempDir()
	makeDirs(t, root, "a", "b", "c")
	pattern := filepath.Join(root, "*")
	got := sortedMatches(t, pattern)
	want := []string{
		filepath.Join(root, "a"),
		filepath.Join(root, "b"),
		filepath.Join(root, "c"),
	}
	require.Equal(t, want, got)
}

func TestMatch_DoubleStar_AnyDepth(t *testing.T) {
	root := t.TempDir()
	// packages/web (1 level)
	// packages/api/inner (2 levels)
	// packages/api/inner/leaf (3 levels)
	makeDirs(t, root,
		"packages/web",
		"packages/api/inner/leaf",
	)
	pattern := filepath.Join(root, "packages", "**")
	got := sortedMatches(t, pattern)
	want := []string{
		filepath.Join(root, "packages"),
		filepath.Join(root, "packages", "api"),
		filepath.Join(root, "packages", "api", "inner"),
		filepath.Join(root, "packages", "api", "inner", "leaf"),
		filepath.Join(root, "packages", "web"),
	}
	require.Equal(t, want, got)
}

func TestMatch_DoubleStarWithSuffix(t *testing.T) {
	root := t.TempDir()
	// We want to find every dir named "src" at any depth under packages/.
	makeDirs(t, root,
		"packages/a/src",
		"packages/b/inner/src",
		"packages/c/notsrc",
	)
	pattern := filepath.Join(root, "packages", "**", "src")
	got := sortedMatches(t, pattern)
	want := []string{
		filepath.Join(root, "packages", "a", "src"),
		filepath.Join(root, "packages", "b", "inner", "src"),
	}
	require.Equal(t, want, got)
}

func TestMatch_PrefixWildcards(t *testing.T) {
	root := t.TempDir()
	// apps/<name>/packages — common monorepo pattern.
	makeDirs(t, root,
		"apps/web/packages/a",
		"apps/web/packages/b",
		"apps/api/packages/c",
	)
	pattern := filepath.Join(root, "apps", "*", "packages", "**")
	got := sortedMatches(t, pattern)
	want := []string{
		filepath.Join(root, "apps", "api", "packages"),
		filepath.Join(root, "apps", "api", "packages", "c"),
		filepath.Join(root, "apps", "web", "packages"),
		filepath.Join(root, "apps", "web", "packages", "a"),
		filepath.Join(root, "apps", "web", "packages", "b"),
	}
	require.Equal(t, want, got)
}

func TestMatch_NonexistentRoot_ReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	// `packages/**` against a dir that doesn't exist should return
	// no matches, not an error — mirrors filepath.Glob's "no match"
	// behavior for the no-`**` case.
	pattern := filepath.Join(root, "packages", "**")
	got, err := Match(pattern)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestMatch_MultipleDoubleStars_Rejected(t *testing.T) {
	root := t.TempDir()
	pattern := filepath.Join(root, "a", "**", "b", "**", "c")
	_, err := Match(pattern)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at most one")
}

// TestMatch_FilesUnderPrefix_NotEmitted asserts we don't emit
// non-directory paths from the recursive walk. Workspace members are
// directories that contain a manifest file; emitting plain files
// would confuse callers that stat them for a manifest.
func TestMatch_FilesUnderPrefix_NotEmitted(t *testing.T) {
	root := t.TempDir()
	makeDirs(t, root, "packages/a")
	makeFile(t, root, "packages/a/manifest.json")
	makeFile(t, root, "packages/stray.txt")

	got := sortedMatches(t, filepath.Join(root, "packages", "**"))
	for _, p := range got {
		info, err := os.Stat(p)
		require.NoError(t, err)
		require.True(t, info.IsDir(), "Match emitted a non-directory path: %s", p)
	}
}
