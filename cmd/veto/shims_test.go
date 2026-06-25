package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnsureShim covers the four states ensureShim can encounter at the
// target path: missing, already-correct symlink, symlink-to-something-else,
// and regular file. The --force toggle decides the last two.
func TestEnsureShim(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	t.Run("creates symlink when target missing", func(t *testing.T) {
		target := filepath.Join(dir, "npm-1")
		action, err := ensureShim(target, veto, false)
		require.NoError(t, err)
		require.Contains(t, action, "created")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})

	t.Run("no-op when already correct", func(t *testing.T) {
		target := filepath.Join(dir, "npm-2")
		require.NoError(t, os.Symlink(veto, target))
		action, err := ensureShim(target, veto, false)
		require.NoError(t, err)
		require.Empty(t, action, "expected silent no-op when symlink is already correct")
	})

	t.Run("refuses to replace symlink pointing elsewhere without force", func(t *testing.T) {
		target := filepath.Join(dir, "npm-3")
		other := filepath.Join(dir, "some-other-binary")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		_, err := ensureShim(target, veto, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "symlink points elsewhere")
	})

	t.Run("force replaces symlink pointing elsewhere", func(t *testing.T) {
		target := filepath.Join(dir, "npm-4")
		other := filepath.Join(dir, "some-other-binary-2")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		action, err := ensureShim(target, veto, true)
		require.NoError(t, err)
		require.Contains(t, action, "updated")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})

	t.Run("refuses to overwrite a regular file without force", func(t *testing.T) {
		target := filepath.Join(dir, "npm-5")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		_, err := ensureShim(target, veto, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "file exists and is not a symlink")
		// Confirm we didn't touch it:
		content, _ := os.ReadFile(target)
		require.Equal(t, "real binary", string(content))
	})

	t.Run("force replaces a regular file", func(t *testing.T) {
		target := filepath.Join(dir, "npm-6")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		action, err := ensureShim(target, veto, true)
		require.NoError(t, err)
		require.Contains(t, action, "updated")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})
}

// TestEnsureShim_Force_RenamesRealBinary proves --force preserves any
// pre-existing real binary at the target path by renaming it to
// <target>.veto-displaced rather than deleting it. Closes the L2
// reviewer's "silently destroys homebrew npm" finding.
func TestEnsureShim_Force_RenamesRealBinary(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	target := filepath.Join(dir, "npm")
	realBinary := []byte("#!/bin/sh\necho real-npm\n")
	require.NoError(t, os.WriteFile(target, realBinary, 0o755))

	action, err := ensureShim(target, veto, true)
	require.NoError(t, err)
	require.Contains(t, action, "updated")

	// Target is now a symlink to veto.
	resolved, err := os.Readlink(target)
	require.NoError(t, err)
	require.Equal(t, veto, resolved)

	// Real binary preserved at .veto-displaced.
	got, err := os.ReadFile(target + ".veto-displaced")
	require.NoError(t, err)
	require.Equal(t, realBinary, got, "real binary must be renamed, not deleted")
}

// TestRemoveShim_RestoresDisplacedBinary proves uninstall-shims puts
// the displaced binary back at its original path.
func TestRemoveShim_RestoresDisplacedBinary(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	target := filepath.Join(dir, "npm")
	original := []byte("real-npm-bytes")
	require.NoError(t, os.WriteFile(target, original, 0o755))

	_, err := ensureShim(target, veto, true)
	require.NoError(t, err)
	// Now: target is symlink, target.veto-displaced has original bytes.

	removed, err := removeShim(target, veto)
	require.NoError(t, err)
	require.True(t, removed)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, original, got, "removeShim must restore the displaced real binary")
	_, statErr := os.Lstat(target + ".veto-displaced")
	require.True(t, os.IsNotExist(statErr), ".veto-displaced must be gone after restore")
}

func TestRemoveShim(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	t.Run("removes a veto-pointing symlink", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r1")
		require.NoError(t, os.Symlink(veto, target))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.True(t, removed)
		_, statErr := os.Lstat(target)
		require.True(t, os.IsNotExist(statErr))
	})

	t.Run("skips a symlink pointing elsewhere", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r2")
		other := filepath.Join(dir, "some-other")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
		// Symlink still in place:
		_, statErr := os.Lstat(target)
		require.NoError(t, statErr)
	})

	t.Run("skips a regular file", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r3")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
	})

	t.Run("skips missing target without error", func(t *testing.T) {
		target := filepath.Join(dir, "missing")
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
	})
}

func TestIsShimName(t *testing.T) {
	// Spot-check that the dispatch table matches the install set. If these
	// drift apart, `veto install-shims` would create a symlink that the
	// shim-dispatch code wouldn't recognize.
	for _, name := range shimmedManagers {
		require.True(t, isShimName(name), "isShimName must recognize %s", name)
	}
	require.False(t, isShimName("veto"))
	require.False(t, isShimName(""))
	// Versioned python aliases must also dispatch as shims so an
	// install-shims-created ~/.local/bin/python3.12 routes through
	// veto when resolved through PATH.
	require.True(t, isShimName("python3.10"))
	require.True(t, isShimName("python3.12"))
	require.True(t, isShimName("python3.11.2"))
	require.False(t, isShimName("python3-config"))
	require.False(t, isShimName("python4"))
}

// TestDiscoverVersionedPythons proves install-shims enumerates the uv
// canonical store and the host PATH for python3.X aliases, deduping
// across both surfaces.
func TestDiscoverVersionedPythons(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// uv canonical store: python3.12 and python3.11
	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(uvBin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(uvBin, "python3.12"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(uvBin, "python3"), []byte("#!/bin/sh\n"), 0o755))

	uvBin11 := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.11.9-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(uvBin11, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(uvBin11, "python3.11"), []byte("#!/bin/sh\n"), 0o755))

	// PATH: python3.10 lives somewhere else (a system / pyenv install
	// the uv store doesn't know about).
	pathDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(pathDir, "python3.10"), []byte("#!/bin/sh\n"), 0o755))
	// PATH also has python3.12 — must dedupe against the uv entry.
	require.NoError(t, os.WriteFile(filepath.Join(pathDir, "python3.12"), []byte("#!/bin/sh\n"), 0o755))
	// Adjacent non-aliases that must NOT be picked up.
	require.NoError(t, os.WriteFile(filepath.Join(pathDir, "python3-config"), []byte(""), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pathDir, "python4"), []byte(""), 0o755))
	t.Setenv("PATH", pathDir)

	got := discoverVersionedPythons()
	require.Equal(t, []string{"python3.10", "python3.11", "python3.12"}, got,
		"versioned pythons must be deduped + sorted; non-aliases skipped")
}

// TestDiscoverVersionedPythonsEmpty proves discovery returns an empty
// slice (not nil-deref) when neither the uv store nor PATH yield any
// versioned aliases. install-shims falls back to the static list in
// that case.
func TestDiscoverVersionedPythonsEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	got := discoverVersionedPythons()
	require.Empty(t, got)
}

// TestRunInstallShims_CreatesVersionedPythonShims drives the install
// flow end-to-end with a faked uv store + tempdir shim dir, asserting
// that every discovered python3.X gets a symlink to the veto binary.
func TestRunInstallShims_CreatesVersionedPythonShims(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	// Plant a fake veto binary so resolveVetoBinary's
	// os.Executable() lookup resolves to a real path.
	// The runtime test binary IS already a real exec; we just need
	// the shim dir.
	shimDir := filepath.Join(home, "shimout")

	// Plant a python3.12 in the uv store.
	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(uvBin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(uvBin, "python3.12"), []byte("#!/bin/sh\n"), 0o755))

	logger := zerologNop()
	cfg := config{CacheDir: filepath.Join(home, ".cache", "veto")}
	rc := runInstallShims(logger, cfg, []string{"--dir", shimDir})
	require.Equal(t, exitOK, rc, "install-shims should succeed")

	// python3.12 shim must exist and be a symlink to the resolved veto
	// binary (the test binary itself, via os.Executable()).
	link := filepath.Join(shimDir, "python3.12")
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink, "expected symlink at python3.12 shim")
	// Static-canonical PMs also got shimmed.
	for _, name := range []string{"npm", "pip", "python", "python3"} {
		_, err := os.Lstat(filepath.Join(shimDir, name))
		require.NoError(t, err, "static-canonical %s should be shimmed", name)
	}
}

// TestScrubVetoOriginalSiblings_RemovesPlanted is the unit-level
// guarantee behind the Layer 2 invariant "no .veto-original siblings in
// the shim dir." We plant a mix of stale siblings (symlinks pointing at
// a fake veto + a regular file with the suffix) alongside normal shim
// symlinks, then assert the scrub removes only the .veto-original
// entries and leaves real shims alone.
func TestScrubVetoOriginalSiblings_RemovesPlanted(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	// Plant a normal shim that must survive.
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(veto, npm))

	// Plant a handful of stale .veto-original siblings: self-referential
	// symlinks (the dzk-observed state) plus one regular file.
	planted := []string{
		filepath.Join(dir, "python3.veto-original"),
		filepath.Join(dir, "python3.10.veto-original"),
		filepath.Join(dir, "python3.11.veto-original"),
		filepath.Join(dir, "python3.12.veto-original"),
	}
	for _, p := range planted {
		require.NoError(t, os.Symlink(veto, p))
	}
	regular := filepath.Join(dir, "pip.veto-original")
	require.NoError(t, os.WriteFile(regular, []byte("garbage"), 0o644))

	removed, errs := scrubVetoOriginalSiblings(dir, false)
	require.Empty(t, errs)
	require.Len(t, removed, len(planted)+1)

	// All planted siblings are gone.
	for _, p := range append(planted, regular) {
		_, err := os.Lstat(p)
		require.True(t, os.IsNotExist(err), "scrub left behind %s", p)
	}
	// Normal shim survives.
	_, err := os.Lstat(npm)
	require.NoError(t, err, "scrub must not touch the npm shim")
}

// TestScrubVetoOriginalSiblings_NoOpWhenClean proves the scrub is
// idempotent: re-running on an already-clean dir does nothing.
func TestScrubVetoOriginalSiblings_NoOpWhenClean(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink(veto, filepath.Join(dir, "npm")))

	removed, errs := scrubVetoOriginalSiblings(dir, false)
	require.Empty(t, errs)
	require.Empty(t, removed)
}

// TestScrubVetoOriginalSiblings_DryRunDoesNotMutate proves dryRun
// reports what would be removed without touching the filesystem.
func TestScrubVetoOriginalSiblings_DryRunDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))
	planted := filepath.Join(dir, "python3.veto-original")
	require.NoError(t, os.Symlink(veto, planted))

	removed, errs := scrubVetoOriginalSiblings(dir, true)
	require.Empty(t, errs)
	require.Equal(t, []string{planted}, removed)
	// Still on disk.
	_, err := os.Lstat(planted)
	require.NoError(t, err)
}

// TestScrubVetoOriginalSiblings_MissingDir proves an absent shim dir is
// reported as "no siblings present" rather than an error. Matches the
// install-shims convergence pass's "nothing to scrub" branch.
func TestScrubVetoOriginalSiblings_MissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	removed, errs := scrubVetoOriginalSiblings(dir, false)
	require.Empty(t, removed)
	require.Empty(t, errs)
}

// TestRunInstallShims_ScrubsStaleSiblings drives runInstallShims through
// a tempdir prepped with stale `<name>.veto-original` siblings and
// asserts they are gone after the install completes.
func TestRunInstallShims_ScrubsStaleSiblings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	shimDir := filepath.Join(home, "shimout")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	// Plant stale siblings BEFORE install-shims runs. These are the
	// real-world bryn-box state: symlinks back into the veto binary.
	planted := []string{
		filepath.Join(shimDir, "python3.veto-original"),
		filepath.Join(shimDir, "python3.12.veto-original"),
	}
	for _, p := range planted {
		require.NoError(t, os.Symlink("/usr/local/bin/veto-fake", p))
	}

	cfg := config{CacheDir: filepath.Join(home, ".cache", "veto")}
	rc := runInstallShims(zerologNop(), cfg, []string{"--dir", shimDir})
	require.Equal(t, exitOK, rc)

	for _, p := range planted {
		_, err := os.Lstat(p)
		require.True(t, os.IsNotExist(err), "install-shims must scrub stale sibling %s", p)
	}
}

// TestRunInstallShims_DryRunDoesNotMutate proves --dry-run lists what
// would be done without touching the filesystem.
func TestRunInstallShims_DryRunDoesNotMutate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	shimDir := filepath.Join(home, "shimout-dryrun")

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	require.NoError(t, os.MkdirAll(uvBin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(uvBin, "python3.12"), []byte("#!/bin/sh\n"), 0o755))

	cfg := config{CacheDir: filepath.Join(home, ".cache", "veto")}
	rc := runInstallShims(zerologNop(), cfg, []string{"--dir", shimDir, "--dry-run"})
	require.Equal(t, exitOK, rc)
	// Shim dir must NOT exist after dry-run.
	_, err := os.Lstat(shimDir)
	require.True(t, os.IsNotExist(err), "dry-run must not create the shim dir")
}

// TestPruneWrappersInShimDir_DropsShimDirEntries is the unit-level
// guarantee behind the Layer 2/Layer 4 territory rule: install-shims
// must reconcile wrappers.json against the shim dir and remove any
// entry whose Path is inside it. Without this, a stale shim-dir entry
// sends recovery commands (notably uninstall-wrappers) on a destructive
// path through the Layer 2 shims themselves — the exact failure mode
// that broke veto-dzk's recovery on bryn's machine.
func TestPruneWrappersInShimDir_DropsShimDirEntries(t *testing.T) {
	cacheDir := t.TempDir()
	shimDir := t.TempDir()
	cfg := config{CacheDir: cacheDir}

	// One legit Layer 4 wrapper (homebrew layout) that MUST survive.
	legit := wrapperEntry{
		Path:         "/opt/homebrew/bin/npm",
		OriginalPath: "/opt/homebrew/bin/npm.veto-original",
		PM:           "npm",
		Source:       "homebrew",
	}
	// Two bogus shim-dir entries that MUST be removed.
	bogus := []wrapperEntry{
		{
			Path:         filepath.Join(shimDir, "python3"),
			OriginalPath: filepath.Join(shimDir, "python3.veto-original"),
			PM:           "python3",
			Source:       "path",
		},
		{
			Path:         filepath.Join(shimDir, "npm"),
			OriginalPath: filepath.Join(shimDir, "npm.veto-original"),
			PM:           "npm",
			Source:       "path",
		},
	}
	state := wrapperState{Wrappers: append([]wrapperEntry{legit}, bogus...)}
	require.NoError(t, saveWrapperState(cfg, state))

	pruned, err := pruneWrappersInShimDir(cfg, shimDir, false)
	require.NoError(t, err)
	require.Len(t, pruned, 2, "expected both shim-dir entries pruned")

	// Reload state and check the legit entry survived.
	got, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, got.Wrappers, 1)
	require.Equal(t, legit.Path, got.Wrappers[0].Path)
}

// TestPruneWrappersInShimDir_NoOpWhenClean proves the prune is idempotent
// when no entries point into the shim dir.
func TestPruneWrappersInShimDir_NoOpWhenClean(t *testing.T) {
	cacheDir := t.TempDir()
	shimDir := t.TempDir()
	cfg := config{CacheDir: cacheDir}

	state := wrapperState{Wrappers: []wrapperEntry{
		{Path: "/opt/homebrew/bin/npm", PM: "npm", Source: "homebrew"},
		{Path: "/usr/local/bin/pnpm", PM: "pnpm", Source: "homebrew"},
	}}
	require.NoError(t, saveWrapperState(cfg, state))

	pruned, err := pruneWrappersInShimDir(cfg, shimDir, false)
	require.NoError(t, err)
	require.Empty(t, pruned)

	got, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, got.Wrappers, 2)
}

// TestPruneWrappersInShimDir_MissingStateFile proves prune is a clean
// no-op when wrappers.json does not exist yet — install-shims must be
// safe to run on a host that has never touched Layer 4.
func TestPruneWrappersInShimDir_MissingStateFile(t *testing.T) {
	cacheDir := t.TempDir()
	shimDir := t.TempDir()
	cfg := config{CacheDir: cacheDir}

	pruned, err := pruneWrappersInShimDir(cfg, shimDir, false)
	require.NoError(t, err)
	require.Empty(t, pruned)
}

// TestPruneWrappersInShimDir_DryRunDoesNotMutate proves dryRun reports
// what would be removed without rewriting wrappers.json.
func TestPruneWrappersInShimDir_DryRunDoesNotMutate(t *testing.T) {
	cacheDir := t.TempDir()
	shimDir := t.TempDir()
	cfg := config{CacheDir: cacheDir}

	state := wrapperState{Wrappers: []wrapperEntry{
		{Path: filepath.Join(shimDir, "python3"), PM: "python3"},
	}}
	require.NoError(t, saveWrapperState(cfg, state))

	// Snapshot bytes before for byte-equality comparison after.
	wantBytes, err := os.ReadFile(filepath.Join(cacheDir, "wrappers.json"))
	require.NoError(t, err)

	pruned, err := pruneWrappersInShimDir(cfg, shimDir, true)
	require.NoError(t, err)
	require.Len(t, pruned, 1)

	gotBytes, err := os.ReadFile(filepath.Join(cacheDir, "wrappers.json"))
	require.NoError(t, err)
	require.Equal(t, wantBytes, gotBytes, "dry-run must not touch wrappers.json")
}

// TestRunInstallShims_PrunesShimDirWrappersJSON is the integration-level
// guarantee for the veto-u6c fix: drive runInstallShims through a
// tempdir where wrappers.json contains a bogus shim-dir entry alongside
// a legit Layer 4 entry. After install-shims, only the legit one remains.
func TestRunInstallShims_PrunesShimDirWrappersJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	shimDir := filepath.Join(home, "shimout")
	cacheDir := filepath.Join(home, ".cache", "veto")
	cfg := config{CacheDir: cacheDir}

	// Plant a wrappers.json containing one legit entry + one bogus
	// shim-dir entry (the exact disaster case from veto-dzk).
	state := wrapperState{Wrappers: []wrapperEntry{
		{Path: "/opt/homebrew/bin/npm", PM: "npm", Source: "homebrew"},
		{Path: filepath.Join(shimDir, "python3"), PM: "python3", Source: "path"},
	}}
	require.NoError(t, saveWrapperState(cfg, state))

	rc := runInstallShims(zerologNop(), cfg, []string{"--dir", shimDir})
	require.Equal(t, exitOK, rc)

	// Reload and assert only the legit entry survives.
	got, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, got.Wrappers, 1, "shim-dir entry must be pruned, legit entry must remain")
	require.Equal(t, "/opt/homebrew/bin/npm", got.Wrappers[0].Path)

	// Sanity: the persisted file is still valid JSON (no truncation).
	data, err := os.ReadFile(filepath.Join(cacheDir, "wrappers.json"))
	require.NoError(t, err)
	var roundtrip wrapperState
	require.NoError(t, json.Unmarshal(data, &roundtrip))
	require.Len(t, roundtrip.Wrappers, 1)
}
