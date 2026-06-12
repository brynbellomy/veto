package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestApplyWrapper_HappyPath_RegularFile is the canonical case: a real
// PM binary sits at <dir>/<pm> as a regular file. We move it aside and
// drop a veto symlink in its place.
func TestApplyWrapper_HappyPath_RegularFile(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(npm, []byte("#!/bin/sh\nexec real-npm\n"), 0o755))

	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	action, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action)

	// npm is now a symlink to veto.
	info, err := os.Lstat(npm)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
	target, _ := os.Readlink(npm)
	require.Equal(t, veto, target)

	// .veto-original holds the real npm.
	original := npm + ".veto-original"
	body, err := os.ReadFile(original)
	require.NoError(t, err)
	require.Contains(t, string(body), "real-npm")
}

// TestApplyWrapper_HappyPath_SymlinkSource exercises the homebrew shape:
// /opt/homebrew/bin/npm is a symlink to ../Cellar/.../bin/npm. Wrapping
// must rename the SYMLINK aside (keeping its target intact) and replace
// the original path with a veto symlink.
func TestApplyWrapper_HappyPath_SymlinkSource(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	cellar := filepath.Join(dir, "cellar-npm")
	require.NoError(t, os.WriteFile(cellar, []byte("real"), 0o755))
	binNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(cellar, binNpm))

	c := wrapCandidate{path: binNpm, pm: "npm", source: "homebrew"}
	action, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action)

	// Symlink at original path now points at veto.
	target, _ := os.Readlink(binNpm)
	require.Equal(t, veto, target)

	// `.veto-original` preserves the homebrew→Cellar symlink (so
	// upgrades that update the symlink target still work after unwrap).
	originalTarget, err := os.Readlink(binNpm + ".veto-original")
	require.NoError(t, err)
	require.Equal(t, cellar, originalTarget)
}

// TestApplyWrapper_IdempotentOnSecondCall: re-running install must not
// double-wrap or corrupt state.
func TestApplyWrapper_IdempotentOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	pip := filepath.Join(dir, "pip")
	require.NoError(t, os.WriteFile(pip, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	c := wrapCandidate{path: pip, pm: "pip", source: "user"}
	_, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)

	action, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipAlreadyOurs, action)
}

// TestApplyWrapper_RefusesToClobberPartialState: if `.veto-original`
// exists but the symlink is gone (interrupted previous run), we refuse
// to silently clobber the .veto-original. --force overrides.
func TestApplyWrapper_RefusesToClobberPartialState(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	pnpm := filepath.Join(dir, "pnpm")
	require.NoError(t, os.WriteFile(pnpm, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	require.NoError(t, os.WriteFile(pnpm+".veto-original", []byte("stale"), 0o644))

	c := wrapCandidate{path: pnpm, pm: "pnpm", source: "user"}
	_, err := applyWrapper(c, veto, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// --force overrides.
	_, err = applyWrapper(c, veto, false, true)
	require.NoError(t, err)
}

// TestApplyWrapper_ForceRelinksAlreadyOurs: with --force, a path that
// is already a veto symlink (with `.veto-original` sibling intact) gets
// re-linked rather than silently skipped. This is what the docstring
// has always promised but the early-return previously short-circuited
// even when force was set. Useful after moving the veto binary, or as
// a paranoia button.
func TestApplyWrapper_ForceRelinksAlreadyOurs(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(npm, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	// First wrap to get into the already-ours state.
	_, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, false, false)
	require.NoError(t, err)

	// Without --force, a second call short-circuits.
	action, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipAlreadyOurs, action)

	// With --force, the symlink gets recreated.
	action, err = applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, false, true)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action, "--force should recreate the symlink, not skip")

	// Symlink still points at veto.
	target, err := os.Readlink(npm)
	require.NoError(t, err)
	require.Equal(t, veto, target)
	// `.veto-original` still present — force-relink must not touch it.
	_, err = os.Lstat(npm + ".veto-original")
	require.NoError(t, err)
}

// TestApplyWrapper_ForceRelinksAlreadyOurs_DryRun: --force --dry-run on
// an already-ours path should report a would-wrap, not silently succeed
// and not actually touch the filesystem.
func TestApplyWrapper_ForceRelinksAlreadyOurs_DryRun(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(npm, []byte("#!/bin/sh\n"), 0o755))
	_, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, false, false)
	require.NoError(t, err)

	before, err := os.Readlink(npm)
	require.NoError(t, err)

	action, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, true, true)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipDryRun, action)

	after, err := os.Readlink(npm)
	require.NoError(t, err)
	require.Equal(t, before, after, "dry-run must not change anything on disk")
}

// TestIsAlreadyOursWrap: truth table for the helper that powers
// reconciliation. True only when path is a symlink whose physical
// target is the real veto binary AND a `.veto-original` sibling exists.
func TestIsAlreadyOursWrap(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	// Case 1: full already-ours state. Symlink + sibling.
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(veto, npm))
	require.NoError(t, os.WriteFile(npm+wrapperSuffix, []byte("real"), 0o755))
	require.True(t, isAlreadyOursWrap(npm, veto))

	// Case 2: symlink to veto but no sibling — broken half-state, not ours yet.
	pip := filepath.Join(dir, "pip")
	require.NoError(t, os.Symlink(veto, pip))
	require.False(t, isAlreadyOursWrap(pip, veto))

	// Case 3: regular file — not a wrapper.
	pnpm := filepath.Join(dir, "pnpm")
	require.NoError(t, os.WriteFile(pnpm, []byte(""), 0o755))
	require.False(t, isAlreadyOursWrap(pnpm, veto))

	// Case 4: symlink to a same-named impostor with sibling present — must
	// not be treated as ours. Closes the same impostor hole pointsAtVeto guards.
	impostor := filepath.Join(dir, "veto-impostor")
	require.NoError(t, os.WriteFile(impostor, []byte(""), 0o755))
	uv := filepath.Join(dir, "uv")
	require.NoError(t, os.Symlink(impostor, uv))
	require.NoError(t, os.WriteFile(uv+wrapperSuffix, []byte(""), 0o755))
	require.False(t, isAlreadyOursWrap(uv, veto))

	// Case 5: nonexistent path.
	require.False(t, isAlreadyOursWrap(filepath.Join(dir, "nope"), veto))
}

// TestDiscoverWrapCandidates_IncludesAlreadyOurs: discovery must emit
// candidates for paths that are already-ours so reconciliation can run.
// Without this, install-wrappers prints "no candidates found" when state
// has drifted from filesystem reality. We assert by path-membership
// rather than slice length because discovery also walks real system
// dirs the test machine may populate.
func TestDiscoverWrapCandidates_IncludesAlreadyOurs(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	// Plant a fully already-ours npm under a user --dir.
	pmDir := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(pmDir, 0o755))
	npm := filepath.Join(pmDir, "npm")
	require.NoError(t, os.Symlink(veto, npm))
	require.NoError(t, os.WriteFile(npm+wrapperSuffix, []byte("real"), 0o755))

	candidates, err := discoverWrapCandidates(wrapperFlags{dirs: []string{pmDir}, only: map[string]struct{}{"npm": {}}}, veto)
	require.NoError(t, err)

	paths := make([]string, 0, len(candidates))
	for _, c := range candidates {
		paths = append(paths, c.path)
	}
	require.Contains(t, paths, npm, "already-ours path must surface as a candidate so reconciliation can register it")
}

func TestDiscoverWrapCandidates_IncludesPyenvAndNvmInstalls(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	veto := filepath.Join(home, ".local", "bin", "veto")
	require.NoError(t, os.MkdirAll(filepath.Dir(veto), 0o755))
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	pyenvPip := filepath.Join(home, ".pyenv", "versions", "3.12.0", "bin", "pip")
	nvmNpm := filepath.Join(home, ".nvm", "versions", "node", "24.7.0", "bin", "npm")
	for _, p := range []string{pyenvPip, nvmNpm} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	}

	candidates, err := discoverWrapCandidates(wrapperFlags{only: map[string]struct{}{"pip": {}, "npm": {}}}, veto)
	require.NoError(t, err)

	byPath := map[string]wrapCandidate{}
	for _, c := range candidates {
		byPath[c.path] = c
	}
	require.Equal(t, "pyenv", byPath[pyenvPip].source)
	require.Equal(t, "pip", byPath[pyenvPip].pm)
	require.Equal(t, "nvm", byPath[nvmNpm].source)
	require.Equal(t, "npm", byPath[nvmNpm].pm)
}

func TestDiscoverWrapCandidates_ReconcilesAlreadyWrappedPyenvAndNvm(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	veto := filepath.Join(home, ".local", "bin", "veto")
	require.NoError(t, os.MkdirAll(filepath.Dir(veto), 0o755))
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	pyenvPip := filepath.Join(home, ".pyenv", "versions", "3.12.0", "bin", "pip")
	nvmNpm := filepath.Join(home, ".nvm", "versions", "node", "24.7.0", "bin", "npm")
	for _, p := range []string{pyenvPip, nvmNpm} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.Symlink(veto, p))
		require.NoError(t, os.WriteFile(p+wrapperSuffix, []byte("real"), 0o755))
	}

	candidates, err := discoverWrapCandidates(wrapperFlags{only: map[string]struct{}{"pip": {}, "npm": {}}}, veto)
	require.NoError(t, err)

	paths := make([]string, 0, len(candidates))
	for _, c := range candidates {
		paths = append(paths, c.path)
	}
	require.Contains(t, paths, pyenvPip)
	require.Contains(t, paths, nvmNpm)
}

// TestApplyWrapper_DryRun_TouchesNothing: --dry-run mode reports what
// would happen without making filesystem changes.
func TestApplyWrapper_DryRun_TouchesNothing(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	pip := filepath.Join(dir, "pip")
	originalBody := []byte("#!/bin/sh\nexec real\n")
	require.NoError(t, os.WriteFile(pip, originalBody, 0o755))

	c := wrapCandidate{path: pip, pm: "pip", source: "user"}
	action, err := applyWrapper(c, veto, true, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipDryRun, action)

	// File unchanged.
	body, err := os.ReadFile(pip)
	require.NoError(t, err)
	require.Equal(t, originalBody, body)
	_, err = os.Lstat(pip + ".veto-original")
	require.True(t, os.IsNotExist(err), "dry-run must not create .veto-original")
}

// TestUnwrap_RestoresOriginal: the canonical unwrap path.
func TestUnwrap_RestoresOriginal(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	npm := filepath.Join(dir, "npm")
	realBody := []byte("#!/bin/sh\nexec real-npm\n")
	require.NoError(t, os.WriteFile(npm, realBody, 0o755))

	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	_, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)

	entry := wrapperEntry{
		Path:         npm,
		OriginalPath: npm + ".veto-original",
		PM:           "npm",
		Source:       "user",
	}
	require.NoError(t, unwrap(entry, veto, false))

	// npm is once again a regular file with the original body.
	info, err := os.Lstat(npm)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeSymlink)
	body, _ := os.ReadFile(npm)
	require.Equal(t, realBody, body)
	// .veto-original is gone.
	_, err = os.Lstat(npm + ".veto-original")
	require.True(t, os.IsNotExist(err))
}

// TestUnwrap_BailsIfSymlinkRetargeted: if something (brew upgrade?)
// replaced our symlink with a non-veto target between install and
// uninstall, unwrap must NOT clobber. Stale .veto-original is left
// for manual cleanup.
func TestUnwrap_BailsIfSymlinkRetargeted(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	npm := filepath.Join(dir, "npm")
	other := filepath.Join(dir, "other")
	require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
	require.NoError(t, os.Symlink(other, npm)) // not pointing at veto

	original := npm + ".veto-original"
	require.NoError(t, os.WriteFile(original, []byte("orig"), 0o755))

	entry := wrapperEntry{Path: npm, OriginalPath: original, PM: "npm"}
	err := unwrap(entry, veto, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer points at veto")

	// Symlink and .veto-original both intact.
	target, _ := os.Readlink(npm)
	require.Equal(t, other, target)
	_, err = os.Stat(original)
	require.NoError(t, err)
}

// TestFindWrappedOriginal exercises the resolver used by execReal. When
// veto is invoked through a wrapper symlink, argv[0] is the wrapper
// path; we want to find the sibling `.veto-original` — but ONLY if the
// wrapper site appears in wrappers.json. Without the provenance check
// any same-UID attacker could plant a sibling and hijack execution
// (see TestFindWrappedOriginal_RejectsUnregisteredSibling below).
func TestFindWrappedOriginal(t *testing.T) {
	dir := t.TempDir()
	pip := filepath.Join(dir, "pip")
	original := pip + ".veto-original"
	require.NoError(t, os.WriteFile(original, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	// Registry says: yes, this wrapper site was installed by veto.
	registered := func(p string) bool { return p == pip }

	got, ok := findWrappedOriginal(pip, registered)
	require.True(t, ok, "should find sibling .veto-original")
	require.Equal(t, original, got)

	// Path with no separator (bare name) — must NOT match. Bare names
	// don't reach the wrapper-resolver; they go through PATH lookup.
	got, ok = findWrappedOriginal("pip", registered)
	require.False(t, ok)
	require.Empty(t, got)

	// Sibling missing — must return false.
	noOriginal := filepath.Join(dir, "yarn")
	require.NoError(t, os.WriteFile(noOriginal, []byte(""), 0o755))
	registeredYarn := func(p string) bool { return p == noOriginal }
	_, ok = findWrappedOriginal(noOriginal, registeredYarn)
	require.False(t, ok, "no .veto-original sibling means no wrapper")
}

// TestFindWrappedOriginal_RejectsUnregisteredSibling demonstrates the
// attack described in B1 and proves the provenance check stops it.
//
// Attack: a same-UID attacker plants <argv0>.veto-original at a path
// that is NOT in wrappers.json (e.g. ~/.local/bin/npm.veto-original).
// Before the fix, findWrappedOriginal accepted any executable file at
// that location, so the planted binary would be exec'd in place of the
// real npm.
//
// Fix: refuse the sibling unless the parent path appears in
// wrappers.json. Here we simulate "registry says no" with a predicate
// that returns false; findWrappedOriginal must NOT honor the planted
// sibling.
func TestFindWrappedOriginal_RejectsUnregisteredSibling(t *testing.T) {
	dir := t.TempDir()
	npm := filepath.Join(dir, "npm")
	// Attacker-planted sibling.
	require.NoError(t, os.WriteFile(npm+".veto-original", []byte("#!/bin/sh\nexit 0\n"), 0o755))

	notRegistered := func(string) bool { return false }
	got, ok := findWrappedOriginal(npm, notRegistered)
	require.False(t, ok, "unregistered .veto-original must NOT be honored")
	require.Empty(t, got)

	// And with a nil predicate (defensive — e.g. caller forgot to pass one):
	got, ok = findWrappedOriginal(npm, nil)
	require.False(t, ok, "nil registry predicate must fail closed")
	require.Empty(t, got)
}

// TestFindRealBinary_RejectsUnregisteredSiblingInPathWalk covers the
// PATH-walk branch of B1. When veto walks PATH and a candidate is
// `selfReal` (i.e. a wrapper at that PATH entry IS veto), the loop
// historically accepted ANY executable `<candidate>.veto-original`
// sibling. The fix gates that on wrappers.json membership.
//
// We exercise this branch by putting the temp dir on PATH, populating
// it with both veto and a planted unregistered sibling. With registry
// disagreement, the resolver must fall through and either find another
// PATH entry or return "not found in PATH".
func TestFindRealBinary_RejectsUnregisteredSiblingInPathWalk(t *testing.T) {
	dir := t.TempDir()

	// Make the test's own binary look like "veto" inside dir, so the
	// resolver's "candidate resolves to selfReal" branch fires. We
	// achieve that by symlinking `dir/npm` to the test executable
	// itself, so EvalSymlinks(candidate) == EvalSymlinks(self).
	self, err := os.Executable()
	require.NoError(t, err)
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(self, npm))

	// Attacker plants a sibling with no entry in wrappers.json.
	require.NoError(t, os.WriteFile(npm+".veto-original", []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("PATH", dir)

	notRegistered := func(string) bool { return false }
	_, err = findRealBinary("npm", notRegistered)
	require.Error(t, err, "PATH-walk must refuse unregistered planted sibling")
	require.Contains(t, err.Error(), "not found in PATH")
}

// TestFindRealBinary_HonorsRegisteredSibling proves the legitimate
// install case still works: when the wrapper site IS in wrappers.json
// (i.e. veto install-wrappers planted the symlink), the sibling is
// honored. This is the success path the security fix MUST NOT break.
func TestFindRealBinary_HonorsRegisteredSibling(t *testing.T) {
	dir := t.TempDir()

	self, err := os.Executable()
	require.NoError(t, err)
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(self, npm))

	original := npm + ".veto-original"
	require.NoError(t, os.WriteFile(original, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("PATH", dir)

	registered := func(p string) bool { return p == npm }
	got, err := findRealBinary("npm", registered)
	require.NoError(t, err)
	require.Equal(t, original, got)
}

// TestWrapperRegisteredFunc_MissingStateFailsClosed: when wrappers.json
// is missing or unreadable, the predicate must report "not registered"
// for every path. This collapses the resolver to PATH-walk-only,
// which is the safe behavior (see findWrappedOriginal docstring).
func TestWrapperRegisteredFunc_MissingStateFailsClosed(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()} // empty dir, no wrappers.json
	pred := wrapperRegisteredFunc(cfg)
	require.NotNil(t, pred)
	require.False(t, pred("/opt/homebrew/bin/npm"), "missing state must report not-registered")
	require.False(t, pred("/anything"))
}

// TestWrapperRegisteredFunc_LoadsRegisteredPaths: with a populated
// wrappers.json the predicate returns true for registered paths and
// false for everything else.
func TestWrapperRegisteredFunc_LoadsRegisteredPaths(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()}
	state := wrapperState{}
	state.add(wrapperEntry{Path: "/opt/homebrew/bin/npm", OriginalPath: "/opt/homebrew/bin/npm.veto-original", PM: "npm"})
	require.NoError(t, saveWrapperState(cfg, state))

	pred := wrapperRegisteredFunc(cfg)
	require.True(t, pred("/opt/homebrew/bin/npm"))
	require.False(t, pred("/opt/homebrew/bin/pip"))
}

// TestWrapperState_RoundTrip: state file survives a save/load cycle.
func TestWrapperState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := config{CacheDir: dir}

	state := wrapperState{}
	state.add(wrapperEntry{Path: "/opt/homebrew/bin/npm", OriginalPath: "/opt/homebrew/bin/npm.veto-original", PM: "npm", Source: "homebrew"})
	state.add(wrapperEntry{Path: "/x/uv", OriginalPath: "/x/uv.veto-original", PM: "uv", Source: "mise"})

	require.NoError(t, saveWrapperState(cfg, state))

	loaded, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, loaded.Wrappers, 2)
	require.Equal(t, "/opt/homebrew/bin/npm", loaded.Wrappers[0].Path)
	require.Equal(t, "uv", loaded.Wrappers[1].PM)
}

// TestWrapperState_AddIsIdempotent: re-adding the same Path updates in
// place rather than duplicating the entry. This matches install-wrappers
// being re-run after an upgrade.
func TestWrapperState_AddIsIdempotent(t *testing.T) {
	state := wrapperState{}
	state.add(wrapperEntry{Path: "/x/npm", PM: "npm", Source: "homebrew"})
	state.add(wrapperEntry{Path: "/x/npm", PM: "npm", Source: "homebrew", OriginalPath: "/x/npm.veto-original"})
	require.Len(t, state.Wrappers, 1, "duplicate Path entry must replace, not append")
	require.Equal(t, "/x/npm.veto-original", state.Wrappers[0].OriginalPath)
}

// TestLoadWrapperState_MissingFile_ReturnsEmpty: first-run experience —
// no state file yet means an empty state, not an error.
func TestLoadWrapperState_MissingFile_ReturnsEmpty(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()}
	state, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Empty(t, state.Wrappers)
}

// TestLoadWrapperState_MalformedJSON_Errors: a corrupted state file
// should fail loud rather than silently treat as empty (which would
// leave wrappers stranded with no record of how to undo them).
func TestLoadWrapperState_MalformedJSON_Errors(t *testing.T) {
	dir := t.TempDir()
	cfg := config{CacheDir: dir}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wrappers.json"), []byte("{not json"), 0o644))
	_, err := loadWrapperState(cfg)
	require.Error(t, err)
}

// TestIsWrappableTarget_FiltersCorrectly: the discovery helper that
// decides whether a candidate is something we should wrap. Critical
// because false positives (wrapping our own symlink) cause loops.
func TestIsWrappableTarget_FiltersCorrectly(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	regular := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(regular, []byte("#!/bin/sh\n"), 0o755))
	require.True(t, isWrappableTarget(regular, veto), "regular executable should be wrappable")

	notExec := filepath.Join(dir, "notexec")
	require.NoError(t, os.WriteFile(notExec, []byte(""), 0o644))
	require.False(t, isWrappableTarget(notExec, veto), "non-executable should be skipped")

	vetoSym := filepath.Join(dir, "veto-shim")
	require.NoError(t, os.Symlink(veto, vetoSym))
	require.False(t, isWrappableTarget(vetoSym, veto), "already-veto symlink must NOT be re-wrappable")

	cellarTarget := filepath.Join(dir, "cellar-real")
	require.NoError(t, os.WriteFile(cellarTarget, []byte(""), 0o755))
	homebrewLink := filepath.Join(dir, "homebrew-link")
	require.NoError(t, os.Symlink(cellarTarget, homebrewLink))
	require.True(t, isWrappableTarget(homebrewLink, veto), "homebrew-style real symlink IS wrappable")

	dirPath := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(dirPath, 0o755))
	require.False(t, isWrappableTarget(dirPath, veto), "directories must not be wrappable")
}

// TestIsWrappableTarget_RejectsImpostorVetoSymlink: an attacker-planted
// symlink whose target merely contains the substring "veto" but does
// NOT resolve to the real veto binary must NOT be accepted as "already
// ours" — otherwise our wrap step would skip and the impostor would
// stay in place. Closes C5 in the audit.
func TestIsWrappableTarget_RejectsImpostorVetoSymlink(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	// Impostor: an executable named to embed "veto" in its target string
	// but living at a path the real veto binary does NOT live at.
	impostorTarget := filepath.Join(dir, "veto-malware")
	require.NoError(t, os.WriteFile(impostorTarget, []byte(""), 0o755))
	npmShadow := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(impostorTarget, npmShadow))

	require.True(t, isWrappableTarget(npmShadow, veto),
		"symlink to a same-named-but-different binary must still be wrappable; "+
			"prior strings.Contains(target,\"veto\") would have wrongly skipped this")
}

// TestUnwrap_RefusesImpostorVetoSymlink: same threat model, unwrap side.
// If a third party has replaced our symlink with one to an impostor
// veto-named target between install and uninstall, we must refuse to
// remove it rather than silently doing the attacker's cleanup for them.
func TestUnwrap_RefusesImpostorVetoSymlink(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))
	impostor := filepath.Join(dir, "veto-attacker")
	require.NoError(t, os.WriteFile(impostor, []byte(""), 0o755))

	// State claims we wrapped this path. Filesystem reality: someone
	// repointed it at the impostor.
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(impostor, npm))
	w := wrapperEntry{Path: npm, OriginalPath: npm + wrapperSuffix, PM: "npm", Source: "test"}

	err := unwrap(w, veto, false)
	require.Error(t, err, "unwrap must refuse a symlink that no longer points at the real veto binary")
	require.Contains(t, err.Error(), "refusing to overwrite")
}

// TestSaveWrapperState_FileIsPrivateMode asserts the registry is
// written with 0o600 — protects "which PMs are wrapped where" on
// shared hosts whose XDG_CACHE_HOME ends up world-traversable.
func TestSaveWrapperState_FileIsPrivateMode(t *testing.T) {
	root := t.TempDir()
	cfg := config{CacheDir: filepath.Join(root, "cache")}
	state := wrapperState{Wrappers: []wrapperEntry{{Path: "/x", OriginalPath: "/x.veto-original", PM: "npm", Source: "test"}}}
	require.NoError(t, saveWrapperState(cfg, state))
	info, err := os.Stat(filepath.Join(cfg.CacheDir, stateFileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"wrappers.json must be 0o600, not 0o644")
}

// TestLoadWrapperState_CorruptJSONReturnsError asserts that a malformed
// wrappers.json fails loudly instead of silently truncating the registry.
// Phase 1.5 propagates this error through runInstallWrappers (previously
// swallowed via `state, _ := loadWrapperState(cfg)`) so an attacker can't
// convert a single tricked-state into permanent gate-defeat by corrupting
// the file.
func TestLoadWrapperState_CorruptJSONReturnsError(t *testing.T) {
	root := t.TempDir()
	cfg := config{CacheDir: root}
	require.NoError(t, os.WriteFile(filepath.Join(root, stateFileName), []byte("{not json"), 0o600))

	_, err := loadWrapperState(cfg)
	require.Error(t, err, "corrupt wrappers.json must return an error, not (empty, nil)")
}

// TestRunInstallWrappers_EndToEnd: drive runInstallWrappers against a
// synthetic install dir, verify wrapping happened, then drive
// runUninstallWrappers and verify it all reverses cleanly.
func TestRunInstallWrappers_EndToEnd(t *testing.T) {
	// Synthetic env: a tempdir containing a fake veto binary and a
	// fake PM dir.
	root := t.TempDir()
	pmDir := filepath.Join(root, "pms")
	require.NoError(t, os.MkdirAll(pmDir, 0o755))
	for _, pm := range []string{"npm", "pip"} {
		require.NoError(t, os.WriteFile(filepath.Join(pmDir, pm), []byte("real"), 0o755))
	}
	// Veto self path: simulate running as a binary under root/bin.
	vetoBin := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte(""), 0o755))

	// Use the cmd binary directly via runInstallWrappers, with cfg
	// pointing at a cache dir under root.
	cfg := config{CacheDir: filepath.Join(root, "cache")}

	// Re-exec ourselves via the same process? Too noisy. We can just
	// call the lower-level function: build candidates manually and
	// hand them to applyWrapper. The end-to-end runInstallWrappers
	// uses resolveVetoBinary(), which depends on os.Executable() —
	// in a `go test` process that's the test binary, not veto, so
	// we substitute by passing a candidate-veto path explicitly.

	candidates := []wrapCandidate{
		{path: filepath.Join(pmDir, "npm"), pm: "npm", source: "user"},
		{path: filepath.Join(pmDir, "pip"), pm: "pip", source: "user"},
	}
	state := wrapperState{}
	for _, c := range candidates {
		_, err := applyWrapper(c, vetoBin, false, false)
		require.NoError(t, err)
		state.add(wrapperEntry{Path: c.path, OriginalPath: c.path + wrapperSuffix, PM: c.pm, Source: c.source})
	}
	require.NoError(t, saveWrapperState(cfg, state))

	// Each candidate is now a veto symlink.
	for _, c := range candidates {
		target, err := os.Readlink(c.path)
		require.NoError(t, err)
		require.Equal(t, vetoBin, target)
	}

	// Confirm state file persisted.
	loaded, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, loaded.Wrappers, 2)

	// Round-trip JSON shape sanity.
	bytes, err := json.Marshal(loaded)
	require.NoError(t, err)
	require.Contains(t, string(bytes), wrapperSuffix)

	// Unwrap each and confirm reversal.
	for _, w := range loaded.Wrappers {
		require.NoError(t, unwrap(w, vetoBin, false))
	}
	for _, c := range candidates {
		info, err := os.Lstat(c.path)
		require.NoError(t, err)
		require.Zero(t, info.Mode()&os.ModeSymlink, "post-unwrap, path should be a regular file again")
	}
}

// TestApplyWrapper_ReadOnlyDir_SkipsUnwritable models the reported bug:
// a stray pip3 in a dir the current user can't write (root-owned
// /usr/local/bin on Apple Silicon). The rename-aside fails with
// permission denied, which must surface as a skip — not an error — so
// install-all keeps going. The real binary is left untouched.
func TestApplyWrapper_ReadOnlyDir_SkipsUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses the dir-write permission check")
	}
	// veto binary lives in a writable dir; the PM lives in a read-only one.
	home := t.TempDir()
	veto := filepath.Join(home, "veto")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	roDir := t.TempDir()
	pip3 := filepath.Join(roDir, "pip3")
	require.NoError(t, os.WriteFile(pip3, []byte("#!/bin/sh\nexec real-pip3\n"), 0o755))

	// Drop the dir's write bit. Restore on cleanup so t.TempDir can prune.
	require.NoError(t, os.Chmod(roDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

	c := wrapCandidate{path: pip3, pm: "pip3", source: "user"}
	action, err := applyWrapper(c, veto, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipUnwritable, action)

	// The real binary is untouched: still a regular file, no symlink, no
	// .veto-original sibling stranded.
	info, err := os.Lstat(pip3)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeSymlink)
	_, err = os.Lstat(pip3 + wrapperSuffix)
	require.True(t, os.IsNotExist(err), "no .veto-original should be left behind")
}

// TestIsReadOnlyFS confirms EROFS is unwrapped through fs.PathError (the
// wrapper os.Rename returns) and through bare syscall errnos, and that
// EACCES / EPERM do NOT match — those route to skippedUnwritable, not
// skippedReadOnlyFS. Regression guard for the macOS SIP path where
// /usr/bin/pip3 surfaced as a hard FAIL.
func TestIsReadOnlyFS(t *testing.T) {
	require.True(t, isReadOnlyFS(syscall.EROFS))
	require.True(t, isReadOnlyFS(&fs.PathError{Op: "rename", Path: "/usr/bin/pip3", Err: syscall.EROFS}))
	require.False(t, isReadOnlyFS(syscall.EACCES))
	require.False(t, isReadOnlyFS(syscall.EPERM))
	require.False(t, isReadOnlyFS(nil))
	require.False(t, isReadOnlyFS(&fs.PathError{Op: "rename", Path: "/tmp/foo", Err: syscall.EACCES}))
}

// TestUnwritableRemediationCommands_GroupsByDir verifies the sudo hint:
// one self-contained command per read-only dir, --only repeated per pm,
// dirs in first-seen order.
func TestUnwritableRemediationCommands_GroupsByDir(t *testing.T) {
	require.Nil(t, unwritableRemediationCommands(nil))

	skipped := []wrapCandidate{
		{path: "/usr/local/bin/pip3", pm: "pip3", source: "homebrew"},
		{path: "/usr/local/bin/pip", pm: "pip", source: "homebrew"},
		{path: "/opt/locked/bin/npm", pm: "npm", source: "user"},
	}
	cmds := unwritableRemediationCommands(skipped)
	require.Equal(t, []string{
		"sudo veto install-wrappers --dir /usr/local/bin --only pip3 --only pip",
		"sudo veto install-wrappers --dir /opt/locked/bin --only npm",
	}, cmds)
}
