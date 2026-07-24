package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
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
	action, err := applyWrapper(c, veto, nil, false, false)
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
	action, err := applyWrapper(c, veto, nil, false, false)
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
	_, err := applyWrapper(c, veto, nil, false, false)
	require.NoError(t, err)

	action, err := applyWrapper(c, veto, nil, false, false)
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
	_, err := applyWrapper(c, veto, nil, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// --force overrides.
	_, err = applyWrapper(c, veto, nil, false, true)
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
	_, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, nil, false, false)
	require.NoError(t, err)

	// Without --force, a second call short-circuits.
	action, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, nil, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipAlreadyOurs, action)

	// With --force, the symlink gets recreated.
	action, err = applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, nil, false, true)
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

// TestApplyWrapper_ForceMigrationFromForeignVeto_PreservesRealBinary is the
// regression guard for the veto→veto exec loop bug: running install-wrappers
// --force a second time with a DIFFERENT veto binary used to call
// os.Rename(c.path, c.path+".veto-original"), which atomically replaced the
// preserved real-binary trail with a stale symlink. After enough --force
// runs, every wrapped PM became a chain of veto binaries with no escape,
// producing an infinite exec loop on the next invocation. The safe-relink
// guard added to applyWrapper now refuses to rename a symlink onto a
// populated .veto-original; this test pins that contract.
func TestApplyWrapper_ForceMigrationFromForeignVeto_PreservesRealBinary(t *testing.T) {
	dir := t.TempDir()
	vetoA := filepath.Join(dir, "vetoA")
	require.NoError(t, os.WriteFile(vetoA, []byte("#!/bin/sh\n# vetoA\n"), 0o755))
	vetoB := filepath.Join(dir, "vetoB")
	require.NoError(t, os.WriteFile(vetoB, []byte("#!/bin/sh\n# vetoB\n"), 0o755))

	// Set up as if a prior install-wrappers run (with vetoA) had wrapped npm:
	//   npm                 -> vetoA           (the previous veto symlink)
	//   npm.veto-original   = real binary file (the preserved real PM)
	npm := filepath.Join(dir, "npm")
	realContent := []byte("#!/bin/sh\nexec real-npm\n")
	require.NoError(t, os.WriteFile(npm+wrapperSuffix, realContent, 0o755))
	require.NoError(t, os.Symlink(vetoA, npm))

	// Now wrap again with vetoB --force. The OLD code would rename the
	// vetoA-pointing symlink onto npm.veto-original, destroying the real
	// binary and replacing it with a symlink to vetoA. After this transition
	// the symlink chain at npm would point at vetoB and the real binary
	// would be unrecoverable.
	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	action, err := applyWrapper(c, vetoB, nil, false, true)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action)

	// npm now points at vetoB (the new install target).
	target, err := os.Readlink(npm)
	require.NoError(t, err)
	require.Equal(t, vetoB, target)

	// npm.veto-original is STILL a regular file holding the real binary.
	// Not a symlink to vetoA — that would mean the rename happened.
	info, err := os.Lstat(npm + wrapperSuffix)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeSymlink, "veto-original must still be a regular file, not a symlink (rename would have replaced it)")
	body, err := os.ReadFile(npm + wrapperSuffix)
	require.NoError(t, err)
	require.Equal(t, realContent, body, "the real PM binary content must be preserved across the --force migration")
}

// TestApplyWrapper_NoForceOnForeignVeto_SkipsAndDoesNotMutate guards the
// inverse: without --force, a symlink-to-a-foreign-veto state must produce
// a Skip and leave both c.path and .veto-original byte-identical.
func TestApplyWrapper_NoForceOnForeignVeto_SkipsAndDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	vetoA := filepath.Join(dir, "vetoA")
	require.NoError(t, os.WriteFile(vetoA, []byte("#!/bin/sh\n"), 0o755))
	vetoB := filepath.Join(dir, "vetoB")
	require.NoError(t, os.WriteFile(vetoB, []byte("#!/bin/sh\n"), 0o755))

	npm := filepath.Join(dir, "npm")
	realContent := []byte("#!/bin/sh\nexec real-npm\n")
	require.NoError(t, os.WriteFile(npm+wrapperSuffix, realContent, 0o755))
	require.NoError(t, os.Symlink(vetoA, npm))

	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	action, err := applyWrapper(c, vetoB, nil, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipForeignWrapper, action)

	// Both files exactly as they were.
	target, err := os.Readlink(npm)
	require.NoError(t, err)
	require.Equal(t, vetoA, target)
	body, err := os.ReadFile(npm + wrapperSuffix)
	require.NoError(t, err)
	require.Equal(t, realContent, body)
}

// TestApplyWrapper_OrphanedVetoSymlink_RefusesToSelfReference is the
// regression guard for the 2026-07-08 brew-upgrade incident: a `brew
// upgrade` of a wrapped formula (go, python@3.13) followed by `brew
// cleanup` deletes the old keg AND prunes the now-dead `.veto-original`
// symlink, leaving `<path> → veto` with NO real-binary anchor. The next
// `install-wrappers --force` used to rename that veto symlink onto
// `<path>.veto-original`, so BOTH `<path>` and `<path>.veto-original`
// pointed at veto — a veto→veto exec loop with the real binary lost.
// applyWrapper must instead refuse loudly and never manufacture a
// self-referential anchor. Covers the classified path (vetoID provided,
// re-classify sees ClassOurs*).
func TestApplyWrapper_OrphanedVetoSymlink_RefusesToSelfReference(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n# veto\n"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// go already wrapped, but the `.veto-original` anchor is GONE.
	goBin := filepath.Join(dir, "go")
	require.NoError(t, os.Symlink(veto, goBin))

	c := wrapCandidate{path: goBin, pm: "go", source: "homebrew"}

	// Without --force: refuse.
	_, err = applyWrapper(c, veto, vetoID, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "orphaned")
	// No self-referential anchor was manufactured.
	_, lerr := os.Lstat(goBin + wrapperSuffix)
	require.Error(t, lerr, "must not create a .veto-original anchor when refusing")

	// With --force: still refuse. --force must not corrupt either.
	_, err = applyWrapper(c, veto, vetoID, false, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "orphaned")
	_, lerr = os.Lstat(goBin + wrapperSuffix)
	require.Error(t, lerr, "--force must not create a self-referential anchor")
}

// TestApplyWrapper_OrphanedVetoSymlink_GuardsRenameWithoutIdentity pins the
// belt-and-suspenders guard sitting directly in front of the destructive
// rename: even when no VetoIdentity is available to re-classify (nil
// vetoID, e.g. older callers), applyWrapper must not rename a path that
// physically resolves to veto onto its `.veto-original` sibling.
func TestApplyWrapper_OrphanedVetoSymlink_GuardsRenameWithoutIdentity(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n# veto\n"), 0o755))

	goBin := filepath.Join(dir, "go")
	require.NoError(t, os.Symlink(veto, goBin))

	// nil vetoID skips the re-classify pass; c.class defaults to ClassReal
	// so the class switch does not early-return. The pre-rename guard is
	// the only thing standing between this and a self-referential anchor.
	c := wrapCandidate{path: goBin, pm: "go", source: "homebrew", class: pmsurvey.ClassReal}
	_, err := applyWrapper(c, veto, nil, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "orphaned")
	_, lerr := os.Lstat(goBin + wrapperSuffix)
	require.Error(t, lerr, "guard must prevent renaming a veto symlink onto its anchor")
}

// TestDiscoverWrapCandidates_ExcludesAliasToWrappedSibling pins the fix for
// the nested self-referential-anchor class (2026-07-08): when an alias is a
// symlink to a SAME-DIR sibling that is itself a wrap target (pyenv
// `python -> python3.10`, `bunx -> bun`), veto must NOT wrap the alias
// independently. Wrapping it makes its `.veto-original` point at the
// already-wrapped sibling, which resolves back to veto — a self-referential
// anchor that mis-resolves (wrong interpreter) or loops at runtime. The
// alias inherits the wrap for free via `alias -> target -> veto`, so it must
// stay a plain symlink. This generalizes veto's uv-store-only guard in
// pmsurvey.PathsFor to every dir. Aliases whose target is NOT a wrap target
// (e.g. `pip -> pip3.10`) must still be wrapped normally.
func TestDiscoverWrapCandidates_ExcludesAliasToWrappedSibling(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n# veto\n"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// python3.10 (real, a versioned-python wrap target) + python/python3
	// aliases symlinked to it in the same dir.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "python3.10"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink("python3.10", filepath.Join(dir, "python")))
	require.NoError(t, os.Symlink("python3.10", filepath.Join(dir, "python3")))
	// bun (real, a wrapped manager) + bunx alias symlinked to it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bun"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink("bun", filepath.Join(dir, "bunx")))
	// pip -> pip3.10, where pip3.10 is NOT a wrap target: pip must stay a
	// candidate (its anchor would point at a real binary, not a wrapper).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pip3.10"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink("pip3.10", filepath.Join(dir, "pip")))

	opts := wrapperFlags{dirs: []string{dir}, only: map[string]struct{}{}}
	cands, err := discoverWrapCandidatesWith(opts, vetoID)
	require.NoError(t, err)

	got := map[string]bool{}
	for _, c := range cands {
		if filepath.Dir(c.path) == dir {
			got[filepath.Base(c.path)] = true
		}
	}
	require.False(t, got["python"], "python (alias -> wrapped sibling python3.10) must be excluded")
	require.False(t, got["python3"], "python3 (alias -> wrapped sibling python3.10) must be excluded")
	require.False(t, got["bunx"], "bunx (alias -> wrapped sibling bun) must be excluded")
	require.True(t, got["bun"], "bun (real wrap target) must remain a candidate")
	require.True(t, got["pip"], "pip (alias -> pip3.10, NOT a wrap target) must remain a candidate")
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
	_, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, nil, false, false)
	require.NoError(t, err)

	before, err := os.Readlink(npm)
	require.NoError(t, err)

	action, err := applyWrapper(wrapCandidate{path: npm, pm: "npm", source: "user"}, veto, nil, true, true)
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

// TestDiscoverWrapCandidates_IncludesUVCanonicalPython proves the
// install-wrappers discovery path enumerates the canonical versioned
// python3.X binary from a uv-managed cpython store — the
// closing-the-uv-venv-bypass surface. Only the canonical `python3.X`
// regular file is a wrap candidate; the `python` / `python3` aliases
// that live next to it are symlinks back to python3.X and inherit the
// wrap via the existing chain. Wrapping the aliases independently
// would corrupt the exec chain (see TestPathsForUVStoreFiltersAliasSymlinks).
func TestDiscoverWrapCandidates_IncludesUVCanonicalPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "") // isolate from the runner's PATH

	veto := filepath.Join(home, ".local", "bin", "veto")
	require.NoError(t, os.MkdirAll(filepath.Dir(veto), 0o755))
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	uvPy3 := filepath.Join(uvBin, "python3")
	uvPy312 := filepath.Join(uvBin, "python3.12")
	// Real uv layout: python3.12 is the canonical regular file; python3
	// is a symlink to it.
	require.NoError(t, os.MkdirAll(uvBin, 0o755))
	require.NoError(t, os.WriteFile(uvPy312, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	require.NoError(t, os.Symlink("python3.12", uvPy3))

	candidates, err := discoverWrapCandidates(
		wrapperFlags{only: map[string]struct{}{"python3": {}, "python3.12": {}}},
		veto,
	)
	require.NoError(t, err)

	byPath := map[string]wrapCandidate{}
	for _, c := range candidates {
		byPath[c.path] = c
	}
	require.Contains(t, byPath, uvPy312,
		"uv canonical python3.12 must be surfaced for wrapping")
	require.Equal(t, "python3.12", byPath[uvPy312].pm)
	require.NotContains(t, byPath, uvPy3,
		"uv-store python3 alias symlink must NOT surface — inherits wrap via python3 → python3.12 → veto chain")
}

// TestRunInstallWrappers_WrapsUVCanonicalPython drives install-wrappers
// end-to-end against a faked uv store + tempdir cache, asserting the
// canonical python3.12 binary gets symlink-replaced with veto and its
// real bytes preserved at .veto-original.
func TestRunInstallWrappers_WrapsUVCanonicalPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	// The uv canonical python is discovered via the uv-store walk (under
	// the temp $HOME), independent of the system prefixes; confine those so
	// the test never wraps the real /opt/homebrew/bin/python3.12.
	t.Setenv(pmsurvey.SystemBinDirsEnv, "")

	veto := filepath.Join(home, ".local", "bin", "veto")
	require.NoError(t, os.MkdirAll(filepath.Dir(veto), 0o755))
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	uvPy312 := filepath.Join(uvBin, "python3.12")
	require.NoError(t, os.MkdirAll(filepath.Dir(uvPy312), 0o755))
	originalBody := []byte("#!/bin/sh\necho real-python3.12\n")
	require.NoError(t, os.WriteFile(uvPy312, originalBody, 0o755))

	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)
	cfg := config{CacheDir: filepath.Join(home, ".cache", "veto")}
	rc, stats := runInstallWrappersWith(
		zerologNop(), cfg,
		wrapperFlags{only: map[string]struct{}{"python3.12": {}}},
		veto, id,
	)
	require.Equal(t, exitOK, rc)
	require.GreaterOrEqual(t, stats.wrapped, 1)

	// python3.12 is now a symlink to veto.
	info, err := os.Lstat(uvPy312)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink, "expected python3.12 to be a symlink")
	tgt, err := os.Readlink(uvPy312)
	require.NoError(t, err)
	require.Equal(t, veto, tgt)

	// Real bytes preserved at .veto-original.
	body, err := os.ReadFile(uvPy312 + ".veto-original")
	require.NoError(t, err)
	require.Equal(t, originalBody, body)
}

// TestRunInstallWrappers_ReentrantOnUVCanonicalPython proves re-running
// install-wrappers when python3.X is ALREADY wrapped (symlink to veto
// + populated .veto-original) is a safe no-op. Regression for the
// safe-relink guard added in 666c33e: a follow-up run must not rename
// the symlink onto the existing .veto-original sibling.
func TestRunInstallWrappers_ReentrantOnUVCanonicalPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	// See TestRunInstallWrappers_WrapsUVCanonicalPython: confine system
	// prefixes so the reentrant run never touches real homebrew binaries.
	t.Setenv(pmsurvey.SystemBinDirsEnv, "")

	veto := filepath.Join(home, ".local", "bin", "veto")
	require.NoError(t, os.MkdirAll(filepath.Dir(veto), 0o755))
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	uvBin := filepath.Join(home, ".local", "share", "uv", "python",
		"cpython-3.12.4-macos-aarch64-none", "bin")
	uvPy312 := filepath.Join(uvBin, "python3.12")
	require.NoError(t, os.MkdirAll(filepath.Dir(uvPy312), 0o755))
	originalBody := []byte("#!/bin/sh\necho real-python3.12\n")
	require.NoError(t, os.WriteFile(uvPy312, originalBody, 0o755))

	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)
	cfg := config{CacheDir: filepath.Join(home, ".cache", "veto")}

	// First run: wraps.
	rc1, _ := runInstallWrappersWith(
		zerologNop(), cfg,
		wrapperFlags{only: map[string]struct{}{"python3.12": {}}},
		veto, id,
	)
	require.Equal(t, exitOK, rc1)

	// Second run: safe-relink guard makes this a no-op (alreadyOurs).
	rc2, stats := runInstallWrappersWith(
		zerologNop(), cfg,
		wrapperFlags{only: map[string]struct{}{"python3.12": {}}},
		veto, id,
	)
	require.Equal(t, exitOK, rc2)
	require.Zero(t, stats.failed,
		"re-running install-wrappers on an already-wrapped python3.X must not fail")
	require.GreaterOrEqual(t, stats.alreadyOurs, 1,
		"re-run must classify python3.X as already-ours")

	// .veto-original is intact and still has the real bytes — the
	// safe-relink guard did not overwrite it with a stale symlink.
	body, err := os.ReadFile(uvPy312 + ".veto-original")
	require.NoError(t, err)
	require.Equal(t, originalBody, body,
		".veto-original must hold the original real bytes after re-run")
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
	action, err := applyWrapper(c, veto, nil, true, false)
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
	_, err := applyWrapper(c, veto, nil, false, false)
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

// TestFindWrappedOriginal_RejectsSelfReferentialSibling proves the
// runtime self-reference guard: if a wrapper's `.veto-original`
// sibling resolves through symlinks back to veto's own executable,
// findWrappedOriginal must refuse to honor it. Without the guard,
// execReal would exec the sibling, which IS veto — an immediate
// infinite re-entry loop.
//
// Concretely we plant `npm` as a regular file in a registered tempdir
// and make `npm.veto-original` a symlink to veto's own executable
// (using the test binary as a stand-in for veto, the same trick the
// PATH-walk tests use). EvalSymlinks(original) then equals
// EvalSymlinks(self), and the guard fires.
//
// This is the belt-and-suspenders complement to the discovery-side
// filter in pmsurvey.PathsFor; together they prevent the chain
// corruption that surfaces when an alias symlink and its target both
// get wrapped (alias.veto-original points at the target, which is
// now a symlink to veto).
func TestFindWrappedOriginal_RejectsSelfReferentialSibling(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	require.NoError(t, err)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(npm, []byte(""), 0o755))

	// Plant a self-referential .veto-original symlink: it resolves to
	// the test binary, which IS veto's "self" inside this test.
	original := npm + ".veto-original"
	require.NoError(t, os.Symlink(self, original))

	registered := func(p string) bool { return p == npm }
	got, ok := findWrappedOriginal(npm, registered)
	require.False(t, ok,
		"self-referential .veto-original must be rejected — exec'ing it would loop veto into itself")
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

// TestFindRealBinary_RejectsSelfReferentialSiblingInPathWalk is the
// regression guard for the veto-dzk python-shim stall (veto-dzk.2).
//
// Before the fix, the PATH-walk branch of findRealBinary honored ANY
// `<candidate>.veto-original` sibling whose os.Stat said "executable,"
// even when the sibling chained through symlinks back into veto
// itself. That produced an immediate exec loop: veto-as-python3 →
// findRealBinary → returns self-referential .veto-original → veto
// exec's it → kernel runs veto again → repeat until the process is
// killed. On bryn's box every ~/.local/bin/python3*.veto-original
// symlink pointed at ~/.local/bin/veto, the wrap site was registered
// in wrappers.json, and the loop pegged a CPU core indefinitely.
//
// The fix mirrors findWrappedOriginal's `isSelfReferential` guard here
// so both the argv[0] lookup path and the PATH walk agree on which
// siblings to reject.
func TestFindRealBinary_RejectsSelfReferentialSiblingInPathWalk(t *testing.T) {
	dir := t.TempDir()

	self, err := os.Executable()
	require.NoError(t, err)

	// `dir/python3` is a symlink to "veto" (the test binary). This puts
	// the PATH-walk on the branch where the candidate resolves to
	// selfReal.
	python3 := filepath.Join(dir, "python3")
	require.NoError(t, os.Symlink(self, python3))

	// `dir/python3.veto-original` is ALSO a symlink to "veto" — the
	// exact bryn-box shape captured in the veto-dzk.1 bead.
	staleOriginal := python3 + ".veto-original"
	require.NoError(t, os.Symlink(self, staleOriginal))

	t.Setenv("PATH", dir)

	// And the wrap site IS registered (matching the on-disk wrappers.json
	// on bryn's box — install-wrappers had recorded the ~/.local/bin
	// python paths).
	registered := func(p string) bool { return p == python3 }

	_, err = findRealBinary("python3", registered)
	require.Error(t, err,
		"PATH-walk must refuse self-referential sibling — exec'ing it would loop veto into itself")
	require.Contains(t, err.Error(), "not found in PATH")
}

// TestFindWrappedOriginalViaChain_FollowsPlainAliasToRegisteredWrapper pins
// the directly-invoked-alias fix (2026-07-08). When veto is invoked via a
// plain alias symlink whose target is a registered wrapper sibling (pyenv
// `python -> python3.10 -> veto`, `bunx -> bun`), argv[0]'s own
// `.veto-original` anchor does not exist — so findWrappedOriginal bails and
// the PATH walk historically found the WRONG interpreter (python3 → 3.14.6)
// or looped into a shim. The chain follower walks argv[0]'s symlinks to the
// first registered wrapper with a valid anchor and returns THAT real binary.
func TestFindWrappedOriginalViaChain_FollowsPlainAliasToRegisteredWrapper(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable() // stands in for veto, same trick as the sibling tests
	require.NoError(t, err)

	real := filepath.Join(dir, "python3.10.real")
	require.NoError(t, os.WriteFile(real, []byte("#!/bin/sh\necho real\n"), 0o755))
	py310 := filepath.Join(dir, "python3.10")
	require.NoError(t, os.Symlink(self, py310))                            // python3.10 -> veto
	require.NoError(t, os.Symlink("python3.10.real", py310+wrapperSuffix)) // anchor -> real
	py := filepath.Join(dir, "python")
	require.NoError(t, os.Symlink("python3.10", py)) // python -> python3.10 (plain alias, unregistered)

	// Only the target is registered; the alias is a plain symlink.
	registered := func(p string) bool { return p == py310 }

	got, ok := findWrappedOriginalViaChain(py, registered)
	require.True(t, ok, "must follow the plain alias to the registered wrapper's anchor")
	require.Equal(t, py310+wrapperSuffix, got)
}

// TestFindWrappedOriginalViaChain_UnregisteredTargetBails: if the alias's
// target chain never reaches a registered wrapper, the follower must bail
// (false) so the caller falls through to the PATH walk — provenance is
// preserved, no unregistered anchor is honored.
func TestFindWrappedOriginalViaChain_UnregisteredTargetBails(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "python3.10")
	require.NoError(t, os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755))
	py := filepath.Join(dir, "python")
	require.NoError(t, os.Symlink("python3.10", py))

	_, ok := findWrappedOriginalViaChain(py, func(string) bool { return false })
	require.False(t, ok, "no registered wrapper in the chain → must bail to PATH walk")
}

// TestFindWrappedOriginalViaChain_CycleBails guards termination: a symlink
// cycle in argv[0]'s chain must return false, not loop forever.
func TestFindWrappedOriginalViaChain_CycleBails(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	require.NoError(t, os.Symlink("b", a)) // a -> b
	require.NoError(t, os.Symlink("a", b)) // b -> a  (cycle)

	_, ok := findWrappedOriginalViaChain(a, func(string) bool { return true })
	require.False(t, ok, "cyclic symlink chain must bail, not loop")
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
		_, err := applyWrapper(c, vetoBin, nil, false, false)
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
	action, err := applyWrapper(c, veto, nil, false, false)
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

// TestPruneStaleWrapperEntries_DropsMissingPathAndSibling proves the
// convergence pass at the top of install-wrappers reconciles
// wrappers.json against disk: any entry whose Path is missing OR whose
// .veto-original sibling is missing gets dropped. Without this,
// install-wrappers only ADDS — drifted state stays drifted forever and
// doctor FAILs the entries indefinitely.
func TestPruneStaleWrapperEntries_DropsMissingPathAndSibling(t *testing.T) {
	dir := t.TempDir()

	// Entry 1: legit, both path and sibling exist.
	legitPath := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(legitPath, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(legitPath+".veto-original", []byte("real"), 0o755))

	// Entry 2: path is missing — pruned.
	missingPath := filepath.Join(dir, "pnpm")

	// Entry 3: path exists but sibling is missing — pruned.
	noSibling := filepath.Join(dir, "yarn")
	require.NoError(t, os.WriteFile(noSibling, []byte("#!/bin/sh\n"), 0o755))

	state := wrapperState{Wrappers: []wrapperEntry{
		{Path: legitPath, OriginalPath: legitPath + ".veto-original", PM: "npm"},
		{Path: missingPath, OriginalPath: missingPath + ".veto-original", PM: "pnpm"},
		{Path: noSibling, OriginalPath: noSibling + ".veto-original", PM: "yarn"},
	}}

	pruned, dirty := pruneStaleWrapperEntries(&state)
	require.True(t, dirty)
	require.Len(t, pruned, 2)
	require.Len(t, state.Wrappers, 1)
	require.Equal(t, legitPath, state.Wrappers[0].Path)

	// Reasons are surfaced for logging.
	reasonByPath := map[string]string{}
	for _, p := range pruned {
		reasonByPath[p.Path] = p.Reason
	}
	require.Equal(t, "path missing", reasonByPath[missingPath])
	require.Equal(t, "sibling missing", reasonByPath[noSibling])
}

// TestPruneStaleWrapperEntries_NoOpWhenClean proves the prune leaves
// state untouched (dirty=false, no records) when every entry is
// reflected on disk.
func TestPruneStaleWrapperEntries_NoOpWhenClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o755))
	require.NoError(t, os.WriteFile(path+".veto-original", []byte(""), 0o755))

	state := wrapperState{Wrappers: []wrapperEntry{{
		Path: path, OriginalPath: path + ".veto-original", PM: "npm",
	}}}
	before := state
	pruned, dirty := pruneStaleWrapperEntries(&state)
	require.False(t, dirty)
	require.Nil(t, pruned)
	require.Equal(t, before, state)
}

// TestPruneStaleWrapperEntries_FallsBackToImpliedSibling proves an
// entry that omits OriginalPath (older registry entries didn't always
// set it) still has its sibling checked at <Path>.veto-original.
func TestPruneStaleWrapperEntries_FallsBackToImpliedSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o755))
	// NO sibling file — implied <path>.veto-original is absent.

	state := wrapperState{Wrappers: []wrapperEntry{{
		Path: path, OriginalPath: "", PM: "npm",
	}}}
	pruned, dirty := pruneStaleWrapperEntries(&state)
	require.True(t, dirty)
	require.Len(t, pruned, 1)
	require.Equal(t, "sibling missing", pruned[0].Reason)
}

// TestApplyWrapper_ReClassifiesAtWrapTime is the veto-3z6 guarantee.
// Discovery (discoverWrapCandidatesWith) classifies every candidate
// once at the top, but the candidates are processed in a loop and an
// earlier wrap can change a later candidate's effective target.
// Concrete case: a sibling-symlink multiplexer like bunx ("./bun") in
// the same dir as bun. After bun gets wrapped, bunx — still cached as
// ClassForeignWrapper from discovery — now resolves through veto. Live
// classification would say "ours-by-path". applyWrapper must use the
// live verdict, not the stale one.
func TestApplyWrapper_ReClassifiesAtWrapTime(t *testing.T) {
	dir := t.TempDir()

	// Plant a "veto" binary and a `.veto-original` so the existence
	// check in applyWrapper's already-ours short-circuit is satisfied.
	veto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	// Plant a candidate that IS already wrapped (symlink → veto +
	// existing .veto-original sibling).
	candidate := filepath.Join(dir, "bunx")
	require.NoError(t, os.Symlink(veto, candidate))
	require.NoError(t, os.WriteFile(candidate+".veto-original", []byte("real-bunx"), 0o755))

	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// Pass a STALE classification (ClassForeignWrapper) — discovery
	// would have set this before bun was wrapped. With re-classify
	// enabled, applyWrapper looks at the actual on-disk state and
	// returns AlreadyOurs instead of trying to overwrite a wrapped
	// candidate.
	c := wrapCandidate{
		path:   candidate,
		pm:     "bunx",
		source: "bun",
		class:  pmsurvey.ClassForeignWrapper,
		target: "./bun",
	}
	action, err := applyWrapper(c, veto, id, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipAlreadyOurs, action,
		"applyWrapper must re-classify and see the live ours-by-path state")
}

// TestClassifySymlink_PMLayoutSymlink_AppleSiliconHomebrew is the
// fixture-A guarantee from veto-2dg: a symlink whose target lives
// inside a canonical Apple Silicon Homebrew Cellar path classifies as
// ClassPMLayoutSymlink (wrappable by default), NOT ClassForeignWrapper.
// Without this, every Homebrew-installed Mach-O on a dev machine would
// be SKIPped as "foreign wrapper" and the user would have to
// --force every install-wrappers run.
func TestClassifySymlink_PMLayoutSymlink_AppleSiliconHomebrew(t *testing.T) {
	root := t.TempDir()
	// Plant a fake veto.
	veto := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto bin"), 0o755))
	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// Plant a Cellar-like layout. The classifier matches on the
	// substring "/homebrew/Cellar/" so a tempdir + that subpath is
	// recognised exactly like /opt/homebrew/Cellar/.
	cellarBin := filepath.Join(root, "homebrew", "Cellar", "python@3.14", "3.14.3_1", "bin")
	require.NoError(t, os.MkdirAll(cellarBin, 0o755))
	realPython := filepath.Join(cellarBin, "python3.14")
	require.NoError(t, os.WriteFile(realPython, []byte("real python bytes"), 0o755))

	// Plant the canonical bin/<pm> → Cellar/.../bin/python3.14 symlink.
	binDir := filepath.Join(root, "homebrew", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	candidate := filepath.Join(binDir, "python3")
	require.NoError(t, os.Symlink(realPython, candidate))

	class, target, err := pmsurvey.ClassifySymlink(candidate, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassPMLayoutSymlink, class,
		"Homebrew Cellar layout must classify as PMLayoutSymlink, not ForeignWrapper; got %s", class)
	resolved, _ := filepath.EvalSymlinks(realPython)
	require.Equal(t, resolved, target)
}

// TestClassifySymlink_PMLayoutSymlink_NpmCliJs proves the npm-cli.js
// case: /opt/homebrew/bin/npm → /opt/homebrew/lib/node_modules/npm/bin/npm-cli.js
// classifies as ClassPMLayoutSymlink. The classifier accepts the
// node_modules subpath as a PM install location.
func TestClassifySymlink_PMLayoutSymlink_NpmCliJs(t *testing.T) {
	root := t.TempDir()
	veto := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))
	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// Plant a Homebrew node_modules layout.
	cliBin := filepath.Join(root, "homebrew", "lib", "node_modules", "npm", "bin")
	require.NoError(t, os.MkdirAll(cliBin, 0o755))
	cliJs := filepath.Join(cliBin, "npm-cli.js")
	require.NoError(t, os.WriteFile(cliJs, []byte("#!/usr/bin/env node\n"), 0o755))

	binDir := filepath.Join(root, "homebrew", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	candidate := filepath.Join(binDir, "npm")
	require.NoError(t, os.Symlink(cliJs, candidate))

	class, _, err := pmsurvey.ClassifySymlink(candidate, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassPMLayoutSymlink, class)
}

// TestClassifySymlink_ForeignWrapper_OutsideAllPMDirs is the fixture-B
// guarantee: a symlink to an executable whose target is NOT in any
// known PM install dir keeps the ClassForeignWrapper verdict.
// Reserves the --force gate for genuinely user-planted custom
// wrappers — the security boundary stays intact.
func TestClassifySymlink_ForeignWrapper_OutsideAllPMDirs(t *testing.T) {
	root := t.TempDir()
	veto := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))
	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)

	// Plant a random executable that is NOT in any known PM dir.
	randomDir := filepath.Join(root, "random", "place")
	require.NoError(t, os.MkdirAll(randomDir, 0o755))
	target := filepath.Join(randomDir, "my-custom-python")
	require.NoError(t, os.WriteFile(target, []byte("custom"), 0o755))

	// Symlink to it from another random path.
	binDir := filepath.Join(root, "user", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	candidate := filepath.Join(binDir, "python3")
	require.NoError(t, os.Symlink(target, candidate))

	class, _, err := pmsurvey.ClassifySymlink(candidate, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassForeignWrapper, class,
		"non-PM-dir target must remain ClassForeignWrapper; got %s", class)
}

// TestApplyWrapper_PMLayoutSymlinkWrapsWithoutForce is the end-to-end
// guarantee that the classifier change reaches install-wrappers: a
// candidate carrying ClassPMLayoutSymlink wraps without --force, the
// rename + symlink dance preserves the original at .veto-original, and
// the new symlink at the candidate path points at veto.
func TestApplyWrapper_PMLayoutSymlinkWrapsWithoutForce(t *testing.T) {
	root := t.TempDir()
	veto := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))

	// Real Cellar-style binary the symlink points at.
	cellarBin := filepath.Join(root, "homebrew", "Cellar", "python@3.14", "3.14.3_1", "bin")
	require.NoError(t, os.MkdirAll(cellarBin, 0o755))
	realPython := filepath.Join(cellarBin, "python3.14")
	require.NoError(t, os.WriteFile(realPython, []byte("real-python"), 0o755))

	// Candidate: bin/python3 → Cellar/.../python3.14.
	binDir := filepath.Join(root, "homebrew", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	candidate := filepath.Join(binDir, "python3")
	require.NoError(t, os.Symlink(realPython, candidate))

	c := wrapCandidate{
		path:   candidate,
		pm:     "python3",
		source: "homebrew",
		class:  pmsurvey.ClassPMLayoutSymlink,
		target: realPython,
	}

	// Pass nil identity so the re-classify pass is skipped and the
	// dispatch hinges on c.class alone. NO --force.
	action, err := applyWrapper(c, veto, nil, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action,
		"ClassPMLayoutSymlink must wrap without --force")

	// candidate is now a symlink to veto.
	resolved, err := filepath.EvalSymlinks(candidate)
	require.NoError(t, err)
	resolvedVeto, err := filepath.EvalSymlinks(veto)
	require.NoError(t, err)
	require.Equal(t, resolvedVeto, resolved)

	// The original symlink (→ Cellar python3.14) is preserved at
	// .veto-original.
	original := candidate + ".veto-original"
	got, err := os.Readlink(original)
	require.NoError(t, err, "expected .veto-original to be the moved-aside symlink")
	require.Equal(t, realPython, got)
}

// TestApplyWrapper_ForeignWrapperStillSkipsWithoutForce proves the
// --force gate is still in force for genuinely-foreign symlinks. The
// security boundary did not loosen: only symlinks into known PM dirs
// get the permissive verdict; everything else stays gated.
func TestApplyWrapper_ForeignWrapperStillSkipsWithoutForce(t *testing.T) {
	root := t.TempDir()
	veto := filepath.Join(root, "veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))

	// Target outside any known PM dir.
	target := filepath.Join(root, "custom", "my-python")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
	require.NoError(t, os.WriteFile(target, []byte("custom-python"), 0o755))

	candidate := filepath.Join(root, "user", "bin", "python3")
	require.NoError(t, os.MkdirAll(filepath.Dir(candidate), 0o755))
	require.NoError(t, os.Symlink(target, candidate))

	c := wrapCandidate{
		path:   candidate,
		pm:     "python3",
		source: "user",
		class:  pmsurvey.ClassForeignWrapper,
		target: target,
	}

	action, err := applyWrapper(c, veto, nil, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipForeignWrapper, action,
		"non-PM-dir foreign wrapper must still SKIP without --force")
}

// TestFindRealBinary_ResolvesDisplacedShimOriginal pins the Layer-2
// displacement resolver (2026-07-24 uv incident). `install-shims
// --force` renames a real binary occupying a shim path to
// `<pm>.veto-displaced` before planting the `<pm> -> veto` symlink —
// but the resolver only ever consulted `.veto-original` siblings gated
// on wrappers.json, which by territory rule never covers the shim dir.
// A host whose ONLY real copy of the PM was the displaced file got
// "cannot find real uv: not found in PATH" (or, with a second wrapper
// tool on PATH, an infinite exec ping-pong). The PATH walk must
// resolve the displaced sibling for shim-dir candidates.
func TestFindRealBinary_ResolvesDisplacedShimOriginal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shimDir := filepath.Join(home, ".local", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	// The shim: uv -> veto (test binary stands in for veto, same trick
	// as the sibling tests — the PATH walk's resolved==selfReal branch
	// fires).
	self, err := os.Executable()
	require.NoError(t, err)
	uv := filepath.Join(shimDir, "uv")
	require.NoError(t, os.Symlink(self, uv))

	// The displaced real binary install-shims --force left behind.
	displaced := uv + ".veto-displaced"
	require.NoError(t, os.WriteFile(displaced, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("PATH", shimDir)

	// Shim-dir paths are NEVER in wrappers.json (territory guard).
	notRegistered := func(string) bool { return false }
	got, err := findRealBinary("uv", notRegistered)
	require.NoError(t, err, "displaced shim original must be resolvable")
	require.Equal(t, displaced, got)
}

// TestFindDisplacedOriginal_DirectShimInvocation covers the argv[0]
// variant of the displacement resolver: someone runs `~/.local/bin/uv`
// by absolute path with a PATH that doesn't contain the shim dir, so
// the PATH walk never sees the shim. findDisplacedOriginal must honor
// the healthy sibling for a shim-dir path and reject bare names
// (they go through the PATH walk).
func TestFindDisplacedOriginal_DirectShimInvocation(t *testing.T) {
	home := t.TempDir()
	shimDir := filepath.Join(home, ".local", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	uv := filepath.Join(shimDir, "uv")
	displaced := uv + ".veto-displaced"
	require.NoError(t, os.WriteFile(displaced, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	got, ok := findDisplacedOriginal(uv, shimDir)
	require.True(t, ok, "healthy displaced sibling of a shim-dir path must resolve")
	require.Equal(t, displaced, got)

	// Bare name: no path separator, not a shim-dir site.
	_, ok = findDisplacedOriginal("uv", shimDir)
	require.False(t, ok, "bare-name argv[0] must not consult displaced siblings")

	// Missing sibling: fail closed.
	pip := filepath.Join(shimDir, "pip")
	_, ok = findDisplacedOriginal(pip, shimDir)
	require.False(t, ok, "no displaced sibling means no resolution")
}

// TestFindRealBinary_SkipsSelfReferentialDisplaced: a
// `<pm>.veto-displaced` that resolves back into veto itself would
// re-enter veto in an exec loop — the same failure class the
// `.veto-original` self-reference guards close. The walk must skip it
// and fail closed with "not found in PATH".
func TestFindRealBinary_SkipsSelfReferentialDisplaced(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shimDir := filepath.Join(home, ".local", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	self, err := os.Executable()
	require.NoError(t, err)
	uv := filepath.Join(shimDir, "uv")
	require.NoError(t, os.Symlink(self, uv))
	// Displaced sibling ALSO chains back to veto (the test binary).
	require.NoError(t, os.Symlink(self, uv+".veto-displaced"))

	t.Setenv("PATH", shimDir)

	_, err = findRealBinary("uv", func(string) bool { return false })
	require.Error(t, err, "self-referential displaced sibling must be skipped")
	require.Contains(t, err.Error(), "not found in PATH")
}

// TestFindRealBinary_IgnoresDisplacedOutsideShimDir enforces the
// provenance gate: `.veto-displaced` files are only ever created by
// install-shims inside the Layer-2 shim dir, so a displaced sibling
// planted ANYWHERE else is not veto-authored and must be ignored —
// exactly as unregistered `.veto-original` siblings are. Otherwise a
// same-UID attacker could plant `<dir>/npm.veto-displaced` at any
// veto-pointing PATH entry and hijack execution.
func TestFindRealBinary_IgnoresDisplacedOutsideShimDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// A veto-pointing candidate OUTSIDE the shim dir with a planted
	// displaced sibling.
	otherBin := filepath.Join(home, "otherbin")
	require.NoError(t, os.MkdirAll(otherBin, 0o755))
	self, err := os.Executable()
	require.NoError(t, err)
	npm := filepath.Join(otherBin, "npm")
	require.NoError(t, os.Symlink(self, npm))
	require.NoError(t, os.WriteFile(npm+".veto-displaced", []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("PATH", otherBin)

	_, err = findRealBinary("npm", func(string) bool { return false })
	require.Error(t, err, "displaced sibling outside the shim dir must be ignored (provenance gate)")
	require.Contains(t, err.Error(), "not found in PATH")
}

// TestClassifyWriteSkip_SIPPathIsReadOnlyFSNotSudo pins the sudo-hint
// fix: an unprivileged write under a SIP root (/usr/bin, ...) fails
// with EPERM/EACCES — the kernel never gets far enough to return
// EROFS — so classifying on errno alone filed SIP candidates under
// "needs sudo" and the epilogue printed `sudo veto install-wrappers
// --dir /usr/bin ...`, which cannot work (SIP blocks root too). The
// classifier must consult SIP-ness before conceding the sudo hint.
func TestClassifyWriteSkip_SIPPathIsReadOnlyFSNotSudo(t *testing.T) {
	permErr := &fs.PathError{Op: "rename", Path: "/usr/bin/pip3", Err: syscall.EPERM}

	action, ok := classifyWriteSkip("/usr/bin/pip3", permErr)
	require.True(t, ok)
	if runtime.GOOS == "darwin" {
		require.Equal(t, wrapperActionSkipReadOnlyFS, action,
			"SIP-protected path must classify as read-only FS — sudo cannot bypass SIP")
	} else {
		// isSIPProtectedPath is runtime-gated: SIP does not exist off
		// darwin, so the plain permission classification stands.
		require.Equal(t, wrapperActionSkipUnwritable, action)
	}
}

// TestClassifyWriteSkip_NonSIPPermissionStillWantsSudo: a permission
// error in a plain root-owned dir is still the "needs sudo" category —
// the remediation hint is genuinely actionable there.
func TestClassifyWriteSkip_NonSIPPermissionStillWantsSudo(t *testing.T) {
	dir := t.TempDir()
	permErr := &fs.PathError{Op: "rename", Path: filepath.Join(dir, "npm"), Err: syscall.EACCES}

	action, ok := classifyWriteSkip(filepath.Join(dir, "npm"), permErr)
	require.True(t, ok)
	require.Equal(t, wrapperActionSkipUnwritable, action)
}

// TestClassifyWriteSkip_EROFSAndGenuineFailures: EROFS is always the
// read-only-FS category regardless of path, and any other error is not
// a skip at all — it propagates as a genuine failure.
func TestClassifyWriteSkip_EROFSAndGenuineFailures(t *testing.T) {
	erofs := &fs.PathError{Op: "rename", Path: "/anywhere/npm", Err: syscall.EROFS}
	action, ok := classifyWriteSkip("/anywhere/npm", erofs)
	require.True(t, ok)
	require.Equal(t, wrapperActionSkipReadOnlyFS, action)

	other := &fs.PathError{Op: "rename", Path: "/anywhere/npm", Err: syscall.EIO}
	_, ok = classifyWriteSkip("/anywhere/npm", other)
	require.False(t, ok, "non-permission, non-EROFS errors are genuine failures, not skips")
}
