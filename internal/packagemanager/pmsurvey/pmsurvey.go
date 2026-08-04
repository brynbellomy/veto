// Package pmsurvey is the single source of truth for "where on this host
// could package manager `foo` live, and is the file at that path our
// wrapper, a foreign wrapper, broken, or a real binary?"
//
// Both veto's install-wrappers command and the doctor's host survey ask
// these questions. Before pmsurvey, they answered them with separately
// maintained helpers that drifted: install walked a strict subset of
// what doctor walked, and install silently dropped broken symlinks that
// doctor surfaced as NOT-wrapped warnings. pmsurvey collapses the two
// answers into one library each call site imports.
//
// The discovery surface (PathsFor, WellKnownBinDirs, IsShimDir) is in
// this file; the symlink classifier (ClassifySymlink, Classification)
// lives in classify.go. Callers that only need discovery don't have to
// pay for the classifier's hash machinery.
package pmsurvey

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
)

// IsShimDir reports whether dir is a $PATH entry the host survey should
// skip when looking for PM binaries to wrap.
//
// It returns true only for directories that are the exclusive territory
// of a known version-manager shim system: mise, asdf, pyenv, or nvm.
// These managers own every entry in their shim dirs and re-create them
// on activate; wrapping would fight the manager every time. The install
// dirs the shims point AT are in WellKnownBinDirs and ARE wrap
// candidates.
//
// Directories that merely contain a veto wrapper (from a prior
// install-wrappers run) alongside unrelated binaries are NOT shim
// dirs — veto's wrappers coexist with other content in normal bin dirs
// like ~/.cargo/bin, and the remaining binaries there are still valid
// wrap candidates. The distinguishing test is "whose exclusive
// territory is this?", not "does this dir contain a veto symlink?".
//
// Path matching is substring-based to cover macOS and Linux layouts
// uniformly.
func IsShimDir(dir string) bool {
	switch {
	case strings.Contains(dir, "/mise/shims"),
		strings.Contains(dir, "/.asdf/shims"),
		strings.Contains(dir, "/.pyenv/shims"):
		return true
	}
	if strings.Contains(dir, "/.nvm/versions/") || strings.Contains(dir, "/nvm/versions/node/") {
		return true
	}
	return false
}

// SystemBinDirsEnv overrides the hardcoded SYSTEM bin-dir prefixes
// (/opt/homebrew/bin, /usr/local/bin) with an explicit colon-separated
// list; an empty value means "no system prefixes". It exists for test
// isolation: those prefixes are absolute paths independent of $HOME, so a
// test exercising wrapper discovery would otherwise walk — and
// install-wrappers would MUTATE — the real /opt/homebrew/bin on the
// developer's machine, breaking it. Tests set this (usually to "") so
// discovery sees only their temp $HOME-derived fixtures. Advanced users
// may also point veto at a non-standard prefix. The $HOME-derived
// version-manager dirs (mise/asdf/pyenv/nvm/bun/cargo) are unaffected — a
// test that sets $HOME to a temp dir already confines those.
const SystemBinDirsEnv = "VETO_SYSTEM_BIN_DIRS"

// systemBinDirs returns the hardcoded system prefixes, honoring the
// SystemBinDirsEnv override. LookupEnv distinguishes set-to-empty (no
// system dirs) from unset (the real defaults).
func systemBinDirs() []string {
	if v, ok := os.LookupEnv(SystemBinDirsEnv); ok {
		return filepath.SplitList(v)
	}
	return []string{"/opt/homebrew/bin", "/usr/local/bin"}
}

// WellKnownBinDirs returns every bin-dir pattern on this host where a
// system or version-manager-installed PM could live: the homebrew
// prefixes plus mise/asdf install bin dirs (one per installed
// tool@version), plus pyenv/nvm versions, plus ~/.bun/bin and
// ~/.cargo/bin.
//
// Patterns that depend on $HOME silently return empty when $HOME is
// unset; callers fall back to whatever WellKnownBinDirs returned plus
// $PATH discovery (PathsFor handles this).
//
// VETO_SYSTEM_BIN_DIRS overrides the system prefixes — see SystemBinDirsEnv.
func WellKnownBinDirs() []string {
	out := systemBinDirs()
	home, err := os.UserHomeDir()
	if err != nil {
		return out
	}
	out = append(out, globToolVersionBinDirs(filepath.Join(home, ".local", "share", "mise", "installs"))...)
	out = append(out, globToolVersionBinDirs(filepath.Join(home, ".asdf", "installs"))...)
	out = append(out, globVersionBinDirs(filepath.Join(home, ".pyenv", "versions"))...)
	out = append(out, globVersionBinDirs(filepath.Join(home, ".nvm", "versions", "node"))...)
	out = append(out, filepath.Join(home, ".bun", "bin"))
	out = append(out, filepath.Join(home, ".cargo", "bin"))
	return out
}

// PathsFor returns every absolute path on this host where pm could live
// and is a Layer-4 wrap candidate. Walks WellKnownBinDirs first, then
// every $PATH entry that is not an IsShimDir, then — only for
// versioned python aliases like `python3.12` — every uv canonical
// cpython bin dir under ~/.local/share/uv/python/cpython-*/bin.
//
// Each candidate is verified to exist via os.Lstat; broken symlinks
// (Lstat succeeds, Stat fails) are INCLUDED for PATH/WellKnownBinDirs
// entries because they're real on-disk entries that install-wrappers
// and doctor both need to surface, not silently drop. uv-store
// candidates are subject to a stricter regular-file check — see the
// comment on the uv branch inside the function body for why.
//
// Why uv canonical dirs matter: uv venvs symlink (or copy) the
// canonical cpython binary out of that store. An `uv run python -c ...`
// invocation reaches the venv python by an absolute path that bypasses
// $PATH entirely; wrapping the canonical store binary closes the
// bypass at the source so every venv that links from it sees the
// wrapper, regardless of whether the user has python / python3 /
// python3.X on PATH. Only the canonical `python3.X` regular file is
// surfaced from a uv cpython bin dir — the `python` and `python3`
// aliases living next to it are symlinks that inherit the wrap via
// the existing chain (python → python3.X → veto) and must NOT be
// wrapped independently (would loop veto back into itself).
//
// Results are deduplicated by absolute path and ordered: well-known
// roots in declaration order first, then $PATH entries in $PATH order,
// then uv canonical dirs in declaration order.
func PathsFor(pm string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(p string) {
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		if _, dup := seen[clean]; dup {
			return
		}
		info, err := os.Lstat(clean)
		if err != nil {
			return
		}
		if info.IsDir() {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}

	for _, dir := range WellKnownBinDirs() {
		add(filepath.Join(dir, pm))
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || IsShimDir(dir) {
			continue
		}
		add(filepath.Join(dir, pm))
	}
	// Gate the uv-canonical-store walk on the versioned-python shape
	// (python3.X). The bare-name `python` / `python3` inside a uv
	// cpython bin dir are aliases — symlinks pointing at the canonical
	// `python3.X` in the same directory. They MUST NOT be surfaced as
	// independent wrap candidates: if veto wraps the alias, its
	// `.veto-original` sibling ends up being a symlink to the
	// already-wrapped `python3.X`, which is itself a symlink to veto.
	// The exec chain then loops veto back into itself on every
	// invocation. The aliases inherit the wrap for free via the
	// existing chain (`python` → `python3.X` → veto) so dropping them
	// from discovery costs nothing and avoids the loop.
	//
	// Aliases on PATH outside the uv store (e.g. /opt/homebrew/bin/python3
	// → Cellar's python3.14) still go through the WellKnownBinDirs and
	// PATH branches above and remain wrap candidates there — that's a
	// different layout where the symlink target is in a separate dir
	// and won't get independently wrapped by this command.
	if pmlist.IsVersionedPython(pm) {
		for _, dir := range uvCanonicalPythonBinDirs() {
			add(filepath.Join(dir, pm))
		}
	}
	return out
}

// uvCanonicalPythonBinDirs returns every
// ~/.local/share/uv/python/cpython-*/bin directory currently on disk.
// uv installs each managed cpython under that root with a release-tagged
// dir name (e.g. cpython-3.12.4-macos-aarch64-none); the bin/ subdir
// holds the python3.X binaries veto needs to wrap so uv venvs that
// symlink them resolve through veto.
//
// Returns empty when $HOME is unset or the uv store doesn't exist.
// Filesystem errors are swallowed silently — PathsFor's caller handles
// the empty case gracefully (no python3.X candidates surfaced).
func uvCanonicalPythonBinDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	root := filepath.Join(home, ".local", "share", "uv", "python")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// The uv store names cpython installs `cpython-…`. Filter on
		// the prefix so a stray dir (or a future pypy install) doesn't
		// trigger a spurious bin walk.
		if !strings.HasPrefix(e.Name(), "cpython-") {
			continue
		}
		bin := filepath.Join(root, e.Name(), "bin")
		// We don't pre-Stat the bin dir — PathsFor's `add` already
		// Lstat's each candidate file, so a release dir missing a bin
		// subdir contributes zero candidates without an extra syscall
		// here.
		out = append(out, bin)
	}
	return out
}

// globToolVersionBinDirs returns every `<root>/<tool>/<version>/bin`
// directory on disk. Mirrors the helper of the same name in
// cmd/veto/install_wrappers.go; lifted here so both call sites use one
// implementation. Returns an empty slice on any filesystem error
// (missing root, unreadable directory).
func globToolVersionBinDirs(root string) []string {
	tools, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, tool := range tools {
		if !tool.IsDir() {
			continue
		}
		toolDir := filepath.Join(root, tool.Name())
		versions, err := os.ReadDir(toolDir)
		if err != nil {
			continue
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			out = append(out, filepath.Join(toolDir, v.Name(), "bin"))
		}
	}
	return out
}

// globVersionBinDirs returns every `<root>/<version>/bin` directory on
// disk (the pyenv/nvm shape, without the intermediate tool name).
func globVersionBinDirs(root string) []string {
	versions, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		out = append(out, filepath.Join(root, v.Name(), "bin"))
	}
	return out
}
