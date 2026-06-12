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
// Two reasons to skip:
//
//   - veto's own Layer-2 shim dir (typically ~/.local/bin), recognised
//     by containing a symlink whose physical target resolves to a
//     "veto" binary. Surveying that dir would flag veto's own shim as
//     a Layer-4 wrap candidate, which is wrong — Layer-2 and Layer-4
//     are different defenses at different paths.
//   - Version-manager shim dirs (mise/asdf/pyenv/nvm): their entries
//     are wrapper scripts the version manager owns and re-creates on
//     activate. Wrapping these would fight the manager every time the
//     user runs `mise activate`. The install dirs the shims point AT
//     are in WellKnownBinDirs and ARE wrap candidates.
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(filepath.Base(resolved), "veto") {
			return true
		}
	}
	return false
}

// WellKnownBinDirs returns every bin-dir pattern on this host where a
// system or version-manager-installed PM could live: the homebrew
// prefixes plus mise/asdf install bin dirs (one per installed
// tool@version), plus pyenv/nvm versions, plus ~/.bun/bin.
//
// Patterns that depend on $HOME silently return empty when $HOME is
// unset; callers fall back to whatever WellKnownBinDirs returned plus
// $PATH discovery (PathsFor handles this).
func WellKnownBinDirs() []string {
	out := []string{"/opt/homebrew/bin", "/usr/local/bin"}
	home, err := os.UserHomeDir()
	if err != nil {
		return out
	}
	out = append(out, globToolVersionBinDirs(filepath.Join(home, ".local", "share", "mise", "installs"))...)
	out = append(out, globToolVersionBinDirs(filepath.Join(home, ".asdf", "installs"))...)
	out = append(out, globVersionBinDirs(filepath.Join(home, ".pyenv", "versions"))...)
	out = append(out, globVersionBinDirs(filepath.Join(home, ".nvm", "versions", "node"))...)
	out = append(out, filepath.Join(home, ".bun", "bin"))
	return out
}

// PathsFor returns every absolute path on this host where pm could live
// and is a Layer-4 wrap candidate. Walks WellKnownBinDirs first, then
// every $PATH entry that is not an IsShimDir, then — for python-family
// names — every uv canonical cpython bin dir under
// ~/.local/share/uv/python/cpython-*/bin.
//
// Each candidate is verified to exist via os.Lstat; broken symlinks
// (Lstat succeeds, Stat fails) are INCLUDED, because they're real
// on-disk entries that install-wrappers and doctor both need to
// surface, not silently drop.
//
// Why uv canonical dirs matter: uv venvs symlink (or copy) the
// canonical cpython binary out of that store. An `uv run python -c ...`
// invocation reaches the venv python by an absolute path that bypasses
// $PATH entirely; wrapping the canonical store binary closes the
// bypass at the source so every venv that links from it sees the
// wrapper, regardless of whether the user has python / python3 /
// python3.X on PATH.
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
	if isPythonFamilyName(pm) {
		for _, dir := range uvCanonicalPythonBinDirs() {
			add(filepath.Join(dir, pm))
		}
	}
	return out
}

// isPythonFamilyName reports whether name belongs to the python family
// (canonical python / python3 OR a versioned alias like python3.12).
// PathsFor uses this to gate the uv-canonical-store walk so we don't
// pay its cost on every PM enumeration; only python requests trigger
// the extra glob.
func isPythonFamilyName(name string) bool {
	return name == "python" || name == "python3" || pmlist.IsVersionedPython(name)
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
