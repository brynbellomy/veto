# Wrapper discovery + symlink classification robustness — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two real install/doctor bugs in veto and add a robust symlink classifier so doctor and install-wrappers agree on what "wrapped" means.

**Bug A — install-wrappers silently skips broken symlinks.** Discovery emits the path, then `isWrappableTarget` drops it on `EvalSymlinks` error with no log line. Doctor's `surveyWrappablePaths` uses `Lstat` (which succeeds on broken symlinks), so doctor warns about paths install can never wrap. Concrete trigger: a previous tool ("bouncer") left orphan symlinks; veto can't see them but doctor screams about them every run.

**Bug B — discovery asymmetry.** Doctor walks well-known roots PLUS `$PATH` (minus shim dirs). install-wrappers walks well-known roots only. So `~/.cargo/bin/cargo`, `/usr/bin/pip3`, and anything else on `$PATH` outside the known roots gets warned about by doctor but is invisible to install. The existing doctor.go comment ("extracting cleanly would balloon this PR") is the tech debt this plan pays down.

**Architecture:** A new `internal/packagemanager/pmsurvey` package owns the canonical "where could PM `foo` live on this host" answer (`PathsFor`) AND a canonical symlink classifier (`ClassifySymlink`) that distinguishes our wrapper, a foreign wrapper, a broken symlink, and a real binary by combining path identity with SHA-256 content identity. Both `install_wrappers.go` and `doctor.go` get refactored to call into pmsurvey, so they cannot drift apart again.

**Tech Stack:** Go 1.26; `crypto/sha256`; existing `internal/packagemanager/pmlist`; `github.com/brynbellomy/go-utils/errors` for wrapping; `github.com/stretchr/testify/require`.

**Branch:** `wrapper-discovery-robustness`, branched from `main` at `2cc9251`.

**Mirror map / source-of-truth files to read first:**

| Read before writing | Why |
|---|---|
| `cmd/veto/install_wrappers.go` (functions `discoverWrapCandidates`, `isWrappableTarget`, `isAlreadyOursWrap`, `applyWrapper`) | Existing predicate semantics; new code must preserve them while extending |
| `cmd/veto/doctor.go` (functions `checkWrappers`, `surveyWrappablePaths`, `isShimDirForSurvey`) | The host-survey logic this plan migrates into pmsurvey |
| `cmd/veto/install_wrappers.go` (`globToolVersionBinDirs`, `globVersionBinDirs`, `pointsAtVeto`) | Helpers pmsurvey will lift / call |
| `internal/packagemanager/pmlist/pmlist.go` | The PM-name source of truth (already in the right place) |

---

## Task 1: `internal/packagemanager/pmsurvey` — `IsShimDir` + `PathsFor`

**Files:**
- Create: `internal/packagemanager/pmsurvey/pmsurvey.go`
- Test:   `internal/packagemanager/pmsurvey/pmsurvey_test.go`

This task creates the shared discovery surface. Both `install_wrappers.go` and `doctor.go` will end up calling `pmsurvey.PathsFor(pm)`, eliminating the asymmetry that is Bug B.

Three responsibilities live here:

1. **`IsShimDir(dir string) bool`** — does this directory hold version-manager shim scripts or veto's own Layer-2 shims? Mirror `doctor.go:isShimDirForSurvey` exactly, with the same heuristics.
2. **`WellKnownBinDirs() []string`** — enumerate the homebrew prefix dirs, mise/asdf install bin dirs, pyenv versions, nvm node versions, `~/.bun/bin`. Mirror `discoverWrapCandidates` precisely.
3. **`PathsFor(pm string) []string`** — combine (1) and (2): every absolute path on this host where `pm` could live. Returns deduplicated, stable order (well-known roots first, then `$PATH` entries minus shim dirs). Each path is verified via `os.Lstat` to exist and not be a directory; broken symlinks are INCLUDED (they're a real on-disk entry doctor and install both need to see).

This task does NOT touch install_wrappers.go or doctor.go yet — that's Tasks 3 and 4. The helpers stand alone with their own tests.

- [ ] **Step 1: Read the source-of-truth functions**

```bash
sed -n '469,545p' cmd/veto/install_wrappers.go
sed -n '891,1013p' cmd/veto/doctor.go
```

Make sure you can answer: what dirs does `discoverWrapCandidates` walk? What dirs does `surveyWrappablePaths` walk? What's the exact rule `isShimDirForSurvey` uses?

- [ ] **Step 2: Write the package skeleton**

Create `internal/packagemanager/pmsurvey/pmsurvey.go`:

```go
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
// every $PATH entry that is not an IsShimDir. Each candidate is
// verified to exist via os.Lstat; broken symlinks (Lstat succeeds,
// Stat fails) are INCLUDED, because they're real on-disk entries that
// install-wrappers and doctor both need to surface, not silently drop.
//
// Results are deduplicated by absolute path and ordered: well-known
// roots in declaration order first, then $PATH entries in $PATH order.
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
```

- [ ] **Step 3: Write the tests (failing first, code already lands above so they'll pass after Step 4 verifies)**

Create `internal/packagemanager/pmsurvey/pmsurvey_test.go`:

```go
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
```

- [ ] **Step 4: Run tests and commit**

```bash
veto go test ./internal/packagemanager/pmsurvey/... -count=1
```

Expected: all pass.

```bash
git add internal/packagemanager/pmsurvey/pmsurvey.go internal/packagemanager/pmsurvey/pmsurvey_test.go
git commit -m "feat(pmsurvey): canonical PM path discovery (well-known roots + PATH)" -m "Single source of truth for 'where could PM foo live on this host?'. Both install-wrappers and doctor will use this, ending the discovery asymmetry where install walked a strict subset of doctor."
```

---

## Task 2: `pmsurvey.ClassifySymlink` — broken / foreign / ours-by-path / ours-by-hash

**Files:**
- Create: `internal/packagemanager/pmsurvey/classify.go`
- Test:   `internal/packagemanager/pmsurvey/classify_test.go`

This task adds the symlink classifier. Both call sites use it to decide: is this our wrapper, someone else's wrapper, broken, or a plain real binary?

- [ ] **Step 1: Write the classifier**

Create `internal/packagemanager/pmsurvey/classify.go`:

```go
package pmsurvey

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	utilerrors "github.com/brynbellomy/go-utils/errors"
)

// Classification is the verdict on one wrap-candidate path.
type Classification int

const (
	// ClassReal: path is a regular file (or hard link). Not a symlink at
	// all. The caller's job is "wrap this" (if writable) or "leave it"
	// (if not).
	ClassReal Classification = iota

	// ClassOursByPath: path is a symlink whose target's absolute path
	// equals the veto binary's path. Cheapest positive identification;
	// no hashing required.
	ClassOursByPath

	// ClassOursByHash: path is a symlink whose target's SHA-256 matches
	// the veto binary's. The path is different from veto's resolved
	// path (e.g. veto moved, or the symlink chains through aliases)
	// but the content is provably ours.
	ClassOursByHash

	// ClassForeignWrapper: path is a symlink to a file that exists, is
	// executable, and whose SHA-256 does NOT match the veto binary.
	// Almost always means a previous version of veto or a different
	// tool (the "bouncer" case) wrapped this path and was later
	// uninstalled or replaced.
	ClassForeignWrapper

	// ClassBrokenSymlink: path is a symlink whose target does not
	// exist. The user can't run it, and install-wrappers can't honestly
	// claim to wrap an already-wrapped binary because there is no
	// wrapped binary.
	ClassBrokenSymlink
)

// String returns a stable short name for use in logs and test diags.
func (c Classification) String() string {
	switch c {
	case ClassReal:
		return "real"
	case ClassOursByPath:
		return "ours-by-path"
	case ClassOursByHash:
		return "ours-by-hash"
	case ClassForeignWrapper:
		return "foreign-wrapper"
	case ClassBrokenSymlink:
		return "broken-symlink"
	}
	return "unknown"
}

// VetoIdentity describes the running veto binary well enough to
// classify wrap candidates. Use VetoIdentityFor to build one once at
// start of a command, then pass to ClassifySymlink for every path.
type VetoIdentity struct {
	// Path is the absolute, fully-resolved path to the veto binary on
	// this host (filepath.EvalSymlinks applied).
	Path string

	hashOnce sync.Once
	hash     [32]byte
	hashErr  error
}

// Hash returns the SHA-256 of the veto binary's contents, computing it
// lazily on first call. Errors propagate; subsequent calls return the
// cached error so the first call's failure is the only one surfaced.
func (v *VetoIdentity) Hash() ([32]byte, error) {
	v.hashOnce.Do(func() {
		v.hash, v.hashErr = hashFile(v.Path)
	})
	return v.hash, v.hashErr
}

// VetoIdentityFor builds a VetoIdentity for the binary at vetoPath.
// vetoPath should be the result of resolveVetoBinary (or equivalent
// caller-side logic); this function calls EvalSymlinks once so the
// stored Path is the physical file every later comparison uses.
func VetoIdentityFor(vetoPath string) (*VetoIdentity, error) {
	if vetoPath == "" {
		return nil, errors.New("pmsurvey: empty vetoPath")
	}
	resolved, err := filepath.EvalSymlinks(vetoPath)
	if err != nil {
		return nil, utilerrors.With(err, "pmsurvey: resolve veto binary").Set("path", vetoPath)
	}
	return &VetoIdentity{Path: resolved}, nil
}

// ClassifySymlink classifies the file at path against the given veto
// identity. The returned target is the resolved symlink target when
// path is a symlink (or "" for ClassReal), so callers can include it
// in diagnostic output.
//
// On any non-classification I/O error (Lstat failure on path that
// supposedly exists, hash read failure on a target that EvalSymlinks
// resolved), the error is returned and Classification is undefined.
// "Target doesn't exist" is NOT an error — it's ClassBrokenSymlink.
func ClassifySymlink(path string, veto *VetoIdentity) (Classification, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, "", utilerrors.With(err, "pmsurvey: lstat candidate").Set("path", path)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return ClassReal, "", nil
	}
	target, readErr := os.Readlink(path)
	if readErr != nil {
		return 0, "", utilerrors.With(readErr, "pmsurvey: readlink").Set("path", path)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)

	// Try to resolve through any intermediate symlinks. EvalSymlinks
	// returns an error for a broken chain — that's the broken case.
	resolved, evalErr := filepath.EvalSymlinks(path)
	if evalErr != nil {
		if errors.Is(evalErr, os.ErrNotExist) {
			return ClassBrokenSymlink, target, nil
		}
		// Lstat-style "not exist" can come back as a *PathError whose
		// Unwrap returns syscall.ENOENT; the IsNotExist helper covers
		// that without the caller having to think about it.
		if os.IsNotExist(evalErr) {
			return ClassBrokenSymlink, target, nil
		}
		return 0, target, utilerrors.With(evalErr, "pmsurvey: evalsymlinks").Set("path", path)
	}

	// Fast path: the resolved target IS the veto binary by path. No
	// need to hash anything.
	if resolved == veto.Path {
		return ClassOursByPath, resolved, nil
	}

	// Slow path: hash the target and compare. A match proves the
	// symlink leads to a binary byte-identical to veto's, even if a
	// path identity check would say otherwise (veto moved, hard link,
	// different physical path).
	resolvedHash, err := hashFile(resolved)
	if err != nil {
		return 0, resolved, utilerrors.With(err, "pmsurvey: hash candidate target").Set("path", resolved)
	}
	vetoHash, err := veto.Hash()
	if err != nil {
		return 0, resolved, utilerrors.With(err, "pmsurvey: hash veto binary")
	}
	if resolvedHash == vetoHash {
		return ClassOursByHash, resolved, nil
	}
	return ClassForeignWrapper, resolved, nil
}

// hashFile returns the SHA-256 of the file's contents. Used both for
// the veto binary and for symlink targets.
func hashFile(path string) ([32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
```

- [ ] **Step 2: Write the tests**

Create `internal/packagemanager/pmsurvey/classify_test.go`:

```go
package pmsurvey_test

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

func writeFileWithContent(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, content, mode))
}

func mustBuildVetoIdentity(t *testing.T, path string) *pmsurvey.VetoIdentity {
	t.Helper()
	id, err := pmsurvey.VetoIdentityFor(path)
	require.NoError(t, err)
	return id
}

func TestClassifySymlinkReal(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	npm := filepath.Join(dir, "npm")
	writeFileWithContent(t, npm, []byte("real npm"), 0o755)

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassReal, c, "got %s", c)
	require.Empty(t, target)
}

func TestClassifySymlinkOursByPath(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(veto, npm))

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassOursByPath, c)
	require.Equal(t, veto, target)
}

func TestClassifySymlinkOursByHash(t *testing.T) {
	dir := t.TempDir()
	content := []byte("veto bin v1")
	vetoA := filepath.Join(dir, "veto-a")
	vetoB := filepath.Join(dir, "veto-b")
	writeFileWithContent(t, vetoA, content, 0o755)
	writeFileWithContent(t, vetoB, content, 0o755) // same bytes, different path
	id := mustBuildVetoIdentity(t, vetoA)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(vetoB, npm))

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassOursByHash, c, "got %s; both vetos have identical bytes", c)
	require.Equal(t, vetoB, target)
}

func TestClassifySymlinkForeignWrapper(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	// A foreign wrapper binary with different bytes.
	bouncer := filepath.Join(dir, "bouncer")
	writeFileWithContent(t, bouncer, []byte("bouncer bin v2"), 0o755)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(bouncer, npm))

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassForeignWrapper, c)
	require.Equal(t, bouncer, target)
}

func TestClassifySymlinkBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	missing := filepath.Join(dir, "vanished")
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(missing, npm)) // target doesn't exist

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassBrokenSymlink, c)
	require.Equal(t, missing, target,
		"broken-symlink classification must surface the intended target for diagnostics")
}

func TestClassifySymlinkLstatErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	_, _, err := pmsurvey.ClassifySymlink(filepath.Join(dir, "does-not-exist"), id)
	require.Error(t, err, "missing path must surface as an error, not a classification")
}

func TestVetoIdentityHashCachesAfterFirstCall(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	content := []byte("veto bin v1")
	writeFileWithContent(t, veto, content, 0o755)
	id := mustBuildVetoIdentity(t, veto)

	h1, err := id.Hash()
	require.NoError(t, err)

	// Mutate the file under it.
	writeFileWithContent(t, veto, []byte("changed"), 0o755)

	h2, err := id.Hash()
	require.NoError(t, err)
	require.Equal(t, h1, h2, "Hash() must cache the first computation; got fresh hash after file mutation")

	// And the cached hash must match what sha256 of the original content
	// would produce.
	expected := sha256.Sum256(content)
	require.Equal(t, expected, h1)
}
```

- [ ] **Step 3: Run tests and commit**

```bash
veto go test ./internal/packagemanager/pmsurvey/... -count=1
```

```bash
git add internal/packagemanager/pmsurvey/classify.go internal/packagemanager/pmsurvey/classify_test.go
git commit -m "feat(pmsurvey): symlink classifier with veto-build hash verification" -m "Adds ClassifySymlink returning real / ours-by-path / ours-by-hash / foreign-wrapper / broken-symlink. Hash check catches a previous-tool wrapper (the 'bouncer' case) that path-equality couldn't distinguish."
```

---

## Task 3: doctor uses pmsurvey for host survey AND symlink classification

**Files:**
- Modify: `cmd/veto/doctor.go`
- Test:   `cmd/veto/doctor_wrapper_classify_test.go`

This task rewires doctor's Phase-2 host survey to consume `pmsurvey.PathsFor` and `pmsurvey.ClassifySymlink`. Two correctness wins:

1. The state-drift loop's "is the target string `veto`?" substring check is replaced by hash-verified classification. A foreign wrapper at `w.Path` no longer reads as "subverted" — it gets its own diagnosis with a target path the user can act on.
2. The Phase-2 host survey calls `pmsurvey.PathsFor(pm)` (so we delete `surveyWrappablePaths` and `isShimDirForSurvey` from doctor.go — they're in pmsurvey now), and classifies each discovered path with `pmsurvey.ClassifySymlink`. Each classification maps to a distinct doctor row:

   - `ClassReal` not in `coveredByState` → existing WARN ("NOT wrapped — run veto install-wrappers")
   - `ClassReal` in `coveredByState` → already reported by Phase 1, skip
   - `ClassOursByPath` / `ClassOursByHash` → PASS (existing emit; carry the resolved target in the detail for `ClassOursByHash` so the user sees veto resolved by hash)
   - `ClassBrokenSymlink` → FAIL ("broken symlink to %s — likely a previous wrapper tool's leftover")
   - `ClassForeignWrapper` → FAIL ("symlink to %s, which is not the veto binary — a foreign wrapper from another tool is installed at this path")

- [ ] **Step 1: Rewire `checkWrappers`'s state-drift loop**

In `cmd/veto/doctor.go`, find the Phase-1 state-drift block. The existing logic at roughly `doctor.go:768-778` reads:

```go
target, _ := os.Readlink(w.Path)
if !strings.Contains(target, "veto") {
    out = append(out, checkResult{
        status: statusFail,
        label:  "wrapper:" + w.PM,
        detail: fmt.Sprintf("%s points at %s, not veto — wrapper subverted", w.Path, target),
        ...
```

Replace with a `pmsurvey.ClassifySymlink` call. Add a local helper at the top of `checkWrappers` to build the `VetoIdentity` once (since it's used for every entry):

```go
import (
	// existing imports...
	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

// At the top of checkWrappers, after vetoPath is resolved:
var vetoID *pmsurvey.VetoIdentity
if vetoErr == nil {
	if id, err := pmsurvey.VetoIdentityFor(vetoPath); err == nil {
		vetoID = id
	} else {
		vetoErr = err
	}
}
```

Then replace the Readlink + substring check with:

```go
class, target, classErr := pmsurvey.ClassifySymlink(w.Path, vetoID)
if classErr != nil {
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + w.PM,
		detail: fmt.Sprintf("%s: classify error — %v", w.Path, classErr),
		howToFix: "Re-run `veto doctor` after resolving the I/O error; if the path is on an unusual filesystem, check permissions.",
	})
	continue
}
switch class {
case pmsurvey.ClassOursByPath, pmsurvey.ClassOursByHash:
	// fall through to the existing OriginalPath stat check below
case pmsurvey.ClassBrokenSymlink:
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + w.PM,
		detail: fmt.Sprintf("%s is a broken symlink to %s — wrapper target vanished (likely a previous wrapper tool's leftover)", w.Path, target),
		howToFix: "Delete the broken symlink. If a sibling `<path>.*-original` exists, restore it to the original name. Then re-run `veto install-wrappers`.",
	})
	continue
case pmsurvey.ClassForeignWrapper:
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + w.PM,
		detail: fmt.Sprintf("%s is a symlink to %s, which is not the veto binary — a foreign wrapper from another tool is installed at this path", w.Path, target),
		howToFix: "Delete the symlink. If a sibling `<path>.*-original` exists (e.g. `.bouncer-original`), restore it to the original name. Then re-run `veto install-wrappers`.",
	})
	continue
case pmsurvey.ClassReal:
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + w.PM,
		detail: fmt.Sprintf("%s is no longer a symlink — wrapper has been replaced by a real binary (likely after upgrade)", w.Path),
		howToFix: "Re-run `veto install-wrappers --force` to re-wrap.",
	})
	continue
}
```

The existing `OriginalPath` stat check after this switch stays as-is.

The earlier `info.Mode()&os.ModeSymlink == 0` early-out at roughly `doctor.go:760-766` can stay, but with the new classifier `ClassReal` covers the same case more uniformly. Keep both for now — the classifier short-circuits to `ClassReal` immediately when the file isn't a symlink, so the cost is negligible and the explicit early-out is still readable. **No code change beyond the substring-check replacement** in this Step.

- [ ] **Step 2: Rewire Phase 2's host survey to use `pmsurvey.PathsFor`**

At `doctor.go:815`:

```go
locations := surveyWrappablePaths(pm)
```

Replace with:

```go
locations := pmsurvey.PathsFor(pm)
```

Inside the loop, replace the `isAlreadyOursWrap(path, vetoPath)` check (around `doctor.go:830`) with a classification switch:

```go
class, target, classErr := pmsurvey.ClassifySymlink(path, vetoID)
if classErr != nil {
	out = append(out, checkResult{
		status: statusWarn,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s: classify error — %v", path, classErr),
		howToFix: "Re-run `veto doctor` after resolving the I/O error.",
	})
	pmHadDiscovery = true
	continue
}
pmHadDiscovery = true
switch class {
case pmsurvey.ClassOursByPath:
	out = append(out, checkResult{
		status: statusPass,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s (wrapped, original at %s%s)", path, path, wrapperSuffix),
	})
	continue
case pmsurvey.ClassOursByHash:
	out = append(out, checkResult{
		status: statusPass,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s (wrapped via hash-identified veto at %s, original at %s%s)", path, target, path, wrapperSuffix),
	})
	continue
case pmsurvey.ClassBrokenSymlink:
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s is a broken symlink to %s — likely a previous wrapper tool's leftover", path, target),
		howToFix: "Delete the broken symlink. If a sibling `<path>.*-original` exists, restore it. Then re-run `veto install-wrappers`.",
	})
	continue
case pmsurvey.ClassForeignWrapper:
	out = append(out, checkResult{
		status: statusFail,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s is a symlink to %s — foreign wrapper, not veto", path, target),
		howToFix: "Delete the symlink. If a sibling `<path>.*-original` exists, restore it. Then re-run `veto install-wrappers`.",
	})
	continue
case pmsurvey.ClassReal:
	// Fall through to existing WARN "NOT wrapped" emit below.
}
if !anyUnwrappedFound {
	firstUnwrappedPM = pm
}
anyUnwrappedFound = true
out = append(out, checkResult{
	status:   statusWarn,
	label:    "wrapper:" + pm,
	detail:   fmt.Sprintf("%s (NOT wrapped — run veto install-wrappers)", path),
	howToFix: "Run `veto install-wrappers` to wrap this binary so absolute-path invocations route through veto.",
})
```

- [ ] **Step 3: Delete the now-unused locals in doctor.go**

Delete:
- `surveyWrappablePaths` (entire function — moved to pmsurvey)
- `isShimDirForSurvey` (entire function — moved to pmsurvey)
- `globToolVersionBinDirs` / `globVersionBinDirs` in doctor.go IF they're only used by the survey (check with `grep -n`). They likely are.

If anything in doctor.go still uses them after the rewire, leave them and add a `@@TODO` comment noting the duplication for a future follow-up (then remove the `@@TODO` before the commit — per CLAUDE.md, no `@@TODO` in shipped commits).

- [ ] **Step 4: Write the doctor classification tests**

Create `cmd/veto/doctor_wrapper_classify_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// findResult locates the checkResult for the given label substring in
// the doctor's output. Test helper only.
func findResult(t *testing.T, results []checkResult, labelSub, detailSub string) checkResult {
	t.Helper()
	for _, r := range results {
		if strings.Contains(r.label, labelSub) && strings.Contains(r.detail, detailSub) {
			return r
		}
	}
	var summary []string
	for _, r := range results {
		summary = append(summary, r.label+": "+r.detail)
	}
	t.Fatalf("no result matching label=%q detail=%q; got %s", labelSub, detailSub, strings.Join(summary, " | "))
	return checkResult{}
}

// TestCheckWrappers_BrokenSymlinkAtSurveyedPath verifies that a broken
// symlink found during the Phase-2 host survey produces a FAIL line
// distinct from the generic "NOT wrapped" WARN. The reproducer is the
// "bouncer leftover" scenario: a symlink at a known PM path whose
// target binary was removed when a previous wrapper tool was
// uninstalled.
func TestCheckWrappers_BrokenSymlinkAtSurveyedPath(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	// Plant a fake "veto" binary so VetoIdentity can build.
	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto"), 0o755))
	t.Setenv("VETO_BINARY_FOR_TEST", vetoBin) // doctor.go must honor this when resolveVetoBinary is testable; if it isn't, see "Note" below

	// Plant a broken symlink at a $PATH dir for "cargo" (the bouncer case).
	pathDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(pathDir, 0o755))
	brokenSym := filepath.Join(pathDir, "cargo")
	require.NoError(t, os.Symlink(filepath.Join(tmp, "vanished-bouncer"), brokenSym))
	t.Setenv("PATH", pathDir)
	t.Setenv("HOME", tmp) // ensure mise/asdf globs hit empty dirs

	cfg := config{CacheDir: cacheDir}
	results := checkWrappers(cfg)

	r := findResult(t, results, "wrapper:cargo", "broken symlink")
	require.Equal(t, statusFail, r.status, "broken symlink at a surveyed path must FAIL")
	require.Contains(t, r.detail, brokenSym)
}

// TestCheckWrappers_ForeignWrapperAtSurveyedPath verifies that a
// symlink to a non-veto binary at a known PM path is classified as a
// foreign wrapper (FAIL with a specific diagnosis), not as a generic
// "NOT wrapped" WARN.
func TestCheckWrappers_ForeignWrapperAtSurveyedPath(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto v1"), 0o755))
	t.Setenv("VETO_BINARY_FOR_TEST", vetoBin)

	// A foreign wrapper binary with content distinct from veto.
	foreignBin := filepath.Join(tmp, "bouncer")
	require.NoError(t, os.WriteFile(foreignBin, []byte("bouncer v2"), 0o755))

	pathDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(pathDir, 0o755))
	foreignSym := filepath.Join(pathDir, "bun")
	require.NoError(t, os.Symlink(foreignBin, foreignSym))
	t.Setenv("PATH", pathDir)
	t.Setenv("HOME", tmp)

	cfg := config{CacheDir: cacheDir}
	results := checkWrappers(cfg)

	r := findResult(t, results, "wrapper:bun", "foreign wrapper")
	require.Equal(t, statusFail, r.status)
	require.Contains(t, r.detail, foreignSym)
	require.Contains(t, r.detail, foreignBin)
}
```

**Note on `VETO_BINARY_FOR_TEST`:** if `resolveVetoBinary()` doesn't currently honor a test-only override, add a tiny seam: at the top of `resolveVetoBinary`, check `os.Getenv("VETO_BINARY_FOR_TEST")` and return it (with a stat check that confirms it exists). Use a `@@TODO`-free comment explaining it's a test-only seam and only used when the env var is set. If you'd rather not add a production-code seam, factor the doctor checks into a `checkWrappersWith(cfg, vetoID)` so tests can pass a constructed `VetoIdentity` directly; that's the cleaner factoring. **Pick the factoring path** if at all possible.

- [ ] **Step 5: Run and commit**

```bash
veto go build ./... && veto go test ./cmd/veto/... -count=1 -run TestCheckWrappers
```

```bash
git add cmd/veto/doctor.go cmd/veto/doctor_wrapper_classify_test.go
git commit -m "feat(doctor): classify wrapper paths via pmsurvey (broken / foreign / ours)" -m "Phase-1 state-drift loop and Phase-2 host survey now agree on classification, with FAIL lines for broken symlinks and foreign wrappers (the 'bouncer leftover' case) distinct from the generic 'NOT wrapped' WARN. Discovery extracted into pmsurvey so install-wrappers and doctor cannot drift again."
```

---

## Task 4: install-wrappers uses pmsurvey + surfaces broken / foreign as visible SKIPs

**Files:**
- Modify: `cmd/veto/install_wrappers.go`
- Test:   `cmd/veto/install_wrappers_classify_test.go`

Two changes:

1. `discoverWrapCandidates` walks the well-known roots AND `$PATH` (via `pmsurvey.PathsFor`), so install-wrappers stops being blind to `~/.cargo/bin` and friends. Bug B closed.
2. The candidate include-predicate (`isWrappableTarget || isAlreadyOursWrap`) is replaced by a classifier call that emits a **visible SKIP** (not a silent drop) for broken symlinks and foreign wrappers. `applyWrapper` gains two new `wrapAction` constants for these cases. Bug A closed.

- [ ] **Step 1: Replace `discoverWrapCandidates` body to use `pmsurvey.PathsFor`**

Read the current `discoverWrapCandidates` (`cmd/veto/install_wrappers.go:476-544`), then replace its body with:

```go
func discoverWrapCandidates(opts wrapperFlags, vetoPath string) ([]wrapCandidate, error) {
	candidates := []wrapCandidate{}
	pmFilter := func(name string) bool {
		if len(opts.only) == 0 {
			return true
		}
		_, ok := opts.only[name]
		return ok
	}

	id, err := pmsurvey.VetoIdentityFor(vetoPath)
	if err != nil {
		return nil, errors.With(err, "discover wrap candidates")
	}

	seen := map[string]struct{}{}
	add := func(c wrapCandidate) {
		if _, dup := seen[c.path]; dup {
			return
		}
		seen[c.path] = struct{}{}
		candidates = append(candidates, c)
	}

	for _, pm := range wrappedManagers {
		if !pmFilter(pm) {
			continue
		}
		for _, path := range pmsurvey.PathsFor(pm) {
			class, target, classErr := pmsurvey.ClassifySymlink(path, id)
			if classErr != nil {
				// I/O failure on a candidate is not a discovery error —
				// applyWrapper will surface it per-candidate. Include
				// the path so the FAIL line emits.
				add(wrapCandidate{path: path, pm: pm, source: sourceFor(path), class: pmsurvey.ClassReal, target: ""})
				continue
			}
			add(wrapCandidate{path: path, pm: pm, source: sourceFor(path), class: class, target: target})
		}
	}

	// 7) User-supplied --dir entries. These are NOT discovered via
	//    pmsurvey (the user knows where they live), but they still
	//    benefit from classification so applyWrapper handles broken /
	//    foreign cases uniformly.
	for _, dir := range opts.dirs {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			class, target, classErr := pmsurvey.ClassifySymlink(p, id)
			if classErr != nil {
				continue // a --dir entry that doesn't exist is a no-op, not an error
			}
			add(wrapCandidate{path: p, pm: pm, source: "user", class: class, target: target})
		}
	}

	return candidates, nil
}

// sourceFor returns a short label describing where a path was
// discovered, used for diagnostic output ("homebrew" / "mise" / etc.).
// Heuristic based on path substrings — exact match is impossible since
// pmsurvey returns flat paths.
func sourceFor(path string) string {
	switch {
	case strings.HasPrefix(path, "/opt/homebrew/"), strings.HasPrefix(path, "/usr/local/bin/"):
		return "homebrew"
	case strings.Contains(path, "/.local/share/mise/installs/"):
		return "mise"
	case strings.Contains(path, "/.asdf/installs/"):
		return "asdf"
	case strings.Contains(path, "/.pyenv/versions/"):
		return "pyenv"
	case strings.Contains(path, "/.nvm/versions/node/"):
		return "nvm"
	case strings.Contains(path, "/.bun/bin"):
		return "bun"
	case strings.Contains(path, "/.cargo/bin"):
		return "cargo"
	case strings.HasPrefix(path, "/usr/bin/"), strings.HasPrefix(path, "/usr/sbin/"):
		return "system"
	default:
		return "path"
	}
}
```

Note: `wrapCandidate` gains two new fields, `class pmsurvey.Classification` and `target string`. Find the struct definition and add:

```go
type wrapCandidate struct {
	path   string
	pm     string
	source string
	class  pmsurvey.Classification // result of pmsurvey.ClassifySymlink at discovery time
	target string                  // resolved target when class != ClassReal; "" otherwise
}
```

- [ ] **Step 2: Add new wrap actions and wire them into `applyWrapper`**

Find the `wrapAction` definitions in `install_wrappers.go`. Add:

```go
const (
	// ... existing constants ...
	wrapperActionSkipBrokenSymlink wrapAction = "skip-broken-symlink"
	wrapperActionSkipForeignWrapper wrapAction = "skip-foreign-wrapper"
)
```

At the top of `applyWrapper`, **before** the existing "already wrapped?" check, dispatch on the candidate's classification:

```go
func applyWrapper(c wrapCandidate, vetoPath string, dryRun, force bool) (wrapAction, error) {
	switch c.class {
	case pmsurvey.ClassBrokenSymlink:
		return wrapperActionSkipBrokenSymlink, nil
	case pmsurvey.ClassForeignWrapper:
		// Without --force, leave foreign wrappers in place — overwriting
		// them silently could break whatever installed them. The skip
		// emits a visible line with the target so the user can decide.
		if !force {
			return wrapperActionSkipForeignWrapper, nil
		}
		// With --force, treat it like the "not ours, clobber" path.
		// Fall through to the regular wrap path; the existing rename
		// dance moves the foreign symlink to .veto-original.
	}
	// ... existing body ...
}
```

In `runInstallWrappersWithStats`, add cases to the switch over `action`:

```go
case action == wrapperActionSkipBrokenSymlink:
	stats.skippedBroken++
	fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — broken symlink to %s (likely a previous wrapper tool's leftover; restore `<path>.*-original` if present, then re-run)\n",
		c.pm, c.path, c.target)
	if !alreadyHad && !opts.dryRun {
		state.remove(c.path)
		if rbErr := saveWrapperState(cfg, state); rbErr != nil {
			logger.Warn().Err(rbErr).Str("path", c.path).Msg("WAL rollback save failed")
		}
	}
case action == wrapperActionSkipForeignWrapper:
	stats.skippedForeign++
	fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — symlink to %s, which is not the veto binary (foreign wrapper; pass --force to overwrite)\n",
		c.pm, c.path, c.target)
	if !alreadyHad && !opts.dryRun {
		state.remove(c.path)
		if rbErr := saveWrapperState(cfg, state); rbErr != nil {
			logger.Warn().Err(rbErr).Str("path", c.path).Msg("WAL rollback save failed")
		}
	}
```

Add the two new counters to `wrapperStats`:

```go
type wrapperStats struct {
	wrapped           int
	reconciled        int
	alreadyOurs       int
	wouldWrap         int
	skippedUnwritable int
	skippedBroken     int  // new
	skippedForeign    int  // new
	failed            int
}
```

Update the summary line at the bottom of `runInstallWrappersWithStats`:

```go
fmt.Printf("\nSummary: %d wrapped, %d reconciled, %d already-ours, %d would-wrap, %d skipped (needs sudo), %d skipped (broken symlink), %d skipped (foreign wrapper), %d failed\n",
	stats.wrapped, stats.reconciled, stats.alreadyOurs, stats.wouldWrap, stats.skippedUnwritable,
	stats.skippedBroken, stats.skippedForeign, stats.failed)
```

- [ ] **Step 3: Update `isWrappableTarget` and `isAlreadyOursWrap` to short-circuit on classification**

These helpers are still called from a few places (the `include` predicate that decided whether to emit a candidate). With the new discoverWrapCandidates pre-classifying, those call sites are obsolete — search for them and either delete the helpers (if no remaining callers) or simplify them.

```bash
grep -n 'isWrappableTarget\|isAlreadyOursWrap' cmd/veto/install_wrappers.go cmd/veto/install_wrappers_test.go
```

If the helpers are still referenced in tests, keep them but mark their semantics in a doc comment: they're now used only by legacy paths (the `--dir` discovery currently uses them) — leave them. If they're not referenced anywhere outside the file, delete them along with `pointsAtVeto` IF that helper is also orphaned.

**Be conservative: if a helper has any caller, keep it.** A delete-and-rebuild risks breaking subtle invariants this task isn't scoped to verify.

- [ ] **Step 4: Write the install-wrappers classification tests**

Create `cmd/veto/install_wrappers_classify_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestInstallWrappers_BrokenSymlinkIsVisibleSkip plants a broken
// symlink at a known PM path and asserts install-wrappers does NOT
// silently drop it — instead emitting a SKIP line with the diagnostic
// target. This is Bug A from the design plan.
func TestInstallWrappers_BrokenSymlinkIsVisibleSkip(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto"), 0o755))
	t.Setenv("VETO_BINARY_FOR_TEST", vetoBin) // same seam as Task 3

	// Mise install layout with a broken symlink for `bun`.
	miseBin := filepath.Join(tmp, ".local", "share", "mise", "installs", "bun", "1.0.0", "bin")
	require.NoError(t, os.MkdirAll(miseBin, 0o755))
	brokenSym := filepath.Join(miseBin, "bun")
	require.NoError(t, os.Symlink(filepath.Join(tmp, "vanished-bouncer"), brokenSym))
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", "")

	cfg := config{CacheDir: cacheDir}
	// Capture stderr to assert the SKIP line emits.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	rc := runInstallWrappers(zerolog.Nop(), cfg, []string{"--only", "bun"})
	require.NoError(t, w.Close())

	var buf strings.Builder
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	out := buf.String()
	t.Logf("stderr:\n%s", out)
	require.Equal(t, exitOK, rc)
	require.Contains(t, out, "broken symlink", "broken symlink must emit a visible SKIP line")
	require.Contains(t, out, brokenSym)
}

// TestInstallWrappers_ForeignWrapperWithoutForceIsSkip plants a
// symlink to a non-veto binary and asserts install-wrappers SKIPs it
// (without --force) instead of either silently dropping it or
// clobbering it.
func TestInstallWrappers_ForeignWrapperWithoutForceIsSkip(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto v1"), 0o755))
	t.Setenv("VETO_BINARY_FOR_TEST", vetoBin)

	foreignBin := filepath.Join(tmp, "bouncer")
	require.NoError(t, os.WriteFile(foreignBin, []byte("bouncer v2"), 0o755))

	miseBin := filepath.Join(tmp, ".local", "share", "mise", "installs", "bun", "1.0.0", "bin")
	require.NoError(t, os.MkdirAll(miseBin, 0o755))
	foreignSym := filepath.Join(miseBin, "bun")
	require.NoError(t, os.Symlink(foreignBin, foreignSym))
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", "")

	cfg := config{CacheDir: cacheDir}
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	rc := runInstallWrappers(zerolog.Nop(), cfg, []string{"--only", "bun"})
	require.NoError(t, w.Close())

	var buf strings.Builder
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	out := buf.String()
	t.Logf("stderr:\n%s", out)
	require.Equal(t, exitOK, rc)
	require.Contains(t, out, "foreign wrapper", "foreign wrapper without --force must emit a visible SKIP line")
	require.Contains(t, out, "--force")
}
```

- [ ] **Step 5: Run and commit**

```bash
veto go build ./... && veto go test ./cmd/veto/... -count=1 -run TestInstallWrappers
```

```bash
git add cmd/veto/install_wrappers.go cmd/veto/install_wrappers_classify_test.go
git commit -m "feat(install-wrappers): surface broken / foreign symlinks; walk PATH" -m "Discovery uses pmsurvey.PathsFor (gains \$PATH walk; closes Bug B). isWrappableTarget's silent-drop on broken symlinks replaced by classification-driven SKIP actions with visible diagnostic lines (closes Bug A). Foreign wrappers without --force are SKIPped, not silently overwritten."
```

---

## Task 5: end-to-end smoke + final test sweep

**Files:** (verification only — no edits)

- [ ] **Step 1: Full test suite**

```bash
veto go test ./... -count=1
```

Expected: green except for any pre-existing failures unrelated to this work. If a doctor or install_wrappers test that ISN'T one of the new tests fails, investigate — that's likely a regression in the rewire.

- [ ] **Step 2: `gofmt` and `vet`**

```bash
veto gofmt -l . && veto go vet ./...
```

Both must be silent.

- [ ] **Step 3: Manual smoke against a synthesized poisoned tree**

```bash
TMPDIR=$(mktemp -d -t vetowsmoke)
mkdir -p "$TMPDIR/cache" "$TMPDIR/mise/bun/1.0/bin"
ln -s /no/such/thing "$TMPDIR/mise/bun/1.0/bin/bun"
HOME="$TMPDIR" XDG_CACHE_HOME="$TMPDIR/cache" PATH="" veto go run ./cmd/veto install-wrappers --only bun 2>&1 | head -10
```

Expected: a line containing `SKIP` and `broken symlink` and the planted path.

(Per CLAUDE.md the veto hook may rewrite or reject this; use `veto bash -c '...'` only if the hook permits, otherwise run the pieces individually.)

- [ ] **Step 4: Commit anything trivial that drifted (formatting)**

```bash
git status
```

If clean, stop. Otherwise commit formatting drift under `chore:`.

---

## Self-Review

**Bug coverage:**

- Bug A (broken-symlink silent skip) — Task 4 adds `wrapperActionSkipBrokenSymlink` with a visible stderr line. Tested by `TestInstallWrappers_BrokenSymlinkIsVisibleSkip`.
- Bug B (discovery asymmetry) — Task 1 centralises discovery in `pmsurvey.PathsFor`; Task 3 and Task 4 both call it. Tested by `TestPathsForFindsWellKnownAndPathEntries`.
- Doctor classifies broken / foreign distinct from "NOT wrapped" — Task 3 wires `ClassifySymlink` into both phases. Tested by `TestCheckWrappers_BrokenSymlinkAtSurveyedPath` and `TestCheckWrappers_ForeignWrapperAtSurveyedPath`.
- Hash verification — Task 2 adds `ClassOursByHash` and the `VetoIdentity` machinery. Tested by `TestClassifySymlinkOursByHash`.

**Placeholder scan:** No `TBD` / `TODO` / `implement later` outside legitimate descriptive comments. The `VETO_BINARY_FOR_TEST` seam in Tasks 3 and 4 is conditional — the plan calls out "pick the factoring path if at all possible" so the executor surfaces it as a real choice, not a placeholder.

**Type consistency:** `pmsurvey.Classification` is the single enum used in `wrapCandidate.class`, `applyWrapper`'s switch, and doctor's switches. `VetoIdentity.Hash()` returns `[32]byte` consistently. `ClassifySymlink` signature `(string, *VetoIdentity) (Classification, string, error)` is used identically in three call sites.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-06-10-wrapper-discovery-robustness.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks. 5 tasks; orchestrator stays clean.

**2. Single subagent inline (project-preferred per CLAUDE.md)** — One agent executes tasks 1–5 sequentially, committing per task; you and I review at the end.

Which approach?
