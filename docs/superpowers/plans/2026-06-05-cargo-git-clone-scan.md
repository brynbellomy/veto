# Cargo git-install clone-and-scan — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `cargo install --git <url>` and `cargo add --git <url>` succeed when their resolved crates.io dependencies are clean — by cloning the repo to a temp dir, regenerating the lockfile to mirror cargo's own resolution, gating the transitive registry deps, and pinning the real install to the exact scanned commit — instead of the current unconditional `OpaqueRemote` refusal.

**Architecture:** A new optional `OpaqueRemoteResolver` capability (mirroring `ResolverPreScanner`/`ProjectPreflighter`) keeps the cargo package pure-argv: it returns a plan describing the clone + resolve. The CLI orchestrator (`cmd/veto/main.go`) executes the plan — clone via `git`, resolve via the real `cargo`, expand the resulting `Cargo.lock` with the existing `cargolock.Expander`, keep only registry-eligible installs, and pin the argv to the scanned `HEAD` commit. Opaque-git installs are expanded into their registry deps *before* `gate.Evaluate`, so a clean tree allows the (pinned) install to proceed; any failure fails closed.

**Tech Stack:** Go, `os/exec` (`git`, `cargo`), `github.com/pelletier/go-toml/v2` (already used by `cargolock`), `github.com/brynbellomy/go-utils/errors`, `zerolog`, `testify`.

**Spec:** `docs/superpowers/specs/2026-06-05-cargo-git-clone-scan-design.md`

---

## File Structure

- **Modify** `internal/packagemanager/packagemanager.go` — add `OpaqueRemoteResolver` interface + `OpaqueRemoteResolvePlan` struct (Task 1).
- **Modify** `internal/packagemanager/cargo/cargo.go` — implement `OpaqueRemoteResolve` and `PinResolvedRevision` + the `hasLockedFlag` helper and interface assertion (Tasks 2, 3).
- **Modify** `internal/packagemanager/cargo/cargo_test.go` — unit tests for both new methods (Tasks 2, 3).
- **Create** `cmd/veto/opaquegit.go` — orchestrator: `filterRegistryInstalls`, `cloneAndCaptureCommit`, `resolveOpaqueGitInstalls`, `applyOpaqueGitResolution`, `hasOpaqueInstall`, the `opaqueGitDeps`/`opaqueGitResolution` types, and the `opaqueResolveTimeout` constant (Tasks 4, 5, 6).
- **Create** `cmd/veto/opaquegit_test.go` — pure + integration tests for the orchestrator (Tasks 4, 5, 6).
- **Modify** `cmd/veto/main.go` — wire `applyOpaqueGitResolution` into `runGate` and print the success note (Task 7).
- **Modify** `README.md`, `TODO.md` — document that cargo git installs now clone-and-scan (Task 8).

Keeping the orchestrator in a new `cmd/veto/opaquegit.go` (rather than growing `main.go`, already ~1400 lines) isolates the git/cargo I/O behind testable functions.

---

## Task 1: Capability interface + plan type

**Files:**
- Modify: `internal/packagemanager/packagemanager.go` (append after the `ProjectPreflighter` interface, ~line 224)

This task adds type declarations only — there is no behavior to unit-test yet (the first behavioral test lands in Task 2, where cargo implements the interface).

- [ ] **Step 1: Add the interface and plan struct**

Append to `internal/packagemanager/packagemanager.go`, immediately after the `ProjectPreflighter` interface block:

```go
// OpaqueRemoteResolver is an optional capability for package managers that can
// turn an opaque git spec (which the gate otherwise refuses unconditionally)
// into a scannable registry dependency set, by cloning the repository and
// re-running the resolver — without compiling the crate or executing any
// project code. Package managers that do not implement it keep the
// unconditional opaque refusal.
//
// The two methods are pure (argv in, data out). The CLI orchestrator performs
// all filesystem and process I/O, consistent with the PackageManager contract.
type OpaqueRemoteResolver interface {
	// OpaqueRemoteResolve returns a plan for cloning + resolving the opaque git
	// spec in args, or (zero, false) when args name no resolvable git spec.
	OpaqueRemoteResolve(args []string) (OpaqueRemoteResolvePlan, bool)

	// PinResolvedRevision rewrites argv so the real install targets exactly
	// `revision` — the commit the clone-scan vetted. It removes any conflicting
	// ref selector (e.g. cargo's --branch/--tag/--rev) and appends the pin.
	// Pure; no I/O. Idempotent against an already-pinned revision.
	PinResolvedRevision(args []string, revision string) []string
}

// OpaqueRemoteResolvePlan is pure data describing how to turn one opaque git
// spec into a scannable lockfile. The CLI orchestrator executes it: it clones
// GitURL, checks out Ref, runs ResolveArgs against the real package-manager
// binary inside the clone, then expands ManifestRefs (relative to the clone
// dir) to discover the resolved dependency tree.
type OpaqueRemoteResolvePlan struct {
	// GitURL is the remote to clone.
	GitURL string

	// Ref is the tag, branch, or revision to check out. Empty means the
	// remote's default branch HEAD.
	Ref string

	// RefIsRevision is true when Ref is a commit-ish that cannot be reached by
	// a shallow --branch clone. The orchestrator full-clones and `git checkout`s
	// it; otherwise it shallow-clones (with --branch Ref when Ref is set).
	RefIsRevision bool

	// ResolveArgs runs against the REAL package-manager binary inside the clone
	// dir to (re)generate or validate the lockfile. Must not compile or execute
	// project code (e.g. cargo's `generate-lockfile` / `fetch --locked`).
	ResolveArgs []string

	// ManifestRefs are the lockfiles to expand after ResolveArgs, with paths
	// relative to the clone dir.
	ManifestRefs []ManifestRef
}
```

- [ ] **Step 2: Verify the package compiles**

Run: `go build ./internal/packagemanager/...`
Expected: builds cleanly, no output.

- [ ] **Step 3: Commit**

```bash
git add internal/packagemanager/packagemanager.go
git commit -m "feat(packagemanager): add OpaqueRemoteResolver capability"
```

---

## Task 2: Cargo `OpaqueRemoteResolve`

**Files:**
- Modify: `internal/packagemanager/cargo/cargo.go`
- Test: `internal/packagemanager/cargo/cargo_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/packagemanager/cargo/cargo_test.go`:

```go
func TestOpaqueRemoteResolve(t *testing.T) {
	m := cargo.New()

	t.Run("install --git produces a generate-lockfile plan", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "my-crate", "--git", "https://github.com/example/my-crate"})
		require.True(t, ok)
		require.Equal(t, "https://github.com/example/my-crate", plan.GitURL)
		require.Empty(t, plan.Ref)
		require.False(t, plan.RefIsRevision)
		require.Equal(t, []string{"generate-lockfile", "--manifest-path", "Cargo.toml"}, plan.ResolveArgs)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, plan.ManifestRefs)
	})

	t.Run("add --git with --branch is a non-revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"add", "my-crate", "--git", "https://x/y", "--branch", "main"})
		require.True(t, ok)
		require.Equal(t, "main", plan.Ref)
		require.False(t, plan.RefIsRevision)
	})

	t.Run("--tag is a non-revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--tag", "v1.2.3"})
		require.True(t, ok)
		require.Equal(t, "v1.2.3", plan.Ref)
		require.False(t, plan.RefIsRevision)
	})

	t.Run("--rev is a revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--rev", "abc123"})
		require.True(t, ok)
		require.Equal(t, "abc123", plan.Ref)
		require.True(t, plan.RefIsRevision)
	})

	t.Run("--locked validates the committed lock instead of regenerating", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--locked"})
		require.True(t, ok)
		require.Equal(t, []string{"fetch", "--locked", "--manifest-path", "Cargo.toml"}, plan.ResolveArgs)
	})

	t.Run("non-git and non-install/add return false", func(t *testing.T) {
		_, ok := m.OpaqueRemoteResolve([]string{"install", "ripgrep"})
		require.False(t, ok)
		_, ok = m.OpaqueRemoteResolve([]string{"add", "serde"})
		require.False(t, ok)
		_, ok = m.OpaqueRemoteResolve([]string{"build", "--git", "https://x/y"})
		require.False(t, ok)
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/packagemanager/cargo/ -run TestOpaqueRemoteResolve`
Expected: FAIL — `m.OpaqueRemoteResolve undefined (type *cargo.Manager has no field or method OpaqueRemoteResolve)`.

- [ ] **Step 3: Implement the method**

In `internal/packagemanager/cargo/cargo.go`, add the interface assertion next to the existing ones (~line 58):

```go
var _ packagemanager.OpaqueRemoteResolver = (*Manager)(nil)
```

Then add the method and helper (place after `ProjectPreflight`, ~line 114):

```go
// OpaqueRemoteResolve implements packagemanager.OpaqueRemoteResolver for
// `cargo install --git` and `cargo add --git`. It returns a plan to clone the
// git crate and regenerate (or, under --locked/--frozen/--offline, validate)
// its lockfile so the resolved crates.io dependencies can be gated. Other
// verbs and non-git specs return false and keep the default opaque refusal.
func (Manager) OpaqueRemoteResolve(args []string) (packagemanager.OpaqueRemoteResolvePlan, bool) {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok || (verb != "install" && verb != "add") {
		return packagemanager.OpaqueRemoteResolvePlan{}, false
	}
	gitURL, ok := firstFlagValue(rest, "--git")
	if !ok || gitURL == "" {
		return packagemanager.OpaqueRemoteResolvePlan{}, false
	}

	plan := packagemanager.OpaqueRemoteResolvePlan{
		GitURL: gitURL,
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		},
	}

	// cargo accepts at most one of --rev/--tag/--branch; --rev is the only one
	// that is not reachable by a shallow --branch clone.
	if rev, ok := firstFlagValue(rest, "--rev"); ok && rev != "" {
		plan.Ref, plan.RefIsRevision = rev, true
	} else if tag, ok := firstFlagValue(rest, "--tag"); ok && tag != "" {
		plan.Ref = tag
	} else if branch, ok := firstFlagValue(rest, "--branch"); ok && branch != "" {
		plan.Ref = branch
	}

	// Mirror cargo's own resolution: by default `cargo install --git` ignores a
	// committed Cargo.lock and re-resolves to the latest semver-compatible
	// versions. Under --locked/--frozen/--offline cargo honors the committed
	// lock, so we validate it (fetch --locked errors on a stale lock) rather
	// than blindly trusting it.
	if hasLockedFlag(rest) {
		plan.ResolveArgs = []string{"fetch", "--locked", "--manifest-path", "Cargo.toml"}
	} else {
		plan.ResolveArgs = []string{"generate-lockfile", "--manifest-path", "Cargo.toml"}
	}
	return plan, true
}

// hasLockedFlag reports whether argv requests cargo's committed-lockfile mode.
// Scanning stops at the POSIX "--" separator.
func hasLockedFlag(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		switch a {
		case "--locked", "--frozen", "--offline":
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/packagemanager/cargo/ -run TestOpaqueRemoteResolve`
Expected: PASS (ok).

- [ ] **Step 5: Commit**

```bash
git add internal/packagemanager/cargo/cargo.go internal/packagemanager/cargo/cargo_test.go
git commit -m "feat(cargo): OpaqueRemoteResolve plan for install/add --git"
```

---

## Task 3: Cargo `PinResolvedRevision`

**Files:**
- Modify: `internal/packagemanager/cargo/cargo.go`
- Test: `internal/packagemanager/cargo/cargo_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/packagemanager/cargo/cargo_test.go`:

```go
func TestPinResolvedRevision(t *testing.T) {
	m := cargo.New()
	const sha = "0123456789abcdef0123456789abcdef01234567"

	t.Run("appends --rev when no ref selector present", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("drops a --branch space-form selector", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--branch", "main"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("drops a --tag=value form selector", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"add", "c", "--git", "https://x/y", "--tag=v1"}, sha)
		require.Equal(t, []string{"add", "c", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("is idempotent against an existing --rev", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--rev", "short"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("preserves unrelated flags and inserts --rev before a -- terminator", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--features", "a", "--", "passthrough"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--features", "a", "--rev", sha, "--", "passthrough"}, out)
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/packagemanager/cargo/ -run TestPinResolvedRevision`
Expected: FAIL — `m.PinResolvedRevision undefined`.

- [ ] **Step 3: Implement the method**

Add to `internal/packagemanager/cargo/cargo.go` (after `OpaqueRemoteResolve`):

```go
// gitRefSelectorFlags are the mutually-exclusive cargo git ref selectors that
// PinResolvedRevision strips before pinning an exact commit.
var gitRefSelectorFlags = map[string]struct{}{
	"--branch": {},
	"--tag":    {},
	"--rev":    {},
}

// PinResolvedRevision implements packagemanager.OpaqueRemoteResolver. It rewrites
// argv so the real `cargo install`/`cargo add` targets exactly `revision`: any
// --branch/--tag/--rev selector is removed (cargo rejects more than one) and
// `--rev <revision>` is appended. Tokens after a POSIX "--" are preserved and
// the pin is inserted before them.
func (Manager) PinResolvedRevision(args []string, revision string) []string {
	out := make([]string, 0, len(args)+2)
	var tail []string
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok == "--" {
			tail = args[i:]
			break
		}
		if name, _, isEq := strings.Cut(tok, "="); isEq {
			if _, drop := gitRefSelectorFlags[name]; drop {
				i++
				continue
			}
			out = append(out, tok)
			i++
			continue
		}
		if _, drop := gitRefSelectorFlags[tok]; drop {
			if i+1 < len(args) {
				i += 2 // skip the flag and its value
			} else {
				i++
			}
			continue
		}
		out = append(out, tok)
		i++
	}
	out = append(out, "--rev", revision)
	out = append(out, tail...)
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/packagemanager/cargo/ -run TestPinResolvedRevision`
Expected: PASS (ok).

- [ ] **Step 5: Run the whole cargo package to confirm no regressions**

Run: `go test ./internal/packagemanager/cargo/`
Expected: PASS (ok).

- [ ] **Step 6: Commit**

```bash
git add internal/packagemanager/cargo/cargo.go internal/packagemanager/cargo/cargo_test.go
git commit -m "feat(cargo): PinResolvedRevision to pin git installs to scanned commit"
```

---

## Task 4: `filterRegistryInstalls` pure helper

**Files:**
- Create: `cmd/veto/opaquegit.go`
- Test: `cmd/veto/opaquegit_test.go`

- [ ] **Step 1: Write the failing test**

Create `cmd/veto/opaquegit_test.go`:

```go
package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func TestFilterRegistryInstalls(t *testing.T) {
	in := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "serde", Version: "1.0.0"}},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "rootcrate", Version: "0.1.0"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evilgit", Version: "0.0.1"}, OpaqueRemote: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "", Version: ""}},
	}
	out := filterRegistryInstalls(in)
	require.Len(t, out, 1)
	require.Equal(t, "serde", out[0].Ref.Name)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/veto/ -run TestFilterRegistryInstalls`
Expected: FAIL — `undefined: filterRegistryInstalls`.

- [ ] **Step 3: Implement the helper**

Create `cmd/veto/opaquegit.go`:

```go
package main

import (
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// filterRegistryInstalls keeps only intel-eligible (registry) installs from a
// clone-scan's expanded lockfile, dropping LocalPath and OpaqueRemote nodes —
// the git root crate and any nested git dependencies. Those are the code the
// user explicitly chose to install; per the "registry deps only" scope they
// are accepted without a name lookup, and the registry crates they pull are
// what gets gated.
func filterRegistryInstalls(in []packagemanager.Install) []packagemanager.Install {
	out := make([]packagemanager.Install, 0, len(in))
	for _, ins := range in {
		if ins.LocalPath || ins.OpaqueRemote || ins.Ref.Name == "" {
			continue
		}
		out = append(out, ins)
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/veto/ -run TestFilterRegistryInstalls`
Expected: PASS (ok).

- [ ] **Step 5: Commit**

```bash
git add cmd/veto/opaquegit.go cmd/veto/opaquegit_test.go
git commit -m "feat(veto): filterRegistryInstalls helper for clone-scan output"
```

---

## Task 5: `cloneAndCaptureCommit`

**Files:**
- Modify: `cmd/veto/opaquegit.go`
- Test: `cmd/veto/opaquegit_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/veto/opaquegit_test.go`. Add these imports to the existing import block: `"context"`, `"os"`, `"os/exec"`, `"path/filepath"`, `"strings"`.

```go
// gitRun runs git in dir and fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// newTestCrateRepo creates a local git repo with a minimal Cargo.toml (no
// committed Cargo.lock) and returns its path (usable as a clone URL) and its
// HEAD commit SHA.
func newTestCrateRepo(t *testing.T) (repoPath, headSHA string) {
	t.Helper()
	repoPath = t.TempDir()
	gitRun(t, repoPath, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "Cargo.toml"),
		[]byte("[package]\nname = \"rootcrate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), 0o644))
	gitRun(t, repoPath, "add", ".")
	gitRun(t, repoPath, "commit", "-q", "-m", "init")
	headSHA = gitRun(t, repoPath, "rev-parse", "HEAD")
	return repoPath, headSHA
}

func TestCloneAndCaptureCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo, sha := newTestCrateRepo(t)

	plan := packagemanager.OpaqueRemoteResolvePlan{GitURL: repo}
	src, got, cleanup, err := cloneAndCaptureCommit(context.Background(), "git", plan)
	defer cleanup()
	require.NoError(t, err)
	require.Equal(t, sha, got)

	_, statErr := os.Stat(filepath.Join(src, "Cargo.toml"))
	require.NoError(t, statErr, "cloned working tree should contain Cargo.toml")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/veto/ -run TestCloneAndCaptureCommit`
Expected: FAIL — `undefined: cloneAndCaptureCommit`.

- [ ] **Step 3: Implement the function**

Add to `cmd/veto/opaquegit.go`. Extend the import block to:

```go
import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/packagemanager"
)
```

Then add:

```go
// cloneAndCaptureCommit clones plan.GitURL into a fresh temp dir, checks out
// the requested ref, and returns the clone's working-tree dir, the exact HEAD
// commit SHA that was checked out, and a cleanup func the caller MUST invoke.
// cleanup is always non-nil. `git clone` runs no remote hooks and we never
// recurse submodules, so the clone itself executes no project code.
func cloneAndCaptureCommit(ctx context.Context, gitPath string, plan packagemanager.OpaqueRemoteResolvePlan) (srcDir, sha string, cleanup func(), err error) {
	root, err := os.MkdirTemp("", "veto-cargo-git-*")
	if err != nil {
		return "", "", func() {}, errors.With(err, "create clone workdir")
	}
	cleanup = func() { _ = os.RemoveAll(root) }
	src := filepath.Join(root, "src")

	var cloneArgs []string
	switch {
	case plan.RefIsRevision:
		// A bare commit-ish is not reachable by --branch; full-clone then check out.
		cloneArgs = []string{"clone", plan.GitURL, src}
	case plan.Ref != "":
		cloneArgs = []string{"clone", "--depth", "1", "--branch", plan.Ref, plan.GitURL, src}
	default:
		cloneArgs = []string{"clone", "--depth", "1", plan.GitURL, src}
	}
	if err := runGitHardened(ctx, gitPath, "", cloneArgs); err != nil {
		cleanup()
		return "", "", func() {}, errors.With(err, "git clone").Set("url", plan.GitURL)
	}

	if plan.RefIsRevision {
		if err := runGitHardened(ctx, gitPath, src, []string{"checkout", "--detach", plan.Ref}); err != nil {
			cleanup()
			return "", "", func() {}, errors.With(err, "git checkout revision").Set("rev", plan.Ref)
		}
	}

	out, err := runGitOutput(ctx, gitPath, src, []string{"rev-parse", "HEAD"})
	if err != nil {
		cleanup()
		return "", "", func() {}, errors.With(err, "git rev-parse HEAD")
	}
	sha = strings.TrimSpace(out)
	if sha == "" {
		cleanup()
		return "", "", func() {}, errors.WithNew("git rev-parse produced an empty commit")
	}
	return src, sha, cleanup, nil
}

// gitHardenedEnv returns a sanitized environment for git invocations that fails
// fast on credential prompts instead of hanging on a private-repo auth challenge.
func gitHardenedEnv() []string {
	return append(sanitizedEnv(os.Environ()), "GIT_TERMINAL_PROMPT=0")
}

func runGitHardened(ctx context.Context, gitPath, dir string, args []string) error {
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Dir = dir
	cmd.Env = gitHardenedEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.With(err, "git command failed").Set("output", truncateForError(string(out), 800))
	}
	return nil
}

func runGitOutput(ctx context.Context, gitPath, dir string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Dir = dir
	cmd.Env = gitHardenedEnv()
	out, err := cmd.Output()
	return string(out), err
}
```

(`sanitizedEnv` and `truncateForError` already exist in `cmd/veto/main.go`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./cmd/veto/ -run TestCloneAndCaptureCommit`
Expected: PASS (ok). (Skips if `git` is unavailable.)

- [ ] **Step 5: Commit**

```bash
git add cmd/veto/opaquegit.go cmd/veto/opaquegit_test.go
git commit -m "feat(veto): cloneAndCaptureCommit for opaque git crates"
```

---

## Task 6: `resolveOpaqueGitInstalls` + `applyOpaqueGitResolution`

**Files:**
- Modify: `cmd/veto/opaquegit.go`
- Test: `cmd/veto/opaquegit_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/veto/opaquegit_test.go`. Add two imports to the existing block: `"runtime"` and `"github.com/rs/zerolog"`. (The tests reach the gate/cargolock layers through the package-local `newCompoundExpander()`, so no direct import of those packages is needed — and Go errors on unused imports.)

```go
// writeStubCargo writes a fake `cargo` executable that, for any args, writes a
// fixed Cargo.lock into its working directory (the clone dir). Returns the
// stub's path. Skips on Windows (shell-script stub).
func writeStubCargo(t *testing.T, lockBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub cargo uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cargo")
	script := "#!/bin/sh\ncat > Cargo.lock <<'LOCK'\n" + lockBody + "\nLOCK\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

const stubLock = `[[package]]
name = "rootcrate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "evilgit"
version = "0.0.1"
source = "git+https://example.com/evil#deadbeef"`

func TestResolveOpaqueGitInstalls(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo, sha := newTestCrateRepo(t)

	deps := opaqueGitDeps{
		gitPath:   "git",
		cargoPath: writeStubCargo(t, stubLock),
		expander:  newCompoundExpander(),
	}
	plan := packagemanager.OpaqueRemoteResolvePlan{
		GitURL:       repo,
		ResolveArgs:  []string{"generate-lockfile"},
		ManifestRefs: []packagemanager.ManifestRef{{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock}},
	}

	installs, gotSHA, err := resolveOpaqueGitInstalls(context.Background(), zerolog.Nop(), deps, plan)
	require.NoError(t, err)
	require.Equal(t, sha, gotSHA)
	require.Len(t, installs, 1, "only the registry dep survives the filter")
	require.Equal(t, "serde", installs[0].Ref.Name)
	require.Equal(t, "1.0.200", installs[0].Ref.Version)
}

func TestResolveOpaqueGitInstallsFailsClosedOnResolveError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if runtime.GOOS == "windows" {
		t.Skip("stub cargo uses a POSIX shell script")
	}
	repo, _ := newTestCrateRepo(t)

	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "cargo")
	require.NoError(t, os.WriteFile(stub, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	deps := opaqueGitDeps{gitPath: "git", cargoPath: stub, expander: newCompoundExpander()}
	plan := packagemanager.OpaqueRemoteResolvePlan{
		GitURL:       repo,
		ResolveArgs:  []string{"generate-lockfile"},
		ManifestRefs: []packagemanager.ManifestRef{{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock}},
	}
	_, _, err := resolveOpaqueGitInstalls(context.Background(), zerolog.Nop(), deps, plan)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/veto/ -run TestResolveOpaqueGitInstalls`
Expected: FAIL — `undefined: opaqueGitDeps`, `undefined: resolveOpaqueGitInstalls`.

- [ ] **Step 3: Implement the resolver and the orchestration wrapper**

Add to `cmd/veto/opaquegit.go`. Extend the import block to also include `"context"` (already added in Task 5), `"time"`, `"github.com/rs/zerolog"`, and `"github.com/brynbellomy/veto/internal/gate"`:

```go
// opaqueResolveTimeout bounds the clone + resolve of an opaque git crate. The
// clone touches the network and the resolve touches the registry index, but
// neither compiles the crate nor runs build scripts.
const opaqueResolveTimeout = 2 * time.Minute

// opaqueGitDeps bundles the externalities of an opaque-git resolution so the
// orchestration logic is testable with an injected stub cargo. The clone +
// resolve deadline is carried by the context the caller passes in.
type opaqueGitDeps struct {
	gitPath   string
	cargoPath string
	expander  gate.ManifestExpander
}

// resolveOpaqueGitInstalls clones the git crate, regenerates or validates its
// lockfile with the real cargo (without compiling it), expands the lockfile,
// and returns the registry-eligible installs plus the exact commit SHA that was
// scanned. Any failure is returned as an error so the caller can fail closed.
func resolveOpaqueGitInstalls(ctx context.Context, logger zerolog.Logger, deps opaqueGitDeps, plan packagemanager.OpaqueRemoteResolvePlan) ([]packagemanager.Install, string, error) {
	src, sha, cleanup, err := cloneAndCaptureCommit(ctx, deps.gitPath, plan)
	defer cleanup()
	if err != nil {
		return nil, "", err
	}

	cmd := exec.CommandContext(ctx, deps.cargoPath, plan.ResolveArgs...)
	cmd.Dir = src
	cmd.Env = sanitizedEnv(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Debug().Str("output", truncateForError(string(out), 800)).Msg("cargo resolve output")
		return nil, "", errors.With(err, "cargo resolve for opaque git crate failed").Set("args", strings.Join(plan.ResolveArgs, " "))
	}
	if ctx.Err() != nil {
		return nil, "", errors.With(ctx.Err(), "cargo resolve timed out")
	}

	var installs []packagemanager.Install
	foundLock := false
	for _, ref := range plan.ManifestRefs {
		ref.Path = filepath.Join(src, ref.Path)
		if _, statErr := os.Stat(ref.Path); statErr != nil {
			continue
		}
		foundLock = true
		extra, err := deps.expander.Expand(ref)
		if err != nil {
			return nil, "", errors.With(err, "expand resolved lockfile").Set("path", ref.Path)
		}
		installs = append(installs, extra...)
	}
	if !foundLock {
		return nil, "", errors.WithNew("cargo resolve produced no lockfile to scan")
	}

	return filterRegistryInstalls(installs), sha, nil
}

// opaqueGitResolution is the outcome the gate orchestrator consumes.
type opaqueGitResolution struct {
	Installs []packagemanager.Install // installs to gate (opaque entries replaced by registry deps)
	ExecArgs []string                 // argv to exec on the allow path, pinned to Commit
	Commit   string                   // the scanned commit SHA
	Scanned  int                      // number of registry deps scanned (for the success note)
	Applied  bool                     // whether a clone-scan ran
}

// applyOpaqueGitResolution clones+scans opaque git installs the package manager
// can resolve, replaces them with their registry deps, and pins the argv to the
// scanned commit. When the PM is not an OpaqueRemoteResolver, or no install is
// an unresolvable git spec, it returns Applied=false with the inputs unchanged.
// A non-nil error means the caller must fail closed.
func applyOpaqueGitResolution(
	ctx context.Context,
	logger zerolog.Logger,
	cfg config,
	pm packagemanager.PackageManager,
	pmArgs []string,
	installs []packagemanager.Install,
	expander gate.ManifestExpander,
) (opaqueGitResolution, error) {
	resolver, ok := pm.(packagemanager.OpaqueRemoteResolver)
	if !ok || !hasOpaqueInstall(installs) {
		return opaqueGitResolution{Installs: installs, ExecArgs: pmArgs}, nil
	}
	plan, ok := resolver.OpaqueRemoteResolve(pmArgs)
	if !ok {
		// PM cannot resolve this opaque spec (e.g. a tarball URL); leave it for
		// the gate to refuse as before.
		return opaqueGitResolution{Installs: installs, ExecArgs: pmArgs}, nil
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return opaqueGitResolution{}, errors.With(err, "git is required to scan a git crate but was not found on PATH")
	}
	cargoPath, err := findRealBinary(pm.Name(), wrapperRegisteredFunc(cfg))
	if err != nil {
		return opaqueGitResolution{}, errors.With(err, "locate real cargo for opaque git resolve")
	}

	rctx, cancel := context.WithTimeout(ctx, opaqueResolveTimeout)
	defer cancel()
	registry, sha, err := resolveOpaqueGitInstalls(rctx, logger, opaqueGitDeps{
		gitPath:   gitPath,
		cargoPath: cargoPath,
		expander:  expander,
	}, plan)
	if err != nil {
		return opaqueGitResolution{}, err
	}

	// Replace every opaque install with the scanned registry deps; keep any
	// non-opaque installs the PM also parsed (e.g. cargo add's project refs).
	kept := make([]packagemanager.Install, 0, len(installs)+len(registry))
	for _, ins := range installs {
		if !ins.OpaqueRemote {
			kept = append(kept, ins)
		}
	}
	kept = append(kept, registry...)

	return opaqueGitResolution{
		Installs: kept,
		ExecArgs: resolver.PinResolvedRevision(pmArgs, sha),
		Commit:   sha,
		Scanned:  len(registry),
		Applied:  true,
	}, nil
}

// hasOpaqueInstall reports whether any install is an opaque remote spec.
func hasOpaqueInstall(installs []packagemanager.Install) bool {
	for _, ins := range installs {
		if ins.OpaqueRemote {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/veto/ -run TestResolveOpaqueGitInstalls`
Expected: PASS (ok). (Skips if `git` is unavailable or on Windows.)

- [ ] **Step 5: Run the full cmd/veto package**

Run: `go test ./cmd/veto/`
Expected: PASS (ok).

- [ ] **Step 6: Commit**

```bash
git add cmd/veto/opaquegit.go cmd/veto/opaquegit_test.go
git commit -m "feat(veto): resolve+pin opaque git crate installs"
```

---

## Task 7: Wire into `runGate` + success note

**Files:**
- Modify: `cmd/veto/main.go:369` (between the project-preflight block and `g := gate.New(...)`)

- [ ] **Step 1: Insert the resolution step before the main Evaluate**

In `cmd/veto/main.go`, locate (around line 369):

```go
	g := gate.New(store, policy, logger)
	decision := g.Evaluate(installs, manifestRefs...)
```

Replace those two lines with:

```go
	gitResolution, err := applyOpaqueGitResolution(context.Background(), logger, cfg, pm, pmArgs, installs, expander)
	if err != nil {
		logger.Error().Err(err).Str("pm", pmName).Msg("opaque git resolve failed; aborting install fail-closed")
		printAbort(os.Stderr, gate.Decision{Outcome: gate.OutcomeAbort, Errors: []error{err}})
		return exitInternal
	}
	installs = gitResolution.Installs
	pmArgs = gitResolution.ExecArgs

	g := gate.New(store, policy, logger)
	decision := g.Evaluate(installs, manifestRefs...)
```

- [ ] **Step 2: Print the success note on the allow path**

Still in `runGate`, find the `case gate.OutcomeAllow:` arm of the `switch decision.Outcome` that immediately follows the Evaluate above (the arm whose comment reads `// Continue into the optional resolver pre-scan below.`, ~line 380). Replace that arm with:

```go
	case gate.OutcomeAllow:
		if gitResolution.Applied {
			fmt.Fprintf(os.Stderr,
				"veto: cargo git source accepted at commit %s; scanned %d registry deps (clean).\n",
				gitResolution.Commit, gitResolution.Scanned)
		}
		// Continue into the optional resolver pre-scan below.
```

The downstream `execPMOrPythonM(cfg, pmName, pmArgs)` calls now use the pinned `pmArgs`. (cargo implements neither `ResolverPreScanner` nor the npm-family gyp path, so those later blocks are no-ops for cargo.)

- [ ] **Step 3: Build and run the full test suite**

Run: `go build ./... && go test ./...`
Expected: builds cleanly; all packages PASS.

- [ ] **Step 4: Manual end-to-end verification**

This exercises the live path (needs network, `git`, and `cargo` installed). Use a tiny real crate:

```bash
go build -o /tmp/veto ./cmd/veto
# A clean git crate should now CLONE, SCAN, and proceed (pinned to HEAD):
/tmp/veto cargo install --git https://github.com/rust-lang/cargo --tag 0.78.0 --dry-run 2>&1 | head -40
```

Expected: a `veto: cargo git source accepted at commit <sha>; scanned <N> registry deps (clean).` line on stderr, then cargo runs (the `--dry-run` keeps it from actually installing). Confirm the prior behavior — an immediate opaque-spec refusal — is gone.

(If `--dry-run` is rejected by the installed cargo version for `install --git`, substitute any small public crate repo; the assertion is the accept-note + cargo launching, not the install completing.)

- [ ] **Step 5: Commit**

```bash
git add cmd/veto/main.go
git commit -m "feat(veto): gate cargo git installs via clone-scan instead of refusing"
```

---

## Task 8: Documentation

**Files:**
- Modify: `README.md` (the Go/Cargo gating paragraph ~line 259, and the refuse-opaque section ~line 443/487)
- Modify: `TODO.md` (the 1.8.2 cargo block ~line 46)

- [ ] **Step 1: Update README — Go/Cargo gating paragraph**

In `README.md`, find the paragraph beginning "Go and Cargo live gating covers fetch/mutate commands…" (~line 259). After the sentence listing `cargo install`, add:

```markdown
For `cargo install --git <url>` and `cargo add --git <url>`, veto no longer
refuses outright: it clones the repository into a temporary directory,
regenerates the lockfile to mirror cargo's own resolution (honoring
`--locked`/`--frozen`/`--offline`), gates every resolved crates.io dependency,
and — if clean — pins the real install to the exact commit it scanned before
letting cargo proceed. The git source code itself (the root crate and any
nested git dependencies) is accepted as the code you explicitly chose to
install; its registry supply chain is what gets vetted. Any clone or resolve
failure fails closed.
```

- [ ] **Step 2: Update README — refuse-opaque section**

In `README.md`, find the "Refuse-opaque-by-default" / "Opaque-spec install" description (~line 443–487). Add a sentence noting the cargo exception:

```markdown
Exception: `cargo install/add --git` specs are not refused on sight — they are
cloned and scanned (see the Cargo gating section above). All other opaque specs
(tarball URLs, `user/repo` shorthand) remain refused.
```

- [ ] **Step 3: Update TODO — 1.8.2 cargo block**

In `TODO.md`, the 1.8.2 block (~line 46) lists deferred cargo work including "ResolverPreScan for Cargo." Mark the git clone-scan as shipped by appending under that block:

```markdown
- SHIPPED: `cargo install --git` / `cargo add --git` clone-and-scan
  (`cmd/veto/opaquegit.go` + `cargo.OpaqueRemoteResolver`). Clones to a temp
  dir, regenerates the lockfile (mirrors cargo's resolution; honors
  --locked/--frozen/--offline), gates the transitive crates.io deps, and pins
  the install to the exact scanned commit. Remaining edges:
  - Registry-version TOCTOU: the git commit is pinned, but cargo re-resolves
    crates.io transitive versions at install time. Window is small (immutable
    crates.io versions, name-keyed intel); full closure needs feeding our
    generated lockfile into the real install. Deferred.
  - No content scan of the cloned tree (malicious build.rs / proc-macros) —
    the Rust analog of the gypscan detector. Separate follow-up.
```

- [ ] **Step 4: Commit**

```bash
git add README.md TODO.md
git commit -m "docs: cargo git installs now clone-and-scan instead of refusing"
```

---

## Self-Review notes (resolved during planning)

- **Spec coverage:** interface (Task 1) → cargo plan incl. `--locked` (Task 2) → commit pin (Task 3) → registry-only filter (Task 4) → clone + capture SHA (Task 5) → resolve/expand/replace/pin + fail-closed (Task 6) → runGate wiring + success note (Task 7) → residual-gap + docs (Task 8). All covered.
- **Type consistency:** `OpaqueRemoteResolvePlan`, `opaqueGitDeps`, `opaqueGitResolution`, `resolveOpaqueGitInstalls`, `applyOpaqueGitResolution`, `filterRegistryInstalls`, `cloneAndCaptureCommit`, `hasOpaqueInstall`, `hasLockedFlag`, `gitRefSelectorFlags`, and `opaqueResolveTimeout` are each defined once and referenced with matching signatures across tasks.
- **No placeholders:** every code/test step shows complete code; the "remaining edges" entries are deliberate, named follow-ups (per the approved spec), not implementation gaps in this plan.
