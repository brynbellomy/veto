# Cargo git-install clone-and-scan — 2026-06-05

## Purpose

`cargo install --git <url>` and `cargo add --git <url>` are hard-refused
today. Both parse into an `Install` with `OpaqueRemote=true`
(`internal/packagemanager/cargo/cargo.go`), and the gate refuses every
`OpaqueRemote` install unconditionally — "There is no override"
(`internal/gate/gate.go:206`). The former `VETO_ALLOW_OPAQUE` opt-through
was already deleted. The net effect: installing a Rust binary or dependency
from a git repository never works.

There is no inherent reason it can't work safely. A git crate's supply-chain
risk is the same one veto already gates everywhere else — the crates.io
packages it pulls in transitively. We can clone the repo into a temp
directory, re-resolve its dependency graph exactly as `cargo install` would,
run every resolved crates.io dependency through the intel gate, and — if
clean — let the real install proceed, pinned to the exact commit we scanned.

This is a deliberate, scoped relaxation of the unconditional opaque refusal,
applied only to git specs the user explicitly initiated and only after their
registry supply chain has been vetted.

## Goals

- Make `cargo install --git <url>` and `cargo add --git <url>` succeed when
  their resolved crates.io dependency graph is clean, instead of refusing
  outright.
- Mirror cargo's own resolution: regenerate the lockfile so we scan the exact
  registry versions `cargo install` will fetch (cargo ignores a committed
  `Cargo.lock` for git binary installs unless `--locked`/`--frozen`/`--offline`
  is passed).
- Close the time-of-check/time-of-use gap on the git source: pin the real
  install/add to the exact commit SHA that was scanned, so the remote can't
  serve a different commit between scan and install.
- Reuse the existing machinery — `gate.Gate`, the temp-workdir +
  real-binary-exec pattern from `runResolverPreScan`, and the
  `cargolock.Expander` that already classifies crates.io vs opaque sources.
- Keep cargo-package code pure-argv (no I/O), consistent with the
  `PackageManager` contract. All filesystem/process work lives in the CLI
  orchestrator.
- Fail closed on any clone or resolve failure, with an abort distinct from a
  malware refusal.
- Add no new override environment variable.
- Print a one-line success note naming the pinned commit and the number of
  registry deps scanned.

## Non-Goals

- No content scan of the cloned source tree (malicious `build.rs`,
  proc-macros — the Rust analog of the binding.gyp worm). Registry deps only.
  Tracked as a follow-up.
- No recursive cloning of nested git dependencies. `cargo generate-lockfile`
  resolves the entire graph, so every crates.io node anywhere in the tree is
  scanned; git-sourced nodes (the root crate and any nested git deps) are the
  code the user explicitly chose to install and are accepted without a
  name-lookup.
- No pinning of the transitive crates.io versions at install time — see
  Residual Gaps. The git commit is pinned; registry re-resolution at install
  is an accepted, named gap for a later phase.
- No change to handling of non-git opaque specs (raw tarball URLs,
  `user/repo` shorthand). Those remain unresolvable and stay refused.
- No new capability for npm/pip/go in this phase. The interface is designed to
  generalize, but only cargo implements it now.

## Current State

- `internal/packagemanager/cargo/cargo.go` — `parseInstall`/`parseAdd` mark
  `--git` specs `OpaqueRemote=true` via `markInstallsOpaque`. The
  `flagsWithValues` table already covers `--git`, `--rev`, `--tag`,
  `--branch`, `--locked` is a bare flag. `firstFlagValue` reads a flag's value.
- `internal/gate/gate.go:206` — `OpaqueRemote` installs synthesize a policy
  refusal verdict and set `OutcomeRefuse`. No override.
- `cmd/veto/main.go`:
  - `runGate` parses installs, evaluates them through `gate.Gate`, and on
    `OutcomeAllow` runs `runResolverPreScanIfAvailable` before exec'ing the
    real binary via `execPMOrPythonM(cfg, pmName, pmArgs)`.
  - `runResolverPreScan` is the template for the temp-workdir + real-binary
    flow: `findRealBinary`, `os.MkdirTemp("", ...)` + `defer RemoveAll`,
    `sanitizedEnv`, `exec.CommandContext` with `resolverPreScanTimeout`, then
    expand `ManifestRefs` from the workdir.
- `internal/packagemanager/cargolock/cargolock.go` — `Expander.Expand` reads
  `Cargo.lock`, emits registry packages as intel-eligible installs, and marks
  non-crates.io sources `OpaqueRemote` / no-source `LocalPath`. Reused as-is.
- The repo does not currently shell out to `git`. This design introduces the
  first `git` invocation, via `exec.LookPath("git")`.
- `TODO.md` 1.8.2 lists deferred cargo work and notes that a Cargo resolver
  pre-scan was deferred because the 2026-05-25 preflight phase was kept
  read-only. This design is that deferred resolver pre-scan, scoped to
  opaque-git installs.

## Design

### 1. Capability interface (`internal/packagemanager/packagemanager.go`)

A new optional capability, mirroring `ResolverPreScanner` and
`ProjectPreflighter`:

```go
// OpaqueRemoteResolver is an optional capability for PMs that can turn an
// opaque git spec into a scannable registry dependency set by cloning the
// repo and re-running the resolver — without compiling or executing project
// code. PMs that don't implement it keep the unconditional opaque refusal.
type OpaqueRemoteResolver interface {
    OpaqueRemoteResolve(args []string) (OpaqueRemoteResolvePlan, bool)

    // PinResolvedRevision rewrites argv so the real install targets exactly
    // `revision` — the commit the clone-scan vetted. It drops any conflicting
    // ref selector (--branch/--tag/--rev) and appends the pin. Pure; no I/O.
    PinResolvedRevision(args []string, revision string) []string
}

// OpaqueRemoteResolvePlan is pure data describing how to turn one opaque git
// spec into a scannable lockfile. The CLI orchestrator executes it; the PM
// package performs no I/O.
type OpaqueRemoteResolvePlan struct {
    GitURL        string        // remote to clone
    Ref           string        // tag/branch/rev to check out ("" = default branch HEAD)
    RefIsRevision bool          // true → full clone + `git checkout <Ref>`; false → shallow (+ --branch <Ref>)
    ResolveArgs   []string      // run against the REAL pm binary inside the clone (e.g. ["generate-lockfile"])
    ManifestRefs  []ManifestRef // lockfiles to expand after resolve, relative to the clone dir
}
```

### 2. Cargo implementation (`internal/packagemanager/cargo/cargo.go`)

`Manager` gains `OpaqueRemoteResolve` and `PinResolvedRevision`, plus the
`var _ packagemanager.OpaqueRemoteResolver = (*Manager)(nil)` assertion.

`OpaqueRemoteResolve(args)`:

- Returns `(plan, false)` unless the verb is `install` or `add` **and** a
  `--git` flag is present. Positional crate specs, `--path`, and tarball URLs
  return `false` and flow through unchanged (the opaque ones stay refused).
- `GitURL` = `firstFlagValue(rest, "--git")`.
- Ref precedence: `--rev` → `{Ref: rev, RefIsRevision: true}`; else `--tag` or
  `--branch` → `{Ref: value, RefIsRevision: false}`; else `{Ref: "",
  RefIsRevision: false}` (default branch HEAD).
- `ResolveArgs`: if any of `--locked`/`--frozen`/`--offline` is present →
  `["fetch", "--locked", "--manifest-path", "Cargo.toml"]` (honor the
  committed lock, as cargo does); otherwise → `["generate-lockfile",
  "--manifest-path", "Cargo.toml"]` (re-resolve to latest semver-compatible,
  cargo's default for git binary installs).
- `ManifestRefs`: `[{Path: "Cargo.lock", Kind: ManifestKindCargoLock}]`.

`generate-lockfile` and `fetch --locked` resolve the dependency graph and
write/validate `Cargo.lock`. Neither compiles the crate nor runs `build.rs` —
that property is what keeps the resolve step safe.

`PinResolvedRevision(args, sha)` (pure):

- Removes any `--branch`, `--tag`, or `--rev` token (both `--flag value` and
  `--flag=value` forms), since cargo rejects more than one git ref selector.
- Appends `--rev <sha>` (before a `--` passthrough terminator if one is
  present).
- Idempotent: a user-supplied full `--rev` is replaced by the same normalized
  SHA; a short sha or ref-ish value is normalized to the full 40-char SHA.

### 3. Orchestrator (`cmd/veto/main.go`)

New `resolveOpaqueGitInstalls(...)`, called in `runGate` **before**
`g.Evaluate`. Signature returns the rewritten install slice, the (possibly
rewritten) argv to exec on the allow path, and an error:

1. Type-assert `pm` to `OpaqueRemoteResolver`. If it doesn't implement it, or
   no parsed install is `OpaqueRemote`, return inputs unchanged.
2. `plan, ok := resolver.OpaqueRemoteResolve(pmArgs)`. If `!ok`, return inputs
   unchanged (the opaque entry stays → gate refuses it as today).
3. `os.MkdirTemp("", "veto-cargo-git-*")`, `defer os.RemoveAll(dir)`.
4. Clone via `exec.LookPath("git")` into `<dir>/src`:
   - `RefIsRevision` → `git clone <url> <dir>/src` then
     `git -C <dir>/src checkout <Ref>`.
   - non-revision with `Ref` → `git clone --depth 1 --branch <Ref> <url>
     <dir>/src`.
   - no `Ref` → `git clone --depth 1 <url> <dir>/src`.
   - Hardened env: `GIT_TERMINAL_PROMPT=0` (fail fast on a private-repo auth
     prompt instead of hanging). No `--recurse-submodules`. `git clone` does
     not execute remote hooks, so the clone itself runs nothing.
5. Capture the scanned commit: `git -C <dir>/src rev-parse HEAD`. Empty or
   error → fail closed.
6. Run `plan.ResolveArgs` against `findRealBinary("cargo", …)` with
   `cmd.Dir = <dir>/src`, `sanitizedEnv`, bounded by a dedicated
   `opaqueResolveTimeout` (~2 min, matching `resolverPreScanTimeout`). Failure
   or timeout → fail closed.
7. Expand `<dir>/src/Cargo.lock` via `cargolock.Expander`. Keep only
   registry (intel-eligible) installs — drop `LocalPath` and `OpaqueRemote`
   nodes (the root crate + nested git deps). This dropped set is the
   "registry deps only" scope.
8. Replace the opaque-git entries in the install slice with the kept registry
   installs. Compute the pinned argv: `resolver.PinResolvedRevision(pmArgs,
   sha)`.

`runGate` then calls `g.Evaluate(installs, manifestRefs...)` over the
registry deps. Clean → exec the **pinned** argv via `execPMOrPythonM`; any
flagged transitive crate → refuse, naming it.

Fail-closed errors from `resolveOpaqueGitInstalls` map to `OutcomeAbort` and
`printAbort`, exactly as `runResolverPreScan` failures already do — visibly
distinct from a malware refusal.

### 4. Success output

On the allow path for a clone-scanned install, print one line to stderr
before exec:

```
veto: cargo git source accepted at commit <sha>; scanned <N> registry deps (clean).
```

This makes the security posture legible: the git source was accepted (not
intel-verified by name), pinned to a specific commit, and its registry supply
chain was vetted.

### 5. Security posture (the deliberate change)

Before: every git install refused. After: the git **code itself** (root crate
+ nested git deps) is allowed to install — inherent to what `cargo install
--git` does and what the user explicitly requested — while its **crates.io
supply chain is fully gated**, and the install is **pinned to the exact commit
that was scanned**.

This is the one scoped place veto stops refusing opaque nodes, and only for
nested deps surfaced by a clone-scan the user initiated. No new override env
var. The clone executes nothing (no remote hooks, no submodules); the resolve
step resolves but never compiles or runs `build.rs`.

### 6. Failure modes (all fail closed → `OutcomeAbort`)

- `git` not on PATH, clone fails, network unreachable, private repo with no
  non-interactive credentials.
- `rev-parse HEAD` empty or errors.
- `cargo` real binary not found, resolve command fails, resolve times out.
- `Cargo.lock` absent after a resolve that reported success (the resolver was
  suppressed) — treat as failure, not "nothing to scan."

A flagged transitive dependency is a refusal (`OutcomeRefuse`), not an abort.

## Residual Gaps (follow-up, accepted)

- **Registry-version TOCTOU.** Pinning `--rev` locks the git commit, but cargo
  re-resolves the crates.io transitive versions at install time, so a version
  published in the gap between scan and install could differ from the scanned
  set. Window is small and well-covered (crates.io versions are immutable;
  much intel is name-keyed). Closing it fully means feeding our generated
  lockfile into the real install, which `cargo install --git` does not accept
  cleanly. Tracked for a later phase.
- **Repo content scan.** Malicious `build.rs` / proc-macros in the cloned tree
  are out of scope here (registry deps only). The Rust analog of the
  gypscan/binding.gyp detector is a separate follow-up.

## Testing

- **Unit (cargo package), pure and fast:**
  - `OpaqueRemoteResolve`: `install --git URL`, `add --git URL`, with
    `--tag` / `--branch` / `--rev`, `--locked` selecting the `fetch --locked`
    resolve args; non-git install/add and `--path` return `false`.
  - `PinResolvedRevision`: drops `--branch`/`--tag`/`--rev` (space and `=`
    forms), appends `--rev <sha>`, respects a `--` terminator, is idempotent
    against an existing full `--rev`.
- **Integration (orchestrator):** a `file://` bare git repo fixture holding a
  tiny crate, plus a stub `cargo` shim on PATH that writes a known
  `Cargo.lock`. Assert: (a) clean registry deps → allow path execs the pinned
  argv (`--rev <sha>` present); (b) a fixture `Cargo.lock` naming a
  known-malicious crate → refuse; (c) clone failure / resolve failure →
  abort. If a full fixture is too heavy, factor clone/rev-parse/resolve/expand
  behind a small seam so the happy/refuse/fail-closed branches are
  unit-testable.
- **Docs:** update `README.md` (the Go/Cargo gating section and the
  refuse-opaque-by-default section) and `TODO.md` 1.8.2 to record that cargo
  git installs now clone-and-scan rather than hard-refuse.
