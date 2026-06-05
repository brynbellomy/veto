# Plan: close two binding.gyp-worm bypasses (Edge 3 `includes:`, Edge 4 `--prefix`)

## Context

`veto` (Go, ~/projects/veto) gates package-manager installs. A content heuristic
for the June 2026 "phantom-gyp / Miasma" npm worm already exists:

- `internal/gypscan/` — pure detector. `Inspect(Input) Verdict`. Critical when a
  GYP command expansion `<!(...)`/`<!@(...)` sits in a `sources`/`inputs`/`outputs`
  array, or payload-shaped shell (`&&`, redirection, pipe-to-interpreter,
  `curl`/`wget`/`eval`) appears inside any `<!()` expansion.
- `internal/gypscan/tarball/` — reads an npm `.tgz` in memory, pulls the root
  `binding.gyp` (+ root `package.json` + root file listing), runs `Inspect`.
- `internal/scan/gyp/` — filesystem walker over `node_modules`; reads each
  `binding.gyp` + siblings, runs `Inspect`.
- `cmd/veto/gyp_preflight.go` — install-hot-path: scans cwd's `node_modules`
  (`gypPreflight(logger, w, cwd)` → `gyp.New(Options{Roots:[cwd]}).Scan`).
- `cmd/veto/gyp_tarball.go` — install-hot-path: `npm pack <spec> --ignore-scripts`
  then `tarball.Inspect`.
- `cmd/veto/hook.go` — Claude Code hook; `gypWormReasonForCwd` scans cwd.

Two confirmed bypasses remain. **node-gyp evaluates GYP `includes` at configure
time**, so an attacker can move the `<!(...)` payload out of the root
`binding.gyp` and into an included `.gypi`, OR install into a different tree via
`--prefix`. Both detonate at install time; neither is currently inspected.

This plan is two independent, mergeable parts. Keep them in separate commits.

---

## Part A — Edge 3: follow GYP `includes:` references

### GYP semantics (authoritative — implement to these)

- A `.gyp`/`.gypi` file may contain a top-level (and per-target) `"includes": [ ... ]`
  array of paths.
- **Include paths are relative to the directory of the file that contains the
  `includes` statement** (NOT relative to the package root). A nested `.gypi`
  that itself has `includes` resolves *its* includes relative to *its own* dir.
- Included content is merged into the including scope before node-gyp evaluates
  command expansions. Therefore a `<!(...)` in an included `.gypi` executes
  exactly as if it were inline.
- Includes can chain (A includes B includes C). Cap recursion depth (e.g. 8) and
  dedupe already-visited files to avoid cycles / zip-bomb-style fan-out.

### A1. Extend the detector to accept included content

`internal/gypscan/gypscan.go`:

- Add to `Input` a field:
  ```go
  // IncludedContents holds the raw bytes of every .gyp/.gypi file transitively
  // referenced via GYP `includes:` from the root binding.gyp. node-gyp merges
  // and evaluates these at configure time, so a command expansion in any of
  // them executes at install time exactly as if inline. Optional; callers that
  // cannot resolve includes (e.g. only have the root file) pass nil and the
  // detector degrades to root-only analysis.
  IncludedContents [][]byte
  ```
- In `Inspect`, run the **critical** checks (`commandExpansionInSources`,
  `payloadShellInExpansion`) over the root content AND over every entry in
  `IncludedContents`. If any included file trips a critical signal, emit a signal
  whose `Code` is the same (`gyp-command-in-sources` / `gyp-payload-shell`) but
  whose `Detail` notes it came from an included file, and set Critical.
  - Implementation: factor the per-content critical scan into a helper
    `scanCriticalSignals(content string, fromInclude bool) []Signal` and call it
    for root + each include; aggregate, then bump severity.
  - The medium structural checks (`type:"none"`, pure-JS) stay keyed off the
    ROOT file + package.json only — an included `.gypi` having `type:"none"`
    is not itself the structural tell.
- Do NOT change the existing exported signature of `Inspect`. New field is
  additive and optional.

### A2. Add a shared include-reference parser

New file `internal/gypscan/includes.go` (same package, stays pure / no I/O):

- `func ParseIncludePaths(gypContent []byte) []string` — extract the values of
  every `"includes"`/`'includes'` array in the content. GYP is python-ish, not
  JSON, so parse with a tolerant regex (mirror the style of the existing
  `sourcesArrayRe` in gypscan.go): match `["']includes["']\s*:\s*\[ ... \]`,
  then pull quoted string literals from the captured array body. Return cleaned,
  forward-slash paths. Ignore entries containing `<!` (a computed include path
  is itself suspicious but out of scope here; the command-expansion check
  already fires on it).
- Document: returns paths verbatim (relative to the including file's dir);
  resolution is the caller's job (filesystem vs tar differ).
- Unit-test against: a flat includes array, multiple includes arrays (top-level
  + per-target), single vs double quotes, no includes (nil), and an includes
  entry that is itself a `<!()` expansion (excluded from the returned list).

### A3. Resolve includes in the filesystem walker (`internal/scan/gyp/gyp.go`)

In `scanGyp(path)`, after reading the root `binding.gyp`:

- Resolve includes relative to the gyp's directory, transitively, depth-capped
  (const `maxIncludeDepth = 8`), deduped by cleaned absolute path. Reuse
  `readCapped`. Confine resolution to **within the package directory subtree**
  (the dir containing the root binding.gyp and below) — never follow an include
  that escapes via `../` outside the package root (defense against an include
  pointing at an unrelated file; also avoids reading the whole disk). If an
  include path escapes, skip it (do not error).
- Collect resolved included contents into `[][]byte` and pass as
  `Input.IncludedContents`.
- A read error on an included file is non-fatal: log/skip that include, continue
  (the root finding still stands). Missing include file → skip.

### A4. Resolve includes in the tarball inspector (`internal/gypscan/tarball/tarball.go`)

The tar stream is **forward-only single-pass**, so you cannot seek back to read
an include discovered later. Restructure:

- During the single pass, buffer the content of EVERY regular file whose name
  (after `stripPackagePrefix`) ends in `.gyp` or `.gypi`, keyed by its cleaned
  relative path, subject to the existing `maxEntryBytes` cap per file and a new
  aggregate cap (e.g. `maxGypByteBudget = 8 MiB`) to bound memory. Keep
  capturing root `package.json` + root siblings as today.
- After the pass: if a root `binding.gyp` exists, resolve its `includes`
  transitively against the buffered map (paths relative to the including file's
  dir, `path.Join` + `path.Clean`, depth-capped at 8, deduped, no escape above
  package root). Assemble `IncludedContents` from the buffered map.
- Pass root gyp + resolved includes to `gypscan.Inspect`. Unchanged behavior
  when there are no includes.
- Nested/vendored `binding.gyp` (dir != root) still must NOT be treated as the
  package's own root gyp — only the root `binding.gyp` drives analysis; buffered
  `.gypi` files are only consulted as include targets.

### A5. Tests for Part A

- `internal/gypscan/gypscan_test.go`: worm payload in `IncludedContents` (not in
  root) → Critical; clean root + clean includes → None; legit root that
  `includes` a benign common.gypi → None.
- `internal/gypscan/includes_test.go`: the parser cases from A2.
- `internal/scan/gyp/gyp_test.go`: build a temp package dir whose root
  `binding.gyp` is benign-looking (`type:"none"`, no inline expansion) but
  `includes` a `payload.gypi` containing `<!(node evil.js && echo stub.c)` →
  scanner emits a Critical finding. Also: include path escaping via `../` is not
  followed. Also: legit better-sqlite3-shaped root that includes `deps/common.gypi`
  (benign) → no finding.
- `internal/gypscan/tarball/tarball_test.go`: build an in-memory `.tgz` whose
  `package/binding.gyp` includes `build/payload.gypi`, with the payload in that
  second tar entry → `Inspect` returns Critical. Order the tar entries so the
  `.gypi` appears BOTH before and after the root gyp (two subtests) to prove the
  buffering handles either ordering. Clean nested includes → None.

---

## Part B — Edge 4: honor `--prefix` / `-C` / `--cwd` install-target dir

The hook and the install hot path both scan the *process* cwd. `npm install
--prefix /other/tree` (and pnpm `-C/--dir`, yarn `--cwd`) install elsewhere, so
the scanned tree is not the installed tree. Close this for the existing-tree
scan (Seam 1 + hook). (Tarball seam is unaffected — it fetches by spec, not by
tree.)

### B1. Resolve the install-target directory from argv

New file `cmd/veto/gyp_target_dir.go`:

- `func installTargetDir(pmName string, pmArgs []string, cwd string) string` —
  returns the directory the install will actually populate:
  - npm: `--prefix <dir>` (already in npm.go `flagsWithValues`). Also accept
    `--prefix=<dir>`.
  - pnpm: `-C <dir>` / `--dir <dir>` / `--prefix <dir>`.
  - yarn: `--cwd <dir>`.
  - bun: bun uses `--cwd <dir>` for some commands; accept `--cwd`.
  - If a relative dir is given, resolve against `cwd`. If none given, return
    `cwd` unchanged.
- Keep it a small, explicit per-PM flag table in this file (do NOT widen the
  parser packages). Use a local scan: walk pmArgs, match `flag value` and
  `flag=value` forms.
- Unit-test each PM form + `=` form + relative-dir resolution + absent flag.

### B2. Use the target dir in the install hot path

`cmd/veto/gyp_preflight.go`:

- Change `runGypPreflightIfNpmFamily(logger, pm)` to also take `pmArgs []string`
  (the same slice `runGate` already has). Compute
  `dir := installTargetDir(pm.Name(), pmArgs, cwd)` and scan `dir` instead of bare
  cwd. If `dir != cwd`, scan BOTH (a worm could be in either — the resolver may
  hoist into cwd's node_modules in some setups), deduping findings.
  - Simpler acceptable v1: scan `dir` (the install target). If `dir == cwd`,
    that's the current behavior. Document the choice.
- Update the one call site in `cmd/veto/main.go` (it has `pmArgs` in scope).

### B3. Use the target dir in the hook

`cmd/veto/hook.go`:

- `gypWormReasonForCwd` currently scans `os.Getwd()`. The hook has already
  parsed the bash command into `finding.Tokens` (the leaf PM argv, e.g.
  `["npm","install","--prefix","/x","foo"]`). Pass those tokens through and
  compute the target dir via `installTargetDir(finding.PM, finding.Tokens[1:], cwd)`.
  Rename to `gypWormReasonForTree(logger, pmName, pmArgs)` and resolve the dir
  inside. Keep fail-open semantics (cwd unresolvable → skip).
- The analyzer (`internal/hook/claudecode`) stays PURE — all of this is in the
  transport (`cmd/veto/hook.go`), consistent with the existing split.

### B4. Tests for Part B

- `cmd/veto/gyp_target_dir_test.go`: the flag-form matrix from B1.
- `cmd/veto/gyp_preflight_test.go`: worm in `/target/node_modules` but cwd clean,
  `npm install --prefix /target foo` → refuse. Worm in cwd, no prefix → still
  refuse (regression).
- `cmd/veto/hook_test.go`: a Bash `npm install --prefix <wormtree> foo` denies
  with the worm reason (chdir cwd to a CLEAN tree; put the worm only under the
  prefix dir) — proves the hook now follows `--prefix`.

---

## Constraints / conventions (from brynsk-architecture + allora-go-style-guide)

- Errors: `github.com/brynbellomy/go-utils/errors` (`errors.With(err,"...").Set(...)`,
  `errors.WithNew(...)`). For stdlib sentinels use `stderrors "errors"` alias
  (see existing tarball.go).
- Keep `gypscan` and `gypscan/tarball` and `scan/gyp` free of new heavy deps.
- `gypscan` stays pure (no I/O). Include *resolution* (I/O) lives in the walker
  and the tarball reader; the detector only consumes already-read bytes.
- Tests: `github.com/stretchr/testify/require`, table-driven where natural.
- Doc comments on every new exported symbol; first sentence is a contract.
- No `@@TODO` left in shipped commits. Run `gofmt -w` on touched files.
- Fail-open on the heuristic layers' OWN errors (a read/parse failure must not
  block every install); a confirmed Critical match always refuses. This matches
  the existing seam behavior — preserve it.

## Acceptance

- `go build ./...` clean.
- `go vet ./internal/gypscan/... ./internal/scan/gyp/... ./cmd/veto/...` clean.
- `go test ./...` green, including all new tests.
- `gofmt -l` reports none of the touched files.
- Manual proof for Part A: a temp package whose root binding.gyp is clean but
  includes a payload .gypi is flagged Critical by `veto scan --root <dir>`.
- Manual proof for Part B: `veto npm install --prefix <wormtree> foo` refuses
  even when run from a clean cwd.
- Two commits: "gypscan: follow GYP includes to close payload-in-.gypi bypass"
  and "veto: honor --prefix/-C/--cwd install dir in gyp worm preflight + hook".
