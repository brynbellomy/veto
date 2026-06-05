# Plan: fix the binding.gyp detector coverage gaps (gyp-defense-review findings)

## Context

A defensive security review of veto's binding.gyp worm detector
(`internal/gypscan` + scan/install wiring) found coverage gaps. Full report at
`/tmp/gyp-defense-review.md`; reproduction tests (currently pass, proving the
miss) at `/tmp/gyp-defense-review-tests/gyp_gap_test.go`. This plan fixes them.

The detector classifies a `binding.gyp` (and transitively-included `.gypi`
files) as None / Medium / Critical. node-gyp runs at npm install time when a
package ships a binding.gyp; a **Critical** verdict refuses the install on the
hot path. The threat is the "phantom-gyp / Miasma" worm family, which executes
a payload during node-gyp's configure step.

**Current architecture (read `internal/gypscan/gypscan.go` first):**
- `Inspect(Input) Verdict` is the entry point. `Input` carries `GypContent`,
  `PackageJSON`, `SiblingFiles`, and `IncludedContents [][]byte`.
- Critical detection is factored into `scanCriticalSignals(content string,
  fromInclude bool) []Signal`, called once for the root content and once per
  included file. THIS IS THE SINGLE CHOKEPOINT — new critical detectors plug in
  here so they automatically cover both root and includes.
- Today `scanCriticalSignals` runs two detectors: `commandExpansionInSources`
  (command expansion `<!(...)`/`<!@(...)` inside `sources`/`inputs`/`outputs`
  arrays) and `payloadShellInExpansion` (payload-shaped shell — `&&`,
  redirection, pipe-to-interpreter, curl/wget/eval — inside any `<!()` body).
- Medium detectors (`hasNoneTypeTarget`, `isPureJSPackage`) stay root-only.

Keep `gypscan` PURE (no I/O). Conventions: `github.com/brynbellomy/go-utils/errors`,
`stderrors "errors"` alias for stdlib sentinels, `testify/require`, doc comments
on exported symbols, no `@@TODO` in shipped commits, `gofmt -w` touched files.

Ship as **four commits** (see end). Each builds and tests green on its own.

---

## Fix 1 (P0) — detect `actions[].action` and `rules[].action` command execution

**The gap:** GYP `actions` and `rules` sections each have an `action` field that
node-gyp runs as a command at build time. It is a plain argv array, e.g.
`"action": ["node", "scripts/prepare.js"]` — **no `<!()` expansion at all**. The
detector keys entirely on `<!()`, so this executes and rates clean. This is the
P0 and the most important fix.

**Where:** `internal/gypscan/gypscan.go`, new detector wired into
`scanCriticalSignals`.

**Implementation:**
- Add `func commandActionArray(content string) (loc int, excerpt string)` that
  finds an `"action"` (or `'action'`) key whose value is an array literal, and
  inspects the array body. Mirror the existing `sourcesArrayRe` style: a tolerant
  regex `["']action["']\s*:\s*\[([^\]]*)\]` capturing the body.
- Classify the action as Critical when the FIRST argv element (argv[0]) is an
  interpreter / shell / package-manager / fetch tool. Maintain an explicit set:
  `node`, `nodejs`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`, `sh`, `bash`,
  `zsh`, `dash`, `python`, `python2`, `python3`, `ruby`, `perl`, `curl`, `wget`,
  `eval`, `osascript`, `powershell`, `pwsh`, `cmd`. Match argv[0] by its base
  name (strip any path: `./scripts/x` → `x`; `/usr/bin/node` → `node`) and
  case-insensitively. ALSO flag when argv[0] itself contains a `<!()` expansion
  (computed command) or when any array element contains payload-shaped shell
  (`payloadShellRe`).
- Do NOT flag an action whose argv[0] is a plain compiler/codegen binary that is
  a normal build step (e.g. a generated tool referenced by `<(PRODUCT_DIR)/...`)
  UNLESS argv[0] base-name is in the interpreter set above. Rationale: the worm's
  whole move is running a JS/shell interpreter against a package-local script;
  flagging every `action` would false-positive on legitimate codegen. Keep the
  interpreter allowlist tight and documented. (A future GYP parser can do better;
  this is the high-signal subset.)
- Emit a `Signal{Code: "gyp-action-exec", Detail: ...}` (use `criticalDetail`
  for the include-vs-root prefix) and have `scanCriticalSignals` append it +
  let `Inspect` bump to Critical.
- The `action` array can appear under both `actions` and `rules`; because the
  regex matches any `"action": [...]` key it covers both. Add a brief doc note.

**Tests** (`internal/gypscan/gypscan_test.go`): port codex's three repro cases
from `/tmp/gyp-defense-review-tests/gyp_gap_test.go` but INVERTED to expect
`SeverityCritical`:
- `actions[].action` with `["node","scripts/prepare.js"]` → Critical.
- `rules[].action` with `["node","tools/generate.js",...]` → Critical.
- A legitimate `action` whose argv[0] is NOT an interpreter (e.g.
  `["<(PRODUCT_DIR)/protoc", "--cpp_out=.", "x.proto"]`) → NOT flagged by this
  rule (stays None for an otherwise-clean native addon). This guards the
  false-positive boundary.
- `action` with a computed `<!(...)` argv[0] → Critical.

---

## Fix 2 (P1) — escalate command expansion in execution-sensitive non-`sources` keys

**The gap:** `<!(node scripts/emit-cflag.js)` in `libraries` / `cflags` /
`ldflags` / `include_dirs` runs at configure time, but because the body has no
shell metacharacters, `payloadShellInExpansion` doesn't escalate it. The
false-positive guard (allow `<!@(node -p "...")` header lookups) is too broad —
it waves through any quiet `node <local>.js`.

**Where:** `internal/gypscan/gypscan.go`, new detector in `scanCriticalSignals`.

**Implementation:**
- Add `func commandExpansionInExecKeys(content string) (loc int, excerpt string)`
  that finds command expansions inside `libraries`/`cflags`/`cflags_c`/
  `cflags_cc`/`ldflags`/`include_dirs`/`library_dirs` array values (regex over
  those keys, same shape as `sourcesArrayRe`), then for each `<!()` body in those
  arrays decides:
  - **Allow (not flagged):** a print-only header/path lookup. Define an explicit
    allowlist predicate: body matches `node -p ...` / `node -e ...` that only
    prints (heuristic: contains `-p` or `--print` AND does not invoke a
    package-local `.js` file path), or `pkg-config ...`, or `python -c` printing
    a path. Keep this allowlist NARROW and documented — it exists only to avoid
    breaking `node -p "require('node-addon-api').include"` and similar.
  - **Critical:** anything else — specifically `node <localfile>.js`,
    `node --eval/-e` running real logic, `sh`/`bash`/`-c`, or any
    `payloadShellRe` hit. Emit `Signal{Code: "gyp-exec-key-command", ...}`.
- IMPORTANT: do not double-flag. If `payloadShellInExpansion` already flags a
  body, that's fine (additive signals are OK), but make the new detector's intent
  clear: it catches the QUIET package-local-interpreter case the shell-shape
  regex misses.

**Tests:** invert codex's `TestGap_CommandExpansionInExecutionKeys...` cases to
expect Critical for `<!(node scripts/emit-*.js)` in libraries/cflags/ldflags/
include_dirs. ADD a guard test: `<!@(node -p "require('node-addon-api').include")`
in `include_dirs` stays None (the existing
`TestInspectLegitIncludeDirExpansionIsClean` must still pass — re-run it).

---

## Fix 3 (P1) — treat truncated/oversized GYP files as unscannable, not clean

**The gap:** the fs walker reads only 256 KiB per file; the tarball reader caps
per-entry at 1 MiB and aggregate at 8 MiB. Both return the truncated prefix with
NO truncation signal. Pad benign content before the payload → scanner sees a
clean prefix, node-gyp later reads the whole file. A confirmed-Critical file
allowed through because the scanner couldn't see the payload.

**Where:** `internal/scan/gyp/gyp.go` and `internal/gypscan/tarball/tarball.go`
(the I/O layers — gypscan stays pure), plus a new signal the detector can carry.

**Implementation:**
- Add a `Verdict`-level or `Input`-level way to express "a relevant GYP file was
  too large to fully scan." Cleanest: the I/O callers detect truncation and, when
  a root binding.gyp or an included `.gyp/.gypi` was truncated, synthesize a
  Critical finding directly (they already turn verdicts into findings). Add a
  signal code `gyp-file-too-large` with a clear Detail.
- Change `readCapped` (both files — they're separate funcs) to read `limit+1`
  bytes and report whether truncation occurred (return `(content []byte,
  truncated bool, err error)`), OR keep the signature and have the caller compare
  bytesRead to the limit. Either way the caller must learn truncation happened.
- **fs walker (`scan/gyp/gyp.go`):** if the root binding.gyp OR any resolved
  include is truncated, emit a Critical finding (`gyp-file-too-large`) for that
  package in addition to / instead of the normal verdict. Rationale on the hot
  path: unscannable == fail-closed for that package (it's about to run node-gyp).
- **tarball (`tarball.go`):** if the root binding.gyp or an included file hit the
  per-entry cap or the aggregate budget was exhausted before a relevant file was
  read, return a verdict carrying a Critical `gyp-file-too-large` signal (so
  `gypTarballPreflight` refuses). Distinguish "no binding.gyp at all" (clean)
  from "binding.gyp present but truncated" (unscannable → Critical).
- Raise the caps while you're here: a legitimate binding.gyp is a few KB;
  256 KiB/1 MiB is already generous, so keep them but ensure the truncation path
  is exercised. The point is not the cap size — it's that truncation must never
  silently downgrade to clean.
- Keep the FAIL-OPEN-on-own-errors discipline for genuine I/O errors (a read
  error is still logged-and-skipped), but truncation of a PRESENT gyp is a
  detection-coverage gap, not an I/O error — treat it as Critical/unscannable.

**Tests:**
- `scan/gyp/gyp_test.go`: a binding.gyp padded past the cap with the payload
  after the cap → scanner emits a `gyp-file-too-large` Critical finding.
- `tarball_test.go`: a tarball whose `package/binding.gyp` exceeds `maxEntryBytes`
  → Inspect returns a Critical `gyp-file-too-large` verdict; a tarball with no
  binding.gyp at all stays None (regression).

---

## Fix 4 (P3) — make the Critical regexes comment- and string-aware

**The gap:** `payloadShellInExpansion` and friends scan raw full-file text. A
GYP `#` comment like `# example: <!(node x.js && echo y)` becomes a false
Critical, which on the hot path is a denial-of-service — and a malicious package
could ship comment-bait to wedge every future install in a tree.

**Where:** `internal/gypscan/gypscan.go`. This fix must land BEFORE/WITH Fixes 1
and 2 conceptually, because all critical detectors should run over normalized
content. Practical ordering: implement the normalizer first, then route every
critical detector through it.

**Implementation:**
- Add `func stripGypComments(content string) string` that removes GYP/Python
  `#`-to-end-of-line comments, BUT only when the `#` is not inside a quoted
  string. GYP strings use `'...'` and `"..."`. Implement a small single-pass
  scanner (NOT a regex) that tracks quote state and blanks out comment spans
  (replace comment chars with spaces to preserve byte offsets so `excerptAround`
  indices stay valid — important: keep length identical so existing offset-based
  excerpts don't shift).
- Route `scanCriticalSignals` to operate on `stripGypComments(content)` for the
  payload/expansion regexes. (Medium structural checks can stay on raw content;
  they don't have the DoS sensitivity.)
- Be conservative: this is a heuristic. The goal is to stop a `#` comment from
  producing a Critical, not to perfectly parse GYP. Document that strings
  containing `#` are preserved (only true comments are stripped).

**Tests:**
- `# <!(node x.js && echo y)` as a full-line comment in an otherwise-clean gyp →
  NOT Critical (None).
- A real payload on a non-comment line still → Critical (regression — comment
  stripping must not blind the detector to live code).
- A `#` inside a quoted string (e.g. a path `"./a#b/c"`) does not start a comment
  and does not change classification.

---

## Out of scope for THIS plan (note in TODO.md, do NOT implement now)

These two P2s are real but are install-plumbing changes, not detector-coverage,
and warrant their own design pass with brynsk. Add a TODO.md entry naming them:

- **P2 npm config/env prefix redirection** (`gyp_target_dir.go`): `npm_config_prefix`
  / `.npmrc` `prefix=` can redirect the real install to a dir the argv parser
  doesn't see. Fix would resolve target roots from the same config inputs npm
  consumes (e.g. a non-executing `npm config get prefix`). Deferred — needs care
  to stay non-executing and cross-PM.
- **P2 local-path install inspection** (`gyp_tarball.go`/gate): `npm install ./pkg`
  reaches npm without the gyp detector inspecting the local package. Fix would
  inspect the local dir / local `.tgz` via `internal/gypscan/tarball.Inspect`
  before exec. Deferred.

Document both in TODO.md under the existing binding.gyp worm section.

---

## Acceptance

- `go build ./...` clean.
- `go vet ./internal/gypscan/... ./internal/scan/gyp/... ./cmd/veto/...` clean.
- `go test ./...` green, including all new/inverted tests.
- `gofmt -l` reports none of the touched files.
- The three repro tests from `/tmp/gyp-defense-review-tests/` (ported into the
  real test files and INVERTED) now require Critical and pass.
- Existing false-positive guards STILL pass: `TestInspectLegitIncludeDirExpansionIsClean`,
  the live-registry-shaped clean addon tests, and the better-sqlite3-shaped
  include test. Run the full gypscan + scan/gyp + tarball suites and confirm no
  legit-addon test regressed to Critical (that would be a supply-chain DoS).

## Commits

1. `gypscan: strip GYP comments before critical matching (fix false-Critical DoS)` — Fix 4
2. `gypscan: detect actions/rules action-array command execution` — Fix 1 (the P0)
3. `gypscan: escalate quiet command expansion in libraries/cflags/ldflags/include_dirs` — Fix 2
4. `gypscan: treat truncated/oversized binding.gyp as unscannable (fail-closed)` — Fix 3

(Order matters: Fix 4's normalizer lands first so Fixes 1–2 build on comment-stripped content.)
