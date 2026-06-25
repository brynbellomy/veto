# Hades / Shai-Hulud `.pth` startup-hook defense — 2026-06-10

## Purpose

The "Hades" wave of the Shai-Hulud / Miasma supply-chain worm (June 2026)
is the PyPI branch of the same lineage veto already fights on npm with
`gypscan` (the `binding.gyp` campaign). It defeats the name+version intel
model the same way: it republishes trusted packages under stolen maintainer
tokens (so the name is not in any malware feed for hours), and it keeps the
package's declared metadata clean (so manifest/lifecycle inspection sees
nothing). The execution surface is different: instead of an npm `binding.gyp`
that node-gyp shells out, the worm ships a `*-setup.pth` file inside the
wheel.

Python's `site` module processes every `*.pth` in `site-packages` **at each
interpreter startup**. Blank lines and `#` lines are ignored; a line whose
first token is `import` is `exec()`'d; every other line is treated as a path
to add to `sys.path`. The worm's `.pth` carries an `import`-line that
downloads the Bun runtime, drops an obfuscated `_index.js`, and runs a
multi-stage credential stealer that harvests secrets (TruffleHog-style),
exfiltrates to attacker-controlled GitHub repos, and self-propagates by
republishing the victim's other packages.

This execution is **broader** than npm's install-time detonation: it
re-fires on *every* `python` invocation in a poisoned environment, not just
at install. The only durable signal — exactly as with `binding.gyp` — is the
`.pth` file's *contents*. So veto gains a Go content heuristic that reads a
`.pth` and classifies it, mirroring `internal/gypscan` precisely, plus
complementary host-artifact and intel surfaces.

## Goals

- Detect the Hades `.pth` startup-hook worm by **content**, not by name, at
  the three points `gypscan` already covers: an already-installed tree, an
  about-to-be-installed wheel, and a package-manager command issued from an
  agent shell.
- Keep the detector **pure** — no I/O, runs no Python, never executes the
  package. Callers own the bytes; the detector classifies them. (Same
  contract as `gypscan.Inspect`.)
- Refuse `pip` / `uv` / `poetry` / `pdm` installs that would operate in, or
  drop a worm into, a poisoned environment — fail-closed on a confirmed
  critical match, fail-open on veto's own fetch/IO errors.
- Surface on-disk Hades infection markers (host artifacts and *local* GitHub
  persistence) through the existing `agentsurface` scanner.
- Seed the intel model with the known-bad Hades package@versions as an
  explicitly-labelled stopgap, the durable defense being the `.pth`
  content heuristic.
- Stay quiet on the legitimate executable-`.pth` idioms that real Python
  tooling ships (`distutils-precedence.pth`, PEP 660 `__editable__*.pth`,
  legacy `easy-install.pth`), the way `gypscan` stays quiet on `sharp` /
  `bcrypt`.

## Non-goals

- **No Python-side guard.** veto will not install a `sitecustomize.py`, an
  import shim, or any runtime artifact into an interpreter to intercept
  `.pth` execution. Detection stays out-of-band byte inspection.
- **No sdist building.** Building an sdist runs `setup.py` (arbitrary code).
  The incoming-artifact prescan inspects **wheels only** (a wheel is an inert
  zip; the `.pth` is a build/install artifact, so the wheel is the correct
  thing to read). When only an sdist is offered, veto surfaces that it cannot
  safely prescan and leans on the existing-tree scan.
- **No GitHub-account enumeration.** Hunting a user's whole GitHub account for
  rogue `Shai-Hulud` / `stygian-cerberus-*` / `tartarean-charon-*` repos needs
  network + `gh` and is a separate opt-in concern. The persistence scan covers
  only what is *locally* observable in project roots and `/tmp`.
- **No payload heuristics on `sitecustomize.py` / `usercustomize.py` bodies.**
  Those files legitimately do real work; running payload regexes over them is a
  false-positive minefield. Their *presence inside `site-packages`* is surfaced
  as a `medium` structural signal only.

## Architecture

Four pieces, the first being the core all others lean on.

### 1. Core detector — `internal/pthscan` (mirrors `internal/gypscan`)

A pure package exposing `Inspect(Input) Verdict`, safe for concurrent use,
performing no I/O. Type shapes match `gypscan` one-for-one so downstream
wiring and tests are familiar:

```go
type Severity string // "none" | "medium" | "critical"

type Signal struct {
    Code    string // stable id, e.g. "pth-import-line-payload"
    Detail  string // one-sentence why-this-is-risk
    Excerpt string // truncated, single-lined offending fragment
}

type Verdict struct {
    Severity Severity
    Signals  []Signal
}
func (v Verdict) Flagged() bool // true for medium and critical

type Input struct {
    PthContent []byte   // raw bytes of the .pth file (required)
    FileName   string   // base name, e.g. "evil-setup.pth" (optional; informs
                        // the known-legit allowlist and the *-setup.pth signal)
    SiblingFiles []string // base names alongside the .pth in the same dist (optional)
}
```

**Classification.** The detector tokenizes the `.pth` line by line, applying
Python's own rule: a line is *executable* iff its first token is `import`
(after stripping leading whitespace; blank and `#` lines are inert; all other
lines are inert path entries).

- **critical** — an executable line carrying *payload-shaped* Python, the
  direct analog of `gypscan`'s `payloadShellRe`. Payload tokens, grouped:
  - **network**: `urllib`, `urlopen`, `urlretrieve`, `requests`, `socket`,
    `http.client`, `httplib`, `ftplib`
  - **process spawn**: `subprocess`, `os.system`, `os.popen`, `popen`,
    `pty.spawn`, `os.exec`
  - **dynamic execution**: `exec(`, `eval(`, `compile(`, `__import__(` with a
    computed/obfuscated argument
  - **deobfuscation**: `b64decode`, `base64`, `marshal.loads`, `codecs.decode`,
    `bytes.fromhex`, `.decode('hex')`, `zlib.decompress`, `lzma`, dense `\x..`
    hex-escape runs
  - **runtime / fetch tokens**: `bun`, `bunx`, `curl`, `wget`, `node`, `deno`
  - **worm markers**: `.bun_ran`, `_index.js`, `Hades`, `shai-hulud`,
    `stygian`, `tartarean`

  Also **unscannable = critical** (fail-closed): a `.pth` larger than the scan
  cap is treated as critical rather than trusting a clean prefix — same posture
  as `gypscan`'s `gyp-file-too-large`.

- **medium** — an executable `.pth` line that does **not** match the
  known-legit allowlist and is **not** obviously payload-shaped. A structural
  anomaly worth surfacing in `veto scan`, not blocking the hot path (where a
  false block stops real work).

- **none** — only inert path lines, or an executable line matching a tightly
  **anchored known-legit allowlist**:
  - `distutils-precedence.pth` — setuptools' `_distutils_hack` shim
    (`import os; ... __import__('_distutils_hack').add_shim();`)
  - PEP 660 editable installs — `__editable__*.pth` of the form
    `import __editable___<name>_finder; __editable___<name>_finder.install()`
    (and the `MapPathFinder` / `from __editable__ ... import` variants)
  - legacy `easy-install.pth` path-munge — `import sys; sys.__plen = ...` /
    `sys.__egginsert = ...`

  The allowlist is anchored (whole-line shape match), not a substring contains,
  so a worm cannot smuggle a payload by *also* mentioning `__editable__`. This
  is the lesson from `gypscan`'s anchored `nativeHelperLookupRe`.

The detector strips `#` comments before payload matching (a commented-out
example must not trigger a block), preserving byte offsets so excerpts stay
accurate — reuse the `stripGypComments`-style normalizer pattern.

### 2. Existing-tree scan — `internal/scan/pth` (mirrors `internal/scan/gyp`)

A `scan.Scanner` that walks Python environment roots and feeds every `.pth`
to `pthscan.Inspect`. Where `internal/scan/gyp` descends into `node_modules`,
this descends into `site-packages` / `dist-packages` directories under:

- the active interpreter(s)' site dirs reachable from the project roots
  (`<venv>/lib/python*/site-packages`, `<venv>/Lib/site-packages` on Windows),
- and `.venv` / `venv` / virtualenv trees inside the project roots.

Each match becomes a `scan.Finding` (Surface `SurfaceProject`), `critical`
verdicts mapped to `scan.SeverityCritical`, `medium` to `scan.SeverityHigh`,
with remediation text: do not run `python` / install in this env; delete the
package; clear the env; rotate credentials reachable from machines that ran it.
Reuse the capped-read / fail-closed-on-too-large machinery from
`internal/scan/gyp/gyp.go` (`readCapped`, `gypTooLargeFinding` analog).

`veto scan` runs this scanner on demand. The project manifest scanner prunes
virtualenvs; this scanner descends into them, because an installed worm lives
there, not in a committed manifest — exactly the `node_modules` rationale.

### 3a. Install hot path — existing tree

Before a Python-family install runs (`pip install`, `uv pip install`,
`python -m pip install`, `poetry add`, `pdm add`, …), the gate runs the
`internal/scan/pth` walk over the **target environment's** site dir (cwd's
active venv, or the `--target` / `--prefix` / `--python` target when one is
given). A `critical` match refuses before the real package manager runs: the
environment is already poisoned and the next interpreter startup (including
many of these install tools themselves) will detonate it.

### 3b. Install hot path — incoming wheel prescan

Before install, veto resolves the wheel(s) about to be installed and fetches
each (download-only — **builds and installs nothing**), opens it as a zip in
memory, and reads any `.pth` it would drop. Wheels place `.pth` files via the
data scheme (`<dist>-<ver>.data/purelib/*.pth` or `…/platlib/*.pth`) or as a
top-level `*.pth` recorded in `RECORD`; the prescan reads both without
extracting to a runnable tree. Each `.pth` runs through `pthscan.Inspect`.

This is the only layer that sees a *brand-new* compromised version — a
freshly-published worm is in no feed for hours, and a lockfile-only resolver
pre-scan never fetches artifacts. Controlled by `VETO_PTH_WHEEL_SCAN`
(default on for the argv-named packages; `=full` to also fetch resolved
transitives; `=off` to disable), mirroring `VETO_GYP_TARBALL_SCAN`. Fail-open
on veto's own fetch/parse errors (a registry hiccup must not block every
install); a confirmed `critical` match always refuses.

### 3c. Claude Code hook (Layer 1)

A Bash `pip install` / `uv pip install` / `python -m pip install` issued in a
poisoned environment is denied at the earliest point, before the shell runs
it — the worm reason supersedes the usual "re-run with veto" nudge, because
prefixing the command would not make that environment safe to install into.
Mirrors the `gypscan` Layer-1 behavior in `internal/hook/claudecode`.

### 4. Host-artifact / persistence scan — extend `internal/scan/agentsurface`

Add Hades infection markers to the existing agent-surface audit:

- **Host artifacts**: `/tmp/.bun_ran`, `/tmp/tmp.*.lock` (the campaign's lock
  shape), a dropped `_index.js` in suspicious locations, and an out-of-place
  `bun` binary fetched at runtime (e.g. under `/tmp`, `~/.cache`).
- **Local GitHub persistence** within project roots only: injected
  `.github/workflows/*.yml` matching the worm's secret-exfil-to-webhook shape,
  and clones whose remote URL or directory name matches the attacker naming
  (`stygian-cerberus-*`, `tartarean-charon-*`, `Shai-Hulud`).
- **Startup-file presence**: a `sitecustomize.py` / `usercustomize.py` sitting
  inside `site-packages` is surfaced as a `medium` structural signal (presence
  only — no payload heuristic on the body, per Non-goals).

### 5. Static IOC package list

A curated `hades-pypi` source plugged into the existing intel feed-merge
(alongside `internal/intel/sources/*`), carrying the known Hades
package@versions (`ensmallen`, `embiggen`, `pyphetools`, `gpsea`,
`phenopacket-store-toolkit`, `ppkt2synergy`, …). Explicitly labelled a
stopgap; it participates in the fail-closed sanity floor like every other
source. The durable defense is `pthscan` — this just shortens the window for
the already-known names.

## Testing

Mirror `gypscan_test.go` and `internal/scan/gyp/gyp_test.go`:

- **Table-driven `pthscan` unit tests.** A synthesized Hades-style malicious
  `.pth` (import-line + Bun/exec/base64 payload) → `critical`; each
  known-legit fixture (`distutils-precedence.pth`, a real `__editable__*.pth`,
  a legacy `easy-install.pth`) → `none`; a non-allowlisted executable line with
  no payload tokens → `medium`; path-only → `none`; oversized → `critical`.
- **False-positive guard.** A `live_real_test.go` analog (build-tag / env
  gated like `gypscan`'s) that fetches a handful of popular real wheels that
  ship `.pth` (e.g. `setuptools`, an editable install) and asserts `none`.
- **Scanner tests.** `internal/scan/pth` over a temp `site-packages` fixture
  tree: finds the planted malicious `.pth`, maps severities, fails closed on
  an oversized file, respects ctx cancellation at directory boundaries.
- **Wheel-prescan tests.** A fixture `.whl` (zip) containing a malicious
  `.pth` in the data scheme → refusal; a clean wheel → pass; a fetch error →
  fail-open (no refusal); env toggle honored.
- **agentsurface tests.** Planted `/tmp` markers and an injected workflow
  fixture produce findings; absence produces none.

## Confirmed scope decisions

1. `sitecustomize.py` / `usercustomize.py`: presence-in-`site-packages` is a
   `medium` agentsurface signal; **no** body payload heuristics.
2. Wheel-only prescan; **sdists out of scope** (never build to inspect).
3. **No** GitHub-account enumeration; persistence scan is local-only.

## Package / file layout

```
internal/pthscan/
    pthscan.go          # Inspect, Severity/Signal/Verdict, classification
    pthscan_test.go     # table-driven unit tests
    live_real_test.go   # gated false-positive guard against real wheels
internal/scan/pth/
    pth.go              # scan.Scanner over site-packages trees
    pth_test.go
internal/scan/agentsurface/
    agentsurface.go     # + Hades host-artifact / persistence markers
internal/gate/          # + Python-family existing-tree gate + wheel prescan wiring
internal/hook/claudecode/ # + worm-reason denial for pip/uv installs
internal/intel/sources/hades/ # curated stopgap package@version source
README.md               # + ".pth startup-hook worm detection" section
```

## Naming note

`internal/scan/gyp` is named for the artifact it scans (`binding.gyp`). The
parallel name here is `internal/scan/pth` (scans `.pth`). The detector package
is `pthscan` to parallel `gypscan`.
