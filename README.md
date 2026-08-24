# veto

A command-level malware scanner for package managers. Veto aggregates
package-intelligence feeds, blocks known malicious package installs by
default, optionally gates broader CVE/GHSA advisories, scans existing
projects and caches for exposure, and audits common agent persistence
surfaces before they can launch package-manager code.

Beyond name+version intel lookup, veto carries a content heuristic for
the **phantom-gyp / Miasma** worm class (the June 2026 `binding.gyp` npm
campaign) — a self-propagating supply-chain worm that the intel model
cannot see on its own, because it rides trusted package names via
maintainer-account takeover and hides install-time code execution in a
`binding.gyp` rather than a flagged package or a lifecycle script. See
"binding.gyp worm detection" below.

## Quickstart

```sh
git clone https://github.com/brynbellomy/veto.git
cd veto
make install
veto install-all --force
```

`install-all` installs the shims, managed shell block, Claude hook,
native interposer, real-binary wrappers, intel cache, and doctor checks.
Open a new terminal or source your shell rc file, then verify the setup:

```sh
veto doctor
veto scan
```

Use `veto npm install <pkg>`, `veto pip install <pkg>`, `veto uv pip
install <pkg>`, `veto go get <pkg>`, or `veto cargo add <crate>` to run
one package-manager command through the gate explicitly.

### Upgrading an existing install

veto iterates quickly. When you pull a new version the layered
install state on disk needs to be re-synced with the new binary —
some shims/wrappers point at the old veto path, the C interposer
header may have changed PMs, and new shim names may have been added
(uv-managed python3.X aliases, for example). The canonical upgrade
sequence:

```sh
cd path/to/veto
git pull
make install                       # rebuild + replace ~/.local/bin/veto
veto install-shims --force         # re-point Layer 2 shims at the new binary,
                                   # add any newly-discovered python3.X shims
make interposer                    # regenerate pm_names.h, rebuild the dylib
veto install-preload --lib $(pwd)/libveto_interpose.dylib  # macOS path; see
                                                            # `install-preload --help`
veto install-wrappers --force      # re-point Layer 4 wrappers; add new ones
                                   # (uv canonical python3.X binaries, …)
veto sync                          # refresh intel
veto doctor                        # confirm green
```

`veto install-all --force` is the one-shot equivalent for the common
case; the granular commands above let you skip layers that haven't
changed.

#### `veto update` — one-command self-update

If all you want is to move to the latest published `veto`, `veto update`
does it without a source checkout. It builds the requested ref with
`go install github.com/brynbellomy/veto/cmd/veto@<ref>` (default `main` —
the repo publishes no semver tags, so `@latest` won't resolve; the build
is checksum-verified through the Go module proxy, with no prebuilt-binary
download) and atomically replaces the running binary in place. Because
every Layer 2 shim is a symlink to that binary path and the Layer 3
interposer routes execs to `$VETO_PATH` (the same path), the replace alone
makes all layers use the new binary immediately — no re-source. `veto
update` also re-points shims (`install-shims --force`) so any
newly-shadowed package managers get their shim.

```sh
veto update              # build latest main, replace this binary in place
veto update --check      # report current vs latest, change nothing
veto update --full       # also run install-all (rebuilds the C interposer;
                         # use when the set of shadowed PMs changed)
veto update --ref v1.2.3 # install a specific branch, tag, or commit
veto update --binary-only  # replace the binary only, touch no other layer
```

Requires a Go toolchain on PATH (veto ships no prebuilt binaries). The
granular `make install` sequence above remains the path when you're
developing veto from a local checkout, or when a release changed the
shadowed-PM set and you want to rebuild the interposer from that tree
rather than via `--full`.

If `veto doctor` reports drift — stray `*.veto-original` siblings in
the Layer 2 shim dir, stale wrappers.json entries, foreign-wrapper
FAILs on the canonical Homebrew install — just run:

```sh
veto install-all
```

install-all is the convergence command: it reconciles each layer
against the current on-disk state, prunes anything stale, and
re-applies anything missing. The same command handles "first install"
and "recover from drift" without flags.

(Older versions of veto exposed `repair-shims` and recommended
`uninstall-wrappers && install-wrappers` for recovery; both are gone.
The scrub-stale-siblings + prune-stale-entries logic now runs at the
top of every install-shims / install-wrappers pass.) See
[docs/2026-06-23--python-shim-stall-postmortem.md](docs/2026-06-23--python-shim-stall-postmortem.md)
for the failure mode that motivated the convergence rewrite.

## What it actually blocks

Tested end-to-end on a macOS / mise / homebrew dev machine against the
Aikido feed's `chai-as-upgraded` malware sample. All of these get
refused:

```sh
npm install chai-as-upgraded                                  # bare name
/opt/homebrew/bin/npm install chai-as-upgraded                # absolute path
~/.local/share/mise/installs/node/24.7.0/bin/npm install …    # mise install dir
npm install https://example.com/evil.tgz                      # opaque tarball URL
veto npm ci  # against a lockfile naming a flagged package # transitive coverage
veto npm install clean-direct # refused if npm resolves a flagged transitive

# The canonical Python install form — caught via the python shim,
# which fast-paths every non-`-m {pm}` invocation back to real python.
# Every versioned `python3.X` alias on disk gets its own shim too
# (install-shims enumerates uv's canonical cpython store) so a venv
# that resolves python3.12 directly still routes through veto:
python -m pip install chai-as-upgraded                        # refused
python3 -m uv pip install chai-as-upgraded                    # refused
python3.12 -m pip install chai-as-upgraded                    # refused (uv-venv path)

# Fetch-and-run forms (npx-style):
npm exec chai-as-upgraded                                     # refused
uv tool install chai-as-upgraded                              # refused
uv run --with chai-as-upgraded python -c …                    # refused

# Python subprocess.run with absolute path AND stripped env — the case
# agents do constantly:
subprocess.run(["/opt/homebrew/bin/npm", "install", "chai-as-upgraded"],
               shell=False, env={"PATH": "/usr/bin:/bin"})       # also refused
```

For a versioned query (`npm install foo@1.2.3` or a lockfile pin),
veto refuses when the version falls inside an advisory's affected
range, is in its explicit `versions` list, or matches an "all
versions" advisory. A flagged `evil@1.0.0` does NOT refuse `evil@2.0.0`
unless the advisory said both — closing the false-positive class that
used to refuse popular packages over a single rogue release of an
otherwise-legitimate name. For an unversioned query, ANY flagged
version of the name refuses, since the caller hasn't pinned.

## Installation Details

`make install` builds `veto` into `~/.local/bin/veto`. `install-all`
builds `libveto_interpose.dylib`/`.so` with `make interposer` when
needed. Open a new terminal, or source your shell rc file, for the
managed shell block and interposer env vars to take effect.

`install-all` supports `--skip-wrappers` for integrators that install the
user-scoped layers (shims, shell rc, Claude hook, preload, intel, doctor)
as the regular user and run `veto install-wrappers` separately under
elevation. It returns structured exit codes so wrapping scripts can route
remediation without parsing human-readable output:

| Exit | Meaning |
|---|---|
| `0` | every requested step succeeded. Candidates on a read-only filesystem (typically SIP-protected paths like `/usr/bin/pip3` on macOS) are reported as `SKIP read-only filesystem (SIP-protected)` and do not affect the exit code — sudo can't bypass SIP, so there's nothing to retry. |
| `10` | a user-scoped layer failed (shims/shell/hook/preload/intel/doctor) |
| `20` | the wrappers step skipped one or more candidate dirs because the current (non-root) user can't write to them — retry under sudo. Distinct from the SIP case above, where elevation does not help. |
| `30` | the wrappers step had write access (or we are already root) and still hit a real failure |

If you want to install the layers one at a time, the equivalent commands are
`veto install-shims`, `veto install-shell`,
`veto install-claude-hook`, `make interposer`,
`veto install-preload --lib ./libveto_interpose.dylib --shell-rc auto`,
`veto install-wrappers`, `veto sync`, and `veto doctor`.

## Defense layers

Four composing layers. Each catches a different class of agent
behavior. None is sufficient alone; together they cover the realistic
agent-bash threat surface.

| # | Layer | Catches | Install |
|---|---|---|---|
| 1 | Claude Code PreToolUse hook | Bash tool calls inside a Claude session, before the shell sees them | `veto install-claude-hook` |
| 2 | PATH shims (`~/.local/bin/{npm,pip,python,…}`) plus shell-managed PATH pinning and pip/uv age quarantine | bare-name PM invocations in any shell that inherits the user's PATH, including `python -m {pip,uv,pipx,poetry,pdm}` via the python shim | `veto install-shims && veto install-shell` |
| 3 | Native execve interposer (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) | absolute-path invocations and `subprocess.run([abs])` in processes that inherit the preload env var | `veto install-preload --lib ./libveto_interpose.{dylib,so}` |
| 4 | Real-binary wrappers | absolute-path invocations even when env vars are stripped — the dylib doesn't need to load | `veto install-wrappers` |

Layer 4 is the strongest single layer because it requires no env-var
inheritance and no process cooperation — the bytes at
`/opt/homebrew/bin/npm` *are* veto. The tradeoff: `brew upgrade
node` or `mise install node@whatever` overwrites the wrapper. Re-run
`veto install-wrappers` after toolchain upgrades; `veto doctor`
flags drift.

### Verb-aware environment sanitization

Layer 3 needs `VETO_PATH` set in the environment to function. By
default, `veto` strips `VETO_PATH` from the child env before exec'ing the
real package manager; this breaks a potential interposer-recursion loop
for PM-style invocations.

For multi-verb tools like `go`, that strip is too coarse: `go run`, `go
build`, and `go test` invoke user-authored binaries, not nested PM calls.
Stripping `VETO_PATH` for these verbs silently disables Layer 3 across
the entire descendant tree, defeating the env-bypass defense.

Veto classifies `go` verbs by recursion risk:

- **Preserved** (`VETO_PATH` survives): `run`, `build`, `test`, `vet`,
  `get`, `list`, `mod *`, `work *`, `env`, `version`, `fmt`, `doc`,
  `clean`, `fix`, `telemetry`, `bug`.
- **Stripped** (status quo): `install`, `generate`, `tool *`.
- **Stripped** (default-deny for safety): any verb not on the list above.

New Go releases that introduce verbs default to stripped until the
classifier is updated. To add a verb to the preserved set, edit
`internal/packagemanager/golang/golang.go` `EnvRecursionRisk`.

Other multi-verb tools (`cargo`, `uv`, `npm`, `pip`) can adopt the same
pattern by implementing `packagemanager.EnvRecursionPolicy`.

## Why this design

Existing shell-function-based protection (e.g. Aikido `safe-chain`)
fails open in several real-world cases:

- the package manager is invoked through a wrapper that `execvp`'s the
  binary directly (`timeout npm install …`, `xargs … npm install …`,
  build systems, subprocess calls from Python/Go),
- the command runs in a non-interactive shell that didn't source the
  shim init script (CI, agent shells),
- the underlying tool's network behavior bypasses HTTPS-proxy
  enforcement (observed with `bun`'s package resolver — the motivating
  case for this project),
- the call uses an absolute path (`subprocess.run(["/opt/homebrew/bin/npm",
  …], shell=False)`) — agents do this constantly.

`veto` operates at the command layer: it parses argv, looks up
package names against an aggregated malware database, and refuses or
passes through. Because the check happens before the package manager
runs, none of the failure modes above apply.

An optional broad vulnerability feed can also be enabled for teams that
want install-time CVE/GHSA blocking. It is intentionally separate from
the default malware feed set because it blocks ordinary vulnerable
versions, not only active supply-chain malware.

## Architecture

```
intel/             ← parent: Source interface, MalwareReport, Store
intel/normalize.go ← PEP 503 + npm name normalization at lookup + ingest
intel/range.go     ← VersionRange + per-ecosystem InRange comparator
                     (semver via Masterminds/semver for npm/Go/crates.io;
                     PEP 440 comparator for PyPI bounded ranges)
intel/sources/
  aikido/          ← https://malware-list.aikido.dev (malware; default)
  datadog/         ← github.com/DataDog/malicious-software-packages-dataset (malware; default)
  openssf/         ← github.com/ossf/malicious-packages (malware; default)
  osv/             ← osv.dev MAL-* advisories; opt-in CVE widening (default)
  pypa/            ← github.com/pypa/advisory-database (PyPI; default)
  ghsa/            ← github.com/github/advisory-database (opt-in CVE/GHSA)
  rustsec/         ← github.com/rustsec/advisory-db (crates.io CVE; opt-in)
  govulndb/        ← vuln.go.dev (Go module CVE; opt-in)
  gemnasium/       ← gitlab.com/gitlab-org/advisories-community (multi-eco CVE; opt-in)
  internal/fsutil/ ← shared atomic-write helper (source-internal)

ioc/               ← parent: host-level IOC Source/Store/Indicator + RuleScanner (YARA seam, deferred)
  sources/
    abusech/       ← abuse.ch MalwareBazaar/Feodo/URLhaus/ThreatFox (opt-in; VETO_ABUSECH_AUTH_KEY)
    misp/          ← CIRCL OSINT MISP feed (opt-in)
    internal/fsutil/ ← shared atomic-write helper (source-internal)

packagemanager/    ← parent: PackageManager interface, Install
packagemanager/
  npm/ pnpm/ yarn/ bun/       ← jsspec-backed
  pip/ uv/ poetry/ pdm/       ← pyspec-backed
  exec/                       ← parameterized for npx/bunx/pnpx/uvx/pipx + npm exec
  jsspec/ pyspec/ argv/       ← shared spec parsers
  jsmanifest/ pymanifest/     ← package.json / pyproject.toml expanders
  jslock/ pylock/             ← lockfile expanders (transitive coverage)
  pyreq/                      ← requirements.txt expander
  gomod/                      ← go.mod / go.sum scan expander
  cargomanifest/ cargolock/    ← Cargo.toml / Cargo.lock scan expanders
  pmlist/                     ← canonical PM-name set (single source of truth
                                consumed by isShimName, install-shims,
                                install-wrappers, the hook, AND the C
                                interposer via a generated pm_names.h)

gate/              ← decision logic (allow / refuse / passthrough / abort)
gypscan/           ← pure content heuristic for the phantom-gyp/Miasma
                     binding.gyp worm (no I/O, runs no node-gyp); reused by
                     the scan walker, the install hot path, and the hook
gypscan/tarball/   ← inspects an npm .tgz in memory (gzip+tar, no extract,
                     no node-gyp); install-time complement to the walker
scan/gyp/          ← existing-exposure scanner: walks node_modules trees and
                     runs each binding.gyp through gypscan
internal/hook/     ← Claude Code analyzer (Layer 1)
internal/interposer/  ← native execve/posix_spawn hooks in C (Layer 3)
  cmd/genpmlist/   ← go-generate tool that emits pm_names.h from pmlist
  gen/             ← hosts the //go:generate directive + drift consistency test
cmd/veto/          ← CLI entrypoint
hooks/             ← per-agent integration docs
```

**Lookup policy: version-aware + range-aware.** Default sources are
malware-only, while optional `ghsa` brings broad vulnerability
advisories. Either way, advisories DO narrow their claims to specific
versions or version ranges. Veto honors those claims:

- **Exact-version reports** (OSV `affected.versions` lists) match
  only the listed versions. A `MAL-*` entry against `react@1.0.0`
  does not refuse `react@18.2.0`.
- **Range-bearing reports** (OSV `affected.ranges` events) match when
  the queried version falls inside the interval per the ecosystem's
  comparison rules. npm uses semver 2.0.0 (Masterminds/semver/v3),
  including pre-release ordering. PyPI uses PEP 440 ordering for
  bounded ranges, including pre/dev/post releases and epochs.
- **All-versions reports** (unbounded `introduced: 0` ranges, or
  sources that don't model versions at all) match every version of
  the name. These are the common shape for typosquats and
  fully-malicious packages.
- **Unversioned queries** (no pin in argv or lockfile) match any
  flagged version of the name — the caller hasn't committed to a
  pin, so any flag is enough to refuse.

**Withdrawn advisories don't gate.** OSV advisories carry a
`withdrawn` timestamp when the upstream retracts (usually as a false
positive). Veto filters those at ingest so a retracted MAL-* entry
can't keep refusing a clean package indefinitely — the advisory stays
in the feed for audit continuity but is treated as inactive.

**Live transitive coverage via lockfiles and resolver pre-scans.**
When an install verb runs in a supported npm-family or Python-family
project with a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`), veto parses the
full resolved transitive tree and gates every (name, version) tuple in
it — not just the verb's explicit argv. For npm install-family
commands, veto also runs the real npm resolver first in an isolated
temp copy with
`--package-lock=true --package-lock-only --ignore-scripts --audit=false --fund=false`, then
gates the generated `package-lock.json`/`npm-shrinkwrap.json` before the
real install is allowed to run. For `pip install` / `pip3 install`, veto
runs pip's resolver with `--dry-run --ignore-installed --report` in an
isolated temp copy and forces `--only-binary=:all:` so the probe does not
build sdists or run setup code. For `uv pip install`, veto runs
`uv pip compile --format pylock.toml` against seeded or synthetic
requirements input with `--only-binary=:all:` and gates the generated
pylock before the real install. If a resolver probe fails, does not
produce expected output, or the generated output does not include the
argv-named packages, veto aborts fail-closed.

Go and Cargo live gating covers fetch/mutate commands that can introduce
or download dependency code (`go get`, `go install`, remote `go run
pkg@version`, `go mod download`, `go mod tidy`, `cargo add`, `cargo
update`, `cargo fetch`, and `cargo install`). It also preflights local
Go and Cargo build/test/run commands by reading already-present project
state before execution: `go build`, `go test`, local `go run`, `go vet`,
`cargo build`, `cargo check`, `cargo test`, `cargo run`, `cargo bench`,
and `cargo clippy`. Default Go and Cargo preflight walks upward for
parent `go.mod`, `Cargo.toml`, and workspace `Cargo.lock`/`Cargo.toml`
files when the command runs from a nested directory; explicit path flags
still take precedence.

For `cargo install --git <url>` and `cargo add --git <url>`, veto no longer
refuses outright. It clones the repository into a temporary directory,
regenerates the lockfile to mirror cargo's own resolution (honoring
`--locked`/`--frozen`/`--offline`), gates every resolved crates.io dependency,
and — if clean — pins the real install to the exact commit it scanned before
letting cargo proceed. The git source code itself (the root crate and any
nested git dependencies) is accepted as the code you explicitly chose to
install; its registry supply chain is what gets vetted. Any clone or resolve
failure fails closed.

**binding.gyp worm detection (phantom-gyp / Miasma).** The June 2026
`binding.gyp` campaign defeats every name-and-version defense at once: it
republishes ~trusted packages under stolen maintainer tokens (so the name
is not in any malware feed for hours), keeps `package.json` `scripts`
clean (so lifecycle-script inspection sees nothing), and hides arbitrary
shell in a tiny `binding.gyp`. When npm finds a `binding.gyp` at a package
root with no preinstall/install script, it falls back to `node-gyp`, which
evaluates GYP command expansion (`<!(...)`, `<!@(...)`) **as a shell during
configure — even under `--ignore-scripts`**, because this is not a lifecycle
hook. The worm puts `<!(node index.js …)` in the `sources` array; node-gyp
runs it at install time.

Veto detects this by **content**, not by name. The `gypscan` package reads a
`binding.gyp` (plus its sibling `package.json` and file listing when
available) and classifies it:

- **critical** — any of node-gyp's install-time execution surfaces carrying a
  payload:
  - a command expansion `<!(...)`/`<!@(...)` inside a `sources`/`inputs`/`outputs`
    array (those hold filenames; node-gyp shells out each one);
  - payload-shaped shell (chaining, redirection, piping into an interpreter,
    `curl`/`wget`/`eval`) inside any expansion;
  - an `actions[].action` or `rules[].action` argv array whose command is an
    interpreter/shell/package-manager (`node`, `python`, `sh`, `npm`, …) — these
    are plain argv that node-gyp runs directly, no `<!()` required;
  - a command expansion in an execution-sensitive build key (`libraries`,
    `cflags`, `ldflags`, `include_dirs`, `library_dirs`) that invokes a
    package-local interpreter script rather than a print-only path lookup;
  - a `binding.gyp` (or included `.gypi`) too large to fully scan — treated as
    **unscannable → critical** (fail-closed) rather than trusting a clean prefix.
- **medium** — structural anomalies consistent with the worm but without a
  confirmed payload: a `type: "none"` target (builds nothing; its only job
  is to run a command), or a `binding.gyp` in a package that ships no native
  source and declares no native-build tooling (`node-gyp`, `node-addon-api`,
  `nan`, `prebuild`, `gypfile`) — a pure-JS package has no reason to carry
  one.

The detector follows GYP `includes:` references transitively (depth-capped,
cycle-guarded, confined to the package subtree), so a payload relocated into an
included `.gypi` is caught, and it strips GYP `#` comments before matching so a
commented-out example can't trigger a false block.

The detector deliberately does **not** flag the legitimate native-addon
header-lookup idiom — an anchored, pure `<!(node -p/-e "require('<helper>')")`
where `<helper>` is `nan`, `node-addon-api`, `bindings`, or `node-gyp-build`
(optionally `.include`, optionally wrapped in `console.log`). So it stays quiet
on `sharp`, `bcrypt`, `better-sqlite3`, `ssh2`, `canvas`, `node-sass`, and
friends (validated against the live registry). Anything beyond that exact shape
— a second statement, an invoked call, a local `.js`, a non-allowlisted module —
stays critical. It runs no `node-gyp` and never executes the package.

The heuristic runs at **three** points, so the worm is caught whether it is
already installed, about to be installed, or merely invoked from an agent
shell:

1. **Install hot path — existing tree.** Before an npm-family install or `ci`
   runs, veto scans the existing `node_modules` binding.gyp files in the tree
   the install will populate — cwd, or the `--prefix`/`-C`/`--cwd` target when
   one is given. An `npm install` re-runs `node-gyp` for the *whole* tree, so a
   worm already sitting in `node_modules` from an earlier install would detonate
   on the next, unrelated install. A critical match refuses before the real
   package manager runs.
2. **Install hot path — incoming tarball.** Before install, veto fetches the
   package(s) about to be installed with `npm pack --ignore-scripts`
   (download only; runs nothing) and inspects each tarball's `binding.gyp` in
   memory, without extracting to a runnable tree. This is the only layer that
   sees a *brand-new* compromised version — the `--package-lock-only` resolver
   pre-scan never fetches tarballs, and a freshly-published worm is not in any
   feed for hours. Controlled by `VETO_GYP_TARBALL_SCAN` (default on for the
   argv-named packages; `=full` to also fetch every resolved transitive;
   `=off` to disable). Fail-open on its own errors (a registry hiccup must not
   block every install); a confirmed critical match always refuses.
3. **Claude Code hook (Layer 1).** A Bash `npm install` in a worm-bearing
   tree is denied at the earliest point, before the shell sees it — the worm
   reason supersedes the usual "re-run with veto" nudge, because prefixing
   would not make that tree safe to install into.

`veto scan` also runs the existing-tree walk on demand over `node_modules`
trees under the project roots (the manifest scanner prunes `node_modules`;
the gyp scanner descends into it, because an installed worm lives there).

Only **critical** matches (any of the install-time execution surfaces listed
above) block an install; **medium** structural anomalies are surfaced by `veto scan` for
review but do not refuse on the hot path, where a false block stops real
work.

**Acknowledging a false positive.** Some long-established native packages
legitimately use payload-shaped shell in their `binding.gyp` (sharp's
pkg-config/readelf ABI probe, bufferutil's `cc -v | perl` version probe).
After you have **inspected the file yourself** and confirmed it is the
package's legitimate build probe, acknowledge it by content hash:

```sh
veto gyp-allow node_modules/sharp/src/binding.gyp
veto gyp-allow --list
```

The allowlist (in the veto cache dir, `gyp-allowlist`) pins the sha256 of
the exact bytes — the same legitimate file is acknowledged once across every
cache and `node_modules` copy, while a tampered variant of the same package
hashes differently and still refuses. `veto scan` keeps reporting
acknowledged findings for visibility; only the install-time block is
lifted.

### `.pth` startup-hook worm detection (Hades / Shai-Hulud)

The June 2026 Hades wave is the PyPI branch of the same Miasma lineage veto
fights on npm with `binding.gyp`. It rides a trusted package name (maintainer
account takeover, so the name is not in any malware feed for hours), keeps the
package metadata clean, and ships its payload as a `*-setup.pth` file inside
a wheel. Python's `site` module exec()s every `*.pth` whose first token is
`import` at *every* interpreter startup — so a poisoned environment detonates
the worm on the next `python` call, not just at install time.

veto detects this by content, not name, at four points:

1. **`veto scan`** — walks every `site-packages` / `dist-packages` directory
   under each project root and classifies each `.pth` via the `pthscan`
   content heuristic. Critical findings are the Hades signature; medium
   findings are non-allowlisted executable lines that warrant attention.
2. **Install hot path — existing tree** — before `pip` / `uv` / `poetry` /
   `pdm` runs, veto scans the target venv for `.pth` worms. A critical hit
   refuses the install fail-closed.
3. **Install hot path — incoming wheels** — veto downloads the wheel(s)
   about to be installed with `pip download --no-deps --only-binary :all:`
   (no sdist building; nothing executed), opens each as a zip in memory,
   and inspects every `.pth` inside. Default-on for argv-direct installs;
   set `VETO_PTH_WHEEL_SCAN=full` for resolved transitives, `=off` to
   disable. The prescan has a default timeout of **120 seconds**
   (`VETO_PTH_WHEEL_SCAN_TIMEOUT` overrides it). On timeout the prescan
   is **best-effort / fail-open** — veto logs a warning and allows the
   install rather than blocking it indefinitely. Critical findings detected
   before the timeout always refuse. This is an intentional UX trade-off:
   a slow registry hiccup must not block every install. Set
   `VETO_PTH_WHEEL_SCAN=off` to skip the prescan entirely when needed.
4. **Claude Code hook** — a `pip install` / `uv pip install` issued by an
   agent in a poisoned environment is denied at the earliest point, with
   the worm reason instead of the usual "re-run with veto" nudge —
   prefixing would not make the environment safe to install into.

veto also surfaces Hades infection markers via `veto scan`'s agent-surface
sub-scanner: host artifacts (`/tmp/.bun_ran`, `/tmp/tmp.*.lock`, dropped
Bun binaries), local GitHub persistence (`.github/workflows/*.yml` exfil
shapes, clones with attacker naming), and `sitecustomize.py` /
`usercustomize.py` *presence inside `site-packages`*.

The intel store also ships a curated stopgap source (`hades`) carrying the
known Hades package@versions. The durable defense is the `.pth` content
heuristic; the stopgap shortens the window for already-catalogued names.

**Fail-closed defaults.** Per-source malware feeds are fetched
concurrently with etag-based caching in `~/.cache/veto/`.
On network outage the last good snapshot is used; if zero sources
succeed on the very first run, the veto refuses installs rather
than fail open. A sanity floor of 1000 reports total catches the
"every feed returned []" case loudly.

**Cache hygiene — orphaned download temps are swept.** Every feed
downloads to a temp file (`npm.zip.tmp-1877699234`) and atomically
renames it into place. A run that dies before the rename leaves
that temp behind forever — on a busy machine that accumulated to
4.7 GB across 126 files. On each source's first fetch, veto now
sweeps `*.tmp-*` files older than 24 hours **in that source's own
cache directory only**. The 24h threshold is what makes this safe
without locks: `os.CreateTemp` names are process-unique and every
writer renames or removes its temp within one fetch, so a live
download's temp can never be 24 hours old. Real payloads, `.sha256`
sidecars, etags, parsed-`.gob` layers, `intel-baseline.json`, and
`last-refresh` are never matched — the pattern is the exact
`<name>.tmp-<digits>` shape `os.CreateTemp` produces, and only
that. Sweep failures (unreadable dir, read-only FS) are logged and
skipped; hygiene never blocks or fails a fetch.

**Cache integrity — corruption only, not an authenticity boundary.**
Every cached payload carries a SHA-256 sidecar, and a persistent
per-source baseline (`intel-baseline.json`) anchors expected report
counts. These layers detect CORRUPTION: crashes, partial writes, disk
rot, and implausibly collapsed feeds. They are NOT tamper detection.
A writer that can modify a payload can also recompute its sidecar and
rewrite the baseline, and the layer will report `HashMatch`. That is a
deliberate scoping decision (corruption-only model): anything that can
write `~/.cache/veto` as your UID can also replace the veto binary
itself, so a stronger hash in the cache defends nothing. Known accepted
limit: a payload retaining >50% of its entries while removing one
specific package defeats the count-based check. A damaged bucket makes
installs, `veto test`, and `veto scan` fail closed (exit 70) with the
source and ecosystem named; `veto status` prints it as a warning.

**Freshness window.** A `last-refresh` marker in the cache dir records
the last successful refresh. Invocations within 3 minutes of it
(`intel.RefreshFreshnessWindow`) skip every upstream round-trip and
serve from the on-disk caches, so agent loops and CI retries don't pay
one HTTP request per (source, ecosystem) per run. A missing, corrupt,
or future-dated marker always falls back to a full refresh — a bad
cache file can never suppress a security update. `veto doctor` ignores
the window deliberately: diagnostics probe real upstream state.

## Usage

```sh
# Gate an install (same shape as safe-chain's CLI).
veto npm install lodash         # → exec real npm
veto npm install chai-as-upgraded
# veto: install refused — package intelligence flagged the following:
#   - chai-as-upgraded@<any> (ecosystem: npm)
#       [aikido] MALWARE

# Ask veto what it thinks of a command line WITHOUT executing anything.
# JSON verdict from the intel+policy gate over argv and on-disk manifests.
# Exit codes match the enforcement path (0 allow/passthrough, 1 refuse,
# 64 usage, 70 internal).
veto test npm install lodash
# {"decision":"allow","pm":"npm","args":["install","lodash"],...}
veto test --format json pip install evil-pkg
#
# SCOPE: an "allow" verdict is NOT a statement that the install is safe.
# It excludes the enforcement-only layers that run after the intel gate:
# the resolver pre-scan (resolved transitive tree), the binding.gyp
# tarball and node_modules tree scans (phantom-gyp / Miasma), and the
# .pth wheel and site-packages tree scans (Hades). A clean-argv package
# with a flagged transitive dep returns "allow" here while the executing
# gate refuses. Use it as a fast intel lookup, not a replacement gate.

# Refresh malware intel manually.
veto sync

# Optional: include GitHub Advisory Database CVE/GHSA findings too.
# This can block normal vulnerable versions, not only malware.
VETO_SOURCES=aikido,openssf,osv,pypa,ghsa veto sync

# Show source health and cache location.
veto status

# Verify all defense layers and intel state — run after any install.
veto doctor

# Detect existing exposure across projects, caches, and agent surfaces.
veto scan

# Targeted follow-up commands for incident response.
veto quarantine-cache --dry-run   # add --purge only after reviewing candidates
veto audit-agent-surface
```

`veto help` lists every subcommand grouped by layer.

### Existing Exposure Scans

`veto scan` is the broad read-only audit. By default it scans
`~/projects` for manifests and lockfiles, known package-manager cache
roots for flagged package artifacts, and agent surfaces for persistence
or fetch-and-run hooks across Claude, Codex, Cursor, Sirene, MCP configs,
and launchd. Use negative flags only when you intentionally want to
narrow the sweep:

Project scanning covers npm-family, Python-family, Go, and Rust committed
dependency files: `package.json`, npm/pnpm/yarn lockfiles,
`requirements*.txt`, `constraints*.txt`, `pyproject.toml`, `uv.lock`,
`poetry.lock`, `pdm.lock`, `go.mod`, `go.sum`, `Cargo.toml`, and
`Cargo.lock`.

```sh
veto scan --json
veto scan --root ~/projects/work --no-caches
veto scan --no-projects --no-agent-surface  # cache exposure only
```

Cache scanning covers npm, pnpm, bun, pip, uv, poetry, Go module caches
(`$GOMODCACHE`, `$GOPATH/pkg/mod`, `~/go/pkg/mod`), and Cargo registry/git
caches (`$CARGO_HOME/registry`, `$CARGO_HOME/git`, or `~/.cargo/...`).

`veto quarantine-cache` runs the cache scanner and plans removals for
confirmed malicious cache artifacts. It defaults to dry-run; `--purge`
deletes only confirmed flagged artifacts after resolving symlinks and
verifying the target remains inside a known cache root. IOC-only residue,
such as `_npx` MCP cache entries without an intel hit, is reported for
manual review.

`veto audit-agent-surface` runs only the agent persistence audit. It does
not need a healthy intel store because it is checking local hook and MCP
configuration rather than package-intel matches.

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `VETO_CACHE_DIR` | `$XDG_CACHE_HOME/veto` | where intel snapshots live |
| `VETO_SOURCES` | `aikido,datadog,openssf,osv,pypa` | comma-separated source IDs to enable. Defaults are malware feeds. Opt-in CVE/vulnerability feeds: `ghsa` (GitHub Advisory DB), `rustsec` (crates.io), `govulndb` (Go modules), `gemnasium` (GitLab, multi-ecosystem) |
| `VETO_IOC_SOURCES` | (empty) | comma-separated host-level IOC feed IDs (opt-in): `abusech` (file hashes / C2 IPs / URLs), `misp` (CIRCL OSINT). When a feed supplies file-hash indicators, the cache scanner additionally SHA256-matches cached package archives against them |
| `VETO_ABUSECH_AUTH_KEY` | (unset) | free abuse.ch Auth-Key (https://auth.abuse.ch/) required by the `abusech` IOC feed; without it the feed logs once and no-ops |
| `VETO_LOG` | (info) | set `debug` for verbose logging |
| `VETO_PATH` | (set by install-preload) | consumed by the Layer 3 interposer |
| `VETO_GYP_TARBALL_SCAN` | (on) | install-time binding.gyp worm tarball inspection. `0`/`off`/`false` disables; `full` also fetches every resolved transitive (slower) |

### Refuse-opaque-by-default

`npm install https://evil.com/foo.tgz`, `pip install
git+https://evil.com/repo`, and `bun install user/repo` (npm's GitHub
shorthand) all bypass the package-registry name lookup — there's no
name to look up against. Veto's default policy refuses these
outright with a `[veto-policy]` source marker so they're
distinguishable from a malware-feed-driven block. Filesystem-path
specs (`./pkg`, `/abs/path`) still pass through — they don't pull
remote code on their own.

Exception: `cargo install/add --git` specs are not refused on sight — they
are cloned and scanned (see the Go and Cargo gating section above). All other
opaque specs (tarball URLs, `user/repo` shorthand) remain refused.

## mise PATH ordering

mise prepends its install dir(s) to PATH on `mise activate`. For
Layer 2 shims to win, let veto install its managed shell block:

```sh
veto install-shell
```

The block is idempotent and contains the PATH pinning hook plus pip/uv
package-age quarantine wrappers:

```sh
PIP_UPLOADED_PRIOR_TO=<3-days-ago> veto pip ...
UV_EXCLUDE_NEWER=<3-days-ago> veto uv ...
```

`veto doctor` detects mise (and asdf, pyenv, nvm) install dirs that
shadow Layer 2 shims, checks that the managed shell block exists, and
emits the `install-shell` fix inline.

If you'd rather not touch PATH ordering at all, Layer 4
(`install-wrappers`) sidesteps the issue entirely: it wraps the actual
binaries at their install paths, so PATH lookup order stops mattering.

## Threat model and fail-closed semantics

**Fail-closed guarantees** (the gate refuses the install in all of
these):

- **Flagged package**: any source flags it → exit 1, "install
  refused — package intelligence flagged …". Default sources flag
  malware; opt-in `ghsa` also flags ordinary vulnerable versions.
- **Opaque-spec install** (URL / git / tarball / `user/repo`
  github-shorthand): refused unconditionally → exit 1,
  `[veto-policy]` source. These specs bypass the package-registry
  name lookup and can carry payloads; there is no opt-in override.
- **Intel store cannot refresh** (every source failed, no cache):
  exit 70, "INTERNAL ERROR — intel refresh failed"
- **Intel store implausibly empty** (< 1000 reports total — aikido
  alone ships >120k): exit 70, "INTERNAL ERROR — intel store has
  only N reports"
- **Per-(source, ecosystem) drop below threshold**: a single feed's
  count cratering between refreshes (e.g. an MITM dropping Aikido's
  response, an upstream wedge) triggers per-bucket retention — the
  previous fetch's slice stays in the index instead of being silently
  replaced with a near-empty one. Threshold defaults to 50%; warn
  logs name the source.
- **Oversized intel payload**: any single feed body exceeding its
  per-source size cap (256 MiB for aikido/osv, 512 MiB for
  openssf/pypa, 1 GiB for opt-in ghsa) is rejected for that refresh —
  a compromised upstream cannot OOM veto by streaming a multi-GB body.
- **Manifest file present but unreadable / malformed** (`package.json`,
  `pyproject.toml`, `requirements.txt`, lockfiles): exit 70, "INTERNAL
  ERROR — install aborted fail-closed"
- **npm resolver pre-scan fails**: before `npm install`/`npm update`
  runs for real, veto asks npm to generate a lockfile in an isolated temp
  directory with scripts disabled. Resolver errors, timeouts, malformed
  generated lockfiles, or missing generated lockfiles abort the install
  fail-closed.
- **Claude Code hook crashes** (parser bug, malformed input): hook
  emits a "deny" with "INTERNAL ERROR in hook script"; if even that
  fails, exits 2 which Claude Code treats as a blocking error
- **Claude Code hook detects veto binary missing on PATH**: hook
  denies with a hard "DO NOT retry" message naming the mis-install
- **Layer 4 symlink identity check**: `install-wrappers` /
  `uninstall-wrappers` use strict physical-path identity (via
  `filepath.EvalSymlinks`) to decide "is this symlink ours" — an
  attacker-planted symlink whose target name merely contains "veto"
  is not accepted as a no-op, so `install-wrappers` will still
  overwrite it with the real veto wrapper.
- **Layer 4 `.veto-original` provenance**: a planted
  `<argv0>.veto-original` next to a veto shim is NOT trusted on its
  own — `findRealBinary` consults `wrappers.json` and refuses to exec
  a sibling whose parent path isn't a registered wrapper. A same-UID
  attacker dropping `~/.local/bin/npm.veto-original` cannot convert
  one tricked install into permanent gate-defeat.
- **Layer 2 `.veto-displaced` provenance**: when `install-shims --force`
  displaces a real binary that occupied a shim path (uv self-installs
  into `~/.local/bin/uv`), the displaced original is resolvable at exec
  time — but ONLY from inside the shim dir, veto's exclusive Layer 2
  territory. A `<pm>.veto-displaced` planted next to any other
  veto-pointing PATH entry is ignored, and a displaced file that
  resolves back into veto is skipped (fail closed) rather than exec'd
  into a loop.
- **Etag persistence**: each feed source writes the upstream etag
  ONLY after the body parses successfully. A transient malformed
  payload doesn't poison the cache — the next refresh re-downloads
  rather than 304-looping on a broken body.
- **Withdrawn-advisory filter**: OSV-format advisories with a
  `withdrawn` timestamp are dropped at ingest. A retracted MAL-*
  cannot keep refusing a clean package indefinitely; the entry
  remains in the feed for audit continuity but doesn't gate.

**Known limitations** (what veto cannot protect against):

- **SIP-protected binaries on macOS** (`/usr/bin/pip3`,
  `/usr/bin/python3 -m pip …`). `DYLD_INSERT_LIBRARIES` is stripped
  by dyld for `/usr/bin/*` and `/System/...`; the dir is also
  read-only so Layer 4 wrappers can't be installed there. Out of
  veto's reach by design — it's a command-layer scanner, not a
  kernel-level interposer. Non-SIP python (mise, pyenv, homebrew,
  uv-managed cpython) IS covered via the Layer 2 python shim and the
  Layer 4 wrappers, including every versioned `python3.X` alias on
  disk — only the system interpreter at `/usr/bin/python3` is
  unreachable. `install-wrappers` emits a clean
  `SKIP /usr/bin/<pm> — read-only filesystem (SIP-protected)` line
  for these paths and exits 0 (a previous version reported them as
  `FAIL`, aborting `install-all` even though no remediation exists).
  SIP-ness is classified by path, not just errno, so the end-of-run
  "needs sudo" hint never suggests `sudo veto install-wrappers --dir
  /usr/bin …` — sudo cannot bypass SIP.
- **Per-python-invocation cost** (intentional). Layer 4 now wraps
  every canonical `python` / `python3` / `python3.X` binary on disk
  — including uv's `~/.local/share/uv/python/cpython-*/bin/*` store
  — to close the uv-venv bypass (an `uv run python -c "..."`
  resolves the venv python by absolute path; without wrapping the
  canonical binary the call skipped Layer 2). Every python
  invocation now exec's through veto, which dispatches the `-m {pm}`
  fast-path and forwards everything else to the real interpreter
  before touching the intel store. The overhead is small (one
  binary load + a few syscalls) but real; the user explicitly
  accepted it as the cost of closing the bypass.
- **Linux `execl*` / `fexecve` / `execveat` coverage**: best-effort.
  The interposer exports LD_PRELOAD shadows for execl/execlp/execle/
  execvpe/fexecve/execveat, but glibc's internal `__execve` calls and
  statically-linked binaries bypass any libc-level interposer. Layers
  2 + 4 still catch these on Linux as long as PATH resolution flows
  through the shim or the real PM has been wrapped.
- **Toolchain upgrades wiping Layer 4 wrappers**. `brew upgrade node`
  re-installs the real npm binary on top of our symlink. `veto
  doctor` flags this; re-run `veto install-wrappers --force` after
  upgrades. If `brew cleanup` then prunes the now-dead `.veto-original`
  anchor (it removes dead symlinks under the prefix once an upgrade drops
  the old keg), the wrapper is *orphaned* — `<pm>` still points at veto
  but the real-binary pointer is gone. `install-wrappers` refuses to
  re-wrap an orphaned path — renaming the veto symlink onto
  `.veto-original` would only create a veto→veto exec loop — and `veto
  doctor` FAILs it. Restore the real binary first (`brew unlink <pkg> &&
  brew link --overwrite <pkg>`), then re-run `veto install-wrappers`.
- **Compromised upstream returning near-empty feeds**. The 1000-report
  floor catches the worst case (literally empty), but a feed that
  omits most malware while still returning hundreds of entries could
  slip through.
- **Malformed version strings over-block**. If a queried version or feed
  range bound cannot be parsed by the ecosystem comparator, veto refuses
  rather than risk under-blocking.
- **Resolver pre-scan is partial.** npm, pip/pip3, and `uv pip install` get
  isolated resolver probes for newly named packages. Project-level uv verbs,
  Poetry, PDM, Go, and Cargo rely on argv, manifests, and already-present
  lockfiles until a safe resolver mode is implemented for them.
- **Statically-linked binaries that bypass libc**. Theoretical; no
  real PM does this today.

### Verifying your install

Run `veto doctor` in a fresh terminal. It checks:

- `veto` resolves on PATH and is executable.
- The managed shell integration block exists in your detected shell rc.
- The shim directory is on PATH, and each PM shim wins the PATH
  lookup (no mise/homebrew binary shadowing it earlier). If a mise
  shadow is detected, the `veto install-shell` fix
  appears inline in the output. Shims that displaced a real binary
  (`<pm>.veto-displaced`) are validated too: the displaced original
  must be executable and must not resolve back into veto (a lost real
  binary FAILs loudly instead of passing as a healthy shim).
- The Claude Code Bash hook is wired in `~/.claude/settings.json`.
- Agent posture beyond Claude: Codex shell PATH policy, the current
  project's Cursor veto rule, and Sirene's launch PATH where inspectable.
- The native interposer env vars are exported and the library file
  exists.
- Layer 4 wrappers — every recorded wrapper still points at veto,
  its `.veto-original` sibling is intact, and that sibling resolves to a
  real binary rather than back to veto (a self-referential anchor is a
  veto→veto exec loop and FAILs). Discovered veto-pointing symlinks that
  wrappers.json does NOT cover get the same anchor verification —
  symlink direction alone is never trusted, so an orphaned wrapper
  (anchor pruned, real binary unreachable) FAILs instead of surveying
  green.
- The intel store is above the 1000-report sanity floor and was
  refreshed in the last 24 hours.

Each row is PASS / WARN / FAIL with a one-line fix. The command exits
1 if any row is FAIL — useful as a CI tripwire or a shell-rc check.
