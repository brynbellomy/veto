# veto

A command-level malware scanner for package managers. Aggregates intel
from four default upstream feeds (Aikido, OpenSSF malicious-packages,
OSV, PyPA advisory-db), supports optional GitHub Advisory Database
CVE/GHSA blocking, deduplicates, and refuses to let an install proceed
if any source flags the requested (package, version) tuple — honoring
the advisory's recorded version pins or affected ranges, with an
unbounded "all versions" fallback for advisories that don't narrow it
down.

**Status:** ready for colleague use on macOS. Linux untested in this
revision; the C interposer should build but layer 4's mise/asdf
discovery paths haven't been verified on a Linux box.

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
# which fast-paths every non-`-m {pm}` invocation back to real python:
python -m pip install chai-as-upgraded                        # refused
python3 -m uv pip install chai-as-upgraded                    # refused

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

## Quick install (60 seconds)

```sh
git clone https://github.com/brynbellomy/veto.git
cd veto
make install                                # builds → ~/.local/bin/veto
veto install-all --force                    # shims, shell block, hook,
                                           # interposer, wrappers, sync, doctor
```

`install-all` builds `libveto_interpose.dylib`/`.so` with `make interposer`
when needed. Then `source ~/.zshrc` (or open a new terminal) for the
managed shell block and interposer env vars to take effect.

`install-all` supports `--skip-wrappers` for integrators that install the
user-scoped layers (shims, shell rc, Claude hook, preload, intel, doctor)
as the regular user and run `veto install-wrappers` separately under
elevation. It returns structured exit codes so wrapping scripts can route
remediation without parsing human-readable output:

| Exit | Meaning |
|---|---|
| `0` | every requested step succeeded |
| `10` | a user-scoped layer failed (shims/shell/hook/preload/intel/doctor) |
| `20` | the wrappers step skipped one or more candidate dirs because the current (non-root) user can't write to them — retry under sudo |
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

Optional broad vulnerability feeds can also be enabled for teams that
want install-time CVE/GHSA blocking. They are intentionally separate
from the default malware feed set because they block ordinary vulnerable
versions, not only active supply-chain malware.

## Architecture

```
intel/             ← parent: Source interface, MalwareReport, Store
intel/normalize.go ← PEP 503 + npm name normalization at lookup + ingest
intel/range.go     ← VersionRange + per-ecosystem InRange comparator
                     (semver via Masterminds/semver for npm/Go/crates.io;
                     PyPI over-blocks bounded ranges with a debug log —
                     no PEP 440 today)
intel/sources/
  aikido/          ← https://malware-list.aikido.dev (implemented)
  openssf/         ← github.com/ossf/malicious-packages (implemented)
  osv/             ← osv.dev MAL-* advisories (implemented)
  pypa/            ← github.com/pypa/advisory-database (PyPI; implemented)
  ghsa/            ← github.com/github/advisory-database (opt-in CVE/GHSA)
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
  including pre-release ordering. PyPI bounded ranges are not yet
  implemented (no current feed entries use them) and over-block when
  encountered — see Known Limitations.
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

**Live transitive coverage via lockfiles and npm resolver pre-scan.**
When an install verb runs in a supported npm-family or Python-family
project with a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`), veto parses the
full resolved transitive tree and gates every (name, version) tuple in
it — not just the verb's explicit argv. For npm install-family
commands, veto also runs the real npm resolver first in an isolated
temp copy with
`--package-lock=true --package-lock-only --ignore-scripts --audit=false --fund=false`, then
gates the generated `package-lock.json`/`npm-shrinkwrap.json` before the
real install is allowed to run. If the resolver probe fails, does not
produce an expected lockfile, or the generated lockfile does not include
the argv-named packages, veto aborts fail-closed.

Go and Cargo phase-1 live gating covers fetch/mutate commands that can
introduce or download dependency code (`go get`, `go install`, remote
`go run pkg@version`, `go mod download`, `go mod tidy`, `cargo add`,
`cargo update`, `cargo fetch`, and `cargo install`). Build/test/run
preflight over already-present project state is intentionally left for
phase 2.

**Fail-closed defaults.** Per-source malware feeds are fetched
concurrently with etag-based caching in `~/.cache/veto/`.
On network outage the last good snapshot is used; if zero sources
succeed on the very first run, the veto refuses installs rather
than fail open. A sanity floor of 1000 reports total catches the
"every feed returned []" case loudly.

## Usage

```sh
# Gate an install (same shape as safe-chain's CLI).
veto npm install lodash         # → exec real npm
veto npm install chai-as-upgraded
# veto: install refused — package intelligence flagged the following:
#   - chai-as-upgraded@<any> (ecosystem: npm)
#       [aikido] MALWARE

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

Project scanning currently covers npm-family, Python-family, Go, and
Rust committed dependency files: `package.json`, npm/pnpm/yarn lockfiles,
`requirements*.txt`, `constraints*.txt`, `pyproject.toml`, `uv.lock`,
`poetry.lock`, `pdm.lock`, `go.mod`, `go.sum`, `Cargo.toml`, and
`Cargo.lock`.

```sh
veto scan --json
veto scan --root ~/projects/work --no-caches
veto scan --no-projects --no-agent-surface  # cache exposure only
```

`veto quarantine-cache` runs the cache scanner and plans removals for
confirmed malicious cache artifacts. It defaults to dry-run; `--purge`
deletes only confirmed flagged artifacts after resolving symlinks and
verifying the target remains inside a known cache root. IOC-only residue,
such as `_npx` MCP cache entries without an intel hit, is reported but
not purged by the MVP.

`veto audit-agent-surface` runs only the agent persistence audit. It does
not need a healthy intel store because it is checking local hook and MCP
configuration rather than package-intel matches.

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `VETO_CACHE_DIR` | `$XDG_CACHE_HOME/veto` | where intel snapshots live |
| `VETO_SOURCES` | `aikido,openssf,osv,pypa` | comma-separated source IDs to enable; add `ghsa` to opt into broad GitHub Advisory Database CVE/GHSA blocking |
| `VETO_LOG` | (info) | set `debug` for verbose logging |
| `VETO_BYPASS` | (unset) | prepend `VETO_BYPASS=1 ` to skip the gate for one invocation |
| `VETO_ALLOW_OPAQUE` | `0` | set `1` to opt URL/git/tarball installs through the gate (refused by default) |
| `VETO_PATH` | (set by install-preload) | consumed by the Layer 3 interposer |

### Refuse-opaque-by-default

`npm install https://evil.com/foo.tgz`, `pip install
git+https://evil.com/repo`, and `bun install user/repo` (npm's GitHub
shorthand) all bypass the package-registry name lookup — there's no
name to look up against. Veto's default policy refuses these
outright with a `[veto-policy]` source marker so they're
distinguishable from a malware-feed-driven block. Filesystem-path
specs (`./pkg`, `/abs/path`) still pass through — they don't pull
remote code on their own.

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
  github-shorthand): refused by default → exit 1,
  `[veto-policy]` source. Set `VETO_ALLOW_OPAQUE=1` to opt in
  after independently verifying the source.
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
- **Etag persistence**: each feed source writes the upstream etag
  ONLY after the body parses successfully. A transient malformed
  payload doesn't poison the cache — the next refresh re-downloads
  rather than 304-looping on a broken body.
- **Withdrawn-advisory filter**: OSV-format advisories with a
  `withdrawn` timestamp are dropped at ingest. A retracted MAL-*
  cannot keep refusing a clean package indefinitely; the entry
  remains in the feed for audit continuity but doesn't gate.

**Known limitations** (what veto cannot protect against):

- **Socket and SafeDep PMG are not cached bulk sources yet.** Socket's
  public vuln path is a website/API surface, and PMG queries SafeDep's
  real-time analysis service per package. Those are good candidates for
  a future authenticated online lookup layer, but veto does not scrape
  them into the cached source set.

- **SIP-protected binaries on macOS** (`/usr/bin/pip3`,
  `/usr/bin/python3 -m pip …`). `DYLD_INSERT_LIBRARIES` is stripped
  by dyld for `/usr/bin/*` and `/System/...`; the dir is also
  read-only so Layer 4 wrappers can't be installed there. Out of
  veto's reach by design — it's a command-layer scanner, not a
  kernel-level interposer. Non-SIP python (mise, pyenv, homebrew) IS
  covered via the Layer 2 python shim — only the system interpreter
  at `/usr/bin/python3` is unreachable.
- **Linux `execl*` / `fexecve` / `execveat` coverage**: best-effort.
  The interposer exports LD_PRELOAD shadows for execl/execlp/execle/
  execvpe/fexecve/execveat, but glibc's internal `__execve` calls and
  statically-linked binaries bypass any libc-level interposer. Layers
  2 + 4 still catch these on Linux as long as PATH resolution flows
  through the shim or the real PM has been wrapped.
- **Toolchain upgrades wiping Layer 4 wrappers**. `brew upgrade node`
  re-installs the real npm binary on top of our symlink. `veto
  doctor` flags this; re-run `veto install-wrappers --force` after
  upgrades.
- **Compromised upstream returning near-empty feeds**. The 1000-report
  floor catches the worst case (literally empty), but a feed that
  omits most malware while still returning hundreds of entries would
  slip through. Track-and-alert on report-count drops is future work.
- **PyPI bounded-range advisories over-block**. The comparator falls
  back to "over-block" (refuse the install) with a debug log rather
  than under-block — safe posture but a known precision gap until PEP
  440 range matching lands.
- **Resolver pre-scan is npm-only today.** Existing lockfiles are gated
  for live npm-family, Python-family, Go, and Cargo install/fetch
  commands, but only npm currently gets a temp-dir resolver probe for
  newly named packages. Other ecosystems still rely on argv,
  manifests, and already-present lockfiles until their safe resolver
  modes are wired in.
- **Go and Cargo build/test/run preflight is phase 2.** `go build`,
  `go test`, local `go run`, `cargo build`, `cargo test`, and local
  `cargo run` still pass through today; phase 1 gates dependency
  fetch/mutate commands only.
- **Statically-linked binaries that bypass libc**. Theoretical; no
  real PM does this today.

### Verifying your install

Run `veto doctor` in a fresh terminal. It checks:

- `veto` resolves on PATH and is executable.
- The managed shell integration block exists in your detected shell rc.
- The shim directory is on PATH, and each PM shim wins the PATH
  lookup (no mise/homebrew binary shadowing it earlier). If a mise
  shadow is detected, the `veto install-shell` fix
  appears inline in the output.
- The Claude Code Bash hook is wired in `~/.claude/settings.json`.
- The native interposer env vars are exported and the library file
  exists.
- Layer 4 wrappers — every recorded wrapper still points at veto
  and its `.veto-original` sibling is intact.
- The intel store is above the 1000-report sanity floor and was
  refreshed in the last 24 hours.

Each row is PASS / WARN / FAIL with a one-line fix. The command exits
1 if any row is FAIL — useful as a CI tripwire or a shell-rc check.

## License

TBD (planning open source once the design has settled).
