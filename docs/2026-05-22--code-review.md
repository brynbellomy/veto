# veto code review — 2026-05-22

~16k LoC Go + 380 LoC C interposer. The architecture is sound — four
defense layers, fail-closed policy, real-I/O tests over mocks, clean
separation between parsers, gate, store, and feed sources. Most of what
follows is real bugs, not stylistic noise. Findings prioritized by how
badly each one breaks the security model.

> Note: an earlier draft of this doc included findings against the
> `internal/daemon` package and `cmd/veto/{daemon,client}.go`. That code
> was removed before this final pass; daemon-only findings have been
> dropped.

## Critical — gate bypasses, fix soon

**B1. `.veto-original` sibling is trusted without provenance check.**
`cmd/veto/main.go:353-367` and `:411-414`. `findWrappedOriginal` accepts
any executable file at `<argv[0]>.veto-original` and execs it without
consulting `wrappers.json`. A same-UID attacker (the threat model — an
agent tricked into one bad install, or any unrelated user-process
compromise) can plant `~/.local/bin/npm.veto-original` and from that
point on every gated `npm` call runs the planted binary instead of real
npm. The gate decision is rendered moot for the install that allowed
the plant AND every subsequent gated call.
**Fix**: require `c.path` to appear in `wrappers.json`
(`loadWrapperState`+`state.has`) before honoring the sibling. Plant
attempts at non-registered locations fall through to PATH walk.

**B2. `python -m pip install …` (and `python -m uv`, `… pipx`, …) skips
veto entirely.** `cmd/veto/main.go:143-151`. `isShimName` matches exact
basenames — `python`/`python3` are not shimmed and the interposer's
PM_NAMES list doesn't include them either. This is the canonical install
form inside virtualenvs, Dockerfiles, and most CI scripts.
**Fix**: shim `python`/`python3` and re-dispatch when `argv[1] == "-m"`
and `argv[2]` is a known PM; add the same logic to `is_risky` in the C
interposer.

**B3. PyPI names are not PEP 503–normalized on either insert or
lookup.** `internal/intel/store.go:64-76` keys on raw `(ecosystem,
name)`; `internal/packagemanager/pyspec/pyspec.go:71`,
`osvschema.go:122/139`, `aikido.go:259`, `pypa.go`, `openssf.go` all
store names verbatim. PyPI treats `Evil_Pkg`, `evil-pkg`, `EVIL.pkg` as
equivalent — feeds and parsers do not. The standard typosquat shape
walks straight past the gate.
**Fix**: at every insertion path AND inside `store.Lookup`, when
`Ecosystem == EcosystemPyPI`, apply `strings.ToLower(strings.NewReplacer("_","-",".","-").Replace(name))`.
(npm is registry-lowercased so a defensive `ToLower` there is cheap
insurance.)

**B4. `pip install .` / `uv pip install -e ..` gates the literal name
`.`.** `internal/packagemanager/pyspec/pyspec.go:82-89`.
`isLocalPathSpec` checks `./`, `../`, `/`, `file:`, but not the bare
strings `.` or `..`. The gate looks up `("pypi", ".")` — misses —
allows.
**Fix**: extend `isLocalPathSpec` to match `spec == "." || spec == ".."`
exactly. Also fix `pdm`'s `--editable`/`-e` registered as
`flagsWithValues` — pdm uses it as a boolean, so its mere presence
silently swallows the next positional.

**B5. `uv tool install/run`, `uv run --with`, `npm exec` are routed to
veto then deliberately allowed.**
`internal/packagemanager/uv/uv.go:152-158` only recognizes
`add`/`sync`/`install`/`pip`. The C interposer (`veto_interpose.c:90`)
and Claude hook BOTH route `uv tool …` through veto — veto then sees an
unrecognized verb and passes through. The user-visible effect:
enforcement is wired up and silently turned off for the modern install
surface.
**Fix**: add `tool {install,run,upgrade}` and
`run --with`/`--with-requirements` to uv's parser; add `npm exec`
(npx-style) to npm's parser.

**B6. Interposer-recursion DoS when Layer 3 is installed but Layer 4
isn't.** `cmd/veto/main.go:329-341`. `execReal` calls
`syscall.Exec(realPath, …, os.Environ())` — preserving
`DYLD_INSERT_LIBRARIES` and `VETO_PATH`. With wrappers installed, the
basename of `realPath` is `npm.veto-original`, not in PM_NAMES, so the
interposer falls through. Without wrappers, basename is `npm`, the
interposer intercepts, rewrites to veto, veto calls execReal, infinite
loop until the user kills it. The current "install all four layers"
guidance hides this, but the install-preload subcommand advertises
Layer 3 as standalone.
**Fix**: in `execReal`, strip `VETO_PATH` and
`DYLD_INSERT_LIBRARIES`/`LD_PRELOAD` from the env passed to
`syscall.Exec`.

**Follow-up note (2026-06-04)**: the implemented mitigation preserves
`DYLD_INSERT_LIBRARIES`/`LD_PRELOAD` and strips `VETO_PATH` to break the
recursion loop. The strip is now verb-aware for Go: `go run`, `go
build`, `go test`, and other explicitly low-recursion-risk verbs preserve
`VETO_PATH` so Layer 3 remains armed in descendant processes, while `go
install`, `go generate`, `go tool`, unknown Go verbs, and PMs without an
`EnvRecursionPolicy` continue to strip by default.

## High — real bugs that degrade enforcement

**H1. Interposer `VETO_BYPASS` is presence-checked; Go side requires
literal `"1"`.** `veto_interpose.c:131` uses `if (getenv("VETO_BYPASS"))`
— so `VETO_BYPASS=0` disables Layer 3 silently while the hook
(`internal/hook/claudecode/claudecode.go:99`) still believes
enforcement is on.
**Fix**: `const char *v = getenv("VETO_BYPASS"); if (v && !strcmp(v, "1")) return NULL;`.

**H2. `VETO_BYPASS=1` is not honored by `runGate`.**
`cmd/veto/main.go:153-244`. The hook and the interposer check it; the
in-process gate (which is now the only gate path) does not. So the
documented `VETO_BYPASS=1 npm install foo` escape hatch is honored at
Layer 1 (hook) and Layer 3 (interposer) but silently ignored when the
shim routes through Layer 2 alone.
**Fix**: at the top of `runGate`, if `os.Getenv("VETO_BYPASS") == "1"`
skip straight to `execReal`.

**H3. Etag is persisted before the body is proven parseable (OSV,
PyPA, Aikido).** `osv.go:208-219`, `pypa.go:205-212`,
`aikido.go:216-223`. The fetch writes the etag, then attempts to parse.
If parse fails (transient malformed payload), the next refresh sends
`If-None-Match`, gets 304, re-parses the same bad payload from disk,
fails again — perma-failure until the operator wipes the cache.
**Fix**: write the etag only after `parseZip`/`parseTarball`/`parsePayload`
returns nil. Or on failure, delete the etag file before returning.

**H4. npm/yarn aliases and PEP 508 URL specs miss the name lookup.**
`internal/packagemanager/jsspec/jsspec.go:102-115` (`pkg@npm:real@v` →
gates `pkg`, installs `real@v`); `pyspec.go:113-127`
(`requests @ https://evil/x.tgz` → name becomes the full string, no
opaque flag set); `pyreq/pyreq.go:110-114` (any line starting with `-`
is dropped, so `-e git+https://evil/repo` in `requirements.txt` is
silently allowed).
**Fix**: detect `npm:` re-aliasing in the version slot and re-split;
detect ` @ ` separator in `pyspec.Parse` and route the right side
through `isOpaqueRemoteSpec`/`isLocalPathSpec`; special-case `-e
`/`--editable ` lines in `pyreq` instead of dropping them.

**H5. Manifest-driven git/URL/path deps are not flagged as opaque.**
`internal/packagemanager/jsmanifest/jsmanifest.go:97-106`: a
package.json value like `"foo": "git+https://evil"` passes through
`exactPin` and emerges as a clean `Install{Name:"foo"}` with no
`OpaqueRemote=true`. Same in `pymanifest/pymanifest.go:155-175` for
Poetry inline-table `{git=…}`/`{path=…}`/`{url=…}` deps.
**Fix**: run `isOpaqueRemoteSpec`/`isLocalPathSpec` against the version
string in `jsmanifest.appendDeps`; in `pymanifest.poetryDeps`, emit
`Install{OpaqueRemote:true}` whenever the inline table has
`git`/`url`/`path`/`source`.

**H6. `yarn` (bare) is not recognized as an install.**
`internal/packagemanager/yarn/yarn.go:14-18`. Yarn classic uses bare
`yarn` (no verb) to install from `package.json` + `yarn.lock`. Veto
sees no install verb → passthrough.
**Fix**: treat bare `yarn` or `yarn` + only flags as the implicit
install; emit `package.json`+`yarn.lock` manifest refs.

**H7. Linux LD_PRELOAD shadowing misses `execl*`, `execvpe`,
`fexecve`, `execveat`.** `veto_interpose.c:281-377`. glibc's `execl*`
family routes through internal `__execve`, not the public symbol we
shadow. C/Rust callers using `execl*` bypass Layer 3 on Linux. macOS's
`__DATA,__interpose` covers call sites, not symbols, so it's more
robust — but `fexecve`/`execveat` are still uncovered on both.
**Fix**: export `execl`/`execlp`/`execle` that re-marshal into the
interposed `execve`/`execvp`; add `execvpe`/`fexecve`/`execveat`. Or,
more honestly, document Linux as best-effort.

## Medium — drift hazards and design smells

**M1. Three independent PM lists.** `cmd/veto/main.go:143-151`
(`isShimName`), `shims.go:37` (`shimmedManagers`),
`install_wrappers.go:85` (`wrappedManagers`) — plus the C interposer's
`PM_NAMES`, plus claudecode's `shimmedPMs`. The comment in
install_wrappers calls this "a guard against drift"; it's the opposite.
**Fix**: one canonical slice consumed by all four sites; cross-language
regen step for the C list (or runtime-loadable from the Go binary).

**M2. OSV and OpenSSF sources have zero tests.**
`internal/intel/sources/osv/` (285 LoC) and
`internal/intel/sources/openssf/` (443 LoC) — the most complex sources,
with gob caches, etag retry, oversize protection, zip/tarball
streaming, and disk fallback. The `aikido` source has thorough coverage
of exactly these paths but the larger ones rely on it by analogy, not
in fact.

**M3. Inconsistent `errors` import inside `internal/intel/sources/`.**
`openssf.go` imports stdlib as `stderrors` alongside the go-utils
package; `pypa.go` aliases the go-utils package as `vetoerrors`;
`aikido.go`/`osv.go` use go-utils under the bare name `errors`. The
shapes diverge for no good reason. `cmd/veto/` is now consistent after
the daemon removal — finish the job in `sources/`.
**Fix**: pick one (go-utils as `errors`, stdlib aliased as `stderrors`
where actually needed) and apply across all four sources.

**M4. Cache poisoning at same-UID.** `~/.cache/veto/` is whatever the
user's umask gives it. A same-UID attacker can drop a forged
`parsed-*.gob` / `aikido/npm.json` that removes specific entries. The
50% drop-floor mitigates wipes but not equal-size mutated payloads.
**Fix**: `os.MkdirAll(cacheDir, 0o700)`; on parse, refuse files whose
mtime is newer than the source tarball (forces re-derive).

**M5. `pipx inject TARGET pkg1 pkg2 …` only gates TARGET.**
`internal/packagemanager/exec/exec.go:171-210` collects one positional.
Inject installs `pkg1 pkg2 …` into TARGET; veto looks up TARGET, which
is the local venv name.
**Fix**: collect all positionals after `inject`; same for multi-arg
`install`/`upgrade`.

**M6. Dead code in `store.Lookup`.** `internal/intel/store.go:151-155`
populates `exactVersionHits := map[*MalwareReport]struct{}{}` but the
dedup at line 164 uses a value comparison (`r.Version == ref.Version`)
— the map is built and never read. Correct result by accident.
**Fix**: delete the map, keep the comparison, document the dedup
intent.

**M7. yarn.lock parser caps at 8 MiB.**
`internal/packagemanager/jslock/jslock.go:298` `bufio.Scanner` with
`8*1024*1024`. Yarn berry lockfiles for sizeable monorepos exceed this
routinely. Silent truncation = silent fail-open.
**Fix**: `bufio.Reader.ReadString('\n')` with no cap, or detect
truncation and abort fail-closed.

**M8. Retention floor erodes across many refreshes.**
`internal/intel/store.go:61, 344-358`. The drop threshold is `0.5 *
previous`; "previous" updates each successful swap. A feed that returns
~51% of last time on each refresh halves the index every tick. The
gate-time invocation of `Refresh` (`main.go:197-217`) DOES recheck the
absolute floor (`minHealthyReportCount = 1000`) so lookups don't
silently return clean. But `veto sync` invocations don't recheck —
a daily CI cron would silently accept an eroded state.
**Fix**: in `runSync`, recheck `store.ReportCount() < minHealthyReportCount`
post-refresh. Or anchor retention against a max-seen baseline rather
than the immediately-previous count.

## Low — smells, dead code, docs

- `ErrNotMalware` declared in `osvschema.go:84`, never returned. Dead
  exported symbol.
- `argv.FirstNonFlag` / `CollectPositionals` (`argv.go:24,77`) used only
  in tests; all production paths use the `*WithTable` variants. Drop or
  rename the variants to drop the suffix.
- `pip.New("")` fallback path (`pip.go:63-68`) dead — only ever called
  with `"pip"` / `"pip3"`.
- `var _ intel.Source = nil` (`doctor.go:625-628`) is an import-keeper;
  the import is held elsewhere. Delete.
- `writeAtomic` redefined in both `aikido.go:274` and `pypa.go:302`;
  same idiom inlined in `osv.go`/`openssf.go`. Lift one shared helper.
- `isLocalPathSpec` / `isOpaqueRemoteSpec` defined separately in
  `jsspec` and `pyspec` and **already diverged**: jsspec covers
  `git://`, `github:`, `gist:`, `bitbucket:`, `gitlab:`, and `user/repo`
  shorthand; pyspec doesn't. Add an ecosystem-tagged predicate to a
  shared `specshape` package.
- `.mockery.yaml` + `make generate-mocks` target with zero mock files
  in the tree. The store_test comment endorses hand-stubs as the design
  choice; remove mockery scaffolding so no one re-introduces mocks.
- `gate.Gate.WithLogger` exists because `gate.New` takes no logger;
  both call sites immediately chain it. Just take a logger in `New`.
- `gate_test.go:138-145` docstring says "manifest expansion is a
  documented @@TODO" — manifest expansion is fully implemented and
  tested in the same file.
- `@@TODO` markers in `pymanifest.go:18` (PEP 508 markers) and
  `pyreq.go:94` (backslash continuations) — either link an issue or
  commit to "won't do."

## Suggested cut order if you're triaging

If you have a day, I'd do **B1 → B2 → B3 → B5 → B6 → H1 → H2 → H3 →
H4 → H5**. That's the entire user-visible bypass surface plus the
etag-poison correctness bug. Most fixes are ~30 lines or less; the
rest is tests. The drift hazard (M1) is tomorrow's bypass — would
refactor it in a follow-up branch.
