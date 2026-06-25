# Python-shim stall postmortem (veto-dzk epic)

Date: 2026-06-23
Affected: any host where `install-wrappers` recorded `~/.local/bin/python*` paths AND `~/.local/bin/python*.veto-original` symlinks resolved back to `~/.local/bin/veto`.
Resolved by: commit `12d832b` (install-shims scrub), commit `19e55c6` (doctor flag), commit `6d76cff` (exec-resolver self-reference guard). The follow-up convergence epic (veto-76f) folded the standalone `repair-shims` recovery command into `install-shims` and removed it as a top-level command.

## Symptom

`python3 -c 'print(1)'` invoked through `~/.local/bin/python3` would never produce output. The process stayed as `veto` (lsof confirmed `txt = ~/.local/bin/veto`), burning ~35% CPU per stuck process. On a multi-call host (pyright's introspection helper, subprocess.run benchmarks, etc.) processes accumulated and the machine climbed toward 100% load.

Reported from inside Claude Code's Bash tool spawn context; user noted the same `~/.local/bin/python3 -c 'print(1)'` invocation worked from an interactive shell and from sirene-spawned shells.

## What we initially thought the differential was

The bead listed five hypotheses to explain "stalls in Claude Code Bash but works elsewhere":

1. `loadConfig()` (viper) hangs on file IO or env-var parsing.
2. `syscall.Exec` fails silently — stderr might be closed/redirected.
3. `findRealBinary` PATH walk bug when every candidate is veto-pointing.
4. Bash-tool spawn env missing something veto needs.
5. `DYLD_INSERT_LIBRARIES` interposer dylib causing recursion (but `sanitizedEnv` should strip `VETO_PATH` for the child).

The framing implied the bug was env-dependent (otherwise it would reproduce everywhere).

## What the differential actually was

Not the spawn context. The bug reproduces in **any** shell whose `findRealBinary` traversal hit the on-disk shape:

- `~/.local/bin/python3.veto-original` is a symlink to `~/.local/bin/veto` (self-referential).
- `wrappers.json` has `~/.local/bin/python3` listed (because `install-wrappers` recorded it).
- `~/.local/bin` is first in `PATH`.

Under those conditions, `findRealBinary` enters an exec loop. Hypothesis (3) was correct — but it took stderr-bypass instrumentation (file-based logging, since stderr inside the loop was discarded between exec generations) to bisect to the specific path.

The reason it _seemed_ spawn-context dependent: the user's interactive shell evidently had a slightly different `PATH` or a stronger early entry that resolved python3 before `~/.local/bin/python3`. Inside Claude Code's Bash tool, `~/.local/bin` was first and the loop fired immediately.

## Root cause

`findRealBinary` has two resolution paths for the wrapped-original lookup:

1. **argv[0] lookup** (when `os.Args[0]` contains a slash): `findWrappedOriginal` checks the registry, locates `<argv[0]>.veto-original`, and **runs an `isSelfReferential` guard** before returning. If the sibling resolves through `EvalSymlinks` back to veto's own executable, it is rejected — the PATH walk takes over as fallback.

2. **PATH walk** (when `os.Args[0]` is a bare name like `python3`): for each candidate that itself resolves to veto, the loop checks if a `<candidate>.veto-original` exists, the wrap site is registered, and the sibling is executable. **Before the fix, this branch did NOT run `isSelfReferential`.** Any sibling that survived the executable check was returned.

When `~/.local/bin/python3.veto-original` was a symlink to `~/.local/bin/veto` itself, `os.Stat` (which follows symlinks) reported it as executable, and the PATH-walk returned it. `execReal`'s `syscall.Exec` then ran veto-as-python3 again — same argv, same env, same outcome — forever.

## Reproducer (works / stalls pair)

Stalls (pre-fix on bryn's box):

```
$ env | grep -E "PATH|VETO|DYLD"
PATH=/Users/.../.local/bin:/opt/homebrew/bin:...
VETO_PATH=/Users/.../.local/bin/veto
DYLD_INSERT_LIBRARIES=/Users/.../.local/lib/libveto_interpose.dylib
$ timeout 5 ~/.local/bin/python3 -c 'print(1)' ; echo "exit=$?"
exit=124
```

Works (with `/opt/homebrew` ahead of `~/.local/bin`, or with the fix):

```
$ timeout 5 ~/.local/bin/python3 -c 'print(1)' ; echo "exit=$?"
1
exit=0
```

## Why both runtime and on-disk fixes ship together

The runtime guard (`isSelfReferential` in the PATH-walk branch) is what makes the bug unreproducible going forward. But the on-disk shape — stray `*.veto-original` siblings in a Layer 2 shim dir — is a Layer-2 invariant violation independent of the loop bug:

- Layer 2 shims (install-shims output) MUST NOT have `.veto-original` siblings. Those are owned by Layer 4 wrap sites and registered in `wrappers.json` with absolute paths.
- The siblings on bryn's box were artifacts of an older install run that didn't separate the two layers cleanly.

So the response was three changes:

1. **`install-shims` scrubs `*.veto-original` siblings** on every run as part of its convergence pass.
2. **`veto doctor` flags any `*.veto-original` entry** in the shim dir as `FAIL`, naming the exact path and pointing at `veto install-all`.
3. **`findRealBinary`'s PATH-walk branch** runs `isSelfReferential` against any sibling it would otherwise return, mirroring `findWrappedOriginal`'s long-standing guard.

(1) and (2) prevent the bad state from accumulating. (3) breaks the loop even if the bad state somehow exists.

(An earlier iteration of veto shipped this fix alongside a standalone `veto repair-shims` command. The follow-up convergence epic (veto-76f) folded that recovery surface into `install-shims` itself — the scrub now runs every install pass — and removed `repair-shims` to keep `install-all` the single command users need.)

## Recovery (existing installs)

If `veto doctor` reports stray `*.veto-original` siblings (or any other Layer 2 / Layer 4 drift), run:

```
veto install-all
```

The convergence passes in `install-shims` (scrubs stale siblings, prunes shim-dir entries from `wrappers.json`) and `install-wrappers` (prunes stale entries whose path or sibling is gone, re-classifies candidates at wrap time) reconcile the layers in a single pass. Idempotent; safe to re-run.

If a host already has a stuck `veto`-as-python3 process from before the fix:

```
pkill -9 -f 'python3'
```

Then upgrade and re-run install:

```
make install
veto install-all
veto doctor   # expect no stray-sibling FAILs
```

## What we learned

- Debugging an exec loop with stderr-only instrumentation is unreliable: stderr writes between exec generations are throw-away unless they survive the kernel discarding the address space (they do not). File-based logging (`/tmp/<name>.log`) is the dependable channel for these cases.
- "Reproduces in spawn context X but not Y" is a tempting framing that can hide a deterministic on-disk bug. The actual env differential was a PATH ordering quirk, not a missing variable.
- When two code paths implement "the same check," one of them is silently weaker — usually the less-recently-touched one. The argv[0] branch in `findWrappedOriginal` had `isSelfReferential` since the discovery-side fix landed; the PATH-walk branch was extended for the "every PATH entry has been wrapped" case but didn't inherit the same guard. Now they agree.

## Regression tests

- `TestFindRealBinary_RejectsSelfReferentialSiblingInPathWalk` (in `cmd/veto/install_wrappers_test.go`) reproduces the exact on-disk shape (python3 symlink to test binary, registered, self-ref sibling) and asserts `findRealBinary` returns "not found in PATH" rather than the looping sibling.
- `TestScrubVetoOriginalSiblings_*` + `TestRunInstallShims_ScrubsStaleSiblings` + `TestRunRepairShims_HappyPath` (in `cmd/veto/shims_test.go`) cover the install-shims scrub and the standalone repair command.
- `TestCheckStaleShimSiblings_*` (in `cmd/veto/doctor_test.go`) covers the doctor row that surfaces the invariant violation.
