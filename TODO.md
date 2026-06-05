# TODO

Actionable follow-ups moved out of the README so the README stays focused on
current user-facing behavior.

- Verify Linux end-to-end: interposer build, shell integration, and Layer 4
  wrapper discovery for common Linux installs, including mise/asdf-managed
  package-manager binaries.
- Phase 1.4.2 deferred: add e2e coverage for `execvpe`, `fexecve`, and
  `execveat` (Linux-only) by extending `cmd/veto/testdata/interpose_spawner`
  with cgo helpers and a `--mode` flag. The Phase 1.4.1 fix (synthetic
  envp via `snapshot_environ` + `rewrite_envp`) closes the actual
  security finding; this task only adds regression coverage for the
  three Linux-only exec variants. Best done from a Linux box / CI.
- Phase 1.6.2 deferred: route `pnpm dlx` / `yarn dlx` / `bun x` /
  `bun create` through `internal/packagemanager/exec.Manager` so the
  `--package=<spec>` flag is honored and trailing positionals after
  the spec are not over-gated. Today these verbs go through
  `jsspec.ParseInstallArgs` which treats every positional as a spec.
- Phase 1.6.5 partial: jsmanifest does NOT yet walk `workspaces`
  glob patterns recursively. The lockfile expanders pick up
  workspace-member deps in practice (the resolver writes them
  through), but the manifest path on a fresh-checkout monorepo
  misses them.
- Phase 1.6 followup: gate `jsspec.tryParseAlias` on
  `isLegalNpmName(name)` so `user/repo@npm:evil@1` is treated as
  github-shorthand (OpaqueRemote) rather than alias-unwrapped to
  `evil`. Minor precedence quirk; no known exploit path in argv.
- Phase 1.7.3 deferred: pip and uv resolver prescans should forward
  user-supplied `--index-url`, `--extra-index-url`, `--find-links`,
  `--keyring-provider`, `--override`, `--prerelease`, `--resolution`,
  `--python` flags so private-index installs prescan correctly, and
  should strip `--no-deps` / `--no-build-isolation` so the dry-run
  sees the full transitive set the real install will pull. Today
  the prescan synthesizes a fixed argv and silently misses these.
- Phase 1.7.4 deferred: `uv add` / `uv install` against a missing or
  stale lockfile should fall through to ResolverPreScan (synthesize
  a requirements input, run `uv pip compile`) instead of gating the
  pre-existing — now incomplete — lockfile. Real fail-OPEN against
  `uv add <new-malware>`.
- Phase 1.7.5 partial: pymanifest does NOT yet read
  `[tool.uv] dependencies / dev-dependencies / workspace.members`
  or `[tool.pdm.dev-dependencies]`. uv/pdm projects fall back to
  the lockfile path (covered) but a fresh checkout with no lockfile
  yet would miss these direct deps.
- Phase 1.8.2 deferred: cargo coverage still needs `publish` in
  ParseInstalls (it fetches + builds); `doc`, `package` added to
  ProjectPreflight (they run build.rs / proc-macros);
  `cargomanifest` registry classifier (non-crates-io `registry = ...`
  should be OpaqueRemote, mirroring cargolock); and `[workspace]`
  members expansion for monorepo Cargo.toml roots.
- binding.gyp worm (phantom-gyp/Miasma) mitigation — SHIPPED across three
  layers: `internal/gypscan` (pure detector), `internal/gypscan/tarball`
  (in-memory .tgz inspector), `internal/scan/gyp` (existing-exposure walker),
  plus install-hot-path wiring (existing-tree scan + `npm pack` tarball
  inspection) and the Claude Code hook. Remaining edges:
  - Tarball scan covers npm-family only (`npm pack`). pnpm/yarn/bun have their
    own fetch verbs (`pnpm pack`? `yarn pack` is local-only) — wire a
    per-PM safe tarball-fetch when their CLIs support a download-only pack of a
    registry spec. Today pnpm/yarn/bun installs get the existing-tree scan but
    not the incoming-tarball scan.
  - Default tarball scope is argv-direct packages; `VETO_GYP_TARBALL_SCAN=full`
    fetches every resolved transitive (one `npm pack` each — slow on big
    trees). Consider parallelizing the fetches, or scoping `full` to only the
    transitives NOT already present in node_modules, before promoting it to
    default.
  - GYP is python-ish, not JSON; the detector heuristics over text rather than
    parsing. A determined attacker could try to obfuscate the expansion across
    lines or via `includes:` of a second .gypi. Consider following `includes`
    references and normalizing whitespace before matching if an evasion variant
    appears in the wild.
  - The hook's cwd worm check assumes the install runs in cwd; an `npm install
    --prefix <dir>` would install elsewhere. Parse `--prefix`/`-C` in the hook
    and scan that tree instead.
  - P2 npm config/env prefix redirection (`gyp_target_dir.go`):
    `npm_config_prefix` / `.npmrc` `prefix=` can redirect the real install to
    a dir the argv parser doesn't see. Fix would resolve target roots from the
    same config inputs npm consumes (e.g. a non-executing
    `npm config get prefix`). Deferred — needs care to stay non-executing and
    cross-PM.
  - P2 local-path install inspection (`gyp_tarball.go`/gate):
    `npm install ./pkg` reaches npm without the gyp detector inspecting the
    local package. Fix would inspect the local dir / local `.tgz` via
    `internal/gypscan/tarball.Inspect` before exec. Deferred.
- Add an authenticated online lookup layer for vulnerability surfaces that do
  not fit the cached bulk-source model yet, especially Socket.dev vuln data and
  SafeDep PMG real-time package analysis.
- Add remaining safe resolver pre-scans where practical: project-level uv verbs,
  poetry, and pdm next for Python-family workflows, then Go/Cargo only if their
  tooling can resolve without executing project code.
- Decide whether IOC-only cache residue can be promoted from report-only to
  purge-safe quarantine rules.
- Choose and add an explicit license before public distribution.
