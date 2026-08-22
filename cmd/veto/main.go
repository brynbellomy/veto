// Command veto is a command-level malware scanner for package-manager
// invocations.
//
// Usage:
//
//	veto <pm> <pm-args...>     gate an install command, then exec the real PM
//	veto test <pm> <pm-args...>  print the gate's verdict; execute nothing
//	veto sync                  refresh the intel store from all sources
//	veto status                show source health and store size
//	veto update                self-update the veto binary (via go install)
//	veto help                  print this message
//
// The "<pm> <pm-args...>" form is the same shape safe-chain uses, so shims
// can route invocations transparently.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
	"github.com/brynbellomy/veto/internal/intel/sources/datadog"
	"github.com/brynbellomy/veto/internal/intel/sources/gemnasium"
	"github.com/brynbellomy/veto/internal/intel/sources/ghsa"
	"github.com/brynbellomy/veto/internal/intel/sources/govulndb"
	"github.com/brynbellomy/veto/internal/intel/sources/hades"
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
	"github.com/brynbellomy/veto/internal/intel/sources/pypa"
	"github.com/brynbellomy/veto/internal/intel/sources/rustsec"
	"github.com/brynbellomy/veto/internal/ioc"
	"github.com/brynbellomy/veto/internal/ioc/sources/abusech"
	"github.com/brynbellomy/veto/internal/ioc/sources/misp"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/bun"
	"github.com/brynbellomy/veto/internal/packagemanager/cargo"
	"github.com/brynbellomy/veto/internal/packagemanager/cargolock"
	"github.com/brynbellomy/veto/internal/packagemanager/cargomanifest"
	pmexec "github.com/brynbellomy/veto/internal/packagemanager/exec"
	"github.com/brynbellomy/veto/internal/packagemanager/golang"
	"github.com/brynbellomy/veto/internal/packagemanager/gomod"
	"github.com/brynbellomy/veto/internal/packagemanager/jslock"
	"github.com/brynbellomy/veto/internal/packagemanager/jsmanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
	"github.com/brynbellomy/veto/internal/packagemanager/pdm"
	"github.com/brynbellomy/veto/internal/packagemanager/pip"
	"github.com/brynbellomy/veto/internal/packagemanager/pipreport"
	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
	"github.com/brynbellomy/veto/internal/packagemanager/pnpm"
	"github.com/brynbellomy/veto/internal/packagemanager/poetry"
	"github.com/brynbellomy/veto/internal/packagemanager/pylock"
	"github.com/brynbellomy/veto/internal/packagemanager/pymanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/pyreq"
	"github.com/brynbellomy/veto/internal/packagemanager/uv"
	"github.com/brynbellomy/veto/internal/packagemanager/yarn"
)

const (
	exitOK       = 0
	exitUsage    = 64
	exitRefused  = 1
	exitInternal = 70
	// exitInstallAllLayerFail fires when a user-scoped install-all layer
	// (shims / shell rc / Claude hook / preload interposer / intel sync /
	// doctor) returns non-zero. It distinguishes "the parts the current
	// user owns broke" from a wrappers-only failure so integrator scripts
	// can route remediation accordingly.
	exitInstallAllLayerFail = 10
	// exitInstallAllNeedsRoot fires when install-all finished every
	// user-scoped layer cleanly but the wrappers step skipped one or more
	// candidate paths because the candidate dir is not writable by the
	// current (non-root) user. Caller can retry the wrappers step under
	// sudo without re-running the user-scoped layers. Distinct from a
	// genuine wrappers failure (30).
	exitInstallAllNeedsRoot = 20
	// exitInstallAllWrappersFail fires when the wrappers step had write
	// access (or we are already root) and still hit a real failure —
	// rename/symlink error, partial-state collision, etc. This is the
	// "something is actually wrong" code; elevation will not fix it.
	exitInstallAllWrappersFail = 30
	// syncTimeout bounds a full refresh across all sources. OpenSSF alone can
	// take ~10s on first sync (35 MB tarball + 454k entries); allow generous
	// headroom so the first-time experience isn't surprising. Subsequent
	// refreshes short-circuit via etag in milliseconds.
	syncTimeout = 5 * time.Minute

	// resolverPreScanTimeout bounds package-manager dry resolver probes. These
	// touch the registry but do not install packages or run lifecycle scripts.
	resolverPreScanTimeout = 2 * time.Minute

	// minHealthyReportCount is the sanity floor below which we treat the
	// intel store as broken and refuse to gate. Aikido alone publishes
	// >120k npm entries today; OpenSSF and OSV add hundreds of thousands
	// more. A value under this floor means either every source is empty,
	// a CDN returned [] for every feed, or the user pointed VETO_SOURCES
	// at a non-source name and got the NopSource fallback. None of these
	// states are safe to gate against.
	minHealthyReportCount = 1000
)

func main() {
	args := os.Args[1:]
	// Shim dispatch: when invoked as a symlink whose basename matches a
	// known package manager (e.g. ~/.local/bin/npm → veto), prepend the
	// PM name so `npm install foo` behaves like `veto npm install foo`.
	// This is the integration path for Codex and any other agent/CI that
	// doesn't expose a per-tool hook protocol.
	if self := filepath.Base(os.Args[0]); isShimName(self) {
		// Special-case python/python3: the only invocation form we gate
		// is `python -m {pip,uv,pipx,poetry,pdm,pip3}`. Every other
		// invocation (running scripts, REPLs, `-c "..."`, `-m
		// http.server`, `-V`, ...) must dispatch fast and transparently
		// to the real python. See pythonDashMTarget() for the
		// classification details, and the python-m branch below for the
		// rewrite that lets the existing gate logic handle the PM lookup
		// while still exec'ing python (not the PM directly) on the allow
		// path.
		if isPythonBasename(self) {
			if pm, ok := pythonDashMTarget(args); ok {
				// `python -m pip install foo` → route through veto as if
				// the user had typed `pip install foo`. We thread the
				// original (python, -mform, ...) invocation through env
				// so runGate's allow-path exec rebuilds it instead of
				// exec'ing the PM directly — `python -m pip` resolves
				// pip relative to this python interpreter (venv scope),
				// and exec'ing pip from PATH would break that contract.
				os.Setenv(pythonDashMEnvOriginal, self)
				rest := args[2:] // drop "-m" and the PM name
				args = append([]string{pm}, rest...)
			} else {
				// Not a gated invocation — defer to real python without
				// touching args. We resolve via the same PATH walk used
				// for PMs (skipping veto-pointing entries) so a python
				// shim chain doesn't loop.
				cfg, err := loadConfig()
				if err != nil {
					fmt.Fprintf(os.Stderr, "veto: load config: %v\n", err)
					os.Exit(exitInternal)
				}
				os.Exit(execReal(cfg, self, args))
			}
		} else {
			args = append([]string{self}, args...)
		}
	}
	os.Exit(run(args))
}

// pythonDashMEnvOriginal carries the original python basename
// ("python" or "python3") from main() through runGate into the
// post-decision exec so the allow path re-invokes `<python> -m <pm>
// …` instead of `<pm> …` directly. `python -m pip` resolves pip
// against the running interpreter (matters for venvs and shebangless
// Dockerfile installs) — exec'ing pip from PATH would silently break
// that resolution. Env is the simplest threading channel that survives
// the runGate signature without ballooning it.
const pythonDashMEnvOriginal = "VETO_PYTHON_M_ORIGINAL"

// pythonDashMTargets is the set of `-m` module names that, when invoked
// via `python -m <module>`, count as package-manager calls we want to
// gate. Deliberately small: `-m venv`, `-m http.server`, `-m unittest`,
// and the many other legitimate uses of `-m` must pass through
// untouched.
var pythonDashMTargets = map[string]string{
	"pip":    "pip",
	"pip3":   "pip3",
	"uv":     "uv",
	"pipx":   "pipx",
	"poetry": "poetry",
	"pdm":    "pdm",
}

// pythonDashMTarget reports whether args describes a `python -m <pm>
// …` invocation we should gate, returning the resolved PM name. The
// caller is expected to have already verified the invoking basename is
// "python" or "python3". `args` here is the python interpreter's own
// argv tail (everything after argv[0]).
//
// Accepts:
//
//	-m <pm> ...                      (canonical)
//	-m<pm> ...                       (no space — valid CPython syntax)
//	<no-arg-flag-bundle> -m <pm> ... (e.g. -I -m pip, -IES -m pip)
//	<no-arg-flag-bundle> -m<pm> ...
//
// Pre-`-m` flag bundles are the union of CPython's no-argument short
// options: -b -B -d -E -h -i -I -O -P -q -s -S -u -v -V -x -? .
// Options that take values (-c CMD, -m MOD, -W ARG, -X ARG) and any
// long option (--check-hash-based-pycs, …) bail conservatively because
// they could conceal arbitrary code or shift the position of -m.
func pythonDashMTarget(args []string) (string, bool) {
	const noArgShortFlags = "bBdEhiIOPqsSuvVxX?"

	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			return "", false
		}
		if tok == "--" {
			return "", false
		}
		// `-m<pm>` (no space).
		if strings.HasPrefix(tok, "-m") && len(tok) > 2 {
			pm, ok := pythonDashMTargets[tok[2:]]
			return pm, ok
		}
		if tok == "-m" {
			if i+1 >= len(args) {
				return "", false
			}
			pm, ok := pythonDashMTargets[args[i+1]]
			return pm, ok
		}
		// Long options bail — we don't model whether they consume a value.
		if strings.HasPrefix(tok, "--") {
			return "", false
		}
		// Short-flag bundle: every char after the leading dash must be in
		// the no-argument set. Otherwise bail (the rune might denote
		// a value-taking short option like -c / -W / -X).
		for _, r := range tok[1:] {
			if !strings.ContainsRune(noArgShortFlags, r) {
				return "", false
			}
		}
	}
	return "", false
}

func run(args []string) int {
	logger := newLogger()

	if len(args) == 0 {
		printUsage(os.Stderr)
		return exitUsage
	}

	cfg, err := loadConfig()
	if err != nil {
		logger.Error().Err(err).Msg("load config")
		return exitInternal
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return exitOK
	case "version", "--version", "-v":
		return runVersion(os.Stdout)
	case "test":
		return runVerdict(logger, cfg, args[1:])
	case "sync":
		return runSync(logger, cfg)
	case "status":
		return runStatus(logger, cfg)
	case "update":
		return runUpdate(logger, cfg, args[1:])
	case "install-shims":
		return runInstallShims(logger, cfg, args[1:])
	case "uninstall-shims":
		return runUninstallShims(logger, args[1:])
	case "hook":
		return runHook(logger, args[1:])
	case "install-claude-hook":
		return runInstallClaudeHook(logger, args[1:])
	case "uninstall-claude-hook":
		return runUninstallClaudeHook(logger, args[1:])
	case "install-codex":
		return runInstallCodex(logger, cfg, args[1:])
	case "install-cursor":
		return runInstallCursor(logger, cfg, args[1:])
	case "install-shell":
		return runInstallShell(logger, args[1:])
	case "uninstall-shell":
		return runUninstallShell(logger, args[1:])
	case "install-preload":
		return runInstallPreload(logger, args[1:])
	case "uninstall-preload":
		return runUninstallPreload(logger, args[1:])
	case "install-wrappers":
		return runInstallWrappers(logger, cfg, args[1:])
	case "uninstall-wrappers":
		return runUninstallWrappers(logger, cfg, args[1:])
	case "install-all":
		return runInstallAll(logger, cfg, args[1:])
	case "doctor":
		return runDoctor(logger, cfg, args[1:])
	case "scan":
		return runScan(logger, cfg, args[1:])
	case "audit-agent-surface":
		return runAuditAgentSurface(logger, cfg, args[1:])
	case "quarantine-cache":
		return runQuarantineCache(logger, cfg, args[1:])
	case "gyp-allow":
		return runGypAllow(logger, cfg, args[1:])
	}

	return runGate(logger, cfg, args)
}

// isShimName reports whether basename matches one of the package-manager
// binaries veto shadows via PATH shims. Delegates to the canonical
// pmlist.MatchesShim so this hot path and `veto install-shims` consume
// one source of truth — see internal/packagemanager/pmlist for why.
//
// "python" and "python3" are in the canonical list because
// `python -m pip install …` is the canonical install form inside
// virtualenvs, Dockerfiles, and most CI scripts — without a python
// shim, that invocation would skip veto entirely. Main()'s dispatch
// hot-paths every non-`-m {pm}` python call straight to the real
// interpreter so REPLs, `-V`, `-c`, scripts, and `-m http.server` etc.
// stay fast and transparent.
//
// Versioned aliases ("python3.10", "python3.11.2", …) match through
// pmlist.MatchesShim's regex too — install-shims creates per-version
// symlinks for every uv-managed cpython on disk, and the dispatch
// here recognises them so the same fast-path applies. Without this,
// a venv that exec's python3.12 directly would dispatch as "unknown"
// and route through the gate's `unknown package manager; passing
// through` branch — slow and noisy.
func isShimName(basename string) bool {
	return pmlist.MatchesShim(basename)
}

// isPythonBasename reports whether basename is one of the python
// flavors veto fast-paths through the `-m <pm>` gate: the canonical
// "python" / "python3" names OR a versioned `python3.X` alias.
// Centralised so main()'s shim-dispatch + execReal lookup stay in
// sync with the python-family classification in pmlist.
func isPythonBasename(basename string) bool {
	return basename == "python" || basename == "python3" || pmlist.IsVersionedPython(basename)
}

// runGate handles the `veto <pm> <args...>` path: parse the invocation,
// refresh and consult the intel store, then exec the real PM (or refuse).
func runGate(logger zerolog.Logger, cfg config, args []string) int {
	pmName, pmArgs := args[0], args[1:]

	pms := buildPackageManagers()
	pm, ok := pms[pmName]
	if !ok {
		logger.Warn().Str("pm", pmName).Msg("unknown package manager; passing through")
		return execPMOrPythonM(cfg, pmName, pmArgs)
	}

	in, decided := gateInputsFor(logger, cfg, pm, pmArgs)
	if !decided {
		// Not an install verb — pass through immediately, no intel needed.
		return execPMOrPythonM(cfg, pmName, pmArgs)
	}
	if in.store == nil {
		// gateInputsFor already logged the failure; storeErr carries the
		// case-specific line (build vs. refresh vs. sanity floor).
		fmt.Fprintln(os.Stderr, in.storeErr)
		fmt.Fprintln(os.Stderr, "Check that your sources are configured correctly and reachable: `veto status` and `veto sync`.")
		return exitInternal
	}
	installs, manifestRefs, expander, policy := in.installs, in.manifestRefs, in.expander, in.policy
	store := in.store

	// Per-source damage check. gateInputsFor computed damageRefusals (the
	// buckets in ecosystems THIS install touches) so the enforcement path
	// and the verdict path share one damage decision and cannot drift on
	// whether damage blocks — the verdict path previously skipped the
	// check and answered "allow" over a damaged bucket. Serving the
	// install anyway is silent degraded coverage, the exact failure mode
	// the integrity layer exists to prevent, so we fail closed (same
	// stance as a missing veto binary). Damage confined to ecosystems
	// this install doesn't touch is reported loudly but does not block:
	// an npm install must not wedge because the crates feed is rotting.
	if len(in.damageRefusals) > 0 {
		fmt.Fprintln(os.Stderr, "veto: INTERNAL ERROR — install aborted fail-closed.")
		fmt.Fprintln(os.Stderr, "  Malware intel for this install is damaged and could not be restored:")
		for _, d := range in.damageRefusals {
			fmt.Fprintf(os.Stderr, "    - source %s (ecosystem %s): %s (got %d reports, baseline %d)\n",
				d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline)
		}
		fmt.Fprintln(os.Stderr, "\n  This is not a malware block — veto could not verify its intel coverage.")
		fmt.Fprintln(os.Stderr, "  Remediation: restore network and run `veto sync` to re-fetch; if the feed")
		fmt.Fprintln(os.Stderr, "  legitimately shrank, delete the baseline file and re-sync:")
		fmt.Fprintf(os.Stderr, "    rm '%s'\n", filepath.Join(cfg.CacheDir, "intel-baseline.json"))
		return exitInternal
	} else if damaged := store.Damaged(); len(damaged) > 0 {
		// Out-of-scope damage: loud, but non-blocking.
		for _, d := range damaged {
			fmt.Fprintf(os.Stderr, "veto: WARN — intel source %s (ecosystem %s) is damaged: %s (got %d, baseline %d); installs for that ecosystem will be refused until restored.\n",
				d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline)
		}
	}

	// expander and policy come from gateInputsFor now (destructured above);
	// the pre-refactor construction that stood here is redundant.
	if in.hasPreflight {
		preflightPolicy := policy
		preflightPolicy.ManifestExpander = projectPreflightExpander{delegate: expander}
		decision := gate.New(store, preflightPolicy, logger).Evaluate([]packagemanager.Install{}, in.preflight.ManifestRefs...)
		switch decision.Outcome {
		case gate.OutcomeRefuse:
			printRefusal(os.Stderr, decision)
			return exitRefused
		case gate.OutcomeAbort:
			printAbort(os.Stderr, decision)
			return exitInternal
		case gate.OutcomePassThrough, gate.OutcomeAllow:
			return execPMOrPythonM(cfg, pmName, pmArgs)
		default:
			logger.Error().Str("outcome", string(decision.Outcome)).Msg("unknown project preflight gate outcome")
			return exitInternal
		}
	}

	gitResolution, err := applyOpaqueGitResolution(context.Background(), logger, cfg, pm, pmArgs, installs, expander)
	if err != nil {
		logger.Error().Err(err).Str("pm", pmName).Msg("opaque git resolve failed; aborting install fail-closed")
		printAbort(os.Stderr, gate.Decision{Outcome: gate.OutcomeAbort, Errors: []error{err}})
		return exitInternal
	}
	installs = gitResolution.Installs
	pmArgs = gitResolution.ExecArgs

	g := gate.New(store, policy, logger)
	decision := g.Evaluate(installs, manifestRefs...)
	switch decision.Outcome {
	case gate.OutcomeRefuse:
		printRefusal(os.Stderr, decision)
		return exitRefused
	case gate.OutcomeAbort:
		printAbort(os.Stderr, decision)
		return exitInternal
	case gate.OutcomePassThrough:
		return execPMOrPythonM(cfg, pmName, pmArgs)
	case gate.OutcomeAllow:
		if gitResolution.Applied {
			fmt.Fprintf(os.Stderr,
				"veto: cargo git source accepted at commit %s; scanned %d registry deps (clean).\n",
				gitResolution.Commit, gitResolution.Scanned)
		}
		// Continue into the optional resolver pre-scan below.
	default:
		logger.Error().Str("outcome", string(decision.Outcome)).Msg("unknown gate outcome")
		return exitInternal
	}

	preScanInstalls, preScanErr := runResolverPreScanIfAvailable(logger, cfg, pm, pmArgs, expander)
	if preScanErr != nil {
		logger.Error().Err(preScanErr).Str("pm", pmName).Msg("resolver pre-scan failed; aborting install fail-closed")
		decision := gate.Decision{Outcome: gate.OutcomeAbort, Errors: []error{preScanErr}}
		printAbort(os.Stderr, decision)
		return exitInternal
	}
	if len(preScanInstalls) > 0 {
		decision = g.Evaluate(preScanInstalls)
		switch decision.Outcome {
		case gate.OutcomeRefuse:
			printRefusal(os.Stderr, decision)
			return exitRefused
		case gate.OutcomeAbort:
			printAbort(os.Stderr, decision)
			return exitInternal
		case gate.OutcomePassThrough:
			return execPMOrPythonM(cfg, pmName, pmArgs)
		case gate.OutcomeAllow:
			// Safe to execute the real package manager below.
		default:
			logger.Error().Str("outcome", string(decision.Outcome)).Msg("unknown resolver pre-scan gate outcome")
			return exitInternal
		}
	}

	// binding.gyp worm layers (phantom-gyp / Miasma). The intel gate above
	// cannot see this worm — it rides a trusted name and keeps package.json
	// scripts clean — so for npm-family installs we apply two content
	// heuristics before letting the real package manager run.
	if isNpmFamily(pm.Ecosystem()) {
		// (a) Tarball inspection: fetch the package(s) about to be installed
		// with `npm pack --ignore-scripts` (download only) and inspect each
		// binding.gyp. Catches a freshly-resolved/compromised version that is
		// not yet in node_modules and not yet in any intel feed. The
		// --package-lock-only resolver pre-scan never fetches tarballs, so
		// this is the only layer that sees a brand-new worm at install time.
		if gypTarballPreflight(logger, os.Stderr, cfg, installs, preScanInstalls) {
			return exitRefused
		}
		// (b) Existing-tree scan: an `npm install` re-runs node-gyp for the
		// WHOLE tree, so a worm already in node_modules (from an earlier
		// install) would detonate on this unrelated install. Scan it.
		if runGypPreflightIfNpmFamily(logger, cfg, pm, pmArgs) {
			return exitRefused
		}
	}

	// Hades / Shai-Hulud .pth startup-hook worm layers. The intel gate
	// above cannot see this worm — it rides a trusted name and keeps
	// package metadata clean — so for Python-family installs we apply
	// the same two content heuristics before letting the real package
	// manager run.
	if isPythonFamily(pm.Ecosystem()) {
		// (a) Wheel prescan: fetch the wheels about to be installed
		// (Task 8) and inspect each .pth they would drop. Catches a
		// freshly-resolved/compromised version that is not yet in any
		// intel feed. Wired below; Task 8 fills the body.
		if pthWheelPreflight(logger, os.Stderr, cfg, installs, preScanInstalls) {
			return exitRefused
		}
		// (b) Existing-tree scan: site.py loads every .pth at every
		// `python` startup, so a worm already in the target venv would
		// detonate before this install completes. Scan it.
		if runPthPreflightIfPythonFamily(logger, pm, pmArgs) {
			return exitRefused
		}
	}
	return execPMOrPythonM(cfg, pmName, pmArgs)
}

func projectPreflightPlan(pm packagemanager.PackageManager, args []string, installs []packagemanager.Install, manifestRefs []packagemanager.ManifestRef) (packagemanager.ProjectPreflightPlan, bool) {
	if installs != nil || len(manifestRefs) > 0 {
		return packagemanager.ProjectPreflightPlan{}, false
	}
	preflighter, ok := pm.(packagemanager.ProjectPreflighter)
	if !ok {
		return packagemanager.ProjectPreflightPlan{}, false
	}
	plan, ok := preflighter.ProjectPreflight(args)
	if !ok || len(plan.ManifestRefs) == 0 {
		return packagemanager.ProjectPreflightPlan{}, false
	}
	return resolveProjectPreflightRoots(plan), true
}

func resolveProjectPreflightRoots(plan packagemanager.ProjectPreflightPlan) packagemanager.ProjectPreflightPlan {
	refs := append([]packagemanager.ManifestRef(nil), plan.ManifestRefs...)
	refs = resolveDefaultGoProjectRoot(refs)
	refs = resolveDefaultCargoProjectRoot(refs)
	plan.ManifestRefs = refs
	return plan
}

func resolveDefaultGoProjectRoot(refs []packagemanager.ManifestRef) []packagemanager.ManifestRef {
	if !hasDefaultRef(refs, packagemanager.ManifestKindGoMod, "go.mod") || !pathIsMissing("go.mod") {
		return refs
	}
	root, ok := findParentProjectFile("go.mod")
	if !ok {
		return refs
	}
	return rewriteDefaultRefs(refs, map[packagemanager.ManifestKind]defaultRefRewrite{
		packagemanager.ManifestKindGoMod: {defaultPath: "go.mod", resolvedPath: filepath.Join(root, "go.mod")},
		packagemanager.ManifestKindGoSum: {defaultPath: "go.sum", resolvedPath: filepath.Join(root, "go.sum")},
	})
}

func resolveDefaultCargoProjectRoot(refs []packagemanager.ManifestRef) []packagemanager.ManifestRef {
	rewrites := map[packagemanager.ManifestKind]defaultRefRewrite{}
	if hasDefaultRef(refs, packagemanager.ManifestKindCargoToml, "Cargo.toml") && pathIsMissing("Cargo.toml") {
		if root, ok := findParentProjectFile("Cargo.toml"); ok {
			rewrites[packagemanager.ManifestKindCargoToml] = defaultRefRewrite{defaultPath: "Cargo.toml", resolvedPath: filepath.Join(root, "Cargo.toml")}
		}
	}
	if hasDefaultRef(refs, packagemanager.ManifestKindCargoLock, "Cargo.lock") && pathIsMissing("Cargo.lock") {
		if root, ok := findParentProjectFile("Cargo.lock"); ok {
			rewrites[packagemanager.ManifestKindCargoLock] = defaultRefRewrite{defaultPath: "Cargo.lock", resolvedPath: filepath.Join(root, "Cargo.lock")}
		}
	}
	out := rewriteDefaultRefs(refs, rewrites)
	workspaceManifest, ok := findParentCargoWorkspaceManifest(out)
	if !ok {
		return out
	}
	if hasManifestRef(out, workspaceManifest, packagemanager.ManifestKindCargoToml) {
		return out
	}
	return append(out, packagemanager.ManifestRef{Path: workspaceManifest, Kind: packagemanager.ManifestKindCargoToml})
}

func findParentCargoWorkspaceManifest(refs []packagemanager.ManifestRef) (string, bool) {
	for _, ref := range refs {
		if ref.Kind != packagemanager.ManifestKindCargoLock || filepath.Base(ref.Path) != "Cargo.lock" || !filepath.IsAbs(ref.Path) {
			continue
		}
		manifest := filepath.Join(filepath.Dir(ref.Path), "Cargo.toml")
		if isCargoWorkspaceManifest(manifest) {
			return manifest, true
		}
	}
	return "", false
}

func isCargoWorkspaceManifest(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return false
	}
	_, ok := doc["workspace"]
	return ok
}

func hasManifestRef(refs []packagemanager.ManifestRef, path string, kind packagemanager.ManifestKind) bool {
	for _, ref := range refs {
		if ref.Kind == kind && filepath.Clean(ref.Path) == filepath.Clean(path) {
			return true
		}
	}
	return false
}

func rewriteDefaultRefs(refs []packagemanager.ManifestRef, rewrites map[packagemanager.ManifestKind]defaultRefRewrite) []packagemanager.ManifestRef {
	if len(rewrites) == 0 {
		return refs
	}
	out := append([]packagemanager.ManifestRef(nil), refs...)
	for i, ref := range out {
		rewrite, ok := rewrites[ref.Kind]
		if !ok || !isDefaultProjectRefPath(ref.Path, rewrite.defaultPath) {
			continue
		}
		out[i].Path = rewrite.resolvedPath
	}
	return out
}

type defaultRefRewrite struct {
	defaultPath  string
	resolvedPath string
}

func hasDefaultRef(refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind, path string) bool {
	for _, ref := range refs {
		if ref.Kind == kind && isDefaultProjectRefPath(ref.Path, path) {
			return true
		}
	}
	return false
}

func isDefaultProjectRefPath(got, want string) bool {
	return !filepath.IsAbs(got) && filepath.Clean(got) == want
}

func pathIsMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func findParentProjectFile(name string) (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil {
			return dir, info.Mode().IsRegular()
		}
		if !os.IsNotExist(err) {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

type projectPreflightExpander struct {
	delegate gate.ManifestExpander
}

var _ gate.ManifestExpander = projectPreflightExpander{}

func (e projectPreflightExpander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if projectPreflightRequires(ref.Kind) {
		info, err := os.Stat(ref.Path)
		if err != nil {
			return nil, errors.With(err, "required project manifest unavailable").Set("path", ref.Path).Set("kind", string(ref.Kind))
		}
		if !info.Mode().IsRegular() {
			return nil, errors.WithNew("required project manifest is not a regular file").Set("path", ref.Path).Set("kind", string(ref.Kind))
		}
	}
	return e.delegate.Expand(ref)
}

func projectPreflightRequires(kind packagemanager.ManifestKind) bool {
	switch kind {
	case packagemanager.ManifestKindGoMod, packagemanager.ManifestKindCargoToml:
		return true
	default:
		return false
	}
}

// damagedRefusals filters the store's damage report down to the buckets
// this gate invocation actually touches: the package manager's own
// ecosystem plus the ecosystems of every install spec. Manifest refs
// expand into installs of the same ecosystem as the PM, so pmEco covers
// them. Damage outside that set is reported (by the caller) but does not
// block — an npm install must not wedge because the crates feed is
// rotting.
func damagedRefusals(damaged []intel.SourceDamage, pmEco intel.Ecosystem, installs []packagemanager.Install) []intel.SourceDamage {
	if len(damaged) == 0 {
		return nil
	}
	touched := map[intel.Ecosystem]struct{}{pmEco: {}}
	for _, ins := range installs {
		touched[ins.Ref.Ecosystem] = struct{}{}
	}
	var out []intel.SourceDamage
	for _, d := range damaged {
		if _, ok := touched[d.Ecosystem]; ok {
			out = append(out, d)
		}
	}
	return out
}

func runSync(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	if err := refreshStoreWithFreshnessWindow(logger, cfg, store); err != nil {
		logger.Error().Err(err).Msg("refresh")
		return exitInternal
	}
	// Post-refresh sanity floor. The per-(source, ecosystem) retention
	// threshold inside store.Refresh is a relative check (50% of previous);
	// it can erode the index geometrically across many successful refreshes
	// if a feed is wedged. The absolute floor here catches that case so a
	// CI cron running `veto sync` daily doesn't silently accept an eroded
	// state. runGate already enforces the same floor on every gate call.
	if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
		logger.Error().
			Int("reports", reportCount).
			Int("floor", minHealthyReportCount).
			Msg("intel store below sanity floor after refresh")
		fmt.Fprintf(os.Stderr, "veto: WARN — intel store has only %d reports (expected at least %d); sync succeeded but the index is implausibly small.\n", reportCount, minHealthyReportCount)
		fmt.Fprintln(os.Stderr, "Check that your sources are configured correctly and reachable: `veto status`.")
		return exitInternal
	}
	// Per-source damage report. sync is the operator's remediation entry
	// point, so damage here fails the sync (non-zero) with the per-source
	// detail — a sync that leaves damaged buckets has not actually synced.
	if damaged := store.Damaged(); len(damaged) > 0 {
		logger.Error().Int("damaged", len(damaged)).Msg("intel sources damaged after refresh")
		fmt.Fprintln(os.Stderr, "veto: WARN — some intel sources are damaged and could not be restored:")
		for _, d := range damaged {
			fmt.Fprintf(os.Stderr, "  - source %s (ecosystem %s): %s (got %d reports, baseline %d)\n",
				d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline)
		}
		fmt.Fprintf(os.Stderr, "If a feed legitimately shrank, delete the baseline file and re-sync: rm '%s'\n",
			filepath.Join(cfg.CacheDir, "intel-baseline.json"))
		return exitInternal
	}
	// Refresh the host-level IOC store alongside intel so `veto sync`
	// populates both. With no feeds configured this is the Nop store and the
	// refresh is a no-op; once Wave-4 feeds are enabled it pulls their
	// indicators on the same schedule. IOC refresh failures are logged but do
	// not fail the sync — the intel gate (the load-bearing refusal path) has
	// already succeeded, and IOC hash-matching is a supplementary scan-time
	// signal, not a gate input.
	iocStore := buildIOCStore(logger, cfg)
	iocCtx, iocCancel := context.WithTimeout(context.Background(), syncTimeout)
	defer iocCancel()
	if err := iocStore.Refresh(iocCtx); err != nil {
		logger.Warn().Err(err).Msg("ioc refresh failed; continuing")
	}

	fmt.Printf("veto: synced sources %v (%d reports)\n", store.SourceIDs(), store.ReportCount())
	if ids := iocStore.SourceIDs(); len(ids) > 0 {
		fmt.Printf("veto: synced ioc feeds %v (%d indicators)\n", ids, iocStore.IndicatorCount())
	}
	return exitOK
}

func runStatus(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	fmt.Printf("veto: configured sources: %v\n", store.SourceIDs())
	if len(cfg.IOCSources) == 0 {
		fmt.Println("veto: configured IOC feeds: none")
	} else {
		fmt.Printf("veto: configured IOC feeds: %v\n", cfg.IOCSources)
	}
	fmt.Printf("veto: cache dir: %s\n", cfg.CacheDir)
	// FIX 3: status is a store consumer too. It does not gate or
	// scan, but reporting damage here is the cheapest operator
	// surface: `veto status` is the first command an operator runs
	// when something looks wrong, and a damaged bucket IS something
	// wrong. Display-only (exit stays 0) — the blocking decisions
	// live in the gate/verdict/scan paths.
	if damaged := store.Damaged(); len(damaged) > 0 {
		for _, d := range damaged {
			fmt.Printf("veto: WARN - intel source %s (ecosystem %s) is damaged: %s (got %d reports, baseline %d)\n",
				d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline)
		}
		fmt.Println("veto: installs and scans for the damaged ecosystems will be refused until restored; see `veto doctor`.")
	}
	return exitOK
}

// printRefusal writes a human-readable explanation of a refusal to w.
func printRefusal(w io.Writer, decision gate.Decision) {
	fmt.Fprintln(w, "veto: install refused — package intelligence flagged the following:")
	for _, v := range decision.Flagged() {
		fmt.Fprintf(w, "  - %s@%s (ecosystem: %s)\n", v.Ref.Name, displayVersion(v.Ref.Version), v.Ref.Ecosystem)
		for _, r := range v.Reports {
			reason := r.Reason
			if reason == "" {
				reason = "flagged"
			}
			fmt.Fprintf(w, "      [%s] %s\n", r.SourceID, reason)
		}
	}
	fmt.Fprintln(w, "\nIf you've independently verified the package is safe, install it through a non-shimmed path (e.g. directly via the real binary in your toolchain), not by bypassing veto.")
}

// printAbort writes a loud, distinct error when the gate could not make a
// confident decision (e.g., a manifest file failed to parse). Distinguishing
// this from a malware-driven refusal matters: a colleague seeing "refused"
// might assume a package was flagged, but Abort means veto's own
// machinery couldn't reach a verdict and refused to take the risk.
func printAbort(w io.Writer, decision gate.Decision) {
	fmt.Fprintln(w, "veto: INTERNAL ERROR — install aborted fail-closed.")
	fmt.Fprintln(w, "  The gate could not make a confident safety decision and refused to run the package manager.")
	if len(decision.Errors) > 0 {
		fmt.Fprintln(w, "  Underlying errors:")
		for _, e := range decision.Errors {
			fmt.Fprintf(w, "    - %v\n", e)
		}
	}
	fmt.Fprintln(w, "\nThis is not a malware block — it's a veto-side failure. Investigate before retrying.")
}

func displayVersion(v string) string {
	if v == "" {
		return "<any>"
	}
	return v
}

func runResolverPreScanIfAvailable(
	logger zerolog.Logger,
	cfg config,
	pm packagemanager.PackageManager,
	pmArgs []string,
	expander gate.ManifestExpander,
) ([]packagemanager.Install, error) {
	scanner, ok := pm.(packagemanager.ResolverPreScanner)
	if !ok {
		return nil, nil
	}
	plan, ok := scanner.ResolverPreScan(pmArgs)
	if !ok || len(plan.Args) == 0 || len(plan.ManifestRefs) == 0 {
		return nil, nil
	}
	return runResolverPreScan(logger, cfg, pm.Name(), plan, expander)
}

func runResolverPreScan(
	logger zerolog.Logger,
	cfg config,
	pmName string,
	plan packagemanager.ResolverPreScanPlan,
	expander gate.ManifestExpander,
) ([]packagemanager.Install, error) {
	realPath, err := findRealBinary(pmName, wrapperRegisteredFunc(cfg))
	if err != nil {
		return nil, errors.With(err, "locate real package manager for resolver pre-scan").Set("pm", pmName)
	}
	workdir, err := os.MkdirTemp("", "veto-resolver-*")
	if err != nil {
		return nil, errors.With(err, "create resolver pre-scan workdir")
	}
	defer os.RemoveAll(workdir)

	if err := seedResolverWorkdir(workdir, plan.SeedFiles); err != nil {
		return nil, err
	}
	if err := writeGeneratedResolverFiles(workdir, plan.GeneratedFiles); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolverPreScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, realPath, plan.Args...)
	cmd.Dir = workdir
	cmd.Env = sanitizedEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, errors.With(ctx.Err(), "resolver pre-scan timed out").Set("pm", pmName)
	}
	if err != nil {
		logger.Debug().Str("pm", pmName).Str("output", truncateForError(string(out), 800)).Msg("resolver pre-scan command output")
		werr := errors.With(err, "resolver pre-scan command failed").Set("pm", pmName)
		if detail := pmErrorSummary(string(out)); detail != "" {
			werr = errors.With(werr, detail)
		}
		return nil, werr
	}

	var installs []packagemanager.Install
	foundOutput := false
	for _, ref := range plan.ManifestRefs {
		cleanPath, ok := cleanSeedPath(ref.Path)
		if !ok {
			return nil, errors.WithNew("resolver pre-scan output path must be relative").Set("path", ref.Path)
		}
		ref.Path = filepath.Join(workdir, cleanPath)
		if ok, err := resolverOutputExists(ref.Path); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		foundOutput = true
		extra, err := expander.Expand(ref)
		if err != nil {
			return nil, errors.With(err, "expand resolver pre-scan output").Set("path", ref.Path)
		}
		installs = append(installs, extra...)
	}
	if !foundOutput {
		return nil, errors.WithNew("resolver pre-scan did not produce expected output").Set("pm", pmName)
	}
	if missing := unresolvedPreScanInstalls(plan.DirectInstalls, installs); len(missing) > 0 {
		return nil, errors.WithNew("resolver pre-scan output did not include every requested package").Set(
			"pm", pmName,
			"missing", strings.Join(missing, ","),
		)
	}
	logger.Debug().Str("pm", pmName).Int("installs", len(installs)).Msg("resolver pre-scan produced install records")
	return installs, nil
}

// pmErrorSummary distills a package manager's combined output down to the
// lines that explain a failure, so the fail-closed abort message names the
// real cause (e.g. npm's ESHRINKWRAPGLOBAL) instead of hiding it behind
// debug-only logging. Returns "" when no error-shaped lines are present.
func pmErrorSummary(out string) string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		lower := strings.ToLower(ln)
		if !strings.Contains(lower, "error") && !strings.Contains(lower, "err!") {
			continue
		}
		// The log-file pointer is noise, not a cause.
		if strings.Contains(lower, "complete log of this run") {
			continue
		}
		lines = append(lines, ln)
	}
	if len(lines) == 0 {
		return ""
	}
	return truncateForError(strings.Join(lines, "; "), 400)
}

func unresolvedPreScanInstalls(want, got []packagemanager.Install) []string {
	seen := map[intel.PackageRef]struct{}{}
	for _, ins := range got {
		if ins.LocalPath || ins.OpaqueRemote || ins.Ref.Name == "" {
			continue
		}
		ref := ins.Ref
		ref.Name = intel.NormalizeName(ref.Ecosystem, ref.Name)
		seen[ref] = struct{}{}
		ref.Version = ""
		seen[ref] = struct{}{}
	}

	missing := make([]string, 0, len(want))
	for _, ins := range want {
		if ins.LocalPath || ins.OpaqueRemote || ins.Ref.Name == "" {
			continue
		}
		ref := ins.Ref
		ref.Name = intel.NormalizeName(ref.Ecosystem, ref.Name)
		if _, ok := seen[ref]; ok {
			continue
		}
		ref.Version = ""
		if _, ok := seen[ref]; ok {
			continue
		}
		missing = append(missing, ins.RawSpec)
	}
	return missing
}

func resolverOutputExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.With(err, "stat resolver pre-scan output").Set("path", path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, errors.WithNew("resolver pre-scan output is a symlink").Set("path", path)
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return false, errors.WithNew("resolver pre-scan output is not a regular file").Set("path", path)
	}
	return true, nil
}

func seedResolverWorkdir(workdir string, relPaths []string) error {
	seen := map[string]struct{}{}
	for _, rel := range relPaths {
		cleanRel, ok := cleanSeedPath(rel)
		if !ok {
			continue
		}
		if _, dup := seen[cleanRel]; dup {
			continue
		}
		seen[cleanRel] = struct{}{}
		if err := copySeedPath(cleanRel, filepath.Join(workdir, cleanRel)); err != nil {
			return err
		}
	}
	return nil
}

func writeGeneratedResolverFiles(workdir string, files map[string][]byte) error {
	for rel, data := range files {
		cleanRel, ok := cleanSeedPath(rel)
		if !ok {
			return errors.WithNew("generated resolver file path must be relative").Set("path", rel)
		}
		dst := filepath.Join(workdir, cleanRel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return errors.With(err, "mkdir generated resolver file parent").Set("path", dst)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return errors.With(err, "write generated resolver file").Set("path", dst)
		}
	}
	return nil
}

func cleanSeedPath(rel string) (string, bool) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	return clean, true
}

func copySeedPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.With(err, "stat resolver pre-scan seed").Set("path", src)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if info.IsDir() {
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return errors.With(err, "read resolver pre-scan seed").Set("path", src)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return errors.With(err, "mkdir resolver pre-scan seed parent").Set("path", dst)
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return errors.With(err, "write resolver pre-scan seed").Set("path", dst)
	}
	return nil
}

// execPMOrPythonM is the post-gate exec for both the regular PM path
// and the `python -m <pm>` shim path. When the python-m env marker is
// set (planted by main()), we reconstruct the original interpreter
// invocation — `<python> -m <pm> <args…>` — rather than exec'ing the
// PM directly. That preserves venv-scoped PM resolution, which is the
// whole reason a user picked the `python -m` form in the first place.
//
// The env var is consumed (Unsetenv) so a downstream interposer-driven
// re-entry into veto doesn't inherit it and double-rewrite.
func execPMOrPythonM(cfg config, pmName string, pmArgs []string) int {
	env := sanitizedEnvFor(pmName, pmArgs, os.Environ())
	if pyBin := os.Getenv(pythonDashMEnvOriginal); pyBin != "" {
		os.Unsetenv(pythonDashMEnvOriginal)
		// Rebuild as `<python> -m <pm> <args…>`.
		newArgs := append([]string{"-m", pmName}, pmArgs...)
		return execRealWithEnv(cfg, pyBin, newArgs, env)
	}
	return execRealWithEnv(cfg, pmName, pmArgs, env)
}

// envRecursionRiskFor returns the recursion-risk level for pmName + pmArgs.
// Unknown PMs and PMs without EnvRecursionPolicy are RecursionRiskUnknown,
// which callers must treat as "strip" — default-deny.
func envRecursionRiskFor(pmName string, pmArgs []string) packagemanager.EnvRecursionRiskLevel {
	pms := buildPackageManagers()
	pm, ok := pms[pmName]
	if !ok {
		return packagemanager.RecursionRiskUnknown
	}
	policy, ok := pm.(packagemanager.EnvRecursionPolicy)
	if !ok {
		return packagemanager.RecursionRiskUnknown
	}
	return policy.EnvRecursionRisk(pmArgs)
}

// execReal replaces the current process with the real package-manager binary.
// Returns an exit code only on errors before exec; on success it never returns.
//
// Resolution preference order:
//
//  1. Sibling `<argv[0]>.veto-original` — set by `veto
//     install-wrappers`, which atomically moves a real PM binary aside
//     and replaces the original path with a veto symlink. This is
//     Layer 4: it catches absolute-path invocations
//     (`/opt/homebrew/bin/npm install …`) that bypass PATH lookup
//     entirely.
//  2. PATH lookup, skipping any candidates whose target IS veto
//     (avoids the shim chain re-entering itself).
//
// The sibling check happens first so an attacker can't bypass Layer 4
// by manipulating PATH inside the process.
//
// Provenance: before honoring any `.veto-original` sibling we consult
// wrappers.json (loaded once here) to confirm the wrapper site at the
// parent path was installed by `veto install-wrappers`. Without this
// check a same-UID attacker could plant `~/.local/bin/npm.veto-original`
// and hijack every gated invocation. If wrappers.json is missing or
// unreadable we fail closed: no sibling is trusted, and resolution
// continues with the PATH walk.
func execReal(cfg config, name string, args []string) int {
	return execRealWithEnv(cfg, name, args, sanitizedEnv(os.Environ()))
}

func execRealWithEnv(cfg config, name string, args []string, env []string) int {
	registered := wrapperRegisteredFunc(cfg)
	realPath, err := findRealBinary(name, registered)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto: cannot find real %s: %v\n", name, err)
		return exitInternal
	}
	if err := syscall.Exec(realPath, append([]string{name}, args...), env); err != nil {
		fmt.Fprintf(os.Stderr, "veto: exec %s: %v\n", realPath, err)
		return exitInternal
	}
	// syscall.Exec doesn't return on success.
	return exitInternal
}

// sanitizedEnvFor returns env passed through sanitizedEnv (the strip primitive)
// unless the (pmName, pmArgs) pair is explicitly classified as
// RecursionRiskLow, in which case env is returned unchanged.
//
// Policy: strip when EnvRecursionPolicy says High or Unknown. Preserve only on
// explicit Low. New verbs in Go, or new PMs that don't implement
// EnvRecursionPolicy, must opt into preservation.
//
// Why preserve VETO_PATH for some verbs: for verbs like `go run` whose child is
// user-authored code, not a PM re-invocation, stripping VETO_PATH silently
// disables the interposer for the entire descendant tree. The sanitizedEnv
// comment below describes the original recursion tradeoff; this refines it by
// keeping the surgical strip for verbs that need it.
func sanitizedEnvFor(pmName string, pmArgs []string, env []string) []string {
	if envRecursionRiskFor(pmName, pmArgs) == packagemanager.RecursionRiskLow {
		return env
	}
	return sanitizedEnv(env)
}

// sanitizedEnv returns env with veto-internal control variables removed,
// so the child process veto is about to exec into doesn't re-trigger the
// veto-side rewrites that brought us here.
//
// Why this matters (B6): without wrappers (Layer 4) installed, the basename
// of realPath is `npm` (or `python`, etc.). With the interposer (Layer 3)
// loaded via DYLD_INSERT_LIBRARIES / LD_PRELOAD, that basename matches
// PM_NAMES; the interposer's is_risky() reads VETO_PATH and, finding it
// set, rewrites the exec to call veto again — which re-enters this
// function and loops until the user kills it. Same hazard applies to the
// `python -m <pm>` shim path landed in B2: re-exec'ing python with
// VETO_PATH still set would let the interposer re-rewrite the call.
//
// We strip VETO_PATH only. The interposer is still loaded in the child
// (DYLD_INSERT_LIBRARIES is preserved), but every interposed function
// short-circuits to the real syscall when VETO_PATH is empty (see
// veto_interpose.c). That breaks the recursion at the immediate child
// without invalidating Layer 3 for sibling processes in the same shell.
//
// Tradeoff: Layer 3 no longer propagates into grandchildren of the
// exec'd PM (e.g. an npm postinstall that spawns another `pip install`).
// Those grandchildren still hit Layer 2 (PATH shims) and Layer 4
// (real-binary wrappers) when installed, so they're not unprotected —
// just not covered by Layer 3. Keeping Layer 3 alive for them would
// require a sentinel like VETO_ALREADY_GATED, but that sentinel would
// itself propagate to grandchildren and disable the defense for the
// nested PM calls we DO want to gate. Stripping VETO_PATH is the
// surgical choice.
//
// VETO_PYTHON_M_ORIGINAL is also stripped as belt-and-suspenders:
// execPMOrPythonM Unsetenv's it before calling here, but a stale value
// in the child env (say, from a future refactor that forgets the
// Unsetenv) would cause the same double-rewrite the B2 commit aimed to
// prevent. Cheap to strip; closes the door.
func sanitizedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "VETO_PATH=") {
			continue
		}
		if strings.HasPrefix(kv, pythonDashMEnvOriginal+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// wrapperRegisteredFunc loads wrappers.json once and returns a predicate
// reporting whether a given path is in the registry. The closure form
// keeps state out of execReal's signature and lets tests substitute their
// own predicate.
//
// Fail-closed policy: if wrappers.json is missing or fails to parse, the
// predicate returns false for every path. That collapses the resolver
// down to the PATH walk, which either finds an unwrapped real binary
// (the legitimate first-install state) or returns "not found in PATH".
// Either outcome is safer than honoring an attacker-planted sibling.
func wrapperRegisteredFunc(cfg config) func(string) bool {
	state, err := loadWrapperState(cfg)
	if err != nil {
		return func(string) bool { return false }
	}
	return state.has
}

// findWrappedOriginal returns the path to a `.veto-original` sibling
// of argv[0] when veto was invoked through a real-binary wrapper, or
// ("", false) otherwise. Layer 4 (`veto install-wrappers`) plants
// these sibling files; the resolver here unwraps them.
//
// argv[0] must contain a path separator — a bare-name shim invocation
// (e.g. from a ~/.local/bin/<pm> resolved through PATH) does not point
// at a real-binary wrapper site, even though os.Args[0] may be the
// resolved absolute path on some platforms. We err on the side of
// false-negative here and let the PATH walk handle bare names.
//
// `registered` reports whether the wrapper site at argv[0] is recorded
// in wrappers.json. We refuse to trust any sibling whose parent path
// isn't registered, since a same-UID attacker could otherwise plant
// `~/.local/bin/npm.veto-original` and have every gated `npm` call
// exec their payload. If wrappers.json is missing or unreadable the
// caller supplies a predicate that returns false for everything; that
// collapses to PATH-walk-only resolution (fail closed).
//
// Self-reference guard: after the sibling passes the registration and
// executable checks, we resolve it through filepath.EvalSymlinks and
// compare against veto's own resolved executable path. If they match,
// the sibling chains back to this very binary — exec'ing it would
// produce an infinite loop. This protects against (a) a manually-
// planted self-referential .veto-original, and (b) a future discovery
// bug that wraps both an alias and its target in the same uv cpython
// bin dir (chain: python -> python3.X -> veto, with
// python.veto-original -> python3.X -> veto). The discovery filter in
// pmsurvey.PathsFor closes case (b) at the source; this runtime check
// is belt-and-suspenders for case (a) and anything else that lands a
// loop on disk.
func findWrappedOriginal(argv0 string, registered func(string) bool) (string, bool) {
	if argv0 == "" || !strings.ContainsRune(argv0, '/') {
		return "", false
	}
	abs, err := filepath.Abs(argv0)
	if err != nil {
		return "", false
	}
	// Walk the symlink chain starting at abs. At each step, the
	// current path is a candidate wrap site: if it is registered in
	// wrappers.json AND has a `.veto-original` sibling that is an
	// executable non-directory and not self-referential, return it.
	//
	// Without the chain walk, a venv that symlinks
	// `.venv/bin/python` → `.venv/bin/python3` → `.venv/bin/python3.12`
	// → <uv canonical cpython bin>/python3.12 (a registered Layer 4
	// wrap site) cannot resolve: findWrappedOriginal checked only the
	// venv path, which is not registered, and fell through to the
	// PATH walk which found only Layer 2 shims (veto itself, skipped).
	// The result was "cannot find real python: not found in PATH"
	// whenever uv inspected a venv whose bin/python chains through a
	// wrapped canonical cpython — the normal uv-managed venv shape.
	// Chain walking discovers the registered wrap site at the far end.
	//
	// Provenance holds at every step: only `.veto-original` siblings
	// at REGISTERED paths are trusted, so an attacker planting a
	// sibling at an unregistered path cannot hijack resolution — the
	// walk passes through unregistered paths without honoring any
	// sibling they happen to carry. The self-reference guard at the
	// final candidate closes the same loop findWrappedOriginal always
	// defended against.
	const maxChainSteps = 40 // bound against pathological / malicious cycles
	current := abs
	for i := 0; i < maxChainSteps; i++ {
		if registered != nil && registered(current) {
			original := current + ".veto-original"
			if info, err := os.Stat(original); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				if !isSelfReferential(original) {
					return original, true
				}
			}
		}
		linkTarget, err := os.Readlink(current)
		if err != nil {
			// Not a symlink (or unreadable) — chain ends here.
			return "", false
		}
		// Resolve the link target relative to the current path's
		// directory, then absolutize for the next iteration's
		// registered/sibling checks. Absolute link targets pass
		// through filepath.Join unchanged; relative targets (the
		// venv's `python3 -> python` alias) resolve against the
		// current path's dir so the next loop's registered() check
		// sees the full absolute path.
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(filepath.Dir(current), linkTarget)
		}
		current = filepath.Clean(linkTarget)
	}
	return "", false
}

// isSelfReferential reports whether the given path resolves through
// filepath.EvalSymlinks to the same physical file as veto's own
// executable. Used by findWrappedOriginal as a belt-and-suspenders
// guard against an exec loop where a .veto-original chains back into
// veto itself. Returns false on any EvalSymlinks error — the caller's
// PATH walk is the fail-safe.
func isSelfReferential(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	self, err := os.Executable()
	if err != nil {
		return false
	}
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		return false
	}
	return resolved == selfReal
}

// findWrappedOriginalViaChain resolves the alias-invocation case:
// argv[0] is a plain symlink whose target chain leads to a registered
// veto wrapper sibling (pyenv `python -> python3.10 -> veto`,
// `bunx -> bun`). findWrappedOriginal only inspects
// `<argv0>.veto-original`, which does not exist for a plain alias — so
// without this the resolver falls through to the PATH walk and finds the
// WRONG binary (python3 → the homebrew 3.14 interpreter) or loops into a
// shim. That was the runtime symptom of the 2026-07-08 nested-wrap class.
//
// We walk argv[0]'s symlink chain one hop at a time. The FIRST hop that
// is a registered wrapper site with a valid, non-self-referential
// `.veto-original` wins — that anchor is the real binary to exec.
// Provenance is preserved exactly as in findWrappedOriginal: only
// wrapper sites recorded in wrappers.json are honored, so a plain alias
// pointing at an attacker-planted sibling is not trusted. Bounded by a
// visited-set so a cyclic symlink chain returns ("", false) rather than
// looping.
//
// This complements the discovery-side fix (aliasInheritsSiblingWrap in
// install_wrappers.go), which keeps such aliases as plain symlinks
// instead of wrapping them: the alias stays native on disk and resolves
// through its target's wrap here at runtime.
func findWrappedOriginalViaChain(argv0 string, registered func(string) bool) (string, bool) {
	if argv0 == "" || !strings.ContainsRune(argv0, '/') {
		return "", false
	}
	cur, err := filepath.Abs(argv0)
	if err != nil {
		return "", false
	}
	visited := map[string]struct{}{}
	for {
		cur = filepath.Clean(cur)
		if _, seen := visited[cur]; seen {
			return "", false // cyclic chain
		}
		visited[cur] = struct{}{}

		// Is this hop itself a registered wrapper with a usable anchor?
		if registered != nil && registered(cur) {
			original := cur + wrapperSuffix
			if isExecutableRegularOrSymlink(original) && !isSelfReferential(original) {
				return original, true
			}
		}
		// Otherwise follow one symlink hop toward the next sibling.
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			return "", false // chain ended without a registered wrapper
		}
		target, err := os.Readlink(cur)
		if err != nil {
			return "", false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = target
	}
}

// findDisplacedOriginal returns the `.veto-displaced` sibling of path
// when path lies inside the Layer-2 shim dir and the sibling is a
// healthy real binary, or ("", false) otherwise.
//
// `install-shims --force` is the ONLY writer of the `.veto-displaced`
// suffix: when a real binary already occupies a shim path (uv
// self-installs into ~/.local/bin/uv), it renames the binary aside
// before planting the `<pm> -> veto` symlink. Until this resolver
// existed the displaced file was invisible at exec time — only
// uninstall-shims ever read the suffix back. wrappers.json never
// covers shim-dir paths (install-wrappers' territory guard refuses to
// enroll there), so the `.veto-original` lookups can't apply, and a
// host whose ONLY real copy of a PM was the displaced file got
// "cannot find real uv: not found in PATH" — or, with a second
// wrapper tool (safe-chain) on PATH, an infinite exec ping-pong
// between the two wrappers.
//
// Provenance gate: shim-dir membership plays exactly the role
// wrappers.json membership plays for `.veto-original` siblings. The
// shim dir is veto's exclusive Layer-2 territory and only install-shims
// writes the `.veto-displaced` suffix, so a displaced sibling inside
// the shim dir is veto-authored by construction. A `.veto-displaced`
// planted anywhere else is NOT trusted — a same-UID attacker could
// otherwise drop `<dir>/npm.veto-displaced` next to any veto-pointing
// PATH entry and hijack execution. Callers continue their walk when
// this returns false (fail closed).
//
// Health gate: the sibling must be an executable regular file or
// symlink AND must not resolve back into veto itself — a
// self-referential displaced file would re-enter veto in an exec
// loop, the same failure class the `.veto-original` guards close.
func findDisplacedOriginal(path, shimDir string) (string, bool) {
	if path == "" || !strings.ContainsRune(path, '/') {
		return "", false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	if !pathInsideDir(abs, shimDir) {
		return "", false
	}
	displaced := abs + displacedSuffix
	if !isExecutableRegularOrSymlink(displaced) {
		return "", false
	}
	if isSelfReferential(displaced) {
		return "", false
	}
	return displaced, true
}

// findRealBinary returns the path veto should exec to satisfy a
// gated install. Prefers a wrapped-original sibling (Layer 4), then
// the alias chain-follower (for plain aliases into a wrapped sibling),
// then a Layer-2 `.veto-displaced` sibling when argv[0] is itself a
// shim-dir path, then falls back to a PATH walk that skips any
// veto-pointing entries (consulting `.veto-original` /
// `.veto-displaced` siblings per their respective provenance gates).
//
// `registered` is a wrappers.json membership predicate; see
// findWrappedOriginal for the provenance rationale.
func findRealBinary(name string, registered func(string) bool) (string, error) {
	if wrapped, ok := findWrappedOriginal(os.Args[0], registered); ok {
		return wrapped, nil
	}
	// Alias case: argv[0] is a plain symlink into a registered wrapper
	// sibling (pyenv `python -> python3.10`, `bunx -> bun`). Follow the
	// chain before falling back to the PATH walk, which would otherwise
	// resolve to the wrong interpreter.
	if wrapped, ok := findWrappedOriginalViaChain(os.Args[0], registered); ok {
		return wrapped, nil
	}
	shimDir := defaultShimDir()
	// Direct shim invocation: argv[0] IS a shim-dir path (someone ran
	// `~/.local/bin/uv` by absolute path, possibly with a PATH that
	// doesn't contain the shim dir — the walk below would never see
	// it). Mirrors the findWrappedOriginal argv[0] lookup above, with
	// shim-dir membership as the provenance gate instead of
	// wrappers.json — see findDisplacedOriginal. The basename must
	// match the PM being resolved so an unrelated argv[0] (e.g. a veto
	// binary that itself lives in the shim dir, invoked as
	// `veto npm install`) can never route resolution through its own
	// siblings.
	if argv0 := os.Args[0]; filepath.Base(argv0) == name {
		if displaced, ok := findDisplacedOriginal(argv0, shimDir); ok {
			return displaced, nil
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "", errors.With(err, "resolve self")
	}
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		selfReal = self
	}

	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		if resolved == selfReal {
			// This PATH entry IS veto (either a Layer 2 shim or a
			// Layer 4 wrapper). If a `.veto-original` sibling exists
			// AND the wrapper site is registered in wrappers.json,
			// that's the wrapped real binary — use it instead of
			// continuing the PATH walk. Without this check, a system
			// where every PATH entry has been wrapped would yield
			// "not found in PATH" because every candidate gets skipped.
			//
			// Provenance gate: same as findWrappedOriginal — an
			// attacker planting `<dir>/<name>.veto-original` at any
			// PATH entry would otherwise hijack execution. Unregistered
			// siblings are ignored; the loop continues.
			//
			// Self-reference guard: mirrors findWrappedOriginal's
			// isSelfReferential check. Without it, a sibling that
			// resolves back to the veto binary itself (e.g. a stale
			// `~/.local/bin/python3.veto-original` symlink pointing
			// at `~/.local/bin/veto`) would be returned here and
			// exec'd, producing an infinite re-entry loop — the root
			// cause of the veto-dzk python-shim stall. PATH walk and
			// argv[0] lookup must agree on which siblings to trust.
			if registered != nil && registered(candidate) {
				if sibling := candidate + ".veto-original"; isExecutableRegularOrSymlink(sibling) && !isSelfReferential(sibling) {
					return sibling, nil
				}
			}
			// Layer-2 displacement: the candidate is a shim-dir entry
			// whose real binary was moved aside by `install-shims
			// --force` (`<pm>.veto-displaced`). The `.veto-original`
			// gate above can never fire for these paths — wrappers.json
			// refuses shim-dir territory by construction — so without
			// this check a PM whose ONLY real copy is the displaced
			// file resolves to "not found in PATH" even though the
			// binary sits right next to its shim. Shim-dir membership
			// is the provenance gate here, exactly as wrappers.json
			// membership gates `.veto-original`; see
			// findDisplacedOriginal. Unhealthy or absent siblings fall
			// through and the walk continues (fail closed).
			if displaced, ok := findDisplacedOriginal(candidate, shimDir); ok {
				return displaced, nil
			}
			continue
		}
		return candidate, nil
	}
	return "", errors.WithNew("not found in PATH").Set("name", name)
}

// isExecutableRegularOrSymlink returns true if `p` exists, is not a
// directory, and resolves to an executable file (resolving symlinks).
// Used by findRealBinary's `.veto-original` sibling lookup —
// homebrew wrappers leave a symlink-into-Cellar as the original, so
// we must follow symlinks here, not just stat.
func isExecutableRegularOrSymlink(p string) bool {
	info, err := os.Stat(p) // Stat follows symlinks
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

type config struct {
	CacheDir   string
	Sources    []string // enabled intel source IDs
	IOCSources []string // enabled IOC feed IDs (host-level indicator feeds)
}

func loadConfig() (config, error) {
	v := viper.New()
	v.SetEnvPrefix("VETO")
	v.AutomaticEnv()
	v.SetDefault("cache_dir", defaultCacheDir())
	v.SetDefault("sources", []string{"aikido", "datadog", "openssf", "osv", "pypa", "hades"})
	// IOC feeds (abuse.ch, MISP, ...) are all opt-in and land in Wave 4. The
	// default is empty so the IOC subsystem costs nothing until a feed is
	// explicitly enabled via ioc_sources / VETO_IOC_SOURCES.
	v.SetDefault("ioc_sources", []string{})
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(filepath.Join(defaultCacheDir(), ".."))
	_ = v.ReadInConfig() // optional config file

	cfg := config{
		CacheDir:   v.GetString("cache_dir"),
		Sources:    v.GetStringSlice("sources"),
		IOCSources: v.GetStringSlice("ioc_sources"),
	}
	if cfg.CacheDir == "" {
		return cfg, errors.New("cache_dir resolved empty")
	}
	return cfg, nil
}

func defaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "veto")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "veto")
	}
	return filepath.Join(home, ".cache", "veto")
}

// refreshStoreWithFreshnessWindow refreshes the intel store, honoring the
// short-lived freshness window: when the recorded last-successful-refresh
// is younger than intel.RefreshFreshnessWindow, sources serve from their
// on-disk caches without network round-trips. A successful refresh records
// the marker. Marker failures are logged and otherwise ignored — the
// fail-safe direction is always "refresh now," never "stay stale."
//
// doctor's checkIntel deliberately does NOT use this helper: a diagnostic
// must probe the real upstream state, not the cache.
func refreshStoreWithFreshnessWindow(logger zerolog.Logger, cfg config, store intel.Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()

	cacheOnly := false
	if last, fresh := intel.ReadLastRefresh(cfg.CacheDir, time.Now()); fresh {
		logger.Debug().Time("last_refresh", last).Msg("advisory cache inside freshness window; serving from disk cache")
		ctx = intel.WithCacheOnly(ctx)
		cacheOnly = true
	}

	if err := store.Refresh(ctx); err != nil {
		return err
	}

	// FIX 4: the marker names the last successful NETWORK refresh. A
	// cache-only refresh has no wire basis, so sliding the marker
	// here would turn the window into a sliding lease — an agent
	// loop invoking veto more often than the window would NEVER
	// contact the network, and never reach the fetch paths that
	// heal a damaged cache. Write it only when the wire was
	// actually consulted.
	if !cacheOnly {
		if err := intel.WriteLastRefresh(cfg.CacheDir, time.Now()); err != nil {
			logger.Warn().Err(err).Msg("record refresh marker")
		}
	}
	return nil
}

// buildStore constructs the intel store from the configured sources. Unknown
// source IDs in config log a warning and are skipped — the user can mistype
// and still get a working store.
//
// The store carries a persistent per-(source, ecosystem) count baseline at
// <cacheDir>/intel-baseline.json so a damaged cache is detected even on a
// cold process (the in-process retention guard resets every invocation).
// See intel.BaselineStore for the detection policy.
// buildStoreFn exists as an injection seam for tests: the verdict-path
// damage tests build a REAL BaselineStore over fake sources (so the
// Damaged() routing runs for real) and need gateInputsFor to consume it
// without going through cfg.Sources → buildSource, which only knows the
// production source IDs. Indirection through a var is the minimal seam;
// production callers are unaffected.
var buildStoreFn = buildStore

func buildStore(logger zerolog.Logger, cfg config) (intel.Store, error) {
	var sources []intel.Source
	for _, id := range cfg.Sources {
		src, err := buildSource(logger, cfg, id)
		if err != nil {
			logger.Warn().Err(err).Str("source", id).Msg("skip source")
			continue
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		return nil, errors.New("no usable sources configured")
	}
	return intel.NewStoreWithBaseline(
		logger,
		filepath.Join(cfg.CacheDir, "intel-baseline.json"),
		sources...), nil
}

func buildSource(logger zerolog.Logger, cfg config, id string) (intel.Source, error) {
	switch id {
	case "aikido":
		return aikido.New(aikido.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "aikido"),
			Logger:   logger,
		})
	case "openssf":
		return openssf.New(openssf.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "openssf"),
		})
	case "ghsa":
		return ghsa.New(ghsa.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "ghsa"),
			Logger:   logger,
		})
	case "osv":
		return osv.New(osv.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "osv"),
		})
	case "pypa":
		return pypa.New(pypa.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "pypa"),
			Logger:   logger,
		})
	case "datadog":
		return datadog.New(datadog.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "datadog"),
			Logger:   logger,
		})
	case "rustsec":
		return rustsec.New(rustsec.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "rustsec"),
			Logger:   logger,
		})
	case "govulndb":
		return govulndb.New(govulndb.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "govulndb"),
			Logger:   logger,
		})
	case "gemnasium":
		return gemnasium.New(gemnasium.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "gemnasium"),
			Logger:   logger,
		})
	case "hades":
		return hades.New(), nil
	default:
		return nil, errors.WithNew("unknown source").Set("id", id)
	}
}

// buildIOCStore constructs the host-level IOC store from the configured feeds.
// With no feeds enabled (the shipping default — ioc_sources is empty), it
// returns ioc.NopStore{}: a zero-cost store that matches nothing and reports
// zero indicators, so the cache hash-scan stays disabled. Unknown feed IDs log
// a warning and are skipped, mirroring buildStore.
//
// Wave-4 seam: when sources/abusech, sources/misp, etc. land, adding a feed is
// a three-line change — a case in buildIOCSource, its import at the top of this
// file, and (optionally) an entry in the ioc_sources default slice in
// loadConfig.
func buildIOCStore(logger zerolog.Logger, cfg config) ioc.Store {
	var sources []ioc.Source
	for _, id := range cfg.IOCSources {
		src, err := buildIOCSource(logger, cfg, id)
		if err != nil {
			logger.Warn().Err(err).Str("ioc_source", id).Msg("skip ioc source")
			continue
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		// No feeds configured: the Nop store is the correct zero-cost default
		// rather than an error, because IOC feeds are opt-in and the cache
		// scanner is built to no-op when no indicators are present.
		return ioc.NopStore{}
	}
	return ioc.NewStore(logger, sources...)
}

// buildIOCSource resolves one IOC feed ID to a concrete ioc.Source. Adding a
// feed is a three-line change: a case here, its import at the top of the file,
// and (optionally) an entry in the ioc_sources default slice in loadConfig.
func buildIOCSource(logger zerolog.Logger, cfg config, id string) (ioc.Source, error) {
	switch id {
	case "abusech":
		return abusech.New(abusech.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "abusech"),
			AuthKey:  os.Getenv("VETO_ABUSECH_AUTH_KEY"),
			Logger:   logger,
		})
	case "misp":
		return misp.New(misp.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "misp"),
			Logger:   logger,
		})
	default:
		return nil, errors.WithNew("unknown ioc source").Set("id", id)
	}
}

// compoundExpander dispatches manifest refs to the leaf expander that owns
// the kind. Keeping the dispatch in one place lets each leaf expander stay
// scoped to its own kinds and testable in isolation.
type compoundExpander struct {
	pyReq  *pyreq.Expander
	js     *jsmanifest.Expander
	pyPrj  *pymanifest.Expander
	jsLock *jslock.Expander
	pyLock *pylock.Expander
	pipRep *pipreport.Expander
	goMod  *gomod.Expander
	cargo  *cargomanifest.Expander
	cLock  *cargolock.Expander
}

// newCompoundExpander wires the leaf expanders behind a single
// gate.ManifestExpander.
func newCompoundExpander() *compoundExpander {
	return &compoundExpander{
		pyReq:  pyreq.New(),
		js:     jsmanifest.New(),
		pyPrj:  pymanifest.New(),
		jsLock: jslock.New(),
		pyLock: pylock.New(),
		pipRep: pipreport.New(),
		goMod:  gomod.New(),
		cargo:  cargomanifest.New(),
		cLock:  cargolock.New(),
	}
}

var _ gate.ManifestExpander = (*compoundExpander)(nil)

// Expand implements gate.ManifestExpander by dispatching on ref.Kind. Unknown
// kinds are a no-op; the gate already tolerates a nil, nil return.
func (c *compoundExpander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindRequirements, packagemanager.ManifestKindConstraint:
		return c.pyReq.Expand(ref)
	case packagemanager.ManifestKindPackageJSON:
		return c.js.Expand(ref)
	case packagemanager.ManifestKindPyProject:
		return c.pyPrj.Expand(ref)
	case packagemanager.ManifestKindPackageLockJSON,
		packagemanager.ManifestKindNpmShrinkwrap,
		packagemanager.ManifestKindPnpmLockYAML,
		packagemanager.ManifestKindYarnLock:
		return c.jsLock.Expand(ref)
	case packagemanager.ManifestKindUvLock,
		packagemanager.ManifestKindPoetryLock,
		packagemanager.ManifestKindPdmLock:
		return c.pyLock.Expand(ref)
	case packagemanager.ManifestKindPipReportJSON:
		return c.pipRep.Expand(ref)
	case packagemanager.ManifestKindGoMod,
		packagemanager.ManifestKindGoSum:
		return c.goMod.Expand(ref)
	case packagemanager.ManifestKindCargoToml:
		return c.cargo.Expand(ref)
	case packagemanager.ManifestKindCargoLock:
		return c.cLock.Expand(ref)
	default:
		return nil, nil
	}
}

// buildPackageManagers returns the registry of supported PMs keyed by binary
// name. Adding a new PM = one entry here plus the impl subpackage.
func buildPackageManagers() map[string]packagemanager.PackageManager {
	return map[string]packagemanager.PackageManager{
		"npm":    npm.New(),
		"pnpm":   pnpm.New(),
		"yarn":   yarn.New(),
		"bun":    bun.New(),
		"pip":    pip.New("pip"),
		"pip3":   pip.New("pip3"),
		"uv":     uv.New(),
		"poetry": poetry.New(),
		"pdm":    pdm.New(),
		"go":     golang.New(),
		"cargo":  cargo.New(),

		// Fetch-and-run binaries — every non-help invocation is treated as install.
		"npx":  pmexec.New(pmexec.Options{Name: "npx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.NpxFlagsWithValues, SpecFlags: pmexec.NpxSpecFlags}),
		"pnpx": pmexec.New(pmexec.Options{Name: "pnpx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.PnpxFlagsWithValues, SpecFlags: pmexec.PnpxSpecFlags}),
		"bunx": pmexec.New(pmexec.Options{Name: "bunx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.BunxFlagsWithValues}),
		"uvx":  pmexec.New(pmexec.Options{Name: "uvx", Ecosystem: intel.EcosystemPyPI, FlagsWithValues: pmexec.UvxFlagsWithValues}),
		"pipx": pmexec.New(pmexec.Options{Name: "pipx", Ecosystem: intel.EcosystemPyPI, PipxStyle: true, FlagsWithValues: pmexec.PipxFlagsWithValues, SpecFlags: pmexec.PipxSpecFlags}),
	}
}

func newLogger() zerolog.Logger {
	level := zerolog.InfoLevel
	if strings.EqualFold(os.Getenv("VETO_LOG"), "debug") {
		level = zerolog.DebugLevel
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(level).
		With().
		Timestamp().
		Logger()
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `veto — command-level malware scanner for package managers

Usage:
  veto <pm> <pm-args...>    gate a package-manager invocation, then exec it
  veto test [--format json|text] <pm> <pm-args...>
                            verdict-only: evaluate the command against the
                            intel+policy gate and print the decision WITHOUT
                            executing anything. JSON by default. Exit codes
                            match the enforcement path (0 allow/passthrough,
                            1 refuse, 64 usage, 70 internal/abort).
                            Scope: "allow" covers argv + on-disk manifests
                            only — it excludes the resolver pre-scan
                            (transitives) and the gyp/.pth worm scans, so
                            it is not a statement that the install is safe.
  veto sync                 refresh malware intel from all configured sources
  veto status               print configured sources and cache location
  veto update [--check] [--full] [--ref REF]
                            self-update: build the latest veto via `+"`go install`"+`
                            and replace this binary in place
  veto doctor               verify defense layers + intel state (run after install)
  veto scan [--root DIR] [--json] [--no-projects] [--no-caches] [--no-agent-surface]
                            scan projects, package-manager caches, and agent
                            surfaces for existing exposure (read-only)
                            Project files include npm-family, Python-family,
                            Go, and Rust manifests and lockfiles.
  veto quarantine-cache [--dry-run] [--purge] [--json]
                            scan cache exposure and optionally purge confirmed
                            malicious cache artifacts
  veto gyp-allow <binding.gyp>... | --list
                            acknowledge an INSPECTED binding.gyp by content
                            hash so its copies stop blocking installs; a
                            modified variant still refuses
  veto audit-agent-surface [--json]
                            inspect Claude/Codex/Cursor/Sirene/MCP/launchd
                            persistence surfaces only
  veto version | --version | -v
                            print the version string (one line)
  veto help                 this message

Layer 1 — Claude Code hook (Bash tool interception):
  veto install-claude-hook [--project] [--settings PATH] [--print]
                               wire veto into ~/.claude/settings.json
  veto uninstall-claude-hook [--settings PATH]
                               remove the veto hook entry (preserves siblings)
  veto hook claude-code     read PreToolUse JSON from stdin, write a deny
                               decision to stdout if the command reaches a PM

Layer 2 — PATH shims (any agent shell, Codex, CI):
  veto install-shims [--dir DIR] [--force] [--dry-run]
                               symlinks ~/.local/bin/{npm,pip,…} → veto.
                               --force displaces a real binary occupying a
                               shim path to <pm>.veto-displaced; veto
                               resolves it, uninstall-shims restores it
  veto uninstall-shims [--dir DIR]
                               remove veto-managed symlinks
  veto install-codex        install-shims + a ~/.codex/config.toml scan
                               for env-policy gotchas
  veto install-cursor [--project-dir DIR] [--shim-dir DIR] [--skip-shims] [--force]
                               install-shims + write .cursor/rules/veto.mdc
                               so Cursor's agent prefixes installs with `+"`veto`"+`
  veto install-shell [--shell-rc PATH|auto] [--print]
                               install one managed shell-rc block for PATH
                               pinning and pip/uv package-age quarantine.
                               Defaults to --shell-rc auto unless --print.
  veto uninstall-shell [--shell-rc PATH|auto]
                               remove the managed shell-rc integration block.
                               Defaults to --shell-rc auto.

Layer 3 — native execve interposer (catches direct child-process spawns):
  veto install-preload --lib PATH [--shell-rc PATH|auto] [--install-to DIR] [--print]
                               install the libveto_interpose.{dylib,so}
                               and export DYLD_INSERT_LIBRARIES / LD_PRELOAD +
                               VETO_PATH from your shell rc. Build the
                               artifact first with `+"`make interposer`"+`.
  veto uninstall-preload [--shell-rc PATH|auto] [--install-to DIR]
                               strip the managed shell-rc block and remove
                               the installed library

Layer 4 — real-binary wrappers (catches absolute-path invocations):
  veto install-wrappers [--dry-run] [--force] [--dir DIR] [--only PM]
                               atomically replace /opt/homebrew/bin/<pm>,
                               mise install dirs, etc. with veto symlinks.
                               Catches `+"`subprocess.run([abs_path,…])`"+` even
                               when DYLD_INSERT_LIBRARIES is stripped.
  veto uninstall-wrappers   reverse every wrapper recorded in state

Install everything:
  veto install-all [--lib PATH] [--shell-rc PATH|auto] [--force]
                   [--skip-interposer] [--skip-wrappers]
                               install shims, shell integration, Claude hook,
                               preload interposer, wrappers, sync intel, then doctor.
                               If --lib is omitted, builds libveto_interpose
                               from the C source embedded in the veto binary
                               (requires `+"`cc`"+` on PATH; override via `+"`CC=...`"+`).
                               Works from any CWD; no veto source tree needed.
                               --skip-wrappers omits the Layer 4 wrappers step
                               entirely (useful when wrappers are installed
                               separately under sudo).
                               Exit codes:
                                  0  success
                                 10  a user-scoped layer failed
                                 20  wrappers need elevation (rerun under sudo)
                                 30  wrappers attempted and genuinely failed

Self-update:
  veto update [--check] [--full] [--binary-only] [--ref REF] [--repo URL] [--module PATH]
                               build the latest veto with `+"`go install <module>@<ref>`"+`
                               (checksum-verified via the module proxy; no source
                               tree or prebuilt-binary download) and atomically
                               replace this binary. Layer 2 shims (symlinks) and the
                               Layer 3 interposer (routes via VETO_PATH) pick up the
                               new binary automatically; by default we also re-point
                               shims (`+"`install-shims --force`"+`).
                               --check       report current vs latest, change nothing
                               --full        also run `+"`install-all`"+` (rebuilds the
                                             interposer; use if the shadowed-PM set
                                             changed)
                               --binary-only replace the binary only, touch no layer
                               --ref REF     branch/tag/commit to install (default: main)
                               Requires a Go toolchain on PATH (veto ships no
                               prebuilt binaries).

Supported package managers:
  npm, pnpm, yarn, bun, pip, pip3, uv, poetry, pdm, go, cargo,
  npx, pnpx, bunx, uvx, pipx,
  python, python3 (only the `+"`python -m {pip,uv,pipx,poetry,pdm}`"+` form
                   is gated; every other invocation fast-paths to
                   real python with no intel-store touch)

Go/Cargo live gating:
  go get/install/run pkg@version, go mod download/tidy, and cargo
  add/update/fetch/install are gated. Go build/test/local run/vet and cargo
  build/check/test/run/bench/clippy preflight project files before exec.

Environment:
  VETO_CACHE_DIR     override cache location (default: $XDG_CACHE_HOME/veto)
  VETO_SOURCES       comma-separated source IDs (default: aikido,datadog,openssf,osv,pypa,hades)
                       optional vulnerability feeds: ghsa, rustsec, govulndb, gemnasium
  VETO_IOC_SOURCES   comma-separated host-level IOC feed IDs (default: none).
                       Available: abusech, misp. When set, cache artifacts are
                       matched against known-malicious file hashes during veto scan.
  VETO_ABUSECH_AUTH_KEY
                     free abuse.ch Auth-Key (https://auth.abuse.ch/) required by the
                     abusech IOC feed; without it the feed logs once and no-ops
  VETO_LOG           set to "debug" for verbose logging
  VETO_PATH          set by install-preload; consumed by the interposer
  VETO_PTH_WHEEL_SCAN
                     enable / disable the .pth wheel prescan for the Hades
                     PyPI worm. Values: on (default; argv-direct only),
                     full (also fetch resolved transitives), off.
  VETO_PTH_WHEEL_SCAN_TIMEOUT
                     timeout for the wheel prescan (default: 120s). The prescan
                     is best-effort: on timeout veto logs a warning and allows
                     the install (fail-open). Critical findings detected before
                     the timeout always refuse. Set VETO_PTH_WHEEL_SCAN=off to
                     skip the prescan entirely.
`)
}
