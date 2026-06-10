// Command veto is a command-level malware scanner for package-manager
// invocations.
//
// Usage:
//
//	veto <pm> <pm-args...>     gate an install command, then exec the real PM
//	veto sync                  refresh the intel store from all sources
//	veto status                show source health and store size
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
	"github.com/brynbellomy/veto/internal/intel/sources/ghsa"
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
	"github.com/brynbellomy/veto/internal/intel/sources/pypa"
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
		if self == "python" || self == "python3" {
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
	case "sync":
		return runSync(logger, cfg)
	case "status":
		return runStatus(logger, cfg)
	case "install-shims":
		return runInstallShims(logger, args[1:])
	case "uninstall-shims":
		return runUninstallShims(logger, args[1:])
	case "hook":
		return runHook(logger, args[1:])
	case "install-claude-hook":
		return runInstallClaudeHook(logger, args[1:])
	case "uninstall-claude-hook":
		return runUninstallClaudeHook(logger, args[1:])
	case "install-codex":
		return runInstallCodex(logger, args[1:])
	case "install-cursor":
		return runInstallCursor(logger, args[1:])
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
	}

	return runGate(logger, cfg, args)
}

// isShimName reports whether basename matches one of the package-manager
// binaries veto shadows via PATH shims. Delegates to the canonical
// pmlist.IsShimmed so this hot path and `veto install-shims` consume
// one source of truth — see internal/packagemanager/pmlist for why.
//
// "python" and "python3" are in the canonical list because
// `python -m pip install …` is the canonical install form inside
// virtualenvs, Dockerfiles, and most CI scripts — without a python
// shim, that invocation would skip veto entirely. Main()'s dispatch
// hot-paths every non-`-m {pm}` python call straight to the real
// interpreter so REPLs, `-V`, `-c`, scripts, and `-m http.server` etc.
// stay fast and transparent.
func isShimName(basename string) bool {
	return pmlist.IsShimmed(basename)
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

	installs := pm.ParseInstalls(pmArgs)
	manifestRefs := pm.ManifestRefs(pmArgs)
	preflight, hasPreflight := projectPreflightPlan(pm, pmArgs, installs, manifestRefs)
	if installs == nil && len(manifestRefs) == 0 && !hasPreflight {
		// Not an install verb — pass through immediately, no intel needed.
		return execPMOrPythonM(cfg, pmName, pmArgs)
	}

	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}

	// Refresh synchronously before gating; the cache layer keeps this fast on
	// the common path.
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		// Don't fail open: if we have zero intel, we can't gate. Refuse with
		// a clear message rather than letting an install through unchecked.
		logger.Error().Err(err).Msg("intel refresh failed — refusing to gate without data")
		fmt.Fprintln(os.Stderr, "veto: INTERNAL ERROR — intel refresh failed; install aborted fail-closed.")
		return exitInternal
	}

	// Sanity floor on store health. An empty store means every lookup would
	// return "clean," which is worse than useless — it's silently allowing
	// packages through under the appearance of being gated. Either upstream
	// is broken or compromised. Fail closed loudly.
	if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
		logger.Error().
			Int("reports", reportCount).
			Int("floor", minHealthyReportCount).
			Msg("intel store below sanity floor — refusing to gate")
		fmt.Fprintf(os.Stderr, "veto: INTERNAL ERROR — intel store has only %d reports (expected at least %d); install aborted fail-closed.\n", reportCount, minHealthyReportCount)
		fmt.Fprintln(os.Stderr, "Check that your sources are configured correctly and reachable: `veto status` and `veto sync`.")
		return exitInternal
	}

	expander := newCompoundExpander()
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = expander
	if hasPreflight {
		preflightPolicy := policy
		preflightPolicy.ManifestExpander = projectPreflightExpander{delegate: expander}
		decision := gate.New(store, preflightPolicy, logger).Evaluate([]packagemanager.Install{}, preflight.ManifestRefs...)
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
		if runGypPreflightIfNpmFamily(logger, pm, pmArgs) {
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

func runSync(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
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
	fmt.Printf("veto: synced sources %v (%d reports)\n", store.SourceIDs(), store.ReportCount())
	return exitOK
}

func runStatus(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	fmt.Printf("veto: configured sources: %v\n", store.SourceIDs())
	fmt.Printf("veto: cache dir: %s\n", cfg.CacheDir)
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
func findWrappedOriginal(argv0 string, registered func(string) bool) (string, bool) {
	if argv0 == "" || !strings.ContainsRune(argv0, '/') {
		return "", false
	}
	abs, err := filepath.Abs(argv0)
	if err != nil {
		return "", false
	}
	if registered == nil || !registered(abs) {
		return "", false
	}
	original := abs + ".veto-original"
	info, err := os.Stat(original)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return "", false
	}
	return original, true
}

// findRealBinary returns the path veto should exec to satisfy a
// gated install. Prefers a wrapped-original sibling (Layer 4), then
// falls back to a PATH walk that skips any veto-pointing entries.
//
// `registered` is a wrappers.json membership predicate; see
// findWrappedOriginal for the provenance rationale.
func findRealBinary(name string, registered func(string) bool) (string, error) {
	if wrapped, ok := findWrappedOriginal(os.Args[0], registered); ok {
		return wrapped, nil
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
			if registered != nil && registered(candidate) {
				if sibling := candidate + ".veto-original"; isExecutableRegularOrSymlink(sibling) {
					return sibling, nil
				}
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
	CacheDir string
	Sources  []string // enabled source IDs
}

func loadConfig() (config, error) {
	v := viper.New()
	v.SetEnvPrefix("VETO")
	v.AutomaticEnv()
	v.SetDefault("cache_dir", defaultCacheDir())
	v.SetDefault("sources", []string{"aikido", "openssf", "osv", "pypa"})
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(filepath.Join(defaultCacheDir(), ".."))
	_ = v.ReadInConfig() // optional config file

	cfg := config{
		CacheDir: v.GetString("cache_dir"),
		Sources:  v.GetStringSlice("sources"),
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

// buildStore constructs the intel store from the configured sources. Unknown
// source IDs in config log a warning and are skipped — the user can mistype
// and still get a working store.
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
	return intel.NewStore(logger, sources...), nil
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
	default:
		return nil, errors.WithNew("unknown source").Set("id", id)
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
  veto sync                 refresh malware intel from all configured sources
  veto status               print configured sources and cache location
  veto doctor               verify defense layers + intel state (run after install)
  veto scan [--root DIR] [--json] [--no-projects] [--no-caches] [--no-agent-surface]
                            scan projects, package-manager caches, and agent
                            surfaces for existing exposure (read-only)
                            Project files include npm-family, Python-family,
                            Go, and Rust manifests and lockfiles.
  veto quarantine-cache [--dry-run] [--purge] [--json]
                            scan cache exposure and optionally purge confirmed
                            malicious cache artifacts
  veto audit-agent-surface [--json]
                            inspect Claude/Codex/Cursor/Sirene/MCP/launchd
                            persistence surfaces only
  veto help                 this message

Layer 1 — Claude Code hook (Bash tool interception):
  veto install-claude-hook [--project] [--settings PATH] [--print]
                               wire veto into ~/.claude/settings.json
  veto uninstall-claude-hook [--settings PATH]
                               remove the veto hook entry (preserves siblings)
  veto hook claude-code     read PreToolUse JSON from stdin, write a deny
                               decision to stdout if the command reaches a PM

Layer 2 — PATH shims (any agent shell, Codex, CI):
  veto install-shims [--dir DIR] [--force]
                               symlinks ~/.local/bin/{npm,pip,…} → veto
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
  veto install-all [--lib PATH] [--shell-rc PATH|auto] [--force] [--skip-interposer]
                               install shims, shell integration, Claude hook,
                               preload interposer, wrappers, sync intel, then doctor.
                               If --lib is omitted, builds libveto_interpose
                               with `+"`make interposer`"+` when run from the repo.

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
  VETO_SOURCES       comma-separated source IDs (default: aikido,openssf,osv,pypa)
                       optional broad vulnerability feed: ghsa
  VETO_LOG           set to "debug" for verbose logging
  VETO_PATH          set by install-preload; consumed by the interposer
`)
}
