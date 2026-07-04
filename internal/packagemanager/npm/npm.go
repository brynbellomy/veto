// Package npm implements packagemanager.PackageManager for the npm CLI.
//
// All real parsing lives in jsspec; this package just declares npm's install
// verb set, the flag-with-value table, and wires the binary name. Same shape
// for pnpm/yarn/bun.
package npm

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

const binaryName = "npm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"ci":     {}, // clean install from lockfile; no explicit specs
	"update": {}, "up": {}, "upgrade": {},
}

// execSpecFlags is the subset of flagsWithValues whose VALUE is the
// package spec to gate for `npm exec`. Mirrors NpxSpecFlags: `npm exec
// --package=foo -- some-cmd` fetches `foo` and runs `some-cmd` from it.
var execSpecFlags = argv.FlagsWithValues{
	"--package": {},
	"-p":        {},
}

// alwaysReadsManifest names the install verbs that consult package.json /
// package-lock.json regardless of argv. `ci` is the canonical case: it always
// resolves from the lockfile and refuses to accept positional specs.
var alwaysReadsManifest = map[string]struct{}{
	"ci": {},
}

// flagsWithValues lists npm flags whose next argv token is the flag's
// value, drawn from `npm --help` plus the common config-overriding flags
// agents and CI scripts actually reach for. Keeping this slim is fine —
// the goal is to stop the parser from mistaking values for the verb, not
// to model the full npm flag surface.
var flagsWithValues = argv.FlagsWithValues{
	"--prefix":       {},
	"--location":     {},
	"--registry":     {},
	"--userconfig":   {},
	"--globalconfig": {},
	"--tag":          {},
	"--workspace":    {},
	"-w":             {},
	"--omit":         {},
	"--include":      {},
	"--cache":        {},
	"--logfile":      {},
	"--loglevel":     {},
	"--depth":        {},
	"--save-prefix":  {},
	"--access":       {},
	// `npm exec` accepts -p / --package to name the package to fetch
	// independently of the trailing command. Listed here so the parser
	// doesn't read the value as the verb or as a positional spec.
	"--package": {},
	"-p":        {},
	// `--call` (-c) takes a shell string; without this, an `-c "evil"`
	// would be read as a positional.
	"--call": {},
	"-c":     {},
}

// Manager parses npm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)
var _ packagemanager.ResolverPreScanner = (*Manager)(nil)
var _ packagemanager.ProjectPreflighter = (*Manager)(nil)

// New builds an npm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
//
// `npm exec` is special-cased: it shares npx's "fetch-and-run a package"
// semantics, so we follow the same precedence — a `--package`/`-p` value
// wins over the trailing positional (which is just a binary name inside
// the fetched package). Everything else routes through the shared
// install-verb parser.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	if installs, ok := parseExec(args); ok {
		return installs
	}
	return jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues)
}

// parseExec returns (installs, true) when args describe `npm exec [...]`,
// otherwise (nil, false). When the user names `--package=foo` (or repeats it),
// the trailing positional is the binary name and we gate the flag values
// instead. Otherwise the first positional after `exec` is the spec —
// matching npx semantics.
func parseExec(args []string) ([]packagemanager.Install, bool) {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok || verb != "exec" {
		return nil, false
	}
	// Spec-via-flag wins. `npm exec -p evil-pkg some-cmd` fetches evil-pkg
	// and runs some-cmd from it.
	if flagSpecs := argv.CollectFlagValues(rest, execSpecFlags, flagsWithValues); len(flagSpecs) > 0 {
		out := make([]packagemanager.Install, 0, len(flagSpecs))
		for _, s := range flagSpecs {
			out = append(out, jsspec.Parse(s))
		}
		return out, true
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		// `npm exec` with no args/flags re-executes the script from the
		// nearest package.json — no fetch, nothing to gate.
		return nil, true
	}
	switch specs[0] {
	case "help", "--help", "-h", "--version", "-v":
		return nil, true
	}
	return []packagemanager.Install{jsspec.Parse(specs[0])}, true
}

// ProjectPreflight implements packagemanager.ProjectPreflighter for npm
// commands that execute project code without installing packages. The gated
// verbs are the lifecycle script runners: run, start, test, restart, stop.
// These execute scripts from node_modules, so veto gates the lockfile's
// transitive dependency tree before exec'ing the command.
func (Manager) ProjectPreflight(args []string) (packagemanager.ProjectPreflightPlan, bool) {
	verb, _, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return packagemanager.ProjectPreflightPlan{}, false
	}
	switch verb {
	case "run", "start", "test", "restart", "stop":
		return packagemanager.ProjectPreflightPlan{ManifestRefs: jsspec.ProjectPreflightRefs()}, true
	default:
		return packagemanager.ProjectPreflightPlan{}, false
	}
}

// ManifestRefs implements packagemanager.PackageManager. Emits a package.json
// ref when the install verb would derive its work from the local manifest —
// `npm install` / `npm i` with no specs, `npm ci` regardless of args — so the
// gate's expander can read the file and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	return jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues)
}

// ResolverPreScan implements packagemanager.ResolverPreScanner. npm can
// produce a complete package-lock.json without installing packages or running
// lifecycle scripts; veto runs that in an isolated temp copy and gates the
// resolved transitive tree before allowing the real install.
func (Manager) ResolverPreScan(args []string) (packagemanager.ResolverPreScanPlan, bool) {
	verb, _, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	if _, isInstall := installVerbs[verb]; !isInstall || verb == "ci" {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	directInstalls := jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues)
	if len(directInstalls) == 0 || hasUnsafeResolverPreScanSpec(directInstalls) {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	if hasGlobalInstall(args) {
		return packagemanager.ResolverPreScanPlan{}, false
	}
	return packagemanager.ResolverPreScanPlan{
		// The probe must resolve inside its isolated temp workdir. Global
		// installs are short-circuited above (hasGlobalInstall: npm cannot
		// generate a lockfile for them at all), but a caller-supplied
		// --prefix on a non-global install re-roots the
		// --package-lock-only resolution into the REAL tree, leaving the
		// workdir without the lockfile the gate inspects — the probe "runs
		// fine" and the gate aborts fail-closed on missing output. Strip
		// every project-re-rooting token and force project-local mode; the
		// appended last-wins overrides also beat an inherited
		// npm_config_global / npm_config_location env. The resolved
		// dependency tree is identical either way, and the real install
		// still runs with the caller's original argv.
		Args: appendResolverFlags(stripProjectRootFlags(args),
			"--package-lock=true",
			"--package-lock-only",
			"--ignore-scripts",
			"--dry-run=false",
			"--audit=false",
			"--fund=false",
			"--global=false",
			"--location=project",
		),
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
			{Path: "npm-shrinkwrap.json", Kind: packagemanager.ManifestKindNpmShrinkwrap},
		},
		SeedFiles: []string{
			"package.json",
			"package-lock.json",
			"npm-shrinkwrap.json",
			".npmrc",
		},
		DirectInstalls: directInstalls,
	}, true
}

// hasGlobalInstall reports whether argv requests a global install. npm cannot
// generate a lockfile for global packages (it errors with ESHRINKWRAPGLOBAL),
// so the --package-lock-only resolver pre-scan is impossible. veto skips the
// pre-scan for these and falls back to direct-spec intel + binding.gyp tarball
// gating. Disable forms (--no-global, --global=false, --location=user) must NOT
// match.
func hasGlobalInstall(args []string) bool {
	for i, a := range args {
		switch a {
		case "-g", "--global", "--global=true", "--location=global":
			return true
		case "--location":
			if i+1 < len(args) && args[i+1] == "global" {
				return true
			}
		}
	}
	return false
}

func hasUnsafeResolverPreScanSpec(installs []packagemanager.Install) bool {
	for _, ins := range installs {
		if ins.LocalPath || ins.OpaqueRemote {
			return true
		}
	}
	return false
}

// stripProjectRootFlags removes the argv tokens that re-root npm's project
// resolution: -g/--global, --location, --prefix. See the ResolverPreScan
// comment for why the probe must not inherit them. The global forms are
// normally short-circuited earlier by hasGlobalInstall; stripping them here
// too keeps this helper correct under future reordering. Tokens after `--`
// are positional and copied through untouched.
func stripProjectRootFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, args[i:]...)
			break
		}
		switch {
		case arg == "-g" || arg == "--global" || strings.HasPrefix(arg, "--global="):
			continue
		case arg == "--location" || arg == "--prefix":
			i++ // the next token is the flag's value; drop both
			continue
		case strings.HasPrefix(arg, "--location=") || strings.HasPrefix(arg, "--prefix="):
			continue
		}
		out = append(out, arg)
	}
	return out
}

func appendResolverFlags(args []string, flags ...string) []string {
	out := make([]string, 0, len(args)+len(flags))
	for i, arg := range args {
		if arg == "--" {
			out = append(out, flags...)
			out = append(out, args[i:]...)
			return out
		}
		out = append(out, arg)
	}
	out = append(out, flags...)
	return out
}
