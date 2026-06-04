// Package yarn implements packagemanager.PackageManager for Yarn (classic and
// berry; verb sets overlap enough that one parser handles both).
package yarn

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

// infoFlags are help/version flags that mean "yarn won't install anything,
// just print info." When the user invokes bare `yarn` with only these flags
// present, we still pass through; otherwise bare `yarn` is treated as the
// implicit `yarn install`.
var infoFlags = map[string]struct{}{
	"--help":    {},
	"-h":        {},
	"--version": {},
	"-v":        {},
}

const binaryName = "yarn"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {},
	"upgrade": {}, "up": {},
	"dlx": {}, // yarn berry's `yarn dlx <pkg>` — equivalent to npx
}

// alwaysReadsManifest is empty for yarn: `yarn install` resolves from the
// manifest only when no specs are given (caught by the empty-specs branch).
var alwaysReadsManifest = map[string]struct{}{}

// flagsWithValues lists yarn flags whose next argv token is the value.
// Covers both classic (--cache-folder, --modules-folder) and berry
// (--cwd, --cache-folder) shapes where they differ; the union is safe
// since the goal is to avoid mistaking a flag-value for a positional.
var flagsWithValues = argv.FlagsWithValues{
	"--cwd":                 {},
	"--cache-folder":        {},
	"--modules-folder":      {},
	"--registry":            {},
	"--prefix":              {},
	"--use-yarnrc":          {},
	"--proxy":               {},
	"--https-proxy":         {},
	"--network-timeout":     {},
	"--network-concurrency": {},
	"--mutex":               {},
	"--otp":                 {},
	"--tag":                 {},
}

// Manager parses yarn install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a yarn manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
//
// Yarn classic treats bare `yarn` (no verb) as `yarn install` — the most
// common form in CI scripts and Dockerfiles. We special-case that here so the
// gate engages on the implicit-install path. Returning an empty-non-nil slice
// (mirroring `yarn install` with no explicit specs) keeps the gate from
// short-circuiting to passthrough; the package.json + lockfile expanders gate
// the dependency tree.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	if installs := jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues); installs != nil {
		return installs
	}
	if isBareInstall(args) {
		return []packagemanager.Install{}
	}
	return nil
}

// ManifestRefs implements packagemanager.PackageManager. Emits a package.json
// ref when an install verb was given with no explicit specs, so the gate's
// expander can read the manifest and gate its direct dependencies. Also
// covers yarn's bare-install form (`yarn`, `yarn --frozen-lockfile`).
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	if refs := jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues); refs != nil {
		return refs
	}
	if isBareInstall(args) {
		return []packagemanager.ManifestRef{
			{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON},
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
			{Path: "npm-shrinkwrap.json", Kind: packagemanager.ManifestKindNpmShrinkwrap},
			{Path: "pnpm-lock.yaml", Kind: packagemanager.ManifestKindPnpmLockYAML},
			{Path: "yarn.lock", Kind: packagemanager.ManifestKindYarnLock},
		}
	}
	return nil
}

// isBareInstall reports whether args describe `yarn` with no verb and no
// info-only flag (i.e. yarn classic's implicit-install form). Args containing
// `--help`, `-h`, `--version`, or `-v` are info queries, not installs.
//
// We use the same flag-table-aware iteration the verb parser uses, so a
// flag-with-value like `--cwd /tmp` doesn't get mistaken for a verb. If any
// non-flag token is present, the standard verb parser has already handled it;
// this function only fires when ParseInstallArgs returned nil.
func isBareInstall(args []string) bool {
	if _, _, hasVerb := argv.FirstNonFlagWithTable(args, flagsWithValues); hasVerb {
		// A verb (or a positional past `--`) was present — the standard
		// parser already classified it; bare-install does not apply.
		return false
	}
	for _, tok := range args {
		if !argv.IsFlag(tok) {
			continue
		}
		name := tok
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			name = tok[:eq]
		}
		if _, info := infoFlags[name]; info {
			return false
		}
	}
	return true
}
