// Package pnpm implements packagemanager.PackageManager for pnpm.
package pnpm

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

const binaryName = "pnpm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"update": {}, "up": {}, "upgrade": {},
	"dlx": {}, // fetches and runs a package; equivalent risk to npx/bunx
}

// alwaysReadsManifest is empty for pnpm: every install verb here only consults
// package.json when no explicit specs were given (the default empty-specs
// branch in PackageJSONManifestRefs handles that). pnpm has no `ci`-equivalent
// that needs unconditional manifest read.
var alwaysReadsManifest = map[string]struct{}{}

// flagsWithValues lists pnpm flags whose next argv token is the value.
// pnpm reuses many of npm's flag names but adds a few of its own
// (--store-dir, --virtual-store-dir, --workspace-root).
var flagsWithValues = argv.FlagsWithValues{
	"--registry":              {},
	"--cache":                 {},
	"--prefix":                {},
	"--store-dir":             {},
	"--virtual-store-dir":     {},
	"--workspace-root":        {},
	"--filter":                {},
	"--filter-prod":           {},
	"--workspace":             {},
	"-w":                      {},
	"--tag":                   {},
	"--config":                {},
	"--loglevel":              {},
	"--reporter":              {},
	"--package-import-method": {},
}

// Manager parses pnpm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a pnpm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	return jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues)
}

// ManifestRefs implements packagemanager.PackageManager. Emits a package.json
// ref when an install verb was given with no explicit specs, so the gate's
// expander can read the manifest and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	return jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues)
}
