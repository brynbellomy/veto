// Package bun implements packagemanager.PackageManager for the bun CLI.
//
// Bun is the motivating case for command-level gating: safe-chain's proxy-only
// approach for bun fails open in non-interactive shells (the bug that prompted
// this project). At the command level we don't care how bun fetches packages
// — we check the names against intel before bun ever runs.
package bun

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

const binaryName = "bun"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"update": {}, "upgrade": {},
	"x":      {}, // `bun x <pkg>` — fetches and runs
	"create": {}, // `bun create <template>` — fetches a starter template
}

// alwaysReadsManifest is empty for bun: install verbs resolve from the
// manifest only when no specs are given (caught by the empty-specs branch).
var alwaysReadsManifest = map[string]struct{}{}

// flagsWithValues lists bun flags whose next argv token is the value.
// Bun's CLI is still evolving; this is the realistic set agents/users
// reach for, not an exhaustive mirror of `bun --help`.
var flagsWithValues = argv.FlagsWithValues{
	"--cwd":           {},
	"--config":        {},
	"-c":              {},
	"--registry":      {},
	"--cache-dir":     {},
	"--backend":       {},
	"--lockfile":      {},
	"--prefix":        {},
	"--target":        {},
	"--bun-debug-jsc": {},
}

// Manager parses bun install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a bun manager.
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
