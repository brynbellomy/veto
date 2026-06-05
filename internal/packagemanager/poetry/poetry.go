// Package poetry implements packagemanager.PackageManager for Poetry.
package poetry

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

const binaryName = "poetry"

var installVerbs = map[string]struct{}{
	"install": {}, "add": {}, "update": {}, "lock": {},
}

// flagsWithValues lists Poetry flags whose next argv token is the value.
// Covers the global options that fronted commands (--directory, --project,
// --source) plus `poetry add`'s own value-taking flags.
var flagsWithValues = argv.FlagsWithValues{
	"--directory":  {},
	"-C":           {},
	"--project":    {},
	"-P":           {},
	"--source":     {},
	"--python":     {},
	"--extras":     {},
	"-E":           {},
	"--group":      {},
	"-G":           {},
	"--with":       {},
	"--without":    {},
	"--only":       {},
	"--platform":   {},
	"--markers":    {},
	"--constraint": {},
	"--cache-dir":  {},
	"--config":     {},
	"--verbosity":  {},
}

// Manager parses poetry install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a poetry manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, pyspec.Parse(spec))
	}
	return installs
}

// pyprojectInstallVerbs names the verbs whose work is derived from
// pyproject.toml when no explicit specs are given. `poetry add` is excluded
// because it requires a spec to act on. `poetry lock` doesn't install anything
// gateable, but it still reads the manifest — keep it conservative and skip.
var pyprojectInstallVerbs = map[string]struct{}{
	"install": {},
	"update":  {},
}

// ManifestRefs implements packagemanager.PackageManager. Emits both
// pyproject.toml AND poetry.lock refs for install-shaped verbs. The
// lockfile carries the resolved transitive tree; the manifest carries
// the direct deps. Emitting both gives transitive coverage without the
// parser having to know which file the user has on disk — the expander
// returns nil, nil for missing files.
//
// pyproject.toml is emitted only when the user named no explicit specs
// (preserving the original "explicit specs supersede manifest pull"
// behavior for direct gating); poetry.lock is emitted unconditionally so
// known-flagged transitives can't sit there unnoticed during e.g.
// `poetry add new-thing`.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	refs := []packagemanager.ManifestRef{
		{Path: "poetry.lock", Kind: packagemanager.ManifestKindPoetryLock},
	}
	if _, derivesFromPyProject := pyprojectInstallVerbs[verb]; derivesFromPyProject {
		if specs := argv.CollectPositionalsWithTable(rest, flagsWithValues); len(specs) == 0 {
			refs = append(refs, packagemanager.ManifestRef{Path: "pyproject.toml", Kind: packagemanager.ManifestKindPyProject})
		}
	}
	return refs
}
