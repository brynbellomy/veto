// Package exec implements packagemanager.PackageManager for the "fetch and
// run" CLIs: npx, bunx, pnpx, uvx, and `pipx run`.
//
// Every non-help invocation of these tools fetches a remote package and
// executes it, so the entire command is treated as an install — the first
// non-flag token after the binary name (or the verb, for pipx) is the spec.
//
// A single parameterized Manager serves all five binaries; veto's main
// constructs one instance per supported binary at startup, passing its
// per-binary FlagsWithValues table so global flags-with-values (e.g.
// `npx --package foo my-cmd`, `pipx --python python3.12 run bar`) don't
// trick the parser into reading the value as the spec.
package exec

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

// NpxFlagsWithValues is the realistic set of npx flags whose next argv
// token is the value (e.g. `npx --package foo cli-cmd`).
var NpxFlagsWithValues = argv.FlagsWithValues{
	"--package":    {},
	"-p":           {},
	"--call":       {},
	"-c":           {},
	"--workspace":  {},
	"-w":           {},
	"--prefix":     {},
	"--registry":   {},
	"--userconfig": {},
}

// NpxSpecFlags is the subset of NpxFlagsWithValues whose value is itself the
// package to fetch. `npx -p evil-pkg some-cmd` must be gated on "evil-pkg",
// not "some-cmd" (which is a binary inside the fetched package).
var NpxSpecFlags = argv.FlagsWithValues{
	"--package": {},
	"-p":        {},
}

// BunxFlagsWithValues mirrors `bunx` (a thin wrapper over `bun x`).
var BunxFlagsWithValues = argv.FlagsWithValues{
	"--cwd":       {},
	"--registry":  {},
	"--cache-dir": {},
	"--config":    {},
	"-c":          {},
}

// PnpxFlagsWithValues mirrors pnpm's dlx (pnpx is the legacy alias).
var PnpxFlagsWithValues = argv.FlagsWithValues{
	"--package":   {},
	"-p":          {},
	"--registry":  {},
	"--store-dir": {},
	"--prefix":    {},
}

// PnpxSpecFlags: like NpxSpecFlags but for pnpm's dlx-style invocation.
var PnpxSpecFlags = argv.FlagsWithValues{
	"--package": {},
	"-p":        {},
}

// UvxFlagsWithValues lists uvx flags whose next argv token is the value.
var UvxFlagsWithValues = argv.FlagsWithValues{
	"--python":            {},
	"-p":                  {},
	"--with":              {},
	"--with-requirements": {},
	"--from":              {},
	"--index":             {},
	"--index-url":         {},
	"-i":                  {},
	"--extra-index-url":   {},
	"--cache-dir":         {},
	"--config-file":       {},
	"--resolution":        {},
	"--prerelease":        {},
}

// PipxFlagsWithValues lists pipx flags whose next argv token is the value.
// Note: pipx accepts both pre-verb global flags (`pipx --python python3.12
// run foo`) and per-verb flags after the verb. The same table covers both
// because the parser uses it on each side of the verb split.
var PipxFlagsWithValues = argv.FlagsWithValues{
	"--python":    {},
	"--pip-args":  {},
	"--spec":      {},
	"--index-url": {},
	"--suffix":    {},
	"--editable":  {},
	"-e":          {},
}

// PipxSpecFlags: `pipx run --spec evil-pkg some-cmd` fetches evil-pkg and
// runs some-cmd from it. The spec to gate is evil-pkg.
var PipxSpecFlags = argv.FlagsWithValues{
	"--spec": {},
}

// Options configures one exec-style Manager.
type Options struct {
	// Name is the binary (e.g. "npx", "bunx", "pipx").
	Name string

	// Ecosystem identifies which spec parser to use.
	Ecosystem intel.Ecosystem

	// PipxStyle treats args as `pipx <verb> <pkg>` rather than `npx <pkg>`.
	// Set true for pipx; false for everything else.
	PipxStyle bool

	// FlagsWithValues lists flags whose next argv token is the flag's
	// value, so the parser doesn't mistake that value for the spec.
	// Optional — a nil table degrades to flag-name-only skipping.
	FlagsWithValues argv.FlagsWithValues

	// SpecFlags is the subset of FlagsWithValues whose VALUE is itself the
	// package spec to be gated, not a tunable to skip. npx uses --package/-p
	// this way: `npx -p evil-pkg some-cmd` fetches evil-pkg, then runs
	// some-cmd from it — the package to gate is evil-pkg, not some-cmd.
	// pipx uses --spec analogously. Each name listed here must ALSO appear
	// in FlagsWithValues so the surrounding parser correctly accounts for
	// the consumed token. When any spec-flag value is present, the
	// first-positional fallback is skipped (the positional is the command
	// name, not a package).
	SpecFlags argv.FlagsWithValues
}

// Manager parses exec-style commands for one binary.
type Manager struct {
	opts Options
}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds an exec Manager.
func New(opts Options) *Manager {
	if opts.Name == "" {
		panic("exec: Options.Name is required")
	}
	if opts.Ecosystem == "" {
		panic("exec: Options.Ecosystem is required")
	}
	return &Manager{opts: opts}
}

// Name implements packagemanager.PackageManager.
func (m *Manager) Name() string { return m.opts.Name }

// Ecosystem implements packagemanager.PackageManager.
func (m *Manager) Ecosystem() intel.Ecosystem { return m.opts.Ecosystem }

// ParseInstalls implements packagemanager.PackageManager.
//
// Two shapes:
//
//   - Spec via flag: `npx -p evil-pkg some-cmd`, `pipx run --spec evil-pkg
//     some-cmd`. The flag's value (or values, when repeated) is the package
//     spec; the trailing positional is the command name, not a package.
//   - Spec via positional: `npx evil-pkg`, `bunx evil-pkg`, `pipx run
//     evil-pkg`. The first non-flag token is the spec.
//
// For PipxStyle managers we first locate the action verb (`run`, `install`,
// `upgrade`, `inject`) and parse what follows. The verb determines how the
// trailing positionals are interpreted:
//
//   - `run`: pipx runs ONE package; only the first positional is the spec
//     (everything after is forwarded to the command being run).
//   - `install`/`upgrade`: pipx accepts multiple package specs in a single
//     invocation; every positional is a separate install to gate.
//   - `inject`: the FIRST positional is the local venv name (already
//     installed, not a package), and every positional after that is a
//     package being injected into that venv. Gating the venv name is wrong
//     and gating only the venv name lets the actual injected packages slip
//     through unchecked.
func (m *Manager) ParseInstalls(args []string) []packagemanager.Install {
	rest := args
	verb := ""
	if m.opts.PipxStyle {
		v, after, ok := argv.FirstNonFlagWithTable(args, m.opts.FlagsWithValues)
		if !ok {
			return nil
		}
		switch v {
		case "run", "install", "upgrade", "inject":
			verb = v
			rest = after
		default:
			return nil
		}
	}

	// Spec-via-flag wins over spec-via-positional: when the user wrote
	// `npx -p foo cmd`, "cmd" is a binary name inside the package "foo",
	// not itself a package. Same for `pipx run --spec foo cmd`.
	if len(m.opts.SpecFlags) > 0 {
		flagSpecs := argv.CollectFlagValues(rest, m.opts.SpecFlags, m.opts.FlagsWithValues)
		if len(flagSpecs) > 0 {
			out := make([]packagemanager.Install, 0, len(flagSpecs))
			for _, spec := range flagSpecs {
				out = append(out, m.parseSpec(spec))
			}
			return out
		}
	}

	// Multi-install pipx verbs: every positional is a package spec to gate.
	// `inject` is the same shape but with the venv name (first positional)
	// dropped — that name refers to an existing local venv, not a package.
	if m.opts.PipxStyle && (verb == "install" || verb == "upgrade" || verb == "inject") {
		positionals := argv.CollectPositionalsWithTable(rest, m.opts.FlagsWithValues)
		if verb == "inject" {
			if len(positionals) <= 1 {
				return nil
			}
			positionals = positionals[1:]
		}
		if len(positionals) == 0 {
			return nil
		}
		out := make([]packagemanager.Install, 0, len(positionals))
		for _, spec := range positionals {
			if spec == "help" {
				continue
			}
			out = append(out, m.parseSpec(spec))
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}

	spec, _, ok := argv.FirstNonFlagWithTable(rest, m.opts.FlagsWithValues)
	if !ok {
		return nil
	}
	// `--help`, `--version` already filtered out by the flag skip.
	// Special-case bare-help arguments that aren't flags:
	if spec == "help" {
		return nil
	}
	return []packagemanager.Install{m.parseSpec(spec)}
}

func (m *Manager) parseSpec(spec string) packagemanager.Install {
	switch m.opts.Ecosystem {
	case intel.EcosystemNPM:
		return jsspec.Parse(spec)
	case intel.EcosystemPyPI:
		return pyspec.Parse(spec)
	default:
		return packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: m.opts.Ecosystem, Name: spec},
			RawSpec: spec,
		}
	}
}

// ManifestRefs implements packagemanager.PackageManager. The exec-style
// tools fetch a single remote package; they don't follow on-disk manifests
// from argv.
func (m *Manager) ManifestRefs(args []string) []packagemanager.ManifestRef { return nil }
