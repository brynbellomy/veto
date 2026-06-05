// Package golang implements packagemanager.PackageManager for the Go CLI.
package golang

import (
	"path/filepath"
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
)

const binaryName = "go"

// flagsWithValues lists Go flags whose next argv token is the value. The Go
// command accepts many command-specific flags after the verb, so this table is
// intentionally shared across covered verbs to avoid mistaking flag values
// for module specs.
var flagsWithValues = argv.FlagsWithValues{
	"-C":            {},
	"-mod":          {},
	"-modfile":      {},
	"-overlay":      {},
	"-tags":         {},
	"-exec":         {},
	"-asmflags":     {},
	"-gcflags":      {},
	"-ldflags":      {},
	"-gccgoflags":   {},
	"-toolexec":     {},
	"-pkgdir":       {},
	"-p":            {},
	"-o":            {},
	"-buildmode":    {},
	"-compiler":     {},
	"-coverpkg":     {},
	"-coverprofile": {},
	"-run":          {},
	"-bench":        {},
	"-benchtime":    {},
	"-count":        {},
	"-cpu":          {},
	"-list":         {},
	"-parallel":     {},
	"-timeout":      {},
	"-vet":          {},
	"-reuse":        {},
}

// Manager parses Go dependency-fetching commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)
var _ packagemanager.ProjectPreflighter = (*Manager)(nil)
var _ packagemanager.EnvRecursionPolicy = (*Manager)(nil)

// New builds a Go manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemGo }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "get":
		return parseModuleSpecs(rest, parseAllPositionals)
	case "install":
		return parseModuleSpecs(rest, parseAllPositionals)
	case "run":
		return parseModuleSpecs(rest, parseFirstRemoteVersioned)
	case "mod":
		subVerb, subRest, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK {
			return nil
		}
		switch subVerb {
		case "download":
			return parseModuleSpecs(subRest, parseAllPositionals)
		case "tidy":
			return []packagemanager.Install{}
		}
	}
	return nil
}

// ManifestRefs implements packagemanager.PackageManager.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	baseDir, modFile := goProjectPaths(args)
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "get":
		if removalOnly(rest) {
			return nil
		}
		// Phase 1.8: `go get -u` (no positionals) walks the existing
		// module graph; gate go.mod's transitive set instead of
		// returning nil.
		if len(argv.CollectPositionalsWithTable(rest, flagsWithValues)) == 0 {
			return goModuleRefs(baseDir, modFile)
		}
		return goModuleRefs(baseDir, modFile)
	case "install":
		// Phase 1.8: `go install ./cmd/foo` (local-path positionals)
		// compiles local code that links to go.mod's deps; emit
		// module refs so the gate sees the transitive set. Pure-
		// remote forms (`go install pkg@v1`) are caught by
		// ParseInstalls and don't need module refs (the remote
		// install uses its own go.mod from the module cache).
		positionals := argv.CollectPositionalsWithTable(rest, flagsWithValues)
		anyLocal := len(positionals) == 0
		for _, p := range positionals {
			if isLocalGoSpec(p) {
				anyLocal = true
				break
			}
		}
		if anyLocal {
			return goModuleRefs(baseDir, modFile)
		}
		return nil
	case "mod":
		subVerb, _, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK {
			return nil
		}
		switch subVerb {
		case "download", "tidy":
			return goModuleRefs(baseDir, modFile)
		}
	}
	return nil
}

// ProjectPreflight implements packagemanager.ProjectPreflighter for Go
// build/test/run commands that execute local project code.
func (Manager) ProjectPreflight(args []string) (packagemanager.ProjectPreflightPlan, bool) {
	baseDir, modFile := goProjectPaths(args)
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return packagemanager.ProjectPreflightPlan{}, false
	}
	switch verb {
	case "build", "test", "vet":
		return packagemanager.ProjectPreflightPlan{ManifestRefs: goModuleRefs(baseDir, modFile)}, true
	case "install":
		// Phase 1.8: `go install` with no positionals compiles current
		// module's commands; same semantics as `go build` but to $GOBIN.
		// With positionals it goes through ParseInstalls + ManifestRefs.
		if len(argv.CollectPositionalsWithTable(rest, flagsWithValues)) == 0 {
			return packagemanager.ProjectPreflightPlan{ManifestRefs: goModuleRefs(baseDir, modFile)}, true
		}
		return packagemanager.ProjectPreflightPlan{}, false
	case "run":
		if !goRunIsLocal(rest) {
			return packagemanager.ProjectPreflightPlan{}, false
		}
		return packagemanager.ProjectPreflightPlan{ManifestRefs: goModuleRefs(baseDir, modFile)}, true
	default:
		return packagemanager.ProjectPreflightPlan{}, false
	}
}

// EnvRecursionRisk implements packagemanager.EnvRecursionPolicy.
//
// Argv parsing reuses flagsWithValues so flags like `-C dir` or
// `-ldflags=...` don't fool the verb classifier.
func (Manager) EnvRecursionRisk(args []string) packagemanager.EnvRecursionRiskLevel {
	verb, _, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		// `go` with no verb prints help. It does not re-enter veto.
		return packagemanager.RecursionRiskLow
	}
	switch verb {
	case "run", "build", "test", "vet", "get", "list", "fmt", "doc",
		"env", "version", "fix", "clean", "telemetry", "bug", "mod", "work":
		// mod/work are intentionally allowed by parent verb: every documented
		// subverb is a metadata op, so treating subverbs as low avoids noise.
		return packagemanager.RecursionRiskLow
	case "install", "generate", "tool":
		return packagemanager.RecursionRiskHigh
	default:
		return packagemanager.RecursionRiskUnknown
	}
}

type parseMode int

const (
	parseAllPositionals parseMode = iota
	parseFirstRemoteVersioned
)

func parseModuleSpecs(rest []string, mode parseMode) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		return nil
	}
	if mode == parseFirstRemoteVersioned {
		_, _, hasVersion := splitModuleVersion(specs[0])
		if !hasVersion {
			return nil
		}
		ins, ok := parseModuleSpec(specs[0])
		if !ok || ins.LocalPath || ins.OpaqueRemote {
			return nil
		}
		return []packagemanager.Install{ins}
	}
	out := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		ins, ok := parseModuleSpec(spec)
		if ok {
			out = append(out, ins)
		}
	}
	if len(out) == 0 {
		return []packagemanager.Install{}
	}
	return out
}

func parseModuleSpec(spec string) (packagemanager.Install, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return packagemanager.Install{}, false
	}
	if isOpaqueRemoteSpec(spec) {
		return packagemanager.Install{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: spec},
			RawSpec:      spec,
			OpaqueRemote: true,
		}, true
	}
	name, version, hasVersion := splitModuleVersion(spec)
	if version == "none" {
		return packagemanager.Install{}, false
	}
	if strings.HasSuffix(name, "/...") {
		name = strings.TrimSuffix(name, "/...")
	}
	if isLocalGoSpec(name) {
		return packagemanager.Install{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: name},
			RawSpec:   spec,
			LocalPath: true,
		}, true
	}
	if !hasVersion && !looksLikeRemoteModulePath(name) {
		return packagemanager.Install{}, false
	}
	if !isExactGoVersion(version) {
		version = ""
	}
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: name, Version: version},
		RawSpec: spec,
	}, true
}

func splitModuleVersion(spec string) (string, string, bool) {
	idx := strings.LastIndex(spec, "@")
	if idx <= 0 || idx == len(spec)-1 {
		return spec, "", false
	}
	return spec[:idx], spec[idx+1:], true
}

func isExactGoVersion(version string) bool {
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return false
	}
	return version[0] >= '0' && version[0] <= '9'
}

func isLocalGoSpec(spec string) bool {
	return spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") || strings.HasSuffix(spec, ".go")
}

func isOpaqueRemoteSpec(spec string) bool {
	for _, prefix := range []string{"git+", "git://", "http://", "https://"} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	return false
}

func looksLikeRemoteModulePath(name string) bool {
	first, _, _ := strings.Cut(name, "/")
	return strings.Contains(first, ".")
}

func removalOnly(rest []string) bool {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		return false
	}
	for _, spec := range specs {
		_, version, ok := splitModuleVersion(spec)
		if !ok || version != "none" {
			return false
		}
	}
	return true
}

func goProjectPaths(args []string) (string, string) {
	baseDir := firstFlagValue(args, "-C")
	modFile := firstFlagValue(args, "-modfile")
	if baseDir == "" {
		baseDir = "."
	}
	return baseDir, modFile
}

func firstFlagValue(args []string, flag string) string {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return ""
		}
		if value, ok := strings.CutPrefix(tok, flag+"="); ok {
			return value
		}
		if tok == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func goRunIsLocal(rest []string) bool {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		return false
	}
	_, _, hasVersion := splitModuleVersion(specs[0])
	if !hasVersion {
		return true
	}
	ins, ok := parseModuleSpec(specs[0])
	return !ok || ins.LocalPath || ins.OpaqueRemote
}

func goModuleRefs(baseDir, modFile string) []packagemanager.ManifestRef {
	if baseDir == "" {
		baseDir = "."
	}
	if modFile == "" {
		return []packagemanager.ManifestRef{
			{Path: filepath.Join(baseDir, "go.mod"), Kind: packagemanager.ManifestKindGoMod},
			{Path: filepath.Join(baseDir, "go.sum"), Kind: packagemanager.ManifestKindGoSum},
		}
	}
	modPath := modFile
	if !filepath.IsAbs(modPath) {
		modPath = filepath.Join(baseDir, modPath)
	}
	// Phase 1.8: only swap the extension when it's literally `.mod`.
	// Go's internal modload behavior: -modfile=foo.bar produces
	// foo.bar.sum (append, not strip). The prior TrimSuffix unconditionally
	// stripped any extension and produced "foo.sum" for "foo.bar".
	sumPath := modPath + ".sum"
	if filepath.Ext(modPath) == ".mod" {
		sumPath = strings.TrimSuffix(modPath, ".mod") + ".sum"
	}
	return []packagemanager.ManifestRef{
		{Path: modPath, Kind: packagemanager.ManifestKindGoMod},
		{Path: sumPath, Kind: packagemanager.ManifestKindGoSum},
	}
}
