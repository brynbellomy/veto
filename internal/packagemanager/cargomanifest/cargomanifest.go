// Package cargomanifest reads Cargo.toml direct dependency declarations and
// emits Install records for project scans.
//
// Cargo.toml carries requirements, not resolved pins. Plain versions such as
// "1.0.0" are caret requirements in Cargo, so this expander leaves Version
// empty unless the requirement is explicitly exact (`=1.0.0`). Cargo.lock is
// the resolved transitive source for exact crate versions.
//
// For a workspace root ([workspace] members = [...]), each member crate's
// Cargo.toml is walked too, since `cargo build` at the root compiles every
// member and a fresh checkout has no Cargo.lock to fall back on.
package cargomanifest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"
	"github.com/pelletier/go-toml/v2"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// Expander handles Cargo.toml files. Stateless and safe for concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand reads Cargo.toml and returns direct dependency declarations. Missing
// files and unknown kinds return nil, nil.
//
// When the root is a workspace ([workspace] members = [...]), each member
// crate's Cargo.toml is walked too: `cargo build` at a workspace root compiles
// every member, so a member-only dep would otherwise be missed on a fresh
// checkout with no Cargo.lock. Members are discovered from the root only;
// `exclude` is honored.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindCargoToml {
		return nil, nil
	}
	doc, ok, err := decodeCargoToml(ref.Path)
	if err != nil || !ok {
		return nil, err
	}

	seen := map[string]struct{}{}
	var out []packagemanager.Install
	visit := func(deps map[string]any) {
		for name, raw := range deps {
			ins, ok := installFromDependency(name, raw)
			if !ok {
				continue
			}
			key := ins.Ref.Name + "@" + ins.Ref.Version
			if ins.LocalPath {
				key += ":path"
			}
			if ins.OpaqueRemote {
				key += ":opaque"
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ins)
		}
	}

	collectDependencyTables(doc, visit)

	members, err := cargoWorkspaceMembers(filepath.Dir(ref.Path), doc)
	if err != nil {
		return nil, err
	}
	for _, memberPath := range members {
		mdoc, ok, err := decodeCargoToml(memberPath)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		collectDependencyTables(mdoc, visit)
	}
	return out, nil
}

// decodeCargoToml reads and parses a Cargo.toml. The bool is false (with a nil
// error) when the file does not exist — workspace globs can name dirs without a
// Cargo.toml, and scans run from non-project directories. Malformed TOML or any
// other read error returns a wrapped error so the gate fails closed.
func decodeCargoToml(path string) (map[string]any, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, vetoerrors.With(err, "read Cargo.toml").Set("path", path)
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, false, vetoerrors.With(err, "parse Cargo.toml").Set("path", path)
	}
	return doc, true, nil
}

// cargoWorkspaceMembers expands the [workspace] members/exclude directory globs
// (relative to rootDir) and returns the Cargo.toml path inside each
// non-excluded member directory that has one. Glob matches that are not
// directories, or lack a Cargo.toml, are skipped. Only explicit members are
// walked — Cargo's implicit path-dependency members are out of scope.
func cargoWorkspaceMembers(rootDir string, doc map[string]any) ([]string, error) {
	workspace, ok := tableValue(doc["workspace"])
	if !ok {
		return nil, nil
	}
	members := stringSlice(workspace["members"])
	if len(members) == 0 {
		return nil, nil
	}

	excluded := make(map[string]struct{})
	for _, pat := range stringSlice(workspace["exclude"]) {
		matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(pat)))
		if err != nil {
			return nil, vetoerrors.With(err, "expand workspace exclude glob").Set("pattern", pat)
		}
		for _, m := range matches {
			excluded[m] = struct{}{}
		}
	}

	var out []string
	seenDir := make(map[string]struct{})
	for _, pat := range members {
		matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(pat)))
		if err != nil {
			return nil, vetoerrors.With(err, "expand workspace member glob").Set("pattern", pat)
		}
		for _, dir := range matches {
			if _, ex := excluded[dir]; ex {
				continue
			}
			if _, dup := seenDir[dir]; dup {
				continue
			}
			seenDir[dir] = struct{}{}
			ct := filepath.Join(dir, "Cargo.toml")
			if info, err := os.Stat(ct); err != nil || info.IsDir() {
				continue
			}
			out = append(out, ct)
		}
	}
	return out, nil
}

// stringSlice extracts the string elements of a TOML array decoded as []any,
// dropping any non-string entries.
func stringSlice(raw any) []string {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func collectDependencyTables(doc map[string]any, visit func(map[string]any)) {
	visitDirectDependencyTables(doc, visit)

	if workspace, ok := tableValue(doc["workspace"]); ok {
		if deps, ok := tableValue(workspace["dependencies"]); ok {
			visit(deps)
		}
	}

	if targets, ok := tableValue(doc["target"]); ok {
		for _, rawTarget := range targets {
			target, ok := tableValue(rawTarget)
			if !ok {
				continue
			}
			visitDirectDependencyTables(target, visit)
		}
	}
}

func visitDirectDependencyTables(node map[string]any, visit func(map[string]any)) {
	for _, key := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		deps, ok := tableValue(node[key])
		if ok {
			visit(deps)
		}
	}
}

func tableValue(raw any) (map[string]any, bool) {
	child, ok := raw.(map[string]any)
	return child, ok
}

func installFromDependency(name string, raw any) (packagemanager.Install, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return packagemanager.Install{}, false
	}
	ins := packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: name},
		RawSpec: name + " (from Cargo.toml)",
	}
	switch v := raw.(type) {
	case string:
		ins.Ref.Version = exactCargoVersion(v)
		return ins, true
	case map[string]any:
		if pkg, ok := stringValue(v["package"]); ok && pkg != "" {
			ins.Ref.Name = pkg
		}
		if _, ok := v["path"]; ok {
			ins.LocalPath = true
			return ins, true
		}
		if _, ok := v["git"]; ok {
			ins.OpaqueRemote = true
			return ins, true
		}
		if version, ok := stringValue(v["version"]); ok {
			ins.Ref.Version = exactCargoVersion(version)
		}
		return ins, true
	default:
		return ins, true
	}
}

func exactCargoVersion(req string) string {
	req = strings.TrimSpace(req)
	if !strings.HasPrefix(req, "=") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(req, "="))
}

func stringValue(raw any) (string, bool) {
	s, ok := raw.(string)
	return strings.TrimSpace(s), ok
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
