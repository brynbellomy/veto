// Package pymanifest reads Python pyproject.toml files and turns their
// direct-dependency tables into Install records.
//
// This is the I/O side of poetry/uv/pdm's "verb implies the manifest" flow
// (`poetry install`, `uv sync`, `pdm install`). The package manager returns a
// ManifestKindPyProject ref from argv; the gate's expander — implemented here
// — opens the TOML and walks the dependency tables that real-world Python
// projects use:
//
//   - [project] dependencies = [...]          (PEP 621 standard)
//   - [project.optional-dependencies.<group>] (PEP 621 extras)
//   - [dependency-groups.<group>]             (PEP 735 dependency groups)
//   - [tool.poetry.dependencies]              (Poetry)
//   - [tool.poetry.group.<name>.dependencies] (Poetry group deps)
//   - [tool.uv] dev-dependencies              (uv legacy dev deps)
//   - [tool.pdm.dev-dependencies.<group>]     (PDM dev deps)
//
// It also reads [tool.uv.sources] to flag declared deps that uv redirects to a
// git/url source (OpaqueRemote) or a path/workspace source (LocalPath), so a
// source redirect can't launder a remote-code fetch past the gate.
//
// When the root declares a [tool.uv.workspace], each member's pyproject.toml is
// walked too (members/exclude are directory globs), because `uv sync` installs
// every member's dependencies alongside the root's.
//
// Direct deps only. The intel store's name-keyed fallback catches every
// flagged version when the spec is a range we can't pin.
//
// Marker evaluation is intentionally not implemented: we over-include
// conditional deps the same way pyspec does. Resolving `sys_platform ==
// "linux"` correctly requires snapshotting the target environment, which
// veto can't observe from a manifest alone. Over-gating is the safe
// posture — a refusal the user can override is better than a missed
// install that wouldn't have happened on their platform anyway.
package pymanifest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	vetoerrors "github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

// Expander reads pyproject.toml files and emits the Install records the gate
// looks up.
//
// Safe for concurrent use; New() returns a stateless instance.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// pyproject is the subset of fields the expander cares about. Unknown
// fields are tolerated — projects mix conventions and load tools we don't
// recognize all the time.
//
// Poetry dependency values vary in shape — a plain string ("^1.0") for the
// common case, or an inline table ({ version = "^1.0", optional = true })
// for path/git/markered specs — so we decode them as `any` and type-switch
// in poetryDeps.
type pyproject struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	// PEP 735 dependency groups. Each group is a list whose entries are
	// usually PEP 508 strings, but an entry can also be an
	// {include-group = "..."} table referencing another group. Decoded as
	// []any so the include-group tables don't break the decode; they carry no
	// package name and are skipped (the referenced group is walked on its own).
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies map[string]any         `toml:"dependencies"`
			Group        map[string]poetryGroup `toml:"group"`
		} `toml:"poetry"`
		// uv's pre-PEP-735 dev dependency list. PEP 508 strings; decoded as
		// []any so an unexpected shape is skipped rather than aborting the
		// whole-file decode.
		//
		// Sources redirects a declared dependency to a non-PyPI source
		// (git/url/path/workspace/index). Each value is an inline table or an
		// array of marker-gated inline tables, so it is decoded as `any` and
		// type-switched in classifyUvSource.
		UV struct {
			DevDependencies []any          `toml:"dev-dependencies"`
			Sources         map[string]any `toml:"sources"`
			// Workspace lists member packages whose own pyproject.toml files
			// `uv sync` installs alongside the root. members/exclude are
			// directory globs relative to this file's directory.
			Workspace struct {
				Members []string `toml:"members"`
				Exclude []string `toml:"exclude"`
			} `toml:"workspace"`
		} `toml:"uv"`
		// PDM dev dependencies: group name → list of PEP 508 (or `-e path`)
		// strings. Decoded as []any for the same robustness reason.
		PDM struct {
			DevDependencies map[string][]any `toml:"dev-dependencies"`
		} `toml:"pdm"`
	} `toml:"tool"`
}

// poetryGroup mirrors the shape of `[tool.poetry.group.<name>]`. Only the
// dependency map is needed for gating.
type poetryGroup struct {
	Dependencies map[string]any `toml:"dependencies"`
}

// Expand reads ref.Path and returns the []Install its direct-dependency
// tables resolve to. Returns nil, nil for any ref.Kind other than
// ManifestKindPyProject so the compound expander can dispatch by kind.
//
// A missing file is not an error — some install verbs run from non-project
// directories. Malformed TOML returns a wrapped error with the path attached.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindPyProject {
		return nil, nil
	}

	pyp, ok, err := decodePyproject(ref.Path)
	if err != nil || !ok {
		return nil, err
	}

	// Dedupe by lower-cased PyPI name across all sources; the install set is
	// a set, not a multiset, and a dep listed in both [project] and
	// [tool.poetry.dependencies] should be gated once.
	seen := make(map[string]struct{}, 16)
	var installs []packagemanager.Install

	addInstall := func(ins packagemanager.Install) {
		key := strings.ToLower(strings.TrimSpace(ins.Ref.Name))
		if key == "" {
			return
		}
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		installs = append(installs, ins)
	}

	// Collect every [tool.uv.sources] table — the root's plus each workspace
	// member's — and apply them once at the end. Source overrides flag where a
	// dep is fetched from, so they must run after all deps are collected. The
	// root's entries take precedence on name collisions (first writer wins).
	var sources map[string]any
	mergeSources := func(s map[string]any) {
		if len(s) == 0 {
			return
		}
		if sources == nil {
			sources = make(map[string]any, len(s))
		}
		for name, raw := range s {
			if _, dup := sources[name]; !dup {
				sources[name] = raw
			}
		}
	}

	walkPyprojectDeps(pyp, addInstall)
	mergeSources(pyp.Tool.UV.Sources)

	// uv workspaces: `uv sync` at the root installs every member's deps too, so
	// a member-only malicious dep would otherwise be missed on a fresh checkout.
	// Members are discovered from the ROOT only — uv workspaces don't nest, and
	// not recursing avoids cycles.
	members, err := workspaceMemberPyprojects(filepath.Dir(ref.Path), pyp.Tool.UV.Workspace.Members, pyp.Tool.UV.Workspace.Exclude)
	if err != nil {
		return nil, err
	}
	for _, memberPath := range members {
		mpyp, ok, err := decodePyproject(memberPath)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		walkPyprojectDeps(mpyp, addInstall)
		mergeSources(mpyp.Tool.UV.Sources)
	}

	// uv: [tool.uv.sources] redirects a declared dep to git/url/path/workspace.
	// A name-keyed lookup can't see that the fetch is opaque-remote, so flag
	// the corresponding install before the gate decides.
	applyUvSources(installs, sources)

	return installs, nil
}

// decodePyproject reads and parses a pyproject.toml. The bool is false (with a
// nil error) when the file does not exist — install verbs run from non-project
// directories, and workspace globs can name dirs without a pyproject. Malformed
// TOML or any other read error returns a wrapped error so the gate fails closed.
func decodePyproject(path string) (pyproject, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return pyproject{}, false, nil
		}
		return pyproject{}, false, vetoerrors.With(err, "reading pyproject.toml").Set("path", path)
	}
	var pyp pyproject
	if _, err := toml.Decode(string(data), &pyp); err != nil {
		return pyproject{}, false, vetoerrors.With(err, "parse pyproject.toml").Set("path", path)
	}
	return pyp, true, nil
}

// walkPyprojectDeps adds every direct dependency declared in pyp's dependency
// tables via add. It does NOT handle [tool.uv.sources] (a cross-cutting flag
// applied after all deps are collected) or [tool.uv.workspace] (expanded only
// from the root). Safe to call for the root and for each workspace member,
// accumulating into a shared dedupe set through add.
func walkPyprojectDeps(pyp pyproject, add func(packagemanager.Install)) {
	// addSpecStrings parses and adds every PEP 508 string entry in specs.
	// Non-string entries — e.g. a PEP 735 {include-group = "..."} table, which
	// names another group walked separately — carry no package and are skipped.
	addSpecStrings := func(specs []any) {
		for _, entry := range specs {
			if spec, ok := entry.(string); ok {
				add(pyspec.Parse(spec))
			}
		}
	}

	// PEP 621: [project] dependencies = ["requests>=2.0", ...]
	for _, spec := range pyp.Project.Dependencies {
		add(pyspec.Parse(spec))
	}

	// PEP 621: [project.optional-dependencies.<group>] = ["pytest>=7", ...]
	for _, group := range pyp.Project.OptionalDependencies {
		for _, spec := range group {
			add(pyspec.Parse(spec))
		}
	}

	// Poetry: [tool.poetry.dependencies]
	for _, ins := range poetryDeps(pyp.Tool.Poetry.Dependencies) {
		add(ins)
	}

	// Poetry: [tool.poetry.group.<name>.dependencies]
	for _, group := range pyp.Tool.Poetry.Group {
		for _, ins := range poetryDeps(group.Dependencies) {
			add(ins)
		}
	}

	// PEP 735: [dependency-groups].<group> = ["pytest>=7", {include-group = ...}]
	for _, group := range pyp.DependencyGroups {
		addSpecStrings(group)
	}

	// uv (pre-PEP-735): [tool.uv] dev-dependencies = ["ruff==0.4.4", ...]
	addSpecStrings(pyp.Tool.UV.DevDependencies)

	// PDM: [tool.pdm.dev-dependencies].<group> = ["mypy>=1.0", ...]
	for _, group := range pyp.Tool.PDM.DevDependencies {
		addSpecStrings(group)
	}
}

// workspaceMemberPyprojects expands the members/exclude directory globs
// (relative to rootDir) and returns the pyproject.toml path inside each
// non-excluded member directory that actually has one. Glob matches that are
// not directories, or directories without a pyproject.toml, are skipped — a
// matched README or a plain data dir must not abort the whole expansion.
func workspaceMemberPyprojects(rootDir string, members, exclude []string) ([]string, error) {
	if len(members) == 0 {
		return nil, nil
	}
	excluded := make(map[string]struct{})
	for _, pat := range exclude {
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
			pj := filepath.Join(dir, "pyproject.toml")
			if info, err := os.Stat(pj); err != nil || info.IsDir() {
				continue
			}
			out = append(out, pj)
		}
	}
	return out, nil
}

// sourceKind classifies how a [tool.uv.sources] entry resolves a dependency.
type sourceKind int

const (
	sourceOpaqueRemote sourceKind = iota + 1 // git / url — fetches remote code
	sourceLocalPath                          // path / workspace — local code
)

// applyUvSources mutates installs in place, flagging any whose name is
// redirected by a [tool.uv.sources] entry. Sources only ever redirect deps
// that are already declared elsewhere, so orphan sources (no matching install)
// are ignored — they install nothing. Names are matched under PyPI (PEP 503)
// normalization so a `my_pkg` dep matches a `my-pkg` source.
func applyUvSources(installs []packagemanager.Install, sources map[string]any) {
	if len(sources) == 0 {
		return
	}
	kinds := make(map[string]sourceKind, len(sources))
	for name, raw := range sources {
		if kind, ok := classifyUvSource(raw); ok {
			kinds[intel.NormalizeName(intel.EcosystemPyPI, name)] = kind
		}
	}
	for i := range installs {
		kind, ok := kinds[intel.NormalizeName(intel.EcosystemPyPI, installs[i].Ref.Name)]
		if !ok {
			continue
		}
		switch kind {
		case sourceOpaqueRemote:
			installs[i].OpaqueRemote = true
		case sourceLocalPath:
			installs[i].LocalPath = true
		}
	}
}

// classifyUvSource inspects a [tool.uv.sources] value. A value is either a
// single inline table or an array of marker-gated inline tables. For an array,
// the most restrictive variant wins: if any platform would fetch git/url code,
// the dep is OpaqueRemote (veto can't evaluate markers, so it over-gates to the
// safe posture). Returns (_, false) for index/registry-only sources, which are
// still resolved from a registry by name.
func classifyUvSource(raw any) (sourceKind, bool) {
	switch v := raw.(type) {
	case map[string]any:
		return classifyUvSourceTable(v)
	case []map[string]any:
		best, found := sourceKind(0), false
		for _, tbl := range v {
			if kind, ok := classifyUvSourceTable(tbl); ok {
				if kind == sourceOpaqueRemote {
					return sourceOpaqueRemote, true
				}
				best, found = kind, true
			}
		}
		return best, found
	case []any:
		best, found := sourceKind(0), false
		for _, entry := range v {
			tbl, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if kind, ok := classifyUvSourceTable(tbl); ok {
				if kind == sourceOpaqueRemote {
					return sourceOpaqueRemote, true
				}
				best, found = kind, true
			}
		}
		return best, found
	default:
		return 0, false
	}
}

// classifyUvSourceTable classifies one [tool.uv.sources] inline table. git/url
// fetch remote code; path and workspace members are local. A bare
// `{ index = "..." }` / `{ registry = "..." }` is a named alternate registry —
// still resolved by name, so it gets no flag.
func classifyUvSourceTable(tbl map[string]any) (sourceKind, bool) {
	if _, ok := tbl["git"]; ok {
		return sourceOpaqueRemote, true
	}
	if _, ok := tbl["url"]; ok {
		return sourceOpaqueRemote, true
	}
	if _, ok := tbl["path"]; ok {
		return sourceLocalPath, true
	}
	if ws, ok := tbl["workspace"].(bool); ok && ws {
		return sourceLocalPath, true
	}
	return 0, false
}

// poetryDeps turns a Poetry-shaped dep map into Installs.
//
// The TOML value for each name can be:
//
//   - A plain string ("^1.0", "*") → name with that string as the version.
//   - An inline table ({ version = "^1.0", ... }) → pull the version key;
//     emit name with empty version if no version key is present.
//   - An inline table with `git`, `url`, or `source` keys (no `version`) →
//     OpaqueRemote dep. Set OpaqueRemote=true so the gate's policy can
//     refuse remote-code-fetching deps by default. Without this, a
//     `{git = "https://evil"}` value would surface as a clean Install with
//     no remote-fetch indication and silently bypass AllowOpaqueRemote.
//   - An inline table with a `path` key → LocalPath dep. Set LocalPath=true
//     for the same reason.
//   - Anything else (array of tables for multi-source deps, etc.) → emit name
//     with empty version. The intel store's name-keyed lookup still catches
//     flagged versions.
//
// The "python" key under [tool.poetry.dependencies] is excluded — it's a
// Python version constraint, not a package.
func poetryDeps(deps map[string]any) []packagemanager.Install {
	if len(deps) == 0 {
		return nil
	}
	out := make([]packagemanager.Install, 0, len(deps))
	for name, raw := range deps {
		if strings.EqualFold(name, "python") {
			continue
		}
		// Inline-table form: inspect for opaque-remote / local-path keys
		// BEFORE we route through pyspec.Parse(name), which would otherwise
		// emit a clean Install with no flag set.
		if tbl, ok := raw.(map[string]any); ok {
			if kind, ok := classifyPoetryInlineTable(tbl); ok {
				ins := packagemanager.Install{
					Ref:     intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: name},
					RawSpec: name + " (from pyproject.toml)",
				}
				switch kind {
				case poetryInlineLocalPath:
					ins.LocalPath = true
				case poetryInlineOpaqueRemote:
					ins.OpaqueRemote = true
				}
				out = append(out, ins)
				continue
			}
		}
		version := decodePoetryVersion(raw)
		// Build an Install directly: pyspec's spec grammar is PEP 508 (the
		// Python ecosystem's "name op version" form), which doesn't match
		// Poetry's ranges ("^1.0", "~1"). We carry the version verbatim and
		// let the intel store's name-keyed fallback do the rest.
		install := pyspec.Parse(name)
		install.Ref.Version = exactVersionOrEmpty(version)
		install.RawSpec = name + " (from pyproject.toml)"
		out = append(out, install)
	}
	return out
}

// poetryInlineKind classifies a Poetry inline-table dep that doesn't resolve
// to a plain version. The classifier only fires when the table lacks a
// `version` key — a `{version = "^1.0", git = "..."}` value still gets the
// version path because Poetry permits both to coexist (the version constrains
// what the git ref must satisfy).
type poetryInlineKind int

const (
	poetryInlineOpaqueRemote poetryInlineKind = iota + 1
	poetryInlineLocalPath
)

// classifyPoetryInlineTable returns (kind, true) when the table carries a
// `git`, `url`, or `path` key and NO `version` key — i.e. when the dep is
// resolved against something other than PyPI by name+version. Returns
// (_, false) otherwise so the caller falls back to the version-string path.
func classifyPoetryInlineTable(tbl map[string]any) (poetryInlineKind, bool) {
	if _, hasVersion := tbl["version"].(string); hasVersion {
		return 0, false
	}
	if _, ok := tbl["path"]; ok {
		return poetryInlineLocalPath, true
	}
	if _, ok := tbl["git"]; ok {
		return poetryInlineOpaqueRemote, true
	}
	if _, ok := tbl["url"]; ok {
		return poetryInlineOpaqueRemote, true
	}
	// `source` alone (without git/url/path) refers to a named alternate
	// PyPI-like index — leave it to the version-string path so the
	// name-keyed lookup still applies.
	return 0, false
}

// decodePoetryVersion returns the version string for a Poetry dep value.
// Returns "" for any shape we can't pin to a version.
func decodePoetryVersion(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]any:
		if s, ok := v["version"].(string); ok {
			return s
		}
		// Inline table with no `version` key — path/git/url dep. Nothing
		// to pin; the name-keyed fallback handles it.
		return ""
	default:
		return ""
	}
}

// exactVersionOrEmpty returns version when it's a literal exact version (no
// range operators, no wildcard) and "" otherwise. Poetry ranges ("^1.0",
// "~1", "*") collapse to empty so the gate falls back to a name-keyed lookup
// that catches every flagged version of that package.
//
// Phase 1.7: delegate to intel.IsExactPEP440 for the actual parse so
// the project has one canonical PyPI version semantics. The cheap
// pre-screen on range characters short-circuits common Poetry/PEP 621
// shapes without invoking the full parser.
func exactVersionOrEmpty(version string) string {
	v := strings.TrimSpace(version)
	if v == "" || v == "*" {
		return ""
	}
	if strings.ContainsAny(v, "^~><=! ,*") {
		return ""
	}
	if !intel.IsExactPEP440(v) {
		return ""
	}
	return v
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
