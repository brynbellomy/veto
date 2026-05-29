// Package jsmanifest reads npm-family package.json files and turns their
// direct-dependency maps into Install records.
//
// This is the I/O side of npm/pnpm/yarn/bun's "verb implies the manifest" flow
// (`npm install` with no specs, `npm ci`, etc.). The package manager returns a
// ManifestKindPackageJSON ref from argv; the gate's expander — implemented
// here — opens the JSON, walks the four direct-dependency maps, and emits
// []Install via jsspec.
//
// Direct deps only. Transitive resolution would require running the real
// package manager (parsing package-lock.json, resolving ranges against the
// registry), which defeats the purpose of a parse-only gate. The intel store's
// name-keyed fallback catches every flagged version when the range is too
// imprecise to pin a single version.
//
// When the root package.json declares "workspaces", each member package.json
// (array form or the {"packages": [...]} object form) is walked too, because
// `npm install` at the root installs every member's deps — a fresh-checkout
// monorepo would otherwise miss them.
package jsmanifest

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

// Expander reads package.json files and emits the Install records the gate
// looks up.
//
// Safe for concurrent use; New() returns a stateless instance.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// packageJSON is the subset of fields the expander cares about. Anything not
// listed here is ignored. The four maps cover the dependency surfaces npm,
// pnpm, yarn, and bun all read from when resolving an install set;
// BundleDependencies (Phase 1.6) catches the array-form list of names
// that get bundled into the published tarball.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundleDependencies   []string          `json:"bundleDependencies"`
	// Workspaces is the npm/yarn/pnpm monorepo member list. It is either a
	// JSON array of directory globs (npm, yarn classic) or an object with a
	// "packages" array (yarn berry), so it is kept raw and parsed by
	// workspacePatterns.
	Workspaces json.RawMessage `json:"workspaces"`
}

// Expand reads ref.Path and returns the []Install its direct-dependency maps
// resolve to. Returns nil, nil for any ref.Kind other than
// ManifestKindPackageJSON so the compound expander can dispatch by kind.
//
// A missing file is not an error — some install verbs run from non-project
// directories (e.g. `npm install <pkg>` outside a project). Malformed JSON
// returns a wrapped error with the path attached.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindPackageJSON {
		return nil, nil
	}

	pkg, ok, err := decodePackageJSON(ref.Path)
	if err != nil || !ok {
		return nil, err
	}

	installs := collectDeps(pkg)

	// npm/yarn/pnpm workspaces: `npm install` at the root installs every
	// member's deps, so a member-only malicious dep would otherwise be missed
	// on a fresh checkout. Members are discovered from the root only (no
	// recursion / cycle risk). A lockfile, when present, already covers member
	// deps via the lockfile expander; this closes the fresh-checkout gap.
	members, err := workspaceMemberManifests(filepath.Dir(ref.Path), workspacePatterns(pkg.Workspaces))
	if err != nil {
		return nil, err
	}
	for _, memberPath := range members {
		mpkg, ok, err := decodePackageJSON(memberPath)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		installs = append(installs, collectDeps(mpkg)...)
	}
	return installs, nil
}

// decodePackageJSON reads and parses a package.json. The bool is false (with a
// nil error) when the file does not exist — install verbs run from non-project
// directories, and workspace globs can name dirs without a package.json.
// Malformed JSON or any other read error returns a wrapped error.
func decodePackageJSON(path string) (packageJSON, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return packageJSON{}, false, nil
		}
		return packageJSON{}, false, vetoerrors.With(err, "reading package.json").Set("path", path)
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return packageJSON{}, false, vetoerrors.With(err, "parse package.json").Set("path", path)
	}
	return pkg, true, nil
}

// collectDeps walks a package.json's four direct-dependency maps plus
// bundleDependencies into Installs. Safe to call for the root and for each
// workspace member; the gate's lookup is order- and duplicate-independent.
func collectDeps(pkg packageJSON) []packagemanager.Install {
	approx := len(pkg.Dependencies) + len(pkg.DevDependencies) + len(pkg.PeerDependencies) + len(pkg.OptionalDependencies)
	installs := make([]packagemanager.Install, 0, approx+len(pkg.BundleDependencies))
	installs = appendDeps(installs, pkg.Dependencies)
	installs = appendDeps(installs, pkg.DevDependencies)
	installs = appendDeps(installs, pkg.PeerDependencies)
	installs = appendDeps(installs, pkg.OptionalDependencies)
	// Phase 1.6: bundleDependencies is a JSON array of names that get
	// bundled into the published tarball. The names exist in the
	// registry and can be flagged by intel; gate by name (no version
	// is recorded in this field).
	for _, name := range pkg.BundleDependencies {
		installs = append(installs, packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: strings.TrimSpace(name)},
			RawSpec: name,
		})
	}
	return installs
}

// workspacePatterns extracts the directory globs from a package.json
// "workspaces" value, which is either a JSON array of globs (npm, yarn
// classic) or an object with a "packages" array (yarn berry). Returns nil for
// any other shape. Negation patterns (yarn's "!pkg") are not interpreted —
// over-including a member is the safe posture for a gate.
func workspacePatterns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Packages
	}
	return nil
}

// workspaceMemberManifests expands the workspace directory globs (relative to
// rootDir) and returns the package.json path inside each member directory that
// has one. Glob matches that are not directories, or directories without a
// package.json, are skipped so a stray file or data dir does not abort
// expansion.
func workspaceMemberManifests(rootDir string, patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(rootDir, filepath.FromSlash(pat)))
		if err != nil {
			return nil, vetoerrors.With(err, "expand workspace member glob").Set("pattern", pat)
		}
		for _, dir := range matches {
			if _, dup := seen[dir]; dup {
				continue
			}
			seen[dir] = struct{}{}
			pj := filepath.Join(dir, "package.json")
			if info, err := os.Stat(pj); err != nil || info.IsDir() {
				continue
			}
			out = append(out, pj)
		}
	}
	return out, nil
}

// appendDeps turns a {name: versionSpec} map into Installs via jsspec.Parse.
//
// package.json version values are almost always range expressions ("^4.17.21",
// "~1.0", ">=2 <3", "*", "latest", "next"). The intel store's exact-version
// index would miss every flagged version under a range, so we strip non-exact
// versions before parsing: jsspec records an empty Version field, and the
// store's name-keyed lookup catches every flagged version of the package.
//
// An exact pin ("4.17.21") is preserved as Version so the store's exact-match
// path still applies — those are the common case for pinned monorepos.
//
// npm package aliases — values like "npm:realname@version" — are unwrapped to
// the real package name+version so the gate looks up the actually-installed
// package, not the local alias the developer typed. Without this, an attacker
// can hide a malicious package under a benign-looking local name.
//
// Opaque-remote values ("git+https://...", "github:user/repo", "user/repo",
// tarball URLs) and local-path values ("./local", "file:./local", "/abs") are
// detected on the VERSION side — package.json keys are always the local
// install name, never the spec — and emit Installs with the appropriate
// OpaqueRemote / LocalPath flag set, so the gate's policy can refuse opaque
// fetches by default. Without this, the version string would be passed to
// jsspec.Parse(name+"@"+version) and the resulting Install would look like a
// clean name with no remote-fetch indication.
func appendDeps(out []packagemanager.Install, deps map[string]string) []packagemanager.Install {
	for name, version := range deps {
		v := strings.TrimSpace(version)
		if alias, aliasVer, ok := jsspec.UnwrapNpmAlias(v); ok {
			spec := alias
			if p := exactPin(aliasVer); p != "" {
				spec = alias + "@" + p
			}
			out = append(out, jsspec.Parse(spec))
			continue
		}
		// Detect opaque-remote / local-path forms on the version side. These
		// fetch code from outside the registry (or from disk), so we MUST set
		// the appropriate flag rather than letting the value be parsed as a
		// "name@version" pin — otherwise the gate sees a clean Install and the
		// AllowOpaqueRemote policy never gets a chance to refuse it.
		if jsspec.IsLocalPathSpec(v) {
			out = append(out, packagemanager.Install{
				Ref:       intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name},
				RawSpec:   name + "@" + version,
				LocalPath: true,
			})
			continue
		}
		if jsspec.IsOpaqueRemoteSpec(v) {
			out = append(out, packagemanager.Install{
				Ref:          intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name},
				RawSpec:      name + "@" + version,
				OpaqueRemote: true,
			})
			continue
		}
		spec := name
		if p := exactPin(version); p != "" {
			spec = name + "@" + p
		}
		out = append(out, jsspec.Parse(spec))
	}
	return out
}

// exactPin returns version when it's a single exact semver-ish literal (no
// range or tag prefix). Anything operator-prefixed ("^1", "~1", ">=2"),
// multi-clause (" >=1 <2"), wildcard ("*"), or tag-named ("latest", "next")
// collapses to empty so the name-keyed lookup takes over.
func exactPin(version string) string {
	v := strings.TrimSpace(version)
	if v == "" || v == "*" || v == "latest" || v == "next" {
		return ""
	}
	// Range / comparator characters disqualify outright.
	if strings.ContainsAny(v, "^~><=| ,") {
		return ""
	}
	// Phase 1.6: anchor x/X wildcards to segment boundaries so legitimate
	// exact pins like "1.0.0-experimental", "1.2.3-Xfix", or
	// "2.0.0+build.x12" stay exact. A bare segment of "x" or "X" — or
	// the literal token "x" / "X" — still counts as a wildcard.
	if v == "x" || v == "X" {
		return ""
	}
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' }) {
		if seg == "x" || seg == "X" {
			return ""
		}
	}
	return v
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
