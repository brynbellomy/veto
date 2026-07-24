// Package jslock reads npm-family lockfiles and emits Install records
// against the resolved, version-pinned transitive tree.
//
// Why lockfiles matter for gating: a manifest (`package.json`) lists
// direct dependencies with version ranges. The resolver picks specific
// versions and writes them — along with every transitive — into the
// lockfile. `npm ci`, `pnpm install`, and `yarn install` deterministically
// install what's in the lockfile. Gating against the lockfile is the core
// primitive for catching a flagged transitive dep; npm can also generate a
// lockfile through veto's resolver pre-scan before the real install runs.
//
// Coverage:
//   - package-lock.json (npm v7+ schema, lockfileVersion 2/3): full
//     transitive coverage via the `packages` map keyed by node_modules path.
//   - npm-shrinkwrap.json: identical schema to package-lock.json.
//   - pnpm-lock.yaml (schema versions 5–9): full transitive coverage via
//     the `packages` map keyed by `/name@version` or similar.
//   - yarn.lock (yarn classic / v1): full transitive coverage via the
//     blocks-of-key+version format pnpm and npm both predate. Yarn 2+
//     ("berry") uses a different schema; we gate it best-effort by
//     extracting `version: "x.y.z"` lines but do not parse the full grammar.
//
// Missing files return (nil, nil) — install verbs emit the ref
// speculatively and the expander tolerates absence.
package jslock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"
	"gopkg.in/yaml.v3"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

// Expander handles npm/pnpm/yarn lockfile kinds. Stateless and safe for
// concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand dispatches by kind to the appropriate format parser.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindPackageLockJSON, packagemanager.ManifestKindNpmShrinkwrap:
		return expandPackageLock(ref.Path)
	case packagemanager.ManifestKindPnpmLockYAML:
		return expandPnpmLock(ref.Path)
	case packagemanager.ManifestKindYarnLock:
		return expandYarnLock(ref.Path)
	case packagemanager.ManifestKindBunLock:
		data, ok, err := readFile(ref.Path)
		if err != nil || !ok {
			return nil, err
		}
		return expandBunLock(data)
	default:
		return nil, nil
	}
}

// readFile is a small wrapper that returns (data, true) on success and
// (nil, false) on missing-file (which we treat as "no transitive tree to
// gate"). Errors other than not-exist are surfaced wrapped.
func readFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, vetoerrors.With(err, "read lockfile").Set("path", path)
	}
	return data, true, nil
}

// packageLockJSON captures the lockfileVersion-2/3 schema. The `packages`
// map is keyed by the package's path inside node_modules ("" is the root
// project; "node_modules/lodash" is direct dep lodash; deeper paths are
// transitives). Each entry's `version` is the resolved pin we gate.
type packageLockJSON struct {
	LockfileVersion int                            `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry    `json:"packages"`
	Dependencies    map[string]packageLockDepEntry `json:"dependencies"` // legacy v1 fallback
}

type packageLockEntry struct {
	Name     string `json:"name"` // present when path doesn't carry the name (e.g. for the root)
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
}

// packageLockDepEntry is the lockfileVersion=1 nested form.
type packageLockDepEntry struct {
	Version      string                         `json:"version"`
	Dependencies map[string]packageLockDepEntry `json:"dependencies"`
}

func expandPackageLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, vetoerrors.With(err, "parse package-lock.json").Set("path", path)
	}

	// v2/v3: walk the packages map.
	if len(lock.Packages) > 0 {
		out := make([]packagemanager.Install, 0, len(lock.Packages))
		for nodePath, entry := range lock.Packages {
			name := nameFromNodeModulesPath(nodePath, entry.Name)
			if name == "" || entry.Version == "" {
				continue
			}
			out = append(out, packagemanager.Install{
				Ref: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      name,
					Version:   entry.Version,
				},
				RawSpec: name + "@" + entry.Version,
			})
		}
		return out, nil
	}

	// v1 fallback: recurse into the nested dependencies tree.
	var out []packagemanager.Install
	walkV1Deps(lock.Dependencies, &out)
	return out, nil
}

// nameFromNodeModulesPath turns a packages-map key into a package name.
// "" is the root project (skip; we don't gate ourselves). "node_modules/x"
// is x; "node_modules/x/node_modules/y" is y; "node_modules/@scope/pkg" is
// "@scope/pkg". The entry.Name override wins when present so npm aliases gate
// the real installed package instead of the local alias path.
func nameFromNodeModulesPath(nodePath, entryName string) string {
	if nodePath == "" {
		// Root project entry — never gate the project against itself.
		return ""
	}
	if entryName != "" {
		return entryName
	}
	// The package name is everything after the LAST "node_modules/" segment.
	idx := strings.LastIndex(nodePath, "node_modules/")
	if idx < 0 {
		return ""
	}
	return nodePath[idx+len("node_modules/"):]
}

func walkV1Deps(deps map[string]packageLockDepEntry, out *[]packagemanager.Install) {
	for name, entry := range deps {
		if entry.Version != "" {
			*out = append(*out, packagemanager.Install{
				Ref: intel.PackageRef{
					Ecosystem: intel.EcosystemNPM,
					Name:      name,
					Version:   entry.Version,
				},
				RawSpec: name + "@" + entry.Version,
			})
		}
		walkV1Deps(entry.Dependencies, out)
	}
}

// pnpmLock is the subset of pnpm-lock.yaml we parse.
//
// `packages` is keyed by "/<name>@<version>" (older schemas) or by
// "<name>@<version>" (newer schemas). For scoped packages the slash inside
// the name (e.g. "@scope/pkg") is preserved.
//
// `lockfileVersion` is informational — we always walk the same `packages`
// map regardless of version. Schemas before 5 used a flatter snapshot
// section; we degrade to direct-deps in that case (see
// expandPnpmLockFlatSnapshots).
type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Packages        map[string]any          `yaml:"packages"`
	Snapshots       map[string]any          `yaml:"snapshots"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmImporterEntry `yaml:"dependencies"`
	DevDependencies      map[string]pnpmImporterEntry `yaml:"devDependencies"`
	PeerDependencies     map[string]pnpmImporterEntry `yaml:"peerDependencies"`
	OptionalDependencies map[string]pnpmImporterEntry `yaml:"optionalDependencies"`
}

type pnpmImporterEntry struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// UnmarshalYAML accepts both pnpm importer-entry shapes so a valid
// lockfile of either schema parses instead of aborting the whole file:
//
//   - lockfileVersion 6+ : a mapping, `pkg: {specifier: ^1, version: 1.2.3}`
//   - lockfileVersion 5.x: a bare version string, `pkg: 1.2.3`
//
// Modeling only the v6 mapping made yaml.Unmarshal fail with "cannot
// unmarshal !!str into pnpmImporterEntry" on any v5 workspace lockfile,
// which the caller treats as fatal — fail-closing every install in that
// repo. A scalar node is taken as the resolved version.
func (e *pnpmImporterEntry) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		e.Version = node.Value
		return nil
	}
	// rawEntry strips the UnmarshalYAML method so node.Decode does the
	// default struct decode (no recursion).
	type rawEntry pnpmImporterEntry
	var r rawEntry
	if err := node.Decode(&r); err != nil {
		return err
	}
	*e = pnpmImporterEntry(r)
	return nil
}

func expandPnpmLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, vetoerrors.With(err, "parse pnpm-lock.yaml").Set("path", path)
	}

	// Modern schemas (lockfileVersion 5+) populate `packages` with the
	// full resolved tree. Older schemas use snapshots/importers — fall
	// back to those for direct-deps coverage.
	var out []packagemanager.Install
	for key := range lock.Packages {
		name, version := parsePnpmPackageKey(key)
		if name == "" || version == "" {
			continue
		}
		out = append(out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      name,
				Version:   version,
			},
			RawSpec: key,
		})
	}
	if len(out) > 0 {
		return out, nil
	}
	// Schema-pre-5 fallback: walk importers' direct dependency maps.
	for _, imp := range lock.Importers {
		appendImporterDeps(imp.Dependencies, &out)
		appendImporterDeps(imp.DevDependencies, &out)
		appendImporterDeps(imp.PeerDependencies, &out)
		appendImporterDeps(imp.OptionalDependencies, &out)
	}
	return out, nil
}

func appendImporterDeps(deps map[string]pnpmImporterEntry, out *[]packagemanager.Install) {
	for name, entry := range deps {
		if entry.Version == "" {
			continue
		}
		*out = append(*out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      name,
				Version:   strings.TrimPrefix(entry.Version, "v"),
			},
			RawSpec: name + "@" + entry.Version,
		})
	}
}

// parsePnpmPackageKey splits a pnpm packages-map key into (name, version).
// Formats handled:
//
//	"/lodash@4.17.21"            → ("lodash", "4.17.21")
//	"/@scope/pkg@1.0.0"          → ("@scope/pkg", "1.0.0")
//	"lodash@4.17.21"             → ("lodash", "4.17.21")   (no leading slash)
//	"/lodash@4.17.21(react@18)"  → ("lodash", "4.17.21")   (peer-suffix stripped)
//	"/lodash@npm:evil@1.0"       → ("evil", "1.0")         (alias unwrapped)
//
// npm-style aliases ("alias@npm:realname@version") are unwrapped so the gate
// looks up the actually-installed package, not the local alias name. pnpm
// records aliased deps with this shape in its packages map.
func parsePnpmPackageKey(key string) (string, string) {
	k := strings.TrimPrefix(key, "/")
	// Drop any "(peer@version)" suffix.
	if idx := strings.IndexByte(k, '('); idx > 0 {
		k = k[:idx]
	}
	name, version := splitPnpmKeyBoundary(k)
	if alias, aliasVer, ok := jsspec.UnwrapNpmAlias(version); ok {
		return alias, aliasVer
	}
	return name, version
}

// splitPnpmKeyBoundary finds the name@version cut, handling the scoped case.
func splitPnpmKeyBoundary(k string) (string, string) {
	// Scoped: "@scope/pkg@version".
	if strings.HasPrefix(k, "@") {
		if idx := strings.Index(k[1:], "@"); idx > 0 {
			return k[:1+idx], k[1+idx+1:]
		}
		return k, ""
	}
	if name, version, ok := strings.Cut(k, "@"); ok {
		return name, version
	}
	return k, ""
}

// expandYarnLock parses yarn.lock (v1) line-by-line. The format is:
//
//	"@scope/pkg@^1.0.0", "@scope/pkg@~1.1":
//	  version "1.1.5"
//	  resolved "..."
//
// We don't enforce the grammar — a permissive scanner that pairs the
// most-recent "version "<v>"" with the closest preceding header line is
// enough to gate the transitive tree.
//
// Yarn 2+ ("berry") uses a YAML-shaped format. We detect the BERRY header
// and fall back to a regex-style version harvest; the gate still works,
// it just doesn't capture peer-specific resolutions correctly.
func expandYarnLock(path string) ([]packagemanager.Install, error) {
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return nil, err
	}
	// We deliberately avoid bufio.Scanner here: its default 64 KiB and even
	// our previous 8 MiB cap silently truncate yarn-berry lockfiles for
	// large monorepos, fail-open. bufio.Reader.ReadString has no per-line
	// cap, so arbitrary line lengths are handled naturally; the only price
	// is dealing with EOF semantics where the final line may not end in
	// '\n'.
	reader := bufio.NewReader(bytes.NewReader(data))
	var out []packagemanager.Install
	var pendingHeader string
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			// Strip the trailing newline (and CR, on Windows lockfiles)
			// without altering interior whitespace, so the header /
			// body distinction below remains sound.
			line = strings.TrimRight(line, "\r\n")
			trimmed := strings.TrimSpace(line)
			switch {
			case trimmed == "" || strings.HasPrefix(trimmed, "#"):
				// Skip blank lines and comments.
			case line == trimmed && strings.HasSuffix(trimmed, ":"):
				// Header line: no leading whitespace and ends with ":".
				pendingHeader = strings.TrimSuffix(trimmed, ":")
			case strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:"):
				// Body line: indented. We look only for `version "..."`
				// (yarn classic) or `version: x` (berry).
				version := extractYarnVersion(trimmed)
				if version == "" {
					break
				}
				name := nameFromYarnHeader(pendingHeader)
				if name == "" {
					break
				}
				out = append(out, packagemanager.Install{
					Ref: intel.PackageRef{
						Ecosystem: intel.EcosystemNPM,
						Name:      name,
						Version:   version,
					},
					RawSpec: name + "@" + version,
				})
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, vetoerrors.With(readErr, "read yarn.lock").Set("path", path)
		}
	}
	return out, nil
}

// extractYarnVersion pulls "1.0.5" out of `version "1.0.5"` or `version: 1.0.5`.
func extractYarnVersion(line string) string {
	// v1: `version "1.0.5"`
	if _, rest, ok := strings.Cut(line, `"`); ok {
		if v, _, ok := strings.Cut(rest, `"`); ok {
			return v
		}
	}
	// berry: `version: 1.0.5`
	if rest, ok := strings.CutPrefix(line, "version:"); ok {
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"'`)
		return rest
	}
	return ""
}

// nameFromYarnHeader pulls the package name out of a yarn.lock header
// like `"@scope/pkg@^1.0.0", "@scope/pkg@~1.1":`. The first comma-separated
// alternative is sufficient (they all share a name).
//
// yarn-berry npm aliases ("name@npm:realname@version") are unwrapped to the
// real package name — the local "name" before the alias is the developer's
// chosen identifier, not the actually-installed package.
func nameFromYarnHeader(header string) string {
	if header == "" {
		return ""
	}
	// Take the first alternative (before any comma).
	first, _, _ := strings.Cut(header, ",")
	first = strings.TrimSpace(first)
	first = strings.Trim(first, `"`)
	// Scoped: "@scope/pkg@^1.0.0" → "@scope/pkg".
	if strings.HasPrefix(first, "@") {
		if idx := strings.Index(first[1:], "@"); idx > 0 {
			rest := first[1+idx+1:]
			if alias, _, ok := jsspec.UnwrapNpmAlias(rest); ok {
				return alias
			}
			return first[:1+idx]
		}
		return first
	}
	// Berry-style "name@npm:realname@version" or "name@^1.0.0".
	if idx := strings.IndexByte(first, '@'); idx > 0 {
		rest := first[idx+1:]
		if alias, _, ok := jsspec.UnwrapNpmAlias(rest); ok {
			return alias
		}
		return first[:idx]
	}
	// Header without an `@` is a yarn-berry pseudo-entry (e.g.
	// `__metadata:`). Return empty so the caller skips emission —
	// these are not real packages and would pollute the gate's
	// verdict log under a synthetic "__metadata" name.
	return ""
}
