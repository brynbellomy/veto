package jsmanifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jsmanifest"
)

func TestExpandPackageJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	contents := `{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.21",
    "@types/node": "20.0.0"
  },
  "devDependencies": {
    "typescript": "~5.0"
  },
  "peerDependencies": {
    "react": ">=17 <19"
  },
  "optionalDependencies": {
    "fsevents": "2.3.3"
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Len(t, installs, 5)

	// Map-iteration order is non-deterministic per-section, so assert by
	// presence rather than position.
	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemNPM, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	require.Contains(t, byName, "lodash")
	require.Equal(t, "", byName["lodash"].Ref.Version, "caret-range collapses to empty for name-keyed lookup")

	require.Contains(t, byName, "@types/node")
	require.Equal(t, "20.0.0", byName["@types/node"].Ref.Version, "exact pin preserved")

	require.Contains(t, byName, "typescript")
	require.Equal(t, "", byName["typescript"].Ref.Version, "tilde-range collapses to empty")

	require.Contains(t, byName, "react")
	require.Equal(t, "", byName["react"].Ref.Version, "multi-clause range collapses to empty")

	require.Contains(t, byName, "fsevents")
	require.Equal(t, "2.3.3", byName["fsevents"].Ref.Version, "exact pin preserved")
}

func TestExpandMissingFileReturnsEmpty(t *testing.T) {
	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(t.TempDir(), "no-such-file.json"),
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandUnknownKindReturnsNil(t *testing.T) {
	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: "irrelevant",
		Kind: packagemanager.ManifestKindRequirements,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandMalformedJSONReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(path, []byte("{ not valid json"), 0o644))

	exp := jsmanifest.New()
	_, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.Error(t, err)
}

// TestExpandPackageJSONNpmAliases ensures values like "npm:realname@version"
// in package.json dependency maps unwrap to the real package, not the local
// alias name. Without this, a developer can shadow a clean-looking name over
// an attacker-controlled package and bypass the gate.
func TestExpandPackageJSONNpmAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	contents := `{
  "name": "demo",
  "dependencies": {
    "lodash": "npm:evil-pkg@1.0",
    "react": "npm:preact",
    "compat": "npm:@scope/real@2.0.0"
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Len(t, installs, 3)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		byName[ins.Ref.Name] = ins
	}

	require.NotContains(t, byName, "lodash", "alias name must not appear; real package wins")
	require.Contains(t, byName, "evil-pkg")
	require.Equal(t, "1.0", byName["evil-pkg"].Ref.Version)

	require.NotContains(t, byName, "react")
	require.Contains(t, byName, "preact")
	require.Equal(t, "", byName["preact"].Ref.Version, "unversioned alias → name-keyed lookup")

	require.NotContains(t, byName, "compat")
	require.Contains(t, byName, "@scope/real")
	require.Equal(t, "2.0.0", byName["@scope/real"].Ref.Version)
}

// TestExpandPackageJSONOpaqueAndLocalSpecs ensures package.json values that
// reference code outside the registry (git URLs, github shorthand, tarballs,
// `user/repo`) are flagged OpaqueRemote, and filesystem-path values are
// flagged LocalPath. Without these flags the gate's policy can't refuse
// remote-code fetches by default — the value would otherwise pass through
// jsspec.Parse(name+"@"+version) and emerge as a clean Install record.
func TestExpandPackageJSONOpaqueAndLocalSpecs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	contents := `{
  "name": "demo",
  "dependencies": {
    "git-https": "git+https://evil/repo",
    "git-plain": "git://evil/repo",
    "github-shorthand": "github:user/repo",
    "user-repo": "user/repo",
    "tarball": "https://evil.example.com/pkg.tgz",
    "rel-path": "./local",
    "rel-parent": "../sibling",
    "file-uri": "file:./local",
    "abs-path": "/abs/path",
    "normal": "^1.0.0",
    "pinned": "1.2.3"
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Len(t, installs, 11)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemNPM, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	for _, name := range []string{"git-https", "git-plain", "github-shorthand", "user-repo", "tarball"} {
		ins, ok := byName[name]
		require.True(t, ok, "missing %s in installs", name)
		require.True(t, ins.OpaqueRemote, "%s must be flagged OpaqueRemote", name)
		require.False(t, ins.LocalPath, "%s must not be flagged LocalPath", name)
		require.Equal(t, "", ins.Ref.Version, "%s must have empty version (no clean name+version)", name)
	}

	for _, name := range []string{"rel-path", "rel-parent", "file-uri", "abs-path"} {
		ins, ok := byName[name]
		require.True(t, ok, "missing %s in installs", name)
		require.True(t, ins.LocalPath, "%s must be flagged LocalPath", name)
		require.False(t, ins.OpaqueRemote, "%s must not be flagged OpaqueRemote", name)
	}

	// Normal version ranges and pins still take the existing path.
	normal := byName["normal"]
	require.False(t, normal.OpaqueRemote)
	require.False(t, normal.LocalPath)
	require.Equal(t, "", normal.Ref.Version, "caret range collapses to empty")

	pinned := byName["pinned"]
	require.False(t, pinned.OpaqueRemote)
	require.False(t, pinned.LocalPath)
	require.Equal(t, "1.2.3", pinned.Ref.Version, "exact pin preserved")
}

func TestExpandEmptyDeps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"name": "demo"}`), 0o644))

	exp := jsmanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

// TestExpandPackageJSONWorkspaceMembers ensures that when the root package.json
// declares workspaces, each member's deps are gated too. `npm install` at the
// root installs every workspace member's deps, so a member-only malicious dep
// on a fresh checkout (no lockfile) is otherwise a direct-dependency fail-open.
// Both the array form and the {"packages": [...]} object form are supported,
// and a member whose version redirects to git is flagged OpaqueRemote.
func TestExpandPackageJSONWorkspaceMembers(t *testing.T) {
	expandRoot := func(t *testing.T, root string) map[string]packagemanager.Install {
		t.Helper()
		exp := jsmanifest.New()
		installs, err := exp.Expand(packagemanager.ManifestRef{
			Path: filepath.Join(root, "package.json"),
			Kind: packagemanager.ManifestKindPackageJSON,
		})
		require.NoError(t, err)
		byName := make(map[string]packagemanager.Install, len(installs))
		for _, ins := range installs {
			byName[ins.Ref.Name] = ins
		}
		return byName
	}

	writeFile := func(t *testing.T, root, rel, contents string) {
		t.Helper()
		full := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(contents), 0o644))
	}

	members := func(t *testing.T, root string) {
		t.Helper()
		writeFile(t, root, "packages/foo/package.json", `{
  "dependencies": {"foo-evil": "1.0.0"},
  "devDependencies": {"foo-dev-evil": "^2"}
}`)
		writeFile(t, root, "packages/bar/package.json", `{
  "dependencies": {"bar-evil": "git+https://evil.example/bar.git"}
}`)
		// A glob match without a package.json must be skipped gracefully.
		require.NoError(t, os.MkdirAll(filepath.Join(root, "packages/notapkg"), 0o755))
	}

	assertMembers := func(t *testing.T, byName map[string]packagemanager.Install) {
		t.Helper()
		require.Contains(t, byName, "root-dep")
		require.Contains(t, byName, "foo-evil")
		require.Equal(t, "1.0.0", byName["foo-evil"].Ref.Version)
		require.Contains(t, byName, "foo-dev-evil")
		require.Contains(t, byName, "bar-evil")
		require.True(t, byName["bar-evil"].OpaqueRemote, "member git: dep must flag OpaqueRemote")
	}

	t.Run("array form", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "package.json", `{
  "name": "root",
  "dependencies": {"root-dep": "^1"},
  "workspaces": ["packages/*"]
}`)
		members(t, root)
		assertMembers(t, expandRoot(t, root))
	})

	t.Run("object form", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "package.json", `{
  "name": "root",
  "dependencies": {"root-dep": "^1"},
  "workspaces": {"packages": ["packages/*"]}
}`)
		members(t, root)
		assertMembers(t, expandRoot(t, root))
	})
}
