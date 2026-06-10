package pylock_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pylock"
)

// All three Python lockfiles share the same `[[package]]` TOML shape, so
// one parameterised test covers them.
func TestExpand_TomlLockfiles(t *testing.T) {
	const body = `version = 1

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "charset-normalizer"
version = "3.3.0"
`

	cases := []struct {
		name string
		path string
		kind packagemanager.ManifestKind
	}{
		{"uv.lock", "uv.lock", packagemanager.ManifestKindUvLock},
		{"poetry.lock", "poetry.lock", packagemanager.ManifestKindPoetryLock},
		{"pdm.lock", "pdm.lock", packagemanager.ManifestKindPdmLock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.path)
			require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
			out, err := pylock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: tc.kind})
			require.NoError(t, err)
			requireContains(t, out, "requests", "2.31.0")
			requireContains(t, out, "urllib3", "2.0.7")
			requireContains(t, out, "charset-normalizer", "3.3.0")
		})
	}
}

func TestExpand_PEP751PylockPackagesShape(t *testing.T) {
	const body = `lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "requests"
version = "2.31.0"

[[packages]]
name = "urllib3"
version = "2.0.7"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "pylock.veto.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := pylock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindUvLock})
	require.NoError(t, err)
	requireContains(t, out, "requests", "2.31.0")
	requireContains(t, out, "urllib3", "2.0.7")
}

// TestExpand_EditableAndVirtualEntriesSkipped: uv.lock marks workspace
// members with `source.editable = "<dir>"` (a path string, not a bool);
// other emitters use a boolean flag. Both forms must parse and be
// excluded from gating.
func TestExpand_EditableAndVirtualEntriesSkipped(t *testing.T) {
	const body = `version = 1

[[package]]
name = "my-workspace-pkg"
version = "1.1.0"
source = { editable = "." }

[[package]]
name = "my-virtual-pkg"
version = "0.1.0"
source = { virtual = "packages/sub" }

[[package]]
name = "my-bool-editable-pkg"
version = "0.2.0"
source = { editable = true }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
`
	dir := t.TempDir()
	path := filepath.Join(dir, "uv.lock")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := pylock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindUvLock})
	require.NoError(t, err)
	require.Len(t, out, 1)
	requireContains(t, out, "requests", "2.31.0")
}

// TestExpand_MissingFile_ReturnsNilNil: PMs emit lock refs speculatively,
// so missing files must not error.
func TestExpand_MissingFile_ReturnsNilNil(t *testing.T) {
	out, err := pylock.New().Expand(packagemanager.ManifestRef{Path: "/nonexistent.lock", Kind: packagemanager.ManifestKindUvLock})
	require.NoError(t, err)
	require.Nil(t, out)
}

// TestExpand_MalformedTOML_Errors: garbage input fails closed.
func TestExpand_MalformedTOML_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uv.lock")
	require.NoError(t, os.WriteFile(path, []byte("not [valid toml ="), 0o644))
	_, err := pylock.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindUvLock})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse lockfile TOML")
}

// TestExpand_UnknownKindIsNoop: a ref kind this expander doesn't own
// (e.g. an npm lockfile) returns (nil, nil), letting the compound
// dispatcher route it elsewhere.
func TestExpand_UnknownKindIsNoop(t *testing.T) {
	out, err := pylock.New().Expand(packagemanager.ManifestRef{Path: "anywhere", Kind: packagemanager.ManifestKindPackageLockJSON})
	require.NoError(t, err)
	require.Nil(t, out)
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemPyPI && ins.Ref.Name == name && ins.Ref.Version == version {
			return
		}
	}
	t.Fatalf("expected %s==%s in:\n%v", name, version, installs)
}
