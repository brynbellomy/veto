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

// TestExpand_UvLockSourceTable covers uv.lock's real `source` table, where
// `editable` and `virtual` are PATH STRINGS (e.g. `source = { editable = "." }`),
// not booleans. Workspace/editable entries are skipped; registry packages are
// emitted. Regression for the bool-typed struct that made go-toml abort the
// entire file with "cannot decode TOML string into ... of type bool", which
// silently dropped every package in any uv.lock containing a workspace root.
func TestExpand_UvLockSourceTable(t *testing.T) {
	const body = `version = 1

[[package]]
name = "my-project"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "my-lib"
version = "0.2.0"
source = { virtual = "packages/lib" }

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
	requireContains(t, out, "requests", "2.31.0")
	requireNotContains(t, out, "my-project")
	requireNotContains(t, out, "my-lib")
}

// TestExpand_UvLockLocalDirectoryAndPath completes the editable/virtual
// skip: uv.lock also emits `source = { directory = ... }` for a
// non-editable local path dependency and `source = { path = ... }` for an
// on-disk sdist/wheel. Both are local, first-party artifacts, so gating
// them against PyPI by name is the same false-positive class the
// editable/virtual skip already avoids. They must be skipped; registry
// packages must still be emitted.
func TestExpand_UvLockLocalDirectoryAndPath(t *testing.T) {
	const body = `version = 1

[[package]]
name = "my-local-lib"
version = "0.1.0"
source = { directory = "libs/my-local-lib" }

[[package]]
name = "vendored-wheel"
version = "2.3.0"
source = { path = "vendor/vendored_wheel-2.3.0-py3-none-any.whl" }

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
	requireContains(t, out, "requests", "2.31.0")
	requireNotContains(t, out, "my-local-lib")
	requireNotContains(t, out, "vendored-wheel")
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

func requireNotContains(t *testing.T, installs []packagemanager.Install, name string) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Name == name {
			t.Fatalf("did not expect %s in:\n%v", name, installs)
		}
	}
}
