package pymanifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pymanifest"
)

func TestExpandPyProject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[project]
name = "demo"
dependencies = [
  "requests>=2.0,<3",
  "httpx==0.27.0",
]

[project.optional-dependencies]
dev = ["pytest>=7", "black==24.3.0"]
docs = ["sphinx>=7"]

[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2"
gunicorn = "21.2.0"
fancy-dep = { version = "^1.0", optional = true }
path-dep = { path = "../sibling" }

[tool.poetry.group.dev.dependencies]
mypy = "^1.0"
ruff = "0.4.4"
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.NotEmpty(t, installs)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemPyPI, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	// PEP 621 [project] dependencies
	require.Contains(t, byName, "requests")
	require.Equal(t, "", byName["requests"].Ref.Version, "range collapses to empty version")
	require.Contains(t, byName, "httpx")
	require.Equal(t, "0.27.0", byName["httpx"].Ref.Version, "exact == version preserved")

	// PEP 621 optional-dependencies — all groups merged
	require.Contains(t, byName, "pytest")
	require.Contains(t, byName, "black")
	require.Equal(t, "24.3.0", byName["black"].Ref.Version)
	require.Contains(t, byName, "sphinx")

	// Poetry [tool.poetry.dependencies]
	require.NotContains(t, byName, "python", "python key must be excluded")
	require.Contains(t, byName, "django")
	require.Equal(t, "", byName["django"].Ref.Version, "Poetry ^4.2 range collapses to empty version")
	require.Contains(t, byName, "gunicorn")
	require.Equal(t, "21.2.0", byName["gunicorn"].Ref.Version, "Poetry literal version preserved")

	// Poetry inline-table with version key
	require.Contains(t, byName, "fancy-dep")
	require.Equal(t, "", byName["fancy-dep"].Ref.Version)

	// Poetry inline-table path dep — name present, version empty
	require.Contains(t, byName, "path-dep")
	require.Equal(t, "", byName["path-dep"].Ref.Version)

	// Poetry group deps
	require.Contains(t, byName, "mypy")
	require.Contains(t, byName, "ruff")
	require.Equal(t, "0.4.4", byName["ruff"].Ref.Version)
}

// TestExpandPyProjectUvPdmAndDependencyGroups covers the dependency tables
// that uv and pdm install from but pymanifest previously ignored: PEP 735
// [dependency-groups], uv's legacy [tool.uv] dev-dependencies, and
// [tool.pdm.dev-dependencies]. On a fresh checkout with no lockfile, a package
// declared only in one of these sections would otherwise sail through
// `uv sync` / `pdm install` ungated — a direct-dependency fail-open.
func TestExpandPyProjectUvPdmAndDependencyGroups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[project]
name = "demo"
dependencies = ["requests"]

[dependency-groups]
dev = ["pytest>=7", "groups-evil==1.2.3", {include-group = "extra"}]
extra = ["sphinx>=7"]

[tool.uv]
dev-dependencies = ["ruff==0.4.4", "uv-evil"]

[tool.pdm.dev-dependencies]
test = ["mypy>=1.0", "pdm-evil==9.9.9"]
lint = ["flake8"]
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemPyPI, ins.Ref.Ecosystem)
		require.NotEmpty(t, ins.Ref.Name, "include-group reference must not create a nameless install")
		byName[ins.Ref.Name] = ins
	}

	// PEP 735 [dependency-groups]
	require.Contains(t, byName, "pytest")
	require.Contains(t, byName, "groups-evil")
	require.Equal(t, "1.2.3", byName["groups-evil"].Ref.Version)
	require.Contains(t, byName, "sphinx", "include-group reference still resolves the included group")

	// uv legacy [tool.uv] dev-dependencies
	require.Contains(t, byName, "ruff")
	require.Equal(t, "0.4.4", byName["ruff"].Ref.Version)
	require.Contains(t, byName, "uv-evil")

	// [tool.pdm.dev-dependencies], all groups merged
	require.Contains(t, byName, "mypy")
	require.Contains(t, byName, "pdm-evil")
	require.Equal(t, "9.9.9", byName["pdm-evil"].Ref.Version)
	require.Contains(t, byName, "flake8")
}

func TestExpandMissingFileReturnsEmpty(t *testing.T) {
	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(t.TempDir(), "no-such-file.toml"),
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandUnknownKindReturnsNil(t *testing.T) {
	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: "irrelevant",
		Kind: packagemanager.ManifestKindPackageJSON,
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandMalformedTOMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte("not [valid toml ===="), 0o644))

	exp := pymanifest.New()
	_, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.Error(t, err)
}

// TestExpandPyProjectPoetryOpaqueAndLocalInlineTables ensures Poetry inline-
// table deps that reference code outside PyPI (git/url) are flagged
// OpaqueRemote, and inline-table path deps are flagged LocalPath. Without
// these flags the gate's policy can't refuse remote-code fetches by default
// — the value would otherwise pass through pyspec.Parse(name) and emerge as
// a clean Install record.
func TestExpandPyProjectPoetryOpaqueAndLocalInlineTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.10"
git-dep = { git = "https://evil/repo.git" }
url-dep = { url = "https://evil.example.com/pkg.tar.gz" }
path-dep = { path = "./local" }
version-dep = { version = "^1.0" }
plain-version = "1.2.3"
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)

	byName := make(map[string]packagemanager.Install, len(installs))
	for _, ins := range installs {
		require.Equal(t, intel.EcosystemPyPI, ins.Ref.Ecosystem)
		byName[ins.Ref.Name] = ins
	}

	gitDep, ok := byName["git-dep"]
	require.True(t, ok)
	require.True(t, gitDep.OpaqueRemote, "Poetry git inline-table must flag OpaqueRemote")
	require.False(t, gitDep.LocalPath)

	urlDep, ok := byName["url-dep"]
	require.True(t, ok)
	require.True(t, urlDep.OpaqueRemote, "Poetry url inline-table must flag OpaqueRemote")
	require.False(t, urlDep.LocalPath)

	pathDep, ok := byName["path-dep"]
	require.True(t, ok)
	require.True(t, pathDep.LocalPath, "Poetry path inline-table must flag LocalPath")
	require.False(t, pathDep.OpaqueRemote)

	// Plain-version path: existing behaviour, no flags set.
	plain, ok := byName["plain-version"]
	require.True(t, ok)
	require.False(t, plain.OpaqueRemote)
	require.False(t, plain.LocalPath)
	require.Equal(t, "1.2.3", plain.Ref.Version)

	// Inline table with `version` key keeps the existing version path
	// (range collapses to empty), no flags set.
	verDep, ok := byName["version-dep"]
	require.True(t, ok)
	require.False(t, verDep.OpaqueRemote)
	require.False(t, verDep.LocalPath)
	require.Equal(t, "", verDep.Ref.Version, "Poetry ^1.0 range collapses to empty")
}

func TestExpandDedupesAcrossSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")

	contents := `
[project]
dependencies = ["requests==2.31.0"]

[tool.poetry.dependencies]
requests = "^2.31"
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))

	exp := pymanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindPyProject,
	})
	require.NoError(t, err)
	require.Len(t, installs, 1, "duplicate dep across PEP 621 and Poetry sections should collapse")
	require.Equal(t, "requests", installs[0].Ref.Name)
}
