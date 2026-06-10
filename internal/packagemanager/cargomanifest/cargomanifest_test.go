package cargomanifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/cargomanifest"
)

func TestExpandCargoToml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.toml")
	body := `[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0"
regex = "=1.10.6"
tokio = { version = "1", features = ["rt"] }
old-rand = { package = "rand", version = "=0.8.5" }
local-crate = { path = "../local-crate" }
git-crate = { git = "https://github.com/example/git-crate" }

[dev-dependencies]
tempfile = "3"

[target.'cfg(unix)'.dependencies]
nix = "0.29"

[package.metadata.generator.dependencies]
not-a-crate = "=9.9.9"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := cargomanifest.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindCargoToml})
	require.NoError(t, err)
	requireContains(t, out, "serde", "", false, false)
	requireContains(t, out, "regex", "1.10.6", false, false)
	requireContains(t, out, "tokio", "", false, false)
	requireContains(t, out, "rand", "0.8.5", false, false)
	requireContains(t, out, "local-crate", "", true, false)
	requireContains(t, out, "git-crate", "", false, true)
	requireContains(t, out, "tempfile", "", false, false)
	requireContains(t, out, "nix", "", false, false)
	requireNotContains(t, out, "not-a-crate")
}

func TestExpandWorkspaceDependencies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.toml")
	body := `[workspace.dependencies]
serde = "1.0"
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	out, err := cargomanifest.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindCargoToml})
	require.NoError(t, err)
	requireContains(t, out, "serde", "", false, false)
}

func TestExpandMissingCargoTomlReturnsNilNil(t *testing.T) {
	out, err := cargomanifest.New().Expand(packagemanager.ManifestRef{Path: "/no/such/Cargo.toml", Kind: packagemanager.ManifestKindCargoToml})
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestExpandMalformedCargoTomlErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.toml")
	require.NoError(t, os.WriteFile(path, []byte("not [toml"), 0o644))

	_, err := cargomanifest.New().Expand(packagemanager.ManifestRef{Path: path, Kind: packagemanager.ManifestKindCargoToml})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse Cargo.toml")
}

func TestExpandUnknownKindIsNoop(t *testing.T) {
	out, err := cargomanifest.New().Expand(packagemanager.ManifestRef{Path: "Cargo.toml", Kind: packagemanager.ManifestKindPackageJSON})
	require.NoError(t, err)
	require.Nil(t, out)
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string, localPath, opaque bool) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemCrates && ins.Ref.Name == name && ins.Ref.Version == version && ins.LocalPath == localPath && ins.OpaqueRemote == opaque {
			return
		}
	}
	t.Fatalf("expected %s@%s local=%t opaque=%t in:\n%v", name, version, localPath, opaque, installs)
}

func requireNotContains(t *testing.T, installs []packagemanager.Install, name string) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemCrates && ins.Ref.Name == name {
			t.Fatalf("did not expect %s in:\n%v", name, installs)
		}
	}
}

// TestExpandCargoWorkspaceMembers ensures that when the root Cargo.toml declares
// a [workspace] members list, each member crate's dependencies are gated too.
// `cargo build` at a workspace root compiles every member, so a member-only
// malicious dep on a fresh checkout (no Cargo.lock) is otherwise a
// direct-dependency fail-open for Rust monorepos. The `exclude` list is
// respected and a matched dir without a Cargo.toml is skipped.
func TestExpandCargoWorkspaceMembers(t *testing.T) {
	root := t.TempDir()

	writeFile := func(rel, contents string) {
		full := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(contents), 0o644))
	}

	writeFile("Cargo.toml", `
[workspace]
members = ["crates/*"]
exclude = ["crates/legacy"]

[workspace.dependencies]
shared-evil = "1.0.0"
`)
	writeFile("crates/foo/Cargo.toml", `
[package]
name = "foo"

[dependencies]
foo-evil = "1.0.0"

[build-dependencies]
foo-build-evil = "=2.0.0"
`)
	writeFile("crates/bar/Cargo.toml", `
[package]
name = "bar"

[dependencies]
bar-git = { git = "https://evil.example/bar.git" }
`)
	writeFile("crates/legacy/Cargo.toml", `
[package]
name = "legacy"

[dependencies]
legacy-evil = "1.0.0"
`)
	// A glob match with no Cargo.toml must be skipped gracefully.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "crates/notacrate"), 0o755))

	exp := cargomanifest.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(root, "Cargo.toml"),
		Kind: packagemanager.ManifestKindCargoToml,
	})
	require.NoError(t, err)

	// Workspace-shared dep (root [workspace.dependencies]); caret "1.0.0" → empty.
	requireContains(t, installs, "shared-evil", "", false, false)
	// Member deps across sections.
	requireContains(t, installs, "foo-evil", "", false, false)
	requireContains(t, installs, "foo-build-evil", "2.0.0", false, false)
	requireContains(t, installs, "bar-git", "", false, true)
	// Excluded member must not be walked.
	requireNotContains(t, installs, "legacy-evil")
}
