package cargo_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/cargo"
)

func TestParseInstalls(t *testing.T) {
	m := cargo.New()

	t.Run("cargo add gates crate specs", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "serde@1.0.228", "regex", "--features", "derive", "--optional"})
		requireContains(t, out, "serde", "1.0.228", false, false)
		requireContains(t, out, "regex", "", false, false)
		require.Len(t, out, 2)
	})

	t.Run("cargo add flags git sources as opaque", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "my-crate", "--git", "https://github.com/example/my-crate"})
		requireContains(t, out, "my-crate", "", false, true)
		require.Len(t, out, 1)
	})

	t.Run("cargo add path source is local", func(t *testing.T) {
		out := m.ParseInstalls([]string{"add", "my-crate", "--path", "../my-crate"})
		requireContains(t, out, "my-crate", "", true, false)
		require.Len(t, out, 1)
	})

	t.Run("cargo install gates crate specs and local paths", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "ripgrep@14.1.1", "./local", "--dry-run"})
		requireContains(t, out, "ripgrep", "14.1.1", false, false)
		requireContains(t, out, "./local", "", true, false)
	})

	t.Run("cargo install git source is opaque", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "my-crate", "--git", "https://github.com/example/my-crate"})
		requireContains(t, out, "my-crate", "", false, true)
		require.Len(t, out, 1)
	})

	t.Run("cargo update and fetch gate manifest refs only", func(t *testing.T) {
		require.Empty(t, m.ParseInstalls([]string{"update"}))
		require.Empty(t, m.ParseInstalls([]string{"fetch"}))
	})

	t.Run("non dependency-fetching commands parse no installs", func(t *testing.T) {
		require.Nil(t, m.ParseInstalls([]string{"build"}))
		require.Nil(t, m.ParseInstalls([]string{"test"}))
		require.Nil(t, m.ParseInstalls([]string{"version"}))
	})
}

func TestManifestRefs(t *testing.T) {
	m := cargo.New()
	for _, args := range [][]string{
		{"add", "serde"},
		{"update"},
		{"fetch"},
	} {
		refs := m.ManifestRefs(args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, refs)
	}

	require.Nil(t, m.ManifestRefs([]string{"install", "ripgrep"}))
	require.Nil(t, m.ManifestRefs([]string{"build"}))
}

func TestProjectPreflight(t *testing.T) {
	m := cargo.New()

	for _, args := range [][]string{
		{"build"},
		{"check"},
		{"test"},
		{"run"},
		{"bench"},
		{"clippy"},
	} {
		plan, ok := m.ProjectPreflight(args)
		require.True(t, ok, "expected project preflight for %v", args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, plan.ManifestRefs)
	}

	plan, ok := m.ProjectPreflight([]string{"test", "--manifest-path", filepath.Join("nested", "Cargo.toml")})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join("nested", "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join("nested", "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
	}, plan.ManifestRefs)

	plan, ok = m.ProjectPreflight([]string{"build", "--manifest-path", filepath.Join("nested", "Cargo.toml"), "--lockfile-path", filepath.Join("locks", "Cargo.lock")})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join("nested", "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join("locks", "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
	}, plan.ManifestRefs)

	_, ok = m.ProjectPreflight([]string{"version"})
	require.False(t, ok)
	_, ok = m.ProjectPreflight([]string{"metadata"})
	require.False(t, ok)
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

func TestOpaqueRemoteResolve(t *testing.T) {
	m := cargo.New()

	t.Run("install --git produces a generate-lockfile plan", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "my-crate", "--git", "https://github.com/example/my-crate"})
		require.True(t, ok)
		require.Equal(t, "https://github.com/example/my-crate", plan.GitURL)
		require.Empty(t, plan.Ref)
		require.False(t, plan.RefIsRevision)
		require.Equal(t, []string{"generate-lockfile", "--manifest-path", "Cargo.toml"}, plan.ResolveArgs)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, plan.ManifestRefs)
	})

	t.Run("add --git with --branch is a non-revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"add", "my-crate", "--git", "https://x/y", "--branch", "main"})
		require.True(t, ok)
		require.Equal(t, "main", plan.Ref)
		require.False(t, plan.RefIsRevision)
	})

	t.Run("--tag is a non-revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--tag", "v1.2.3"})
		require.True(t, ok)
		require.Equal(t, "v1.2.3", plan.Ref)
		require.False(t, plan.RefIsRevision)
	})

	t.Run("--rev is a revision ref", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--rev", "abc123"})
		require.True(t, ok)
		require.Equal(t, "abc123", plan.Ref)
		require.True(t, plan.RefIsRevision)
	})

	t.Run("--locked validates the committed lock instead of regenerating", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"install", "--git", "https://x/y", "--locked"})
		require.True(t, ok)
		require.Equal(t, []string{"fetch", "--locked", "--manifest-path", "Cargo.toml"}, plan.ResolveArgs)
	})

	t.Run("non-git and non-install/add return false", func(t *testing.T) {
		_, ok := m.OpaqueRemoteResolve([]string{"install", "ripgrep"})
		require.False(t, ok)
		_, ok = m.OpaqueRemoteResolve([]string{"add", "serde"})
		require.False(t, ok)
		_, ok = m.OpaqueRemoteResolve([]string{"build", "--git", "https://x/y"})
		require.False(t, ok)
	})
}

func TestPinResolvedRevision(t *testing.T) {
	m := cargo.New()
	const sha = "0123456789abcdef0123456789abcdef01234567"

	t.Run("appends --rev when no ref selector present", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("drops a --branch space-form selector", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--branch", "main"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("drops a --tag=value form selector", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"add", "c", "--git", "https://x/y", "--tag=v1"}, sha)
		require.Equal(t, []string{"add", "c", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("is idempotent against an existing --rev", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--rev", "short"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--rev", sha}, out)
	})

	t.Run("preserves unrelated flags and inserts --rev before a -- terminator", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"install", "--git", "https://x/y", "--features", "a", "--", "passthrough"}, sha)
		require.Equal(t, []string{"install", "--git", "https://x/y", "--features", "a", "--rev", sha, "--", "passthrough"}, out)
	})

	t.Run("preserves a leading +toolchain override", func(t *testing.T) {
		out := m.PinResolvedRevision([]string{"+nightly", "install", "--git", "https://x/y", "--branch", "main"}, sha)
		require.Equal(t, []string{"+nightly", "install", "--git", "https://x/y", "--rev", sha}, out)
	})
}

// TestToolchainOverride covers `cargo +<toolchain> <verb>` invocations, where
// rustup's toolchain override (e.g. `+nightly`) is the first argument. It is
// not a flag, so without explicit handling the parser reads it as the verb and
// the command slips through ungated.
func TestToolchainOverride(t *testing.T) {
	m := cargo.New()

	t.Run("install --git is still detected as opaque", func(t *testing.T) {
		out := m.ParseInstalls([]string{"+nightly", "install", "my-crate", "--git", "https://github.com/example/my-crate"})
		requireContains(t, out, "my-crate", "", false, true)
		require.Len(t, out, 1)
	})

	t.Run("add crate spec is still gated", func(t *testing.T) {
		out := m.ParseInstalls([]string{"+stable", "add", "serde@1.0.228"})
		requireContains(t, out, "serde", "1.0.228", false, false)
		require.Len(t, out, 1)
	})

	t.Run("manifest refs are still emitted for add", func(t *testing.T) {
		refs := m.ManifestRefs([]string{"+1.75", "add", "serde"})
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, refs)
	})

	t.Run("project preflight still fires for build", func(t *testing.T) {
		plan, ok := m.ProjectPreflight([]string{"+nightly", "build"})
		require.True(t, ok)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
			{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
		}, plan.ManifestRefs)
	})

	t.Run("opaque resolve threads the toolchain into the resolve command", func(t *testing.T) {
		plan, ok := m.OpaqueRemoteResolve([]string{"+nightly", "install", "--git", "https://x/y"})
		require.True(t, ok)
		require.Equal(t, "https://x/y", plan.GitURL)
		require.Equal(t, []string{"+nightly", "generate-lockfile", "--manifest-path", "Cargo.toml"}, plan.ResolveArgs)
	})

	t.Run("non-toolchain leading token is untouched", func(t *testing.T) {
		// A normal install must not be mistaken for a toolchain override.
		out := m.ParseInstalls([]string{"install", "ripgrep@14.1.1"})
		requireContains(t, out, "ripgrep", "14.1.1", false, false)
	})
}
