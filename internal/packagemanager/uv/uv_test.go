package uv_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/uv"
)

func TestParseInstalls(t *testing.T) {
	m := uv.New()
	require.Equal(t, "uv", m.Name())
	require.Equal(t, intel.EcosystemPyPI, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--python", "3.12", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--python=3.12", "add", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--index-url", "https://example.com", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"add", "--dev", "pytest"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "pytest"}, RawSpec: "pytest"},
			},
		},
		{
			name: "uv pip install with flag-value after verb",
			args: []string{"pip", "install", "--index-url", "https://example.com", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		{
			name: "uv pip install with global flag-value before pip subcommand",
			args: []string{"--cache-dir", "/tmp/uv-cache", "pip", "install", "requests"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests"}, RawSpec: "requests"},
			},
		},
		// `uv tool {install,run,upgrade}` fetch a package into an isolated
		// environment; uninstall does not. `uv run --with X` similarly
		// pulls X for that invocation. Regressions here silently route
		// fetch-y verbs to the gate and then drop the package on the floor.
		{
			name: "uv tool install gates the package",
			args: []string{"tool", "install", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "uv tool run gates the package",
			args: []string{"tool", "run", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "uv tool upgrade gates the package",
			args: []string{"tool", "upgrade", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "uv tool uninstall does not fetch — returns nil",
			args: []string{"tool", "uninstall", "evil"},
			want: nil,
		},
		{
			name: "uv tool install with --with gates both",
			args: []string{"tool", "install", "ruff", "--with", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "ruff"}, RawSpec: "ruff"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "uv run --with gates the spec, not the script",
			args: []string{"run", "--with", "evil", "python", "-c", "x"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "uv run --with=value form",
			args: []string{"run", "--with=evil", "script.py"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "bare uv run passes through (no --with)",
			args: []string{"run", "script.py"},
			want: nil,
		},
		{
			name: "uv run --with-requirements does not yield argv specs",
			args: []string{"run", "--with-requirements", "reqs.txt", "script.py"},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := uv.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantKinds []packagemanager.ManifestKind
	}{
		{name: "non-install verb returns nil", args: []string{"build"}, wantNil: true},
		{
			name:      "uv add with -r",
			args:      []string{"add", "-r", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv pip install -r",
			args:      []string{"pip", "install", "-r", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{
			name:      "uv pip install -c",
			args:      []string{"pip", "install", "-c", "constraints.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindConstraint},
		},
		{
			name:      "uv pip install with --requirement long form",
			args:      []string{"pip", "install", "--requirement", "reqs.txt"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{
			name:      "uv sync emits pyproject + uv.lock refs",
			args:      []string{"sync"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindPyProject, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv add with no specs emits pyproject + uv.lock refs",
			args:      []string{"add"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindPyProject, packagemanager.ManifestKindUvLock},
		},
		{
			name:      "uv add with explicit spec emits uv.lock ref only",
			args:      []string{"add", "requests"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindUvLock},
		},
		{name: "uv pip install with no -r and no specs emits nothing (pip semantics)", args: []string{"pip", "install"}, wantNil: true},
		{
			name:      "uv run --with-requirements emits a Requirements ref",
			args:      []string{"run", "--with-requirements", "reqs.txt", "script.py"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{
			name:      "uv tool run --with-requirements emits a Requirements ref",
			args:      []string{"tool", "run", "--with-requirements", "reqs.txt", "ruff"},
			wantKinds: []packagemanager.ManifestKind{packagemanager.ManifestKindRequirements},
		},
		{name: "uv tool install with explicit spec emits no manifest refs", args: []string{"tool", "install", "ruff"}, wantNil: true},
		{name: "uv run script (no --with) emits nothing", args: []string{"run", "script.py"}, wantNil: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			for _, kind := range c.wantKinds {
				requireKindUv(t, got, kind)
			}
		})
	}
}

func TestResolverPreScan(t *testing.T) {
	m := uv.New()

	t.Run("uv pip install specs produce wheel-only pylock compile plan", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"pip", "install", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{
			"pip", "compile",
			"veto-uv-requirements.in",
			"--output-file", "pylock.veto.toml",
			"--format", "pylock.toml",
			"--only-binary", ":all:",
			"--no-progress",
		}, plan.Args)
		require.Equal(t, []packagemanager.ManifestRef{{Path: "pylock.veto.toml", Kind: packagemanager.ManifestKindUvLock}}, plan.ManifestRefs)
		require.Equal(t, map[string][]byte{"veto-uv-requirements.in": []byte("clean-direct\n")}, plan.GeneratedFiles)
		require.Equal(t, []packagemanager.Install{{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"}}, plan.DirectInstalls)
	})

	t.Run("requirements and constraints are compiled and seeded", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"pip", "install", "-r", "requirements.txt", "-c", "constraints.txt"})
		require.True(t, ok)
		require.Equal(t, []string{"pip", "compile", "requirements.txt", "--constraint", "constraints.txt", "--output-file", "pylock.veto.toml", "--format", "pylock.toml", "--only-binary", ":all:", "--no-progress"}, plan.Args)
		require.ElementsMatch(t, []string{"requirements.txt", "constraints.txt"}, plan.SeedFiles)
		require.Empty(t, plan.GeneratedFiles)
	})

	t.Run("uv pip install forwards user index flags into the compile probe", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"pip", "install", "--index-url", "https://example.com", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{
			"pip", "compile",
			"veto-uv-requirements.in",
			"--index-url", "https://example.com",
			"--output-file", "pylock.veto.toml",
			"--format", "pylock.toml",
			"--only-binary", ":all:",
			"--no-progress",
		}, plan.Args)
	})

	t.Run("uv add compiles the pyproject union with synthesized requirements", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"add", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{
			"pip", "compile",
			"pyproject.toml",
			"veto-uv-requirements.in",
			"--output-file", "pylock.veto.toml",
			"--format", "pylock.toml",
			"--only-binary", ":all:",
			"--no-progress",
		}, plan.Args)
		require.Equal(t, []packagemanager.ManifestRef{{Path: "pylock.veto.toml", Kind: packagemanager.ManifestKindUvLock}}, plan.ManifestRefs)
		require.Equal(t, []string{"pyproject.toml"}, plan.SeedFiles)
		require.Equal(t, map[string][]byte{"veto-uv-requirements.in": []byte("clean-direct\n")}, plan.GeneratedFiles)
		require.Equal(t, []packagemanager.Install{{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"}}, plan.DirectInstalls)
	})

	t.Run("uv add forwards user index flags into the compile probe", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"add", "--index-url", "https://example.com", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{
			"pip", "compile",
			"pyproject.toml",
			"veto-uv-requirements.in",
			"--index-url", "https://example.com",
			"--output-file", "pylock.veto.toml",
			"--format", "pylock.toml",
			"--only-binary", ":all:",
			"--no-progress",
		}, plan.Args)
		require.Equal(t, []packagemanager.Install{{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"}}, plan.DirectInstalls)
	})

	t.Run("uv install resolves the same way as uv add", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"install", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{"pyproject.toml"}, plan.SeedFiles)
		require.Equal(t, map[string][]byte{"veto-uv-requirements.in": []byte("clean-direct\n")}, plan.GeneratedFiles)
	})

	t.Run("uv sync is not pre-scanned (installs the already-locked tree)", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"sync"})
		require.False(t, ok)
	})

	t.Run("uv add with no explicit specs is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"add"})
		require.False(t, ok)
	})

	t.Run("uv add of a local path is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"add", "./local-pkg"})
		require.False(t, ok)
	})

	t.Run("uv add of an opaque remote is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"add", "https://example.com/pkg.whl"})
		require.False(t, ok)
	})

	t.Run("uv add with a user no-binary flag is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"add", "--no-binary", ":all:", "clean-direct"})
		require.False(t, ok)
	})

	t.Run("empty install is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"pip", "install"})
		require.False(t, ok)
	})

	t.Run("local path is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"pip", "install", "./local-pkg"})
		require.False(t, ok)
	})

	t.Run("opaque remote is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"pip", "install", "https://example.com/pkg.whl"})
		require.False(t, ok)
	})

	t.Run("user no-binary flag is not pre-scanned", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"pip", "install", "--no-binary", ":all:", "clean-direct"})
		require.False(t, ok)
	})
}

func requireKindUv(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}
