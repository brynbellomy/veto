package npm_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
)

func TestParseInstalls(t *testing.T) {
	m := npm.New()
	require.Equal(t, "npm", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "no args returns nil",
			args: nil,
			want: nil,
		},
		{
			name: "non-install verb returns nil",
			args: []string{"run", "dev"},
			want: nil,
		},
		{
			name: "version-only flag returns nil",
			args: []string{"--version"},
			want: nil,
		},
		{
			name: "install with explicit packages",
			args: []string{"install", "lodash", "express@4.18"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "express", Version: "4.18"}, RawSpec: "express@4.18"},
			},
		},
		{
			name: "i alias works",
			args: []string{"i", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "install with no specs returns empty slice (implicit from package.json)",
			args: []string{"install"},
			want: []packagemanager.Install{},
		},
		{
			name: "ci returns empty slice",
			args: []string{"ci"},
			want: []packagemanager.Install{},
		},
		{
			name: "flags between verb and specs are skipped",
			args: []string{"install", "--save-dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
		{
			name: "scoped package",
			args: []string{"install", "@types/node@20"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "@types/node", Version: "20"}, RawSpec: "@types/node@20"},
			},
		},
		{
			name: "local filesystem path marked LocalPath",
			args: []string{"install", "./local-pkg"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "./local-pkg"}, RawSpec: "./local-pkg", LocalPath: true},
			},
		},
		{
			name: "tarball URL marked OpaqueRemote",
			args: []string{"install", "https://example.com/x.tgz"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "https://example.com/x.tgz"}, RawSpec: "https://example.com/x.tgz", OpaqueRemote: true},
			},
		},
		{
			// Regression for leading-dash typosquats: without `--` handling, a
			// package name starting with `-` would be filtered out as a flag,
			// silently bypassing the gate.
			name: "leading-dash package after -- separator is parsed",
			args: []string{"install", "--", "--hiljson"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "--hiljson"}, RawSpec: "--hiljson"},
			},
		},
		{
			name: "flags and positionals interleaved with separator",
			args: []string{"install", "--save-dev", "typescript", "--", "-evil-pkg"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "-evil-pkg"}, RawSpec: "-evil-pkg"},
			},
		},
		// Flag-with-value table tests: these regress the bug where a value
		// like "/tmp" or "https://example.com" was misread as the verb or
		// as a positional package name.
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--prefix", "/tmp", "install", "foo"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "foo"}, RawSpec: "foo"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--prefix=/tmp", "install", "foo"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "foo"}, RawSpec: "foo"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"install", "--registry", "https://example.com", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"install", "--save-dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
		// `npm exec` is the npx-equivalent built into npm 7+. The first
		// non-flag positional is the package spec to fetch and run; a
		// `--package` flag overrides that.
		{
			name: "npm exec with positional fetches package",
			args: []string{"exec", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "npm exec with -- separator",
			args: []string{"exec", "--", "evil"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "npm exec --package=value wins over positional",
			args: []string{"exec", "--package=evil", "--", "some-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "npm exec -p value wins over positional",
			args: []string{"exec", "-p", "evil", "some-cmd"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"}, RawSpec: "evil"},
			},
		},
		{
			name: "npm exec with no positional and no --package returns nil",
			args: []string{"exec"},
			want: nil,
		},
		{
			name: "npm exec --help is not risky",
			args: []string{"exec", "--help"},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ParseInstalls(c.args)
			if c.want == nil {
				require.Nil(t, got)
				return
			}
			require.Equal(t, c.want, got)
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := npm.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantPkg   bool
		wantLocks bool
	}{
		{name: "non-install verb returns nil", args: []string{"run", "dev"}, wantNil: true},
		{name: "install with no specs emits package.json + lockfile refs", args: []string{"install"}, wantPkg: true, wantLocks: true},
		{name: "i alias with no specs emits package.json + lockfile refs", args: []string{"i"}, wantPkg: true, wantLocks: true},
		{name: "install with explicit specs emits lockfile refs only", args: []string{"install", "lodash"}, wantLocks: true},
		{name: "ci always reads manifest + lockfile", args: []string{"ci"}, wantPkg: true, wantLocks: true},
		{name: "install with flags but no specs still emits manifest+lockfile refs", args: []string{"install", "--save-dev"}, wantPkg: true, wantLocks: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ManifestRefs(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			if c.wantPkg {
				requireKind(t, got, packagemanager.ManifestKindPackageJSON)
			} else {
				requireNotKind(t, got, packagemanager.ManifestKindPackageJSON)
			}
			if c.wantLocks {
				requireKind(t, got, packagemanager.ManifestKindPackageLockJSON)
				requireKind(t, got, packagemanager.ManifestKindPnpmLockYAML)
				requireKind(t, got, packagemanager.ManifestKindYarnLock)
				requireKind(t, got, packagemanager.ManifestKindNpmShrinkwrap)
			}
		})
	}
}

func TestResolverPreScan(t *testing.T) {
	m := npm.New()

	t.Run("install appends safe lock-only resolver flags", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"install", "clean-direct"})
		require.True(t, ok)
		require.Equal(t, []string{
			"install",
			"clean-direct",
			"--package-lock=true",
			"--package-lock-only",
			"--ignore-scripts",
			"--dry-run=false",
			"--audit=false",
			"--fund=false",
			"--global=false",
			"--location=project",
		}, plan.Args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
			{Path: "npm-shrinkwrap.json", Kind: packagemanager.ManifestKindNpmShrinkwrap},
		}, plan.ManifestRefs)
		require.ElementsMatch(t, []string{
			"package.json",
			"package-lock.json",
			"npm-shrinkwrap.json",
			".npmrc",
		}, plan.SeedFiles)
		require.Equal(t, []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct"}, RawSpec: "clean-direct"},
		}, plan.DirectInstalls)
	})

	t.Run("flags are inserted before separator", func(t *testing.T) {
		plan, ok := m.ResolverPreScan([]string{"install", "--", "--leading-dash-name"})
		require.True(t, ok)
		require.Equal(t, []string{
			"install",
			"--package-lock=true",
			"--package-lock-only",
			"--ignore-scripts",
			"--dry-run=false",
			"--audit=false",
			"--fund=false",
			"--global=false",
			"--location=project",
			"--",
			"--leading-dash-name",
		}, plan.Args)
	})

	t.Run("non-global --prefix is stripped so the probe resolves in the workdir", func(t *testing.T) {
		// A caller-supplied --prefix re-roots npm's project resolution: the
		// --package-lock-only output lands in the REAL prefix dir, the
		// workdir never receives the lockfile, and the gate aborts
		// fail-closed on missing output. Self-updating CLIs commonly pass
		// --prefix <their node prefix> this way. Global installs are
		// already skipped by hasGlobalInstall; this covers the non-global
		// form.
		plan, ok := m.ResolverPreScan([]string{"i", "--prefix", "/usr/local", "typescript@latest", "--omit=optional"})
		require.True(t, ok)
		require.Equal(t, []string{
			"i",
			"typescript@latest",
			"--omit=optional",
			"--package-lock=true",
			"--package-lock-only",
			"--ignore-scripts",
			"--dry-run=false",
			"--audit=false",
			"--fund=false",
			"--global=false",
			"--location=project",
		}, plan.Args)
		require.Equal(t, []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript", Version: "latest"}, RawSpec: "typescript@latest"},
		}, plan.DirectInstalls)
	})

	t.Run("ci is already lockfile-based", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"ci"})
		require.False(t, ok)
	})

	t.Run("bare install has no newly named package", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install"})
		require.False(t, ok)
	})

	t.Run("local path is not safe to reproduce in temp resolver workdir", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install", "./local-pkg"})
		require.False(t, ok)
	})

	t.Run("opaque remote is refused by the normal gate before pre-scan", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"install", "https://example.com/pkg.tgz"})
		require.False(t, ok)
	})

	t.Run("non-install is unsupported", func(t *testing.T) {
		_, ok := m.ResolverPreScan([]string{"run", "build"})
		require.False(t, ok)
	})

	t.Run("global installs cannot generate a lockfile (ESHRINKWRAPGLOBAL)", func(t *testing.T) {
		// npm refuses --package-lock-only for global packages, so the
		// resolver pre-scan is impossible; veto must skip it and fall back
		// to direct-spec intel + binding.gyp tarball gating.
		for _, args := range [][]string{
			{"install", "-g", "@openai/codex@latest"},
			{"install", "--global", "@openai/codex@latest"},
			{"install", "--global=true", "@openai/codex@latest"},
			{"install", "--location=global", "@openai/codex@latest"},
			{"install", "--location", "global", "@openai/codex@latest"},
			{"i", "-g", "typescript"},
		} {
			_, ok := m.ResolverPreScan(args)
			require.False(t, ok, "args: %v", args)
		}
	})

	t.Run("non-global location and disabled global still pre-scan", func(t *testing.T) {
		for _, args := range [][]string{
			{"install", "--location=user", "pkg"},
			{"install", "--no-global", "pkg"},
			{"install", "--global=false", "pkg"},
		} {
			_, ok := m.ResolverPreScan(args)
			require.True(t, ok, "args: %v", args)
		}
	})
}

func requireKind(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected ref of kind %q in %v", kind, refs)
}

func requireNotKind(t *testing.T, refs []packagemanager.ManifestRef, kind packagemanager.ManifestKind) {
	t.Helper()
	for _, r := range refs {
		if r.Kind == kind {
			t.Fatalf("did not expect ref of kind %q in %v", kind, refs)
		}
	}
}
