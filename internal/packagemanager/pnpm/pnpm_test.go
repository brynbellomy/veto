package pnpm_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pnpm"
)

func TestParseInstalls(t *testing.T) {
	m := pnpm.New()
	require.Equal(t, "pnpm", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name string
		args []string
		want []packagemanager.Install
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--store-dir", "/tmp/pnpm-store", "add", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--store-dir=/tmp/pnpm-store", "add", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "flag-with-value after verb does not eat the package",
			args: []string{"add", "--registry", "https://example.com", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "plain flag (no value) still works",
			args: []string{"add", "--save-dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, m.ParseInstalls(c.args))
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := pnpm.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantPkg   bool
		wantLocks bool
	}{
		{name: "non-install verb returns nil", args: []string{"run", "dev"}, wantNil: true},
		{name: "install with no specs emits package.json + lockfile refs", args: []string{"install"}, wantPkg: true, wantLocks: true},
		{name: "add with explicit specs emits lockfile refs only", args: []string{"add", "lodash"}, wantLocks: true},
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
			}
		})
	}
}

func TestProjectPreflight(t *testing.T) {
	m := pnpm.New()

	cases := []struct {
		name    string
		args    []string
		wantOK  bool
		wantRef bool
	}{
		{name: "run dev triggers preflight", args: []string{"run", "dev"}, wantOK: true, wantRef: true},
		{name: "start triggers preflight", args: []string{"start"}, wantOK: true, wantRef: true},
		{name: "test triggers preflight", args: []string{"test"}, wantOK: true, wantRef: true},
		{name: "restart triggers preflight", args: []string{"restart"}, wantOK: true, wantRef: true},
		{name: "stop triggers preflight", args: []string{"stop"}, wantOK: true, wantRef: true},
		{name: "install is not a preflight verb", args: []string{"install"}, wantOK: false},
		{name: "add is not a preflight verb", args: []string{"add", "lodash"}, wantOK: false},
		{name: "dlx is not a preflight verb", args: []string{"dlx", "some-tool"}, wantOK: false},
		{name: "flag-with-value before verb still finds run", args: []string{"--store-dir", "/tmp", "run", "dev"}, wantOK: true, wantRef: true},
		{name: "bare run with no script name still returns refs", args: []string{"run"}, wantOK: true, wantRef: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan, ok := m.ProjectPreflight(c.args)
			require.Equal(t, c.wantOK, ok)
			if c.wantRef {
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindPackageJSON)
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindPackageLockJSON)
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindYarnLock)
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindPnpmLockYAML)
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindNpmShrinkwrap)
				requireKind(t, plan.ManifestRefs, packagemanager.ManifestKindBunLock)
			}
		})
	}
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
