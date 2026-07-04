package yarn_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/yarn"
)

func TestParseInstalls(t *testing.T) {
	m := yarn.New()
	require.Equal(t, "yarn", m.Name())
	require.Equal(t, intel.EcosystemNPM, m.Ecosystem())

	cases := []struct {
		name    string
		args    []string
		want    []packagemanager.Install
		wantNil bool // distinguishes nil (passthrough) from empty-non-nil (implicit install)
	}{
		{
			name: "global flag-with-value before verb is skipped",
			args: []string{"--cwd", "/tmp/proj", "add", "lodash"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "lodash"}, RawSpec: "lodash"},
			},
		},
		{
			name: "--flag=value form before verb is skipped",
			args: []string{"--cwd=/tmp/proj", "add", "lodash"},
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
			args: []string{"add", "--dev", "typescript"},
			want: []packagemanager.Install{
				{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "typescript"}, RawSpec: "typescript"},
			},
		},
		{
			name: "install verb with no specs returns empty slice",
			args: []string{"install"},
			want: []packagemanager.Install{},
		},
		// Yarn classic treats bare `yarn` as `yarn install`. The parser must
		// return an empty-non-nil slice so the gate engages (a nil result
		// triggers passthrough).
		{
			name: "bare yarn (no args) returns empty slice for implicit install",
			args: nil,
			want: []packagemanager.Install{},
		},
		{
			name: "bare yarn with only --frozen-lockfile returns empty slice",
			args: []string{"--frozen-lockfile"},
			want: []packagemanager.Install{},
		},
		{
			name: "bare yarn with flag-with-value returns empty slice",
			args: []string{"--cwd", "/tmp/proj"},
			want: []packagemanager.Install{},
		},
		// Info flags mean yarn won't install anything; passthrough.
		{
			name:    "yarn --help passes through",
			args:    []string{"--help"},
			wantNil: true,
		},
		{
			name:    "yarn -h passes through",
			args:    []string{"-h"},
			wantNil: true,
		},
		{
			name:    "yarn --version passes through",
			args:    []string{"--version"},
			wantNil: true,
		},
		{
			name:    "yarn -v passes through",
			args:    []string{"-v"},
			wantNil: true,
		},
		// Non-install verbs are not bare-install; passthrough.
		{
			name:    "yarn config set passes through",
			args:    []string{"config", "set", "registry", "https://example.com"},
			wantNil: true,
		},
		{
			name:    "yarn run dev passes through",
			args:    []string{"run", "dev"},
			wantNil: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ParseInstalls(c.args)
			if c.wantNil {
				require.Nil(t, got)
				return
			}
			require.Equal(t, c.want, got)
		})
	}
}

func TestManifestRefs(t *testing.T) {
	m := yarn.New()

	cases := []struct {
		name      string
		args      []string
		wantNil   bool
		wantPkg   bool // expect a package.json ref
		wantLocks bool // expect the lockfile refs (always emitted for install verbs)
	}{
		{name: "non-install verb returns nil", args: []string{"run", "dev"}, wantNil: true},
		{name: "install with no specs emits package.json + lock refs", args: []string{"install"}, wantPkg: true, wantLocks: true},
		{name: "add with explicit specs emits lock refs only", args: []string{"add", "lodash"}, wantLocks: true},
		// Bare `yarn` is yarn classic's implicit `yarn install`; must emit
		// the full manifest+lockfile set so the gate engages.
		{name: "bare yarn emits package.json + lock refs", args: nil, wantPkg: true, wantLocks: true},
		{name: "bare yarn with --frozen-lockfile emits package.json + lock refs", args: []string{"--frozen-lockfile"}, wantPkg: true, wantLocks: true},
		{name: "yarn --help returns nil", args: []string{"--help"}, wantNil: true},
		{name: "yarn --version returns nil", args: []string{"--version"}, wantNil: true},
		{name: "yarn -v returns nil", args: []string{"-v"}, wantNil: true},
		{name: "yarn config set passes through (nil)", args: []string{"config", "set", "registry", "https://example.com"}, wantNil: true},
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
				// Each lockfile we know about must be referenced; the
				// expander tolerates missing files at scan time.
				requireKind(t, got, packagemanager.ManifestKindPackageLockJSON)
				requireKind(t, got, packagemanager.ManifestKindPnpmLockYAML)
				requireKind(t, got, packagemanager.ManifestKindYarnLock)
				requireKind(t, got, packagemanager.ManifestKindNpmShrinkwrap)
			}
		})
	}
}

func TestProjectPreflight(t *testing.T) {
	m := yarn.New()

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
		{name: "flag-with-value before verb still finds run", args: []string{"--cwd", "/tmp", "run", "dev"}, wantOK: true, wantRef: true},
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
