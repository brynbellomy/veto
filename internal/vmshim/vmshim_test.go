package vmshim

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeScript plants an executable shell script and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755))
	return p
}

func TestRunWhich(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-go")

	tests := []struct {
		name         string
		script       string // "" = no dispatcher at all
		ctxTimeout   time.Duration
		wantPath     string
		wantUnresolv bool
		wantDetail   string
		wantHint     string
		wantOtherErr bool
	}{
		{
			name:     "exit 0 prints the resolved path",
			script:   "echo '" + real + "'\n",
			wantPath: real,
		},
		{
			name:     "leading blank lines and whitespace are ignored",
			script:   "printf '\\n  " + real + "  \\n'\n",
			wantPath: real,
		},
		{
			name:         "exit 0 with empty stdout is unresolvable",
			script:       "exit 0\n",
			wantUnresolv: true,
			wantDetail:   "which printed no path",
		},
		{
			name: "non-zero exit is unresolvable with mise-shaped detail and hint",
			script: "echo 'mise ERROR No executable found for configured tool: go' >&2\n" +
				"echo 'The installed version does not provide this executable with its current backend metadata.' >&2\n" +
				"echo 'Reinstall it with:' >&2\n" +
				"echo 'mise install --force go@1.25.1' >&2\n" +
				"echo 'mise ERROR Version: 2026.9.5 macos-arm64' >&2\n" +
				"echo 'mise ERROR Run with --verbose or MISE_VERBOSE=1 for more information' >&2\n" +
				"exit 1\n",
			wantUnresolv: true,
			wantDetail:   "No executable found for configured tool: go The installed version does not provide this executable with its current backend metadata. Reinstall it with: mise install --force go@1.25.1",
			wantHint:     "mise install --force go@1.25.1",
		},
		{
			name:         "non-zero exit without a hint line",
			script:       "echo 'No version is set for command go' >&2\nexit 126\n",
			wantUnresolv: true,
			wantDetail:   "No version is set for command go",
		},
		{
			name:         "missing dispatcher is a plain error, not unresolvable",
			script:       "",
			wantOtherErr: true,
		},
		{
			name:         "deadline expiry is a plain error, not unresolvable",
			script:       "sleep 5\necho '" + real + "'\n",
			ctxTimeout:   150 * time.Millisecond,
			wantOtherErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dispatcher := ""
			if tt.script != "" {
				dispatcher = writeScript(t, t.TempDir(), "mise", tt.script)
			}
			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}

			got, err := RunWhich(ctx, "mise", dispatcher, []string{"which", "go"}, "go", dir, os.Environ())

			switch {
			case tt.wantOtherErr:
				require.Error(t, err)
				require.False(t, errors.Is(err, ErrUnresolvable), "probe-level failures must not masquerade as unresolvable: %v", err)
			case tt.wantUnresolv:
				require.ErrorIs(t, err, ErrUnresolvable)
				var ue *UnresolvableError
				require.ErrorAs(t, err, &ue)
				require.Equal(t, "mise", ue.Manager)
				require.Equal(t, "go", ue.Name)
				require.Equal(t, tt.wantDetail, ue.Detail)
				require.Equal(t, tt.wantHint, ue.Hint)
			default:
				require.NoError(t, err)
				require.Equal(t, tt.wantPath, got)
			}
		})
	}
}

// TestRunWhich_RunsInRequestedDirWithGivenEnv pins the two inputs that
// make the probe faithful to the shim: the manager resolves config from
// dir, and it sees exactly the env the caller sanitized.
func TestRunWhich_RunsInRequestedDirWithGivenEnv(t *testing.T) {
	dir := t.TempDir()
	dispatcher := writeScript(t, t.TempDir(), "mise", "echo \"$PWD/$PROBE_MARK\"\n")

	got, err := RunWhich(context.Background(), "mise", dispatcher, []string{"which", "go"}, "go", dir, []string{"PROBE_MARK=marked", "PATH=/usr/bin:/bin"})
	require.NoError(t, err)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(resolvedDir, "marked"), got)
}

type fakeManager struct {
	name string
	owns func(candidate, resolved string) bool
}

func (f fakeManager) Name() string                    { return f.name }
func (f fakeManager) OwnsShim(c, r string) bool       { return f.owns(c, r) }
func (f fakeManager) Which(context.Context, string, string, string, []string) (string, error) {
	return "", nil
}

func TestRegistry_Owner(t *testing.T) {
	a := fakeManager{name: "a", owns: func(c, _ string) bool { return filepath.Base(c) == "a-shim" }}
	b := fakeManager{name: "b", owns: func(_, r string) bool { return filepath.Base(r) == "b-bin" }}
	reg := Registry{a, b}

	require.Equal(t, "a", reg.Owner("/x/a-shim", "/x/whatever").Name())
	require.Equal(t, "b", reg.Owner("/x/go", "/y/b-bin").Name())
	require.Nil(t, reg.Owner("/x/go", "/y/go"))
	require.Nil(t, Registry(nil).Owner("/x/a-shim", "/x/a-shim"))
}

func TestUnresolvableError_Message(t *testing.T) {
	require.Equal(t, "mise cannot resolve go: no exe", (&UnresolvableError{Manager: "mise", Name: "go", Detail: "no exe"}).Error())
	require.Equal(t, "asdf cannot resolve python", (&UnresolvableError{Manager: "asdf", Name: "python"}).Error())
}
