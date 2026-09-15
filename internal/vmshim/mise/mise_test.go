package mise

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/vmshim"
)

func TestOwnsShim(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MISE_DATA_DIR", "")
	defaultShims := filepath.Join(home, ".local", "share", "mise", "shims")

	tests := []struct {
		name      string
		opts      Options
		env       map[string]string
		candidate string
		resolved  string
		want      bool
	}{
		{
			name:      "symlink resolving to a mise binary is owned regardless of location",
			candidate: "/opt/somewhere/shims/go",
			resolved:  "/usr/local/bin/mise",
			want:      true,
		},
		{
			name:      "entry in the default shims dir is owned",
			candidate: filepath.Join(defaultShims, "go"),
			resolved:  filepath.Join(defaultShims, "go"),
			want:      true,
		},
		{
			name:      "entry in MISE_DATA_DIR/shims is owned",
			env:       map[string]string{"MISE_DATA_DIR": "/srv/mise"},
			candidate: "/srv/mise/shims/npm",
			resolved:  "/srv/mise/shims/npm",
			want:      true,
		},
		{
			name:      "entry in an explicit shims dir is owned",
			opts:      Options{ShimsDir: "/custom/shims"},
			candidate: "/custom/shims/uv",
			resolved:  "/custom/shims/uv",
			want:      true,
		},
		{
			name:      "conventional path substring is owned",
			candidate: "/home/x/.local/share/mise/shims/cargo",
			resolved:  "/home/x/.local/share/mise/shims/cargo",
			want:      true,
		},
		{
			name:      "a mise install dir is NOT a shim",
			candidate: "/home/x/.local/share/mise/installs/go/1.27.1/bin/go",
			resolved:  "/home/x/.local/share/mise/installs/go/1.27.1/bin/go",
			want:      false,
		},
		{
			name:      "homebrew binary is not owned",
			candidate: "/opt/homebrew/bin/go",
			resolved:  "/opt/homebrew/Cellar/go/1.26.2/bin/go",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			require.Equal(t, tt.want, NewWithOptions(tt.opts).OwnsShim(tt.candidate, tt.resolved))
		})
	}
}

// TestWhich_UsesTheShimsOwnMiseBinary: the dispatcher probed is the mise
// the shim itself points at, not whichever mise happens to be first on
// PATH.
func TestWhich_UsesTheShimsOwnMiseBinary(t *testing.T) {
	dir := t.TempDir()
	miseBin := filepath.Join(dir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\n[ \"$1\" = which ] || exit 9\necho \"/real/$2\"\n"), 0o755))
	shims := filepath.Join(dir, "shims")
	require.NoError(t, os.MkdirAll(shims, 0o755))
	shim := filepath.Join(shims, "go")
	require.NoError(t, os.Symlink(miseBin, shim))
	t.Setenv("PATH", "/nonexistent")

	got, err := New().Which(context.Background(), shim, "go", dir, []string{"PATH=/usr/bin:/bin"})
	require.NoError(t, err)
	require.Equal(t, "/real/go", got)
}

func TestWhich_UnresolvableSurfacesMiseHint(t *testing.T) {
	dir := t.TempDir()
	miseBin := filepath.Join(dir, "mise")
	require.NoError(t, os.WriteFile(miseBin, []byte(
		"#!/bin/sh\necho 'mise ERROR No executable found for configured tool: go' >&2\necho 'Reinstall it with:' >&2\necho 'mise install --force go@1.25.1' >&2\nexit 1\n"), 0o755))

	_, err := NewWithOptions(Options{Dispatcher: miseBin}).Which(context.Background(), "/x/go", "go", dir, []string{"PATH=/usr/bin:/bin"})
	require.ErrorIs(t, err, vmshim.ErrUnresolvable)
	var ue *vmshim.UnresolvableError
	require.ErrorAs(t, err, &ue)
	require.Equal(t, "mise install --force go@1.25.1", ue.Hint)
}

func TestWhich_NoMiseAnywhereIsAProbeError(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	_, err := New().Which(context.Background(), filepath.Join(t.TempDir(), "go"), "go", "", []string{"PATH=/nonexistent"})
	require.Error(t, err)
	require.NotErrorIs(t, err, vmshim.ErrUnresolvable)
}
