package asdf

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
	t.Setenv("ASDF_DATA_DIR", "")

	tests := []struct {
		name      string
		opts      Options
		env       map[string]string
		candidate string
		want      bool
	}{
		{name: "default shims dir", candidate: filepath.Join(home, ".asdf", "shims", "python"), want: true},
		{name: "ASDF_DATA_DIR shims dir", env: map[string]string{"ASDF_DATA_DIR": "/srv/asdf"}, candidate: "/srv/asdf/shims/npm", want: true},
		{name: "explicit shims dir", opts: Options{ShimsDir: "/c/shims"}, candidate: "/c/shims/go", want: true},
		{name: "conventional substring", candidate: "/home/x/.asdf/shims/cargo", want: true},
		{name: "asdf install dir is not a shim", candidate: "/home/x/.asdf/installs/golang/1.22/bin/go", want: false},
		{name: "unrelated", candidate: "/usr/bin/python3", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			require.Equal(t, tt.want, NewWithOptions(tt.opts).OwnsShim(tt.candidate, tt.candidate))
		})
	}
}

func TestWhich(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "asdf-ok")
	require.NoError(t, os.WriteFile(ok, []byte("#!/bin/sh\n[ \"$1\" = which ] || exit 9\necho \"/real/$2\"\n"), 0o755))
	bad := filepath.Join(dir, "asdf-bad")
	require.NoError(t, os.WriteFile(bad, []byte("#!/bin/sh\necho 'No version is set for command go' >&2\nexit 126\n"), 0o755))
	env := []string{"PATH=/usr/bin:/bin"}

	got, err := NewWithOptions(Options{Dispatcher: ok}).Which(context.Background(), "/x/go", "go", dir, env)
	require.NoError(t, err)
	require.Equal(t, "/real/go", got)

	_, err = NewWithOptions(Options{Dispatcher: bad}).Which(context.Background(), "/x/go", "go", dir, env)
	require.ErrorIs(t, err, vmshim.ErrUnresolvable)

	t.Setenv("PATH", "/nonexistent")
	_, err = New().Which(context.Background(), "/x/go", "go", dir, env)
	require.Error(t, err)
	require.NotErrorIs(t, err, vmshim.ErrUnresolvable)
}
