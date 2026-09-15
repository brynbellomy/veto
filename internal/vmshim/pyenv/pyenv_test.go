package pyenv

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
	t.Setenv("PYENV_ROOT", "")

	tests := []struct {
		name      string
		opts      Options
		env       map[string]string
		candidate string
		want      bool
	}{
		{name: "default shims dir", candidate: filepath.Join(home, ".pyenv", "shims", "python"), want: true},
		{name: "PYENV_ROOT shims dir", env: map[string]string{"PYENV_ROOT": "/srv/pyenv"}, candidate: "/srv/pyenv/shims/pip", want: true},
		{name: "explicit shims dir", opts: Options{ShimsDir: "/c/shims"}, candidate: "/c/shims/python3", want: true},
		{name: "conventional substring", candidate: "/home/x/.pyenv/shims/python3.12", want: true},
		{name: "pyenv versions dir is not a shim", candidate: "/home/x/.pyenv/versions/3.12.1/bin/python", want: false},
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
	ok := filepath.Join(dir, "pyenv-ok")
	require.NoError(t, os.WriteFile(ok, []byte("#!/bin/sh\n[ \"$1\" = which ] || exit 9\necho \"/real/$2\"\n"), 0o755))
	bad := filepath.Join(dir, "pyenv-bad")
	require.NoError(t, os.WriteFile(bad, []byte("#!/bin/sh\necho 'pyenv: python: command not found' >&2\nexit 127\n"), 0o755))
	env := []string{"PATH=/usr/bin:/bin"}

	got, err := NewWithOptions(Options{Dispatcher: ok}).Which(context.Background(), "/x/python", "python", dir, env)
	require.NoError(t, err)
	require.Equal(t, "/real/python", got)

	_, err = NewWithOptions(Options{Dispatcher: bad}).Which(context.Background(), "/x/python", "python", dir, env)
	require.ErrorIs(t, err, vmshim.ErrUnresolvable)

	t.Setenv("PATH", "/nonexistent")
	_, err = New().Which(context.Background(), "/x/python", "python", dir, env)
	require.Error(t, err)
	require.NotErrorIs(t, err, vmshim.ErrUnresolvable)
}
