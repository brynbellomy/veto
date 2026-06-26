package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

// captureStderr redirects os.Stderr through a pipe and returns the
// captured output once close is called. Test helper.
func captureStderr(t *testing.T) (close func() string) {
	t.Helper()
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	closed := false
	return func() string {
		if closed {
			return ""
		}
		closed = true
		require.NoError(t, w.Close())
		os.Stderr = origStderr
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read pipe: %v", err)
		}
		return string(data)
	}
}

// TestInstallWrappers_BrokenSymlinkIsVisibleSkip plants a broken
// symlink at a known PM path and asserts install-wrappers does NOT
// silently drop it — instead emitting a SKIP line with the diagnostic
// target. This is Bug A from the design plan.
func TestInstallWrappers_BrokenSymlinkIsVisibleSkip(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	// Mise install layout with a broken symlink for `bun`.
	miseBin := filepath.Join(tmp, ".local", "share", "mise", "installs", "bun", "1.0.0", "bin")
	require.NoError(t, os.MkdirAll(miseBin, 0o755))
	brokenSym := filepath.Join(miseBin, "bun")
	require.NoError(t, os.Symlink(filepath.Join(tmp, "vanished-bouncer"), brokenSym))
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", "")
	// Keep discovery off the real /opt/homebrew/bin (see SystemBinDirsEnv);
	// the mise fixture below lives under the temp $HOME and is unaffected.
	t.Setenv(pmsurvey.SystemBinDirsEnv, "")

	cfg := config{CacheDir: cacheDir}
	opts := wrapperFlags{only: map[string]struct{}{"bun": {}}}

	closeCapture := captureStderr(t)
	t.Cleanup(func() { _ = closeCapture() })

	rc, _ := runInstallWrappersWith(zerolog.Nop(), cfg, opts, vetoBin, vetoID)
	out := closeCapture()
	t.Logf("stderr:\n%s", out)
	require.Equal(t, exitOK, rc)
	require.Contains(t, out, "broken symlink", "broken symlink must emit a visible SKIP line")
	require.Contains(t, out, brokenSym)
}

// TestInstallWrappers_ForeignWrapperWithoutForceIsSkip plants a
// symlink to a non-veto binary and asserts install-wrappers SKIPs it
// (without --force) instead of either silently dropping it or
// clobbering it.
func TestInstallWrappers_ForeignWrapperWithoutForceIsSkip(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto v1"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	foreignBin := filepath.Join(tmp, "bouncer")
	require.NoError(t, os.WriteFile(foreignBin, []byte("bouncer v2"), 0o755))

	miseBin := filepath.Join(tmp, ".local", "share", "mise", "installs", "bun", "1.0.0", "bin")
	require.NoError(t, os.MkdirAll(miseBin, 0o755))
	foreignSym := filepath.Join(miseBin, "bun")
	require.NoError(t, os.Symlink(foreignBin, foreignSym))
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", "")
	// Keep discovery off the real /opt/homebrew/bin (see SystemBinDirsEnv);
	// the mise fixture below lives under the temp $HOME and is unaffected.
	t.Setenv(pmsurvey.SystemBinDirsEnv, "")

	cfg := config{CacheDir: cacheDir}
	opts := wrapperFlags{only: map[string]struct{}{"bun": {}}}

	closeCapture := captureStderr(t)
	t.Cleanup(func() { _ = closeCapture() })

	rc, _ := runInstallWrappersWith(zerolog.Nop(), cfg, opts, vetoBin, vetoID)
	out := closeCapture()
	t.Logf("stderr:\n%s", out)
	require.Equal(t, exitOK, rc)
	require.Contains(t, out, "foreign wrapper", "foreign wrapper without --force must emit a visible SKIP line")
	require.Contains(t, out, "--force")
}
