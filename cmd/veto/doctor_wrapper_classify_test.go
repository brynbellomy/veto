package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

// findResult locates the checkResult for the given label substring in
// the doctor's output. Test helper only.
func findResult(t *testing.T, results []checkResult, labelSub, detailSub string) checkResult {
	t.Helper()
	for _, r := range results {
		if strings.Contains(r.label, labelSub) && strings.Contains(r.detail, detailSub) {
			return r
		}
	}
	var summary []string
	for _, r := range results {
		summary = append(summary, r.label+": "+r.detail)
	}
	t.Fatalf("no result matching label=%q detail=%q; got %s", labelSub, detailSub, strings.Join(summary, " | "))
	return checkResult{}
}

// TestCheckWrappers_BrokenSymlinkAtSurveyedPath verifies that a broken
// symlink found during the Phase-2 host survey produces a FAIL line
// distinct from the generic "NOT wrapped" WARN. The reproducer is the
// "bouncer leftover" scenario: a symlink at a known PM path whose
// target binary was removed when a previous wrapper tool was
// uninstalled.
//
// Uses checkWrappersWith with a tempdir-planted veto so the
// classification is deterministic regardless of where `go test` is
// running from.
func TestCheckWrappers_BrokenSymlinkAtSurveyedPath(t *testing.T) {
	if hostHasAbsolutePathPM(t) {
		t.Skip("host has PM installs in /opt/homebrew/bin or /usr/local/bin; can't isolate survey")
	}
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	// Plant a fake "veto" binary so VetoIdentity can build.
	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	// Plant a broken symlink at a $PATH dir for "cargo" (the bouncer case).
	pathDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(pathDir, 0o755))
	brokenSym := filepath.Join(pathDir, "cargo")
	require.NoError(t, os.Symlink(filepath.Join(tmp, "vanished-bouncer"), brokenSym))
	t.Setenv("PATH", pathDir)
	t.Setenv("HOME", tmp) // ensure mise/asdf globs hit empty dirs

	cfg := config{CacheDir: cacheDir}
	results := checkWrappersWith(cfg, vetoID, nil)

	r := findResult(t, results, "wrapper:cargo", "broken symlink")
	require.Equal(t, statusFail, r.status, "broken symlink at a surveyed path must FAIL")
	require.Contains(t, r.detail, brokenSym)
}

// TestCheckWrappers_ForeignWrapperAtSurveyedPath verifies that a
// symlink to a non-veto binary at a known PM path is classified as a
// foreign wrapper (FAIL with a specific diagnosis), not as a generic
// "NOT wrapped" WARN.
func TestCheckWrappers_ForeignWrapperAtSurveyedPath(t *testing.T) {
	if hostHasAbsolutePathPM(t) {
		t.Skip("host has PM installs in /opt/homebrew/bin or /usr/local/bin; can't isolate survey")
	}
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto v1"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	// A foreign wrapper binary with content distinct from veto.
	foreignBin := filepath.Join(tmp, "bouncer")
	require.NoError(t, os.WriteFile(foreignBin, []byte("bouncer v2"), 0o755))

	pathDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(pathDir, 0o755))
	foreignSym := filepath.Join(pathDir, "bun")
	require.NoError(t, os.Symlink(foreignBin, foreignSym))
	t.Setenv("PATH", pathDir)
	t.Setenv("HOME", tmp)

	cfg := config{CacheDir: cacheDir}
	results := checkWrappersWith(cfg, vetoID, nil)

	r := findResult(t, results, "wrapper:bun", "foreign wrapper")
	require.Equal(t, statusFail, r.status)
	require.Contains(t, r.detail, foreignSym)
	// Foreign target path may resolve through /var → /private/var on macOS.
	// We accept either the planted path or its resolved form.
	resolvedForeign, err := filepath.EvalSymlinks(foreignBin)
	require.NoError(t, err)
	containsTarget := strings.Contains(r.detail, foreignBin) || strings.Contains(r.detail, resolvedForeign)
	require.True(t, containsTarget, "detail %q should mention foreign target %q (or its resolved form %q)", r.detail, foreignBin, resolvedForeign)
}
