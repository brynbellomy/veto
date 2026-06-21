package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUpsertManagedBlock_AppendsToExisting: a typical zshrc has existing
// content; our block goes at the end with a blank-line separator.
func TestUpsertManagedBlock_AppendsToExisting(t *testing.T) {
	src := "export PATH=/usr/bin\nalias ll=\"ls -la\"\n"
	block := preloadMarkerStart + "\nexport FOO=bar\n" + preloadMarkerEnd + "\n"
	out := upsertManagedBlock(src, block)
	require.True(t, strings.HasPrefix(out, src), "existing content must be preserved verbatim")
	require.Contains(t, out, "export FOO=bar")
	require.Contains(t, out, preloadMarkerStart)
	require.Contains(t, out, preloadMarkerEnd)
}

// TestUpsertManagedBlock_ReplacesExisting: a stale managed block (older
// install with a different lib path) is replaced in place.
func TestUpsertManagedBlock_ReplacesExisting(t *testing.T) {
	src := "alias ll=\"ls -la\"\n\n" +
		preloadMarkerStart + "\n" +
		`export DYLD_INSERT_LIBRARIES="/old/lib.dylib"` + "\n" +
		preloadMarkerEnd + "\n" +
		"export PATH=$PATH:/usr/local/bin\n"
	newBlock := preloadMarkerStart + "\n" +
		`export DYLD_INSERT_LIBRARIES="/new/lib.dylib"` + "\n" +
		preloadMarkerEnd + "\n"
	out := upsertManagedBlock(src, newBlock)
	require.Contains(t, out, "/new/lib.dylib")
	require.NotContains(t, out, "/old/lib.dylib")
	require.Contains(t, out, "alias ll=\"ls -la\"", "content before the block must remain")
	require.Contains(t, out, "export PATH=$PATH:/usr/local/bin", "content after the block must remain")
	require.Equal(t, 1, strings.Count(out, preloadMarkerStart), "must not duplicate the start marker")
}

// TestRemoveShellRCBlock_StripsManagedRegion exercises the full round
// trip — write a file with content + block, strip it, confirm the
// surrounding content survives.
func TestRemoveShellRCBlock_StripsManagedRegion(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	content := "# my rc\nexport EDITOR=vim\n\n" +
		preloadMarkerStart + "\n" +
		`export DYLD_INSERT_LIBRARIES="/lib.dylib"` + "\n" +
		preloadMarkerEnd + "\n" +
		"alias g=\"git\"\n"
	require.NoError(t, os.WriteFile(rc, []byte(content), 0o644))

	removed, err := removeShellRCBlock(rc)
	require.NoError(t, err)
	require.True(t, removed)

	out, err := os.ReadFile(rc)
	require.NoError(t, err)
	s := string(out)
	require.NotContains(t, s, preloadMarkerStart)
	require.NotContains(t, s, preloadMarkerEnd)
	require.NotContains(t, s, "/lib.dylib")
	require.Contains(t, s, "export EDITOR=vim")
	require.Contains(t, s, "alias g=\"git\"")
}

// TestRemoveShellRCBlock_NoMatchIsNoOp: removing from a file with no
// managed block returns (false, nil) and does not write the file.
func TestRemoveShellRCBlock_NoMatchIsNoOp(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	require.NoError(t, os.WriteFile(rc, []byte("export EDITOR=vim\n"), 0o644))

	stat1, err := os.Stat(rc)
	require.NoError(t, err)

	removed, err := removeShellRCBlock(rc)
	require.NoError(t, err)
	require.False(t, removed)

	stat2, err := os.Stat(rc)
	require.NoError(t, err)
	require.Equal(t, stat1.ModTime(), stat2.ModTime(), "file mtime must not change when no block was matched")
}

// TestRenderPreloadEnvBlock_HasBothExports: the rendered block must
// export both VETO_PATH and the platform-appropriate preload var.
func TestRenderPreloadEnvBlock_HasBothExports(t *testing.T) {
	block := renderPreloadEnvBlock("/path/to/lib.dylib", "/path/to/veto")
	require.Contains(t, block, preloadMarkerStart)
	require.Contains(t, block, preloadMarkerEnd)
	require.Contains(t, block, "/path/to/veto")
	require.Contains(t, block, "/path/to/lib.dylib")
	// macOS-specific in this test env (CI may differ); test both keys
	// to keep the assertion portable.
	hasMacKey := strings.Contains(block, "DYLD_INSERT_LIBRARIES")
	hasLinuxKey := strings.Contains(block, "LD_PRELOAD")
	require.True(t, hasMacKey || hasLinuxKey, "must export a preload env var")
}

// TestParsePreloadFlags_AcceptsLongAndEqualsForms: the flag parser needs
// to accept both `--lib path` and `--lib=path` because users mix them.
func TestParsePreloadFlags_AcceptsLongAndEqualsForms(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		want   preloadOpts
		errMsg string
	}{
		{"--lib space form", []string{"--lib", "/foo.dylib"}, preloadOpts{libPath: "/foo.dylib"}, ""},
		{"--lib equals form", []string{"--lib=/foo.dylib"}, preloadOpts{libPath: "/foo.dylib"}, ""},
		{"--shell-rc=auto", []string{"--shell-rc=auto"}, preloadOpts{autoRC: true}, ""},
		{"--shell-rc auto", []string{"--shell-rc", "auto"}, preloadOpts{autoRC: true}, ""},
		{"--shell-rc explicit", []string{"--shell-rc=/x/.zshrc"}, preloadOpts{shellRC: "/x/.zshrc"}, ""},
		{"--print", []string{"--print"}, preloadOpts{print: true}, ""},
		{"unknown flag", []string{"--whatever"}, preloadOpts{}, "unknown argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parsePreloadFlags(tc.args)
			if tc.errMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, opts)
		})
	}
}

// TestPreloadShellRCTargets_ExplicitPathReturnsSingle: an explicit
// --shell-rc PATH bypasses the auto-fan-out and only that one file gets
// touched. Mirrors the contract install-shell already honors.
func TestPreloadShellRCTargets_ExplicitPathReturnsSingle(t *testing.T) {
	paths, err := preloadShellRCTargets(preloadOpts{shellRC: "/x/.myrc"})
	require.NoError(t, err)
	require.Equal(t, []string{"/x/.myrc"}, paths)
}

// TestPreloadShellRCTargets_NoFlagsReturnsEmpty: with neither
// --shell-rc nor --shell-rc auto, the caller is responsible for
// printing the block — we return zero paths so no write happens.
func TestPreloadShellRCTargets_NoFlagsReturnsEmpty(t *testing.T) {
	paths, err := preloadShellRCTargets(preloadOpts{})
	require.NoError(t, err)
	require.Empty(t, paths)
}

// TestPreloadShellRCTargets_AutoFansOutLikeShellIntegration: this is
// the regression guard. install-all calls install-preload with
// --shell-rc auto; the resulting target set MUST match the shell
// integration target set so a zsh+bash user gets the preload env vars
// in every rc that install-shell already wrote to. Without parity,
// `bash -c 'go build'` silently loses Layer 3.
func TestPreloadShellRCTargets_AutoFansOutLikeShellIntegration(t *testing.T) {
	want, err := defaultShellIntegrationTargets()
	if err != nil {
		t.Skipf("cannot determine default shell integration targets in this env: %v", err)
	}
	got, err := preloadShellRCTargets(preloadOpts{autoRC: true})
	require.NoError(t, err)
	require.Len(t, got, len(want), "preload fan-out must match shell-integration fan-out")
	for i, target := range want {
		require.Equal(t, target.path, got[i], "rc path %d must match shell-integration order", i)
	}
}
