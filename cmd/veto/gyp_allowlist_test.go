package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/scan"
)

func TestLoadGypAllowlistMissingFileIsEmpty(t *testing.T) {
	require.Empty(t, loadGypAllowlist(zerolog.Nop(), t.TempDir()))
	require.Empty(t, loadGypAllowlist(zerolog.Nop(), ""))
}

func TestLoadGypAllowlistParsesEntriesAndSkipsJunk(t *testing.T) {
	dir := t.TempDir()
	digest := strings.Repeat("ab", 32)
	content := "# comment line\n\n" +
		digest + "  # sharp src/binding.gyp (added 2026-06-10)\n" +
		"not-a-hash entry\n" +
		strings.ToUpper(digest) + "\n" // duplicate, different case
	require.NoError(t, os.WriteFile(gypAllowlistPath(dir), []byte(content), 0o644))

	allowed := loadGypAllowlist(zerolog.Nop(), dir)
	require.Len(t, allowed, 1)
	_, ok := allowed[digest]
	require.True(t, ok)
}

func TestFilterAllowedGypFindings(t *testing.T) {
	dir := t.TempDir()
	legit := filepath.Join(dir, "binding.gyp")
	require.NoError(t, os.WriteFile(legit, []byte("legit probe"), 0o644))
	digest, err := sha256File(legit)
	require.NoError(t, err)

	other := filepath.Join(dir, "other", "binding.gyp")
	require.NoError(t, os.MkdirAll(filepath.Dir(other), 0o755))
	require.NoError(t, os.WriteFile(other, []byte("different content"), 0o644))

	findings := []scan.Finding{
		{Path: legit},
		{Path: other},
		{Path: filepath.Join(dir, "missing", "binding.gyp")}, // unreadable → kept
	}
	allowed := map[string]struct{}{digest: {}}

	out := filterAllowedGypFindings(zerolog.Nop(), findings, allowed)
	require.Len(t, out, 2)
	require.Equal(t, other, out[0].Path)

	// Empty allowlist is a no-op passthrough.
	require.Equal(t, findings, filterAllowedGypFindings(zerolog.Nop(), findings, nil))
}

func TestRunGypAllowRoundTrip(t *testing.T) {
	cacheDir := t.TempDir()
	cfg := config{CacheDir: cacheDir}
	tree := t.TempDir()
	gyp := filepath.Join(tree, "binding.gyp")
	require.NoError(t, os.WriteFile(gyp, []byte("probe content"), 0o644))

	require.Equal(t, exitOK, runGypAllow(zerolog.Nop(), cfg, []string{gyp}))

	digest, err := sha256File(gyp)
	require.NoError(t, err)
	allowed := loadGypAllowlist(zerolog.Nop(), cacheDir)
	_, ok := allowed[digest]
	require.True(t, ok)

	// Idempotent: acknowledging again adds nothing.
	require.Equal(t, exitOK, runGypAllow(zerolog.Nop(), cfg, []string{gyp}))
	require.Len(t, loadGypAllowlist(zerolog.Nop(), cacheDir), 1)

	// Non-binding.gyp files are refused.
	stray := filepath.Join(tree, "package.json")
	require.NoError(t, os.WriteFile(stray, []byte("{}"), 0o644))
	require.Equal(t, exitUsage, runGypAllow(zerolog.Nop(), cfg, []string{stray}))

	// --list prints the stored entry.
	require.Equal(t, exitOK, runGypAllow(zerolog.Nop(), cfg, []string{"--list"}))
}
