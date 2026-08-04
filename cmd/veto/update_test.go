package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseUpdateFlags_Defaults(t *testing.T) {
	opts, err := parseUpdateFlags(nil)
	require.NoError(t, err)
	require.Equal(t, defaultUpdateRef, opts.ref)
	require.Equal(t, defaultUpdateRepo, opts.repo)
	require.Equal(t, defaultUpdateModule, opts.module)
	require.False(t, opts.check)
	require.False(t, opts.full)
	require.False(t, opts.binaryOnly)
}

func TestParseUpdateFlags_Booleans(t *testing.T) {
	opts, err := parseUpdateFlags([]string{"--check"})
	require.NoError(t, err)
	require.True(t, opts.check)

	opts, err = parseUpdateFlags([]string{"--full"})
	require.NoError(t, err)
	require.True(t, opts.full)

	opts, err = parseUpdateFlags([]string{"--binary-only"})
	require.NoError(t, err)
	require.True(t, opts.binaryOnly)
}

func TestParseUpdateFlags_ValuedForms(t *testing.T) {
	// Space form.
	opts, err := parseUpdateFlags([]string{"--ref", "v1.2.3", "--repo", "https://example.com/x", "--module", "example.com/x/cmd/veto"})
	require.NoError(t, err)
	require.Equal(t, "v1.2.3", opts.ref)
	require.Equal(t, "https://example.com/x", opts.repo)
	require.Equal(t, "example.com/x/cmd/veto", opts.module)

	// Equals form.
	opts, err = parseUpdateFlags([]string{"--ref=abc123def4567", "--repo=https://ex.com/y", "--module=ex.com/y"})
	require.NoError(t, err)
	require.Equal(t, "abc123def4567", opts.ref)
	require.Equal(t, "https://ex.com/y", opts.repo)
	require.Equal(t, "ex.com/y", opts.module)
}

func TestParseUpdateFlags_Errors(t *testing.T) {
	_, err := parseUpdateFlags([]string{"--ref"})
	require.Error(t, err)

	_, err = parseUpdateFlags([]string{"--repo"})
	require.Error(t, err)

	_, err = parseUpdateFlags([]string{"--module"})
	require.Error(t, err)

	_, err = parseUpdateFlags([]string{"--ref="})
	require.Error(t, err, "empty ref must be rejected")

	_, err = parseUpdateFlags([]string{"--full", "--binary-only"})
	require.Error(t, err, "--full and --binary-only are mutually exclusive")

	_, err = parseUpdateFlags([]string{"--nope"})
	require.Error(t, err)
}

func TestInstallSpec(t *testing.T) {
	require.Equal(t,
		"github.com/brynbellomy/veto/cmd/veto@main",
		installSpec(defaultUpdateModule, "main"))
	require.Equal(t, "m@v1.0.0", installSpec("m", "v1.0.0"))
}

func TestLooksHex(t *testing.T) {
	require.True(t, looksHex("2b28d87"))      // 7-char short sha
	require.True(t, looksHex("2b28d87abcde")) // 12-char pseudo-version tail
	require.True(t, looksHex("2B28D87"))      // uppercase
	require.False(t, looksHex("2b28d8"))      // too short (<7)
	require.False(t, looksHex(""))            // empty
	require.False(t, looksHex("mainbranch"))  // non-hex letters
	require.False(t, looksHex("2b28d8g"))     // 'g' not hex
}

func TestExtractCommit(t *testing.T) {
	require.Equal(t, "2b28d87", extractCommit("2b28d87"))
	require.Equal(t, "2b28d87", extractCommit("2b28d87-dirty"))
	require.Equal(t, "2b28d87abcde", extractCommit("v0.0.0-20260608131203-2b28d87abcde"))
	require.Equal(t, "", extractCommit("dev"))
	require.Equal(t, "", extractCommit(""))
	require.Equal(t, "", extractCommit("v1.2.3")) // clean tag, no sha
}

func TestCommitsMatch(t *testing.T) {
	// short sha is a prefix of the full sha → match.
	require.True(t, commitsMatch("2b28d87", "2b28d87abcdef0123456789"))
	// full and short swapped → still match.
	require.True(t, commitsMatch("2b28d87abcdef0123456789", "2b28d87"))
	// pseudo-version tail (12) is a prefix of full sha.
	require.True(t, commitsMatch("2b28d87abcde", "2b28d87abcdef0123456789"))
	// case-insensitive.
	require.True(t, commitsMatch("2B28D87", "2b28d87abcdef"))
	// different commits.
	require.False(t, commitsMatch("2b28d87", "deadbeef1234567"))
	// empties never match.
	require.False(t, commitsMatch("", "2b28d87abcde"))
	require.False(t, commitsMatch("2b28d87", ""))
}

func TestShortSha(t *testing.T) {
	require.Equal(t, "2b28d87", shortSha("2b28d87abcdef0123456789"))
	require.Equal(t, "2b28d87", shortSha("2b28d87")) // already short
	require.Equal(t, "main", shortSha("main"))       // non-sha passes through
}
