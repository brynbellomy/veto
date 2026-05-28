package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunVersion_LdflagsSet(t *testing.T) {
	// Save + restore package vars so other tests aren't affected.
	origV, origC, origD := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = origV, origC, origD })

	version = "v1.2.3"
	commit = "abc1234"
	buildDate = "2026-05-28T12:34:56Z"

	var buf bytes.Buffer
	rc := runVersion(&buf)
	require.Equal(t, exitOK, rc)

	out := buf.String()
	require.Contains(t, out, "veto v1.2.3")
	require.Contains(t, out, "commit abc1234")
	require.Contains(t, out, "built 2026-05-28T12:34:56Z")
	require.Contains(t, out, runtime.Version())
	require.Contains(t, out, runtime.GOOS+"/"+runtime.GOARCH)
	require.True(t, strings.HasSuffix(out, "\n"))
}

func TestRunVersion_DevFallback(t *testing.T) {
	origV, origC, origD := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = origV, origC, origD })
	version, commit, buildDate = "", "", ""

	var buf bytes.Buffer
	rc := runVersion(&buf)
	require.Equal(t, exitOK, rc)

	out := buf.String()
	// Either we got a sensible dev marker or — when running under `go test`
	// with vcs info available — we got the real commit short-sha.
	require.Contains(t, out, "veto ") // prefix line
	require.True(t,
		strings.Contains(out, "dev") || strings.Contains(out, "(devel)") ||
			strings.Contains(out, "commit "))
}

func TestResolveVersionInfo_DefaultsToUntagged(t *testing.T) {
	origV, origC, origD := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = origV, origC, origD })
	version, commit, buildDate = "v0.1.0", "", ""

	v, c, d := resolveVersionInfo()
	require.Equal(t, "v0.1.0", v)
	// In a worktree the BuildInfo may or may not fill commit/date — accept either.
	require.NotEmpty(t, c)
	require.NotEmpty(t, d)
}
