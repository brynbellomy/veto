package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/vmshim"
	"github.com/brynbellomy/veto/internal/vmshim/mise"
)

// vmLoopLayout is the on-disk shape of the 2026-09-15 incident: veto's
// Layer-2 shim first on PATH, a mise shim second, and (optionally) a
// plain real binary third — the one mise's own PATH fallback would have
// reached had veto's shim not been in the way.
type vmLoopLayout struct {
	shimDir  string // veto's shim dir; holds `go -> self`
	vmShims  string // mise's shims dir; holds `go -> mise`
	miseBin  string // the fake mise dispatcher
	fallback string // dir holding a real `go`
}

// plantVMLoopLayout writes the layout with a fake mise whose `which go`
// runs whichScript. It sets HOME and PATH for the test and returns the
// registry that recognizes the planted mise.
func plantVMLoopLayout(t *testing.T, whichScript string, withFallback bool) (vmLoopLayout, vmshim.Registry) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	l := vmLoopLayout{
		shimDir:  filepath.Join(home, ".local", "bin"),
		vmShims:  filepath.Join(home, "mise", "shims"),
		miseBin:  filepath.Join(home, "mise", "mise"),
		fallback: filepath.Join(home, "fallback"),
	}
	require.NoError(t, os.MkdirAll(l.shimDir, 0o755))
	require.NoError(t, os.MkdirAll(l.vmShims, 0o755))

	self, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, os.Symlink(self, filepath.Join(l.shimDir, "go")))

	require.NoError(t, os.WriteFile(l.miseBin, []byte("#!/bin/sh\n[ \"$1\" = which ] || exit 9\n"+whichScript), 0o755))
	require.NoError(t, os.Symlink(l.miseBin, filepath.Join(l.vmShims, "go")))

	path := l.shimDir + string(os.PathListSeparator) + l.vmShims
	if withFallback {
		require.NoError(t, os.MkdirAll(l.fallback, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(l.fallback, "go"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
		path += string(os.PathListSeparator) + l.fallback
	}
	t.Setenv("PATH", path)

	return l, vmshim.Registry{mise.NewWithOptions(mise.Options{ShimsDir: l.vmShims})}
}

const miseCannotResolveGo = "echo 'mise ERROR No executable found for configured tool: go' >&2\n" +
	"echo 'The installed version does not provide this executable with its current backend metadata.' >&2\n" +
	"echo 'Reinstall it with:' >&2\n" +
	"echo 'mise install --force go@1.25.1' >&2\n" +
	"exit 1\n"

// TestResolveRealBinary_SkipsVersionManagerShimThatCannotResolve is the
// regression guard for the exec loop: with mise unable to serve `go`
// from this directory, the walk must NOT return mise's shim (mise would
// bounce back to veto's shim) — it must continue to the next real `go`
// and report the skip with mise's remediation.
func TestResolveRealBinary_SkipsVersionManagerShimThatCannotResolve(t *testing.T) {
	l, reg := plantVMLoopLayout(t, miseCannotResolveGo, true)

	res, err := resolveRealBinary("go", func(string) bool { return false }, reg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(l.fallback, "go"), res.Path)
	require.Nil(t, res.Probed)
	require.Len(t, res.Skipped, 1)
	s := res.Skipped[0]
	require.Equal(t, "mise", s.Manager)
	require.Equal(t, filepath.Join(l.vmShims, "go"), s.Candidate)
	require.Contains(t, s.Reason, "mise cannot resolve go from this directory")
	require.Contains(t, s.Reason, "No executable found for configured tool: go")
	require.Contains(t, s.Reason, "loop back into veto")
	require.Equal(t, "mise install --force go@1.25.1", s.Hint)
}

// With no other `go` on PATH the resolver fails closed — "not found in
// PATH" — rather than exec'ing the shim that would loop. The skip is
// still reported so the failure explains itself.
func TestResolveRealBinary_UnresolvableShimAndNothingElseFailsClosed(t *testing.T) {
	_, reg := plantVMLoopLayout(t, miseCannotResolveGo, false)

	res, err := resolveRealBinary("go", func(string) bool { return false }, reg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in PATH")
	require.Empty(t, res.Path)
	require.Len(t, res.Skipped, 1)
}

// When mise CAN resolve the tool, the walk hands off to the shim exactly
// as before (not to mise's answer directly, so mise's env injection still
// applies) and records what mise reported.
func TestResolveRealBinary_ExecsShimWhenManagerResolves(t *testing.T) {
	l, reg := plantVMLoopLayout(t, "echo /toolchains/go-1.25.1/bin/go\n", true)

	res, err := resolveRealBinary("go", func(string) bool { return false }, reg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(l.vmShims, "go"), res.Path)
	require.Empty(t, res.Skipped)
	require.NotNil(t, res.Probed)
	require.Equal(t, "mise", res.Probed.Manager)
	require.Equal(t, "/toolchains/go-1.25.1/bin/go", res.Probed.RealPath)
}

// A probe that cannot run at all (dispatcher missing, timeout) is not the
// same as "unresolvable", but the fail-safe direction is identical: skip
// the shim. A wrong toolchain is visible; a loop is a hang.
func TestResolveRealBinary_ProbeFailureSkipsShim(t *testing.T) {
	l, _ := plantVMLoopLayout(t, "echo unused\n", true)
	reg := vmshim.Registry{mise.NewWithOptions(mise.Options{ShimsDir: l.vmShims, Dispatcher: filepath.Join(l.vmShims, "does-not-exist")})}

	res, err := resolveRealBinary("go", func(string) bool { return false }, reg)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(l.fallback, "go"), res.Path)
	require.Len(t, res.Skipped, 1)
	require.Contains(t, res.Skipped[0].Reason, "probe failed")
	require.Empty(t, res.Skipped[0].Hint)
}

// mise may resolve the tool to a Layer-4 wrap site (its install dir was
// wrapped by install-wrappers). That is fine when the wrap's anchor is
// healthy and registered; when the anchor is missing the shim would exec
// a wrapper that cannot unwrap, so the shim is skipped.
func TestResolveRealBinary_ManagerAnswerThatIsVetoNeedsUsableAnchor(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	t.Run("wrap site without anchor is skipped", func(t *testing.T) {
		l, reg := plantVMLoopLayout(t, "", true)
		wrapSite := filepath.Join(l.fallback, "wrapped", "go")
		require.NoError(t, os.MkdirAll(filepath.Dir(wrapSite), 0o755))
		require.NoError(t, os.Symlink(self, wrapSite))
		require.NoError(t, os.WriteFile(l.miseBin, []byte("#!/bin/sh\necho '"+wrapSite+"'\n"), 0o755))

		res, err := resolveRealBinary("go", func(string) bool { return false }, reg)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(l.fallback, "go"), res.Path)
		require.Len(t, res.Skipped, 1)
		require.Contains(t, res.Skipped[0].Reason, "real-binary anchor is missing")
	})

	t.Run("registered wrap site with healthy anchor is accepted", func(t *testing.T) {
		l, reg := plantVMLoopLayout(t, "", true)
		wrapSite := filepath.Join(l.fallback, "wrapped", "go")
		require.NoError(t, os.MkdirAll(filepath.Dir(wrapSite), 0o755))
		require.NoError(t, os.Symlink(self, wrapSite))
		require.NoError(t, os.WriteFile(wrapSite+wrapperSuffix, []byte("#!/bin/sh\nexit 0\n"), 0o755))
		require.NoError(t, os.WriteFile(l.miseBin, []byte("#!/bin/sh\necho '"+wrapSite+"'\n"), 0o755))

		res, err := resolveRealBinary("go", func(p string) bool { return p == wrapSite }, reg)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(l.vmShims, "go"), res.Path)
		require.Empty(t, res.Skipped)
		require.Equal(t, wrapSite, res.Probed.RealPath)
	})
}

// A PATH entry no manager claims is returned untouched — the probe must
// not change behavior for plain binaries.
func TestResolveRealBinary_PlainBinaryIsNotProbed(t *testing.T) {
	l, _ := plantVMLoopLayout(t, miseCannotResolveGo, true)
	t.Setenv("PATH", l.shimDir+string(os.PathListSeparator)+l.fallback)

	res, err := resolveRealBinary("go", func(string) bool { return false }, vmshim.Registry{mise.NewWithOptions(mise.Options{ShimsDir: l.vmShims})})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(l.fallback, "go"), res.Path)
	require.Nil(t, res.Probed)
	require.Empty(t, res.Skipped)
}
