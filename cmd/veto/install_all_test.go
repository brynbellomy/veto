package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestParseInstallAllFlags(t *testing.T) {
	opts, err := parseInstallAllFlags([]string{"--lib", "/tmp/lib.dylib", "--shell-rc=auto", "--force", "--skip-interposer"})
	require.NoError(t, err)
	require.Equal(t, "/tmp/lib.dylib", opts.libPath)
	require.True(t, opts.autoRC)
	require.True(t, opts.force)
	require.True(t, opts.skipInterpos)

	_, err = parseInstallAllFlags([]string{"--bad"})
	require.Error(t, err)
}

// TestParseInstallAllFlags_SkipWrappers covers the new --skip-wrappers
// flag. The existing flag style uses bare and equals forms for other
// boolean-ish flags (--force is bare-only because it takes no value, and
// --shell-rc supports both forms); --skip-wrappers takes no value, so
// only the bare form is meaningful. An `=` form is rejected like any
// unknown argument because the switch doesn't strip the prefix — we
// assert that explicitly to lock the contract.
func TestParseInstallAllFlags_SkipWrappers(t *testing.T) {
	opts, err := parseInstallAllFlags([]string{"--skip-wrappers"})
	require.NoError(t, err)
	require.True(t, opts.skipWrappers, "--skip-wrappers must set opts.skipWrappers")

	// Default: skipWrappers is false.
	opts, err = parseInstallAllFlags(nil)
	require.NoError(t, err)
	require.False(t, opts.skipWrappers)

	// Compose with other flags.
	opts, err = parseInstallAllFlags([]string{"--skip-wrappers", "--force", "--skip-interposer"})
	require.NoError(t, err)
	require.True(t, opts.skipWrappers)
	require.True(t, opts.force)
	require.True(t, opts.skipInterpos)

	// `--skip-wrappers=true` is NOT supported (value-less flag) — must
	// surface as an unknown-arg error, not silently succeed.
	_, err = parseInstallAllFlags([]string{"--skip-wrappers=true"})
	require.Error(t, err)
}

// TestRunInstallAllSkipWrappers_OmitsStep asserts the wrappers step is
// dropped from the composed step list when --skip-wrappers is set, and
// present otherwise. We test the pure helper (buildInstallAllSteps) so
// no actual install side-effects fire.
func TestRunInstallAllSkipWrappers_OmitsStep(t *testing.T) {
	logger := zerolog.Nop()
	cfg := config{CacheDir: t.TempDir()}

	with := buildInstallAllSteps(installAllOpts{skipInterpos: true}, cfg, "", logger)
	requireHasStepNamed(t, with, "install real-binary wrappers", true)

	without := buildInstallAllSteps(installAllOpts{skipInterpos: true, skipWrappers: true}, cfg, "", logger)
	requireHasStepNamed(t, without, "install real-binary wrappers", false)

	// Sync/doctor still present — skipping wrappers does NOT short-circuit
	// the layers that come after it in the slice.
	requireHasStepNamed(t, without, "sync intel", true)
	requireHasStepNamed(t, without, "doctor", true)
}

func requireHasStepNamed(t *testing.T, steps []installAllStep, name string, want bool) {
	t.Helper()
	for _, s := range steps {
		if s.name == name {
			if !want {
				t.Fatalf("did not expect step %q in steps; full list: %v", name, stepNames(steps))
			}
			return
		}
	}
	if want {
		t.Fatalf("expected step %q in steps; full list: %v", name, stepNames(steps))
	}
}

func stepNames(steps []installAllStep) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.name)
	}
	return out
}

// TestExitCodeClassifier exhaustively covers classifyWrappersResult.
// One row per documented outcome: clean success, needs-root (skipped +
// non-root), root-still-skipped (skipped + root), genuine wrapper
// failure (regardless of root). Plus a defensive "rc != 0 with clean
// stats" row to lock the safety-net branch.
func TestExitCodeClassifier(t *testing.T) {
	cases := []struct {
		name string
		rc   int
		st   wrapperStats
		euid int
		want int
	}{
		{
			name: "clean success",
			rc:   exitOK,
			st:   wrapperStats{wrapped: 2},
			euid: 501,
			want: exitOK,
		},
		{
			name: "needs root: non-root user hit unwritable dir",
			rc:   exitOK,
			st:   wrapperStats{wrapped: 1, skippedUnwritable: 1},
			euid: 501,
			want: exitInstallAllNeedsRoot,
		},
		{
			name: "root still skipped: dir read-only even to root",
			rc:   exitOK,
			st:   wrapperStats{skippedUnwritable: 1},
			euid: 0,
			want: exitInstallAllWrappersFail,
		},
		{
			name: "genuine wrappers failure (non-root)",
			rc:   exitInternal,
			st:   wrapperStats{failed: 1},
			euid: 501,
			want: exitInstallAllWrappersFail,
		},
		{
			name: "genuine wrappers failure (root)",
			rc:   exitInternal,
			st:   wrapperStats{failed: 1},
			euid: 0,
			want: exitInstallAllWrappersFail,
		},
		{
			name: "failed dominates skippedUnwritable",
			rc:   exitInternal,
			st:   wrapperStats{failed: 1, skippedUnwritable: 1},
			euid: 501,
			want: exitInstallAllWrappersFail,
		},
		{
			name: "non-zero rc with clean stats falls through to wrappersFail",
			rc:   exitInternal,
			st:   wrapperStats{},
			euid: 501,
			want: exitInstallAllWrappersFail,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyWrappersResult(c.rc, c.st, c.euid)
			require.Equal(t, c.want, got)
		})
	}
}

func TestShellRCArgsDefaultsToAuto(t *testing.T) {
	opts := installAllOpts{autoRC: true}
	require.Equal(t, []string{"--shell-rc", "auto"}, shellRCArgs(opts))

	opts = installAllOpts{shellRC: "/tmp/.zshrc", autoRC: true}
	require.Equal(t, []string{"--shell-rc", "/tmp/.zshrc"}, shellRCArgs(opts))
}

func TestPinPathEnvMovesShimDirToFront(t *testing.T) {
	sep := string(os.PathListSeparator)
	got := pinPathEnv(strings.Join([]string{"/usr/bin", "/Users/x/.local/bin", "/bin"}, sep), "/Users/x/.local/bin")
	require.Equal(t, strings.Join([]string{"/Users/x/.local/bin", "/usr/bin", "/bin"}, sep), got)
}

func TestFindInterposerArtifactExplicit(t *testing.T) {
	dir := t.TempDir()
	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

	got, err := findInterposerArtifact(path)
	require.NoError(t, err)
	require.Equal(t, path, got)
}
