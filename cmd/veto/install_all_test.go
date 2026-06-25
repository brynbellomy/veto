package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
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
		{
			// SIP-protected /usr/bin/pip3 surfaces as skippedReadOnlyFS.
			// Sudo cannot help, so the result must be success regardless
			// of euid — install-all must NOT abort over it.
			name: "read-only FS (SIP) skip is success for non-root",
			rc:   exitOK,
			st:   wrapperStats{wrapped: 3, skippedReadOnlyFS: 1},
			euid: 501,
			want: exitOK,
		},
		{
			name: "read-only FS (SIP) skip is success for root too",
			rc:   exitOK,
			st:   wrapperStats{skippedReadOnlyFS: 2},
			euid: 0,
			want: exitOK,
		},
		{
			// Mixed case: unwritable still dominates. If there are paths
			// the user could fix under sudo, we still need to tell them.
			name: "unwritable dominates read-only FS (non-root)",
			rc:   exitOK,
			st:   wrapperStats{skippedUnwritable: 1, skippedReadOnlyFS: 1},
			euid: 501,
			want: exitInstallAllNeedsRoot,
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

// TestInstallAllConvergence_FromBrokenState is the veto-76f epic
// acceptance test. It simulates the exact disaster state that broke
// bryn's machine during the veto-dzk recovery — Layer 2 shims gone, a
// stale .veto-original sibling in the shim dir, and wrappers.json
// containing one legit Layer 4 entry plus one bogus shim-dir entry —
// then drives install-shims + install-wrappers (the layers that
// install-all invokes) in sequence and asserts the convergence passes
// reconcile everything to a working state.
//
// The contract this test enforces: starting from any drifted state,
// `make install && veto install-all` produces a fully working
// installation with no FAIL rows, no stale entries, and the
// genuinely-legit state untouched. No --force, no manual cleanup
// commands.
func TestInstallAllConvergence_FromBrokenState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Empty PATH so install-wrappers' discovery doesn't pick up the
	// host's real $PATH dirs — the test must stay hermetic.
	t.Setenv("PATH", "")

	shimDir := filepath.Join(home, ".local", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	cacheDir := filepath.Join(home, ".cache", "veto")
	cfg := config{CacheDir: cacheDir}

	// --- State setup: simulate the post-disaster shape ---
	//
	// (a) Plant a stale `.veto-original` sibling in the shim dir.
	// This is the on-disk shape that broke exec resolution in the
	// veto-dzk postmortem.
	staleSibling := filepath.Join(shimDir, "python3.veto-original")
	require.NoError(t, os.Symlink("/usr/local/bin/veto-fake", staleSibling))

	// (b) Plant a wrappers.json with one legit entry + one bogus
	// shim-dir entry. The bogus entry is the failure mode that turned
	// uninstall-wrappers into a destroyer of Layer 2 shims.
	legitFixture := filepath.Join(home, "fake-pm-install", "npm")
	require.NoError(t, os.MkdirAll(filepath.Dir(legitFixture), 0o755))
	require.NoError(t, os.WriteFile(legitFixture, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(legitFixture+".veto-original", []byte("real-npm"), 0o755))

	planted := wrapperState{Wrappers: []wrapperEntry{
		{
			Path:         legitFixture,
			OriginalPath: legitFixture + ".veto-original",
			PM:           "npm",
			Source:       "user",
		},
		{
			Path:         filepath.Join(shimDir, "python3"),
			OriginalPath: filepath.Join(shimDir, "python3.veto-original"),
			PM:           "python3",
			Source:       "path",
		},
	}}
	require.NoError(t, saveWrapperState(cfg, planted))

	// --- Run the convergence passes install-all would invoke ---
	logger := zerolog.Nop()

	rc := runInstallShims(logger, cfg, []string{"--dir", shimDir})
	require.Equal(t, exitOK, rc, "install-shims must succeed on the broken-state fixture")

	// install-wrappers, given an empty PATH + no homebrew on the test
	// host's known dirs, discovers nothing. But its convergence pass
	// still prunes stale wrappers.json entries — that's what we care
	// about here. Use the *With variant with an explicitly-built
	// identity so we don't need a real veto binary on disk; we also
	// pass an empty wrapperFlags so discovery walks only WellKnownBinDirs.
	// The bogus shim-dir entry was already removed by install-shims;
	// install-wrappers verifies the remaining state survives.
	veto := filepath.Join(home, "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("veto"), 0o755))
	id, err := pmsurvey.VetoIdentityFor(veto)
	require.NoError(t, err)
	rc2, _ := runInstallWrappersWith(logger, cfg, wrapperFlags{}, veto, id)
	require.Equal(t, exitOK, rc2, "install-wrappers must succeed on the broken-state fixture")

	// --- Post-state assertions ---

	// 1. Shims recreated. Spot-check the static set — install-shims
	// creates a symlink per name from pmlist.Shimmed.
	for _, name := range []string{"npm", "python3", "pip"} {
		link := filepath.Join(shimDir, name)
		info, err := os.Lstat(link)
		require.NoError(t, err, "shim %s missing after install-shims", name)
		require.NotZero(t, info.Mode()&os.ModeSymlink, "%s must be a symlink", name)
	}

	// 2. Stale `.veto-original` sibling gone.
	_, err = os.Lstat(staleSibling)
	require.True(t, os.IsNotExist(err), "stale sibling must be scrubbed by install-shims; got err=%v", err)

	// 3. Bogus shim-dir wrappers.json entry gone; legit entry survives.
	got, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, got.Wrappers, 1, "expected only the legit entry to remain; got %d", len(got.Wrappers))
	require.Equal(t, legitFixture, got.Wrappers[0].Path)
	require.Equal(t, "npm", got.Wrappers[0].PM)

	// 4. Sanity: no wrappers.json entry has a path inside the shim dir.
	for _, w := range got.Wrappers {
		require.False(t, strings.HasPrefix(filepath.Clean(w.Path), shimDir+string(filepath.Separator)),
			"wrappers.json should not contain shim-dir entries after install-all; found %s", w.Path)
	}
}
