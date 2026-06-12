// End-to-end test for the native interposer.
//
// The flow:
//
//  1. Build the interposer .dylib/.so (skip the test if `make interposer`
//     hasn't been run AND we can't run it from here).
//  2. Build a tiny "spawner" helper that calls syscall.Exec(target, args)
//     — the spawner's posix_spawn / execve calls are what the interposer
//     hooks.
//  3. Drop a fake veto into a temp dir. It just dumps argv to a log
//     file and exits.
//  4. Drop a fake `npm` next to it. The interposer should see "the
//     program being exec'd is named npm with verb=install" and route the
//     call through fake-veto instead of executing fake-npm.
//  5. Run the spawner with DYLD_INSERT_LIBRARIES (macOS) / LD_PRELOAD
//     (Linux) pointing at the interposer, VETO_PATH pointing at the
//     fake veto.
//  6. Assert the fake veto received argv == [veto, npm, install, foo].
//
// This catches the failure modes that unit tests cannot: argv-allocation
// bugs, NULL termination off-by-ones, dyld linkage issues, and the
// "interposer loaded but doesn't actually intercept" class of bugs.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterposerEndToEnd_RewritesNpmInstall(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")

	// Fake veto: writes argv (one arg per line) to argLog.
	fakeVeto := filepath.Join(dir, "veto")
	vetoScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeVeto, []byte(vetoScript), 0o755))

	// Fake npm: should NEVER run; sentinel exit code so a false-negative
	// (interposer fails to intercept) produces a clearly distinct failure.
	fakeNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(fakeNpm, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	// Build the spawner helper inside the temp dir so we don't pollute
	// the repo. Go run would work too but `go build` keeps the binary
	// around for debugging if the test fails.
	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	build := exec.Command("go", "build", "-o", spawnerBin, spawnerSrc)
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "build interpose_spawner helper")

	// Spawn the helper, asking it to exec fakeNpm with install+foo.
	cmd := exec.Command(spawnerBin, fakeNpm, "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoError(t, err, "spawner exit error; stderr=%s", stderr.String())

	// If the interposer didn't fire, fakeNpm would have run and exited 77.
	// We're here, so something exec'd successfully (we expect fakeVeto).
	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeVeto did not write argv.log — interposer may not have rewritten")
	lines := splitLines(string(data))
	// fakeVeto's "$@" excludes argv[0] ("veto"). The interposer
	// rewrites to [veto, npm, install, foo]; the script sees npm,
	// install, foo.
	require.Equal(t, []string{"npm", "install", "foo"}, lines)
}

func TestInterposerEndToEnd_PassesThroughNonPM(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	// Marker file the target writes to confirm it actually ran.
	marker := filepath.Join(dir, "ran")
	target := filepath.Join(dir, "myprog")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(target, []byte(script), 0o755))

	// fake veto that would log if mistakenly invoked.
	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, target)
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "target program did not run — interposer rewrote a non-PM call (false positive)")
}

// TestInterposerEndToEnd_RewritesPythonDashMPipInstall confirms the
// canonical install form `python -m pip install …` — which would
// otherwise skip every veto layer except this one — gets rewritten
// to a veto-gated invocation. The expected rewritten argv drops
// `python` and `-m` from the front, replacing them with [veto, pip],
// so the existing per-PM gate logic in main.go handles the rest.
// VETO_PYTHON_M_ORIGINAL gets set on the child so the allow-path
// exec rebuilds the `python -m pip` invocation rather than exec'ing
// pip directly.
func TestInterposerEndToEnd_RewritesPythonDashMPipInstall(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")
	envLog := filepath.Join(dir, "env.log")

	// Fake veto: log argv (one arg per line) AND the threading env var
	// so we can assert both the rewrite shape and the env-channel hint.
	fakeVeto := filepath.Join(dir, "veto")
	vetoScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"printf '%s\\n' \"${VETO_PYTHON_M_ORIGINAL:-<unset>}\" > " + envLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeVeto, []byte(vetoScript), 0o755))

	// Fake python: must NEVER run on this path; sentinel exit code so
	// a false-negative (interposer fails to intercept) produces a
	// clearly distinct failure.
	fakePython := filepath.Join(dir, "python3")
	require.NoError(t, os.WriteFile(fakePython, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	build := exec.Command("go", "build", "-o", spawnerBin, spawnerSrc)
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "build interpose_spawner helper")

	cmd := exec.Command(spawnerBin, fakePython, "-m", "pip", "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "spawner exit error; stderr=%s", stderr.String())

	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeVeto did not write argv.log — interposer may not have rewritten")
	lines := splitLines(string(data))
	// Interposer rewrites to [veto, pip, install, foo] — python AND -m
	// drop out; the gate sees `pip install foo`.
	require.Equal(t, []string{"pip", "install", "foo"}, lines)

	envData, err := os.ReadFile(envLog)
	require.NoError(t, err)
	require.Equal(t, "python3", strings.TrimSpace(string(envData)),
		"VETO_PYTHON_M_ORIGINAL must be propagated so the allow-path exec rebuilds the python -m form")
}

// TestInterposerEndToEnd_RewritesPythonVersionedDashMPipInstall is the
// uv-venv-bypass regression: a venv that exec's `python3.12 -m pip
// install foo` (the canonical uv install form inside a 3.12 venv)
// must hit the interposer's versioned-python pattern and route
// through veto. Without the matches_python_versioned() check in is_risky,
// PM_NAMES alone would not classify `python3.12` as a covered PM and
// the call would silently skip Layer 3.
func TestInterposerEndToEnd_RewritesPythonVersionedDashMPipInstall(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")
	envLog := filepath.Join(dir, "env.log")

	fakeVeto := filepath.Join(dir, "veto")
	vetoScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"printf '%s\\n' \"${VETO_PYTHON_M_ORIGINAL:-<unset>}\" > " + envLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeVeto, []byte(vetoScript), 0o755))

	// Fake python3.12 — the versioned alias an uv venv would exec.
	fakePython := filepath.Join(dir, "python3.12")
	require.NoError(t, os.WriteFile(fakePython, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakePython, "-m", "pip", "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "spawner exit error; stderr=%s", stderr.String())

	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeVeto did not write argv.log — interposer missed python3.12 -m pip install")
	require.Equal(t, []string{"pip", "install", "foo"}, splitLines(string(data)))

	envData, err := os.ReadFile(envLog)
	require.NoError(t, err)
	require.Equal(t, "python3.12", strings.TrimSpace(string(envData)),
		"VETO_PYTHON_M_ORIGINAL must carry the versioned basename so the allow-path exec rebuilds python3.12 -m pip")
}

// TestInterposerEndToEnd_PassesThroughPythonVersionedScript ensures
// the matches_python_versioned() check doesn't accidentally rewrite
// bare `python3.12 script.py` — the fast-path guarantee from the
// canonical python branch must extend to every versioned alias.
func TestInterposerEndToEnd_PassesThroughPythonVersionedScript(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	fakePython := filepath.Join(dir, "python3.12")
	require.NoError(t, os.WriteFile(fakePython, []byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"), 0o755))

	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakePython, "script.py")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err,
		"fake python3.12 did not run — `python3.12 script.py` was incorrectly rewritten")
}

// TestInterposerEndToEnd_PassesThroughPython3Config proves the
// versioned-python regex is strict enough to reject adjacent shapes
// like python3-config. Without strict bounds, a benign developer tool
// could get rewritten and break configure / pkg-config flows.
func TestInterposerEndToEnd_PassesThroughPython3Config(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	target := filepath.Join(dir, "python3-config")
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"), 0o755))

	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, target, "--cflags")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err,
		"python3-config was incorrectly rewritten by the interposer — versioned-python regex is too loose")
}

// TestInterposerEndToEnd_PassesThroughPythonScript covers the
// fast-path: a plain `python script.py` invocation MUST exec the real
// interpreter, not get rewritten. Without this guarantee veto would
// inject itself into every script run — an unacceptable hot path.
func TestInterposerEndToEnd_PassesThroughPythonScript(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	fakePython := filepath.Join(dir, "python")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(fakePython, []byte(script), 0o755))

	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakePython, "script.py")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "fake python did not run — `python script.py` was incorrectly rewritten")
}

// TestInterposerEndToEnd_PassesThroughPythonMHttpServer covers the
// other fast-path: `python -m http.server` (or any non-PM `-m` target)
// MUST pass through. The interposer must distinguish gated `-m`
// modules (pip/uv/pipx/poetry/pdm) from benign ones.
func TestInterposerEndToEnd_PassesThroughPythonMHttpServer(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	fakePython := filepath.Join(dir, "python3")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(fakePython, []byte(script), 0o755))

	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakePython, "-m", "http.server", "8000")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "fake python did not run — `python -m http.server` was incorrectly rewritten")
}

// TestInterposerEndToEnd_BypassEnvIsIgnored proves the legacy
// VETO_BYPASS escape hatch has been removed: a child that explicitly
// sets VETO_BYPASS=1 (the historical "disable Layer 3" value) MUST
// still be intercepted. The env is dead; only the `veto <pm> ...`
// argv form is honored at veto's own startup.
func TestInterposerEndToEnd_BypassEnvIsIgnored(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")

	fakeVeto := filepath.Join(dir, "veto")
	vetoScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeVeto, []byte(vetoScript), 0o755))

	fakeNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(fakeNpm, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	build := exec.Command("go", "build", "-o", spawnerBin, spawnerSrc)
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "build interpose_spawner helper")

	cmd := exec.Command(spawnerBin, fakeNpm, "install", "foo")
	cmd.Env = append(withPreloadEnv(libPath, fakeVeto), "VETO_BYPASS=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "spawner exit error; stderr=%s", stderr.String())

	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeVeto did not write argv.log — VETO_BYPASS=1 wrongly disabled Layer 3; fake npm ran (sentinel exit 77)")
	lines := splitLines(string(data))
	require.Equal(t, []string{"npm", "install", "foo"}, lines)
}

func TestInterposerEndToEnd_AllowsNpmRunDev(t *testing.T) {
	// `npm run dev` is a PM invocation with a NON-dangerous verb; the
	// interposer must let it through unchanged.
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	fakeNpm := filepath.Join(dir, "npm")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(fakeNpm, []byte(script), 0o755))

	fakeVeto := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(fakeVeto, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakeNpm, "run", "dev")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "fake npm did not run — `npm run dev` was incorrectly rewritten")
}

// TestInterposerEndToEnd_RewritesExeclNpmInstall covers H7: the variadic
// execl() call site. Without the new shadow, glibc routes execl through
// an internal __execve symbol that LD_PRELOAD/dlsym can't reach, and the
// macOS interpose surface only swaps direct execve/execv/execvp call
// sites — execl() goes through none of those when libc dispatches it
// internally. The fix adds explicit shadows that marshal the va_list
// and delegate to our existing exec wrappers.
//
// We exercise the path with a small C spawner that calls execl directly,
// then assert the rewrite went through veto exactly like the
// syscall.Exec test above.
func TestInterposerEndToEnd_RewritesExeclNpmInstall(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")

	fakeVeto := filepath.Join(dir, "veto")
	vetoScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeVeto, []byte(vetoScript), 0o755))

	fakeNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(fakeNpm, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	// Build the C spawner via the same compiler that built the
	// interposer. cc is required for `make interposer` to have produced
	// libPath in the first place, so it's safe to assume here.
	spawnerSrc := filepath.Join("testdata", "interpose_execl_spawner", "main.c")
	spawnerBin := filepath.Join(dir, "execl_spawner")
	build := exec.Command("cc", "-O0", "-Wall", "-o", spawnerBin, spawnerSrc)
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "build interpose_execl_spawner helper")

	cmd := exec.Command(spawnerBin, fakeNpm, "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeVeto)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "spawner exit error; stderr=%s", stderr.String())

	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeVeto did not write argv.log — execl shadow may not have rewritten")
	lines := splitLines(string(data))
	require.Equal(t, []string{"npm", "install", "foo"}, lines)
}

// interposerLibPath returns the absolute path to the built interposer
// artifact, or "" if it doesn't exist. We look both in the repo root
// (where `make interposer` puts it) and in the testdata dir, so the test
// can be wired up either way.
func interposerLibPath(t *testing.T) string {
	t.Helper()
	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}
	// Tests run with cwd = the package dir (cmd/veto). The library
	// lives in the repo root, two levels up.
	candidates := []string{
		filepath.Join("..", "..", name),
		filepath.Join(name),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}

// withPreloadEnv returns os.Environ() augmented with the preload env
// vars. Preserves the current PATH so the Go toolchain (for the build
// step above) still resolves correctly.
func withPreloadEnv(libPath, vetoPath string) []string {
	env := os.Environ()
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	env = append(env, envVar+"="+libPath)
	env = append(env, "VETO_PATH="+vetoPath)
	// Optional: VETO_INTERPOSE_LOG=1 emits a stderr marker each time the
	// interposer rewrites. Useful when debugging a failing test locally.
	return env
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
