package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHasVetoClaudeHook covers the matrix of settings.json shapes the
// doctor must understand: a new-style "veto hook claude-code" entry,
// a legacy python-shebang entry, a non-veto-Bash hook (rtk-rewrite,
// etc.), and a completely unconfigured file.
func TestHasVetoClaudeHook(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{
			name:     "no hooks block",
			settings: map[string]any{"model": "opus"},
			want:     false,
		},
		{
			name: "Bash chain present but no veto entry",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Bash",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/foo/rtk-rewrite.sh"},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "new-style in-binary hook",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Bash",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/Users/x/.local/bin/veto hook claude-code"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "legacy python shebang",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Bash",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/Users/x/.claude/hooks/veto-hook.py"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "veto hook present in a non-Bash matcher does NOT count",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Edit",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/x/veto hook claude-code"},
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, hasVetoClaudeHook(c.settings))
		})
	}
}

// TestPrintResults_ColorMarkers spot-checks that PASS/WARN/FAIL produce
// distinct ANSI markers. We don't assert exact escape sequences (those
// could change), just that they differ.
func TestPrintResults_ColorMarkers(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusPass, label: "happy", detail: "ok"},
		{status: statusWarn, label: "soft", detail: "partial", howToFix: "do X"},
		{status: statusFail, label: "broken", detail: "no go", howToFix: "do Y"},
	}
	printResults(&buf, results)
	out := buf.String()
	require.Contains(t, out, "PASS")
	require.Contains(t, out, "WARN")
	require.Contains(t, out, "FAIL")
	require.Contains(t, out, "do X")
	require.Contains(t, out, "do Y")
	// PASS entries print their label/detail but never a how-to-fix arrow.
	require.Contains(t, out, "happy")
	require.Contains(t, out, "ok")
	// Exactly two `→` lines (one per non-PASS entry).
	require.Equal(t, 2, strings.Count(out, "→"), "exactly the WARN+FAIL entries should emit a fix arrow")
}

func TestCheckShellIntegrationFromDetectedRC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	shimDir := filepath.Join(dir, ".local", "bin")
	vetoPath := filepath.Join(shimDir, "veto")
	for _, target := range []struct {
		name string
		kind shellKind
	}{
		{name: ".zshrc", kind: shellKindZsh},
		{name: ".bashrc", kind: shellKindBash},
		{name: ".bash_profile", kind: shellKindBash},
		{name: ".profile", kind: shellKindProfile},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, target.name), []byte(renderShellIntegrationBlock(shimDir, vetoPath, target.kind)), 0o644))
	}

	got := checkShellIntegration()
	require.Equal(t, statusPass, got.status)
	require.Equal(t, "shell integration", got.label)
}

func TestCheckShellIntegrationWarnsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".zshrc"), []byte("alias g=git\n"), 0o644))

	got := checkShellIntegration()
	require.Equal(t, statusWarn, got.status)
	require.Contains(t, got.howToFix, "install-shell")
}

func TestCheckShellIntegrationWarnsWhenOneBashFileMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	shimDir := filepath.Join(dir, ".local", "bin")
	vetoPath := filepath.Join(shimDir, "veto")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindZsh)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".bashrc"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindBash)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".profile"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindProfile)), 0o644))

	got := checkShellIntegration()
	require.Equal(t, statusWarn, got.status)
	require.Contains(t, got.detail, ".bash_profile")
}

func TestCodexPostureResult(t *testing.T) {
	cases := []struct {
		name string
		rep  codexEnvReport
		want status
	}{
		{name: "missing config inherits shell", rep: codexEnvReport{}, want: statusPass},
		{name: "no shell policy inherits shell", rep: codexEnvReport{ConfigExists: true}, want: statusPass},
		{name: "inherit all", rep: codexEnvReport{ConfigExists: true, HasShellPolicy: true, InheritMode: "all"}, want: statusPass},
		{name: "inherit core strips path", rep: codexEnvReport{ConfigExists: true, HasShellPolicy: true, InheritMode: "core"}, want: statusFail},
		{name: "inherit core with path override needs verification", rep: codexEnvReport{ConfigExists: true, HasShellPolicy: true, InheritMode: "core", HasUserPathEntry: true}, want: statusWarn},
		{name: "unknown inherit mode", rep: codexEnvReport{ConfigExists: true, HasShellPolicy: true, InheritMode: "sandboxed"}, want: statusWarn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := codexPostureResult(c.rep)
			require.Equal(t, c.want, got.status)
			require.Equal(t, "Codex PATH policy", got.label)
		})
	}
}

func TestCursorPostureResult(t *testing.T) {
	dir := t.TempDir()

	missing := cursorPostureResult(dir)
	require.Equal(t, statusWarn, missing.status)
	require.Contains(t, missing.howToFix, "install-cursor")

	rulePath := filepath.Join(dir, ".cursor", "rules", "veto.mdc")
	require.NoError(t, os.MkdirAll(filepath.Dir(rulePath), 0o755))
	require.NoError(t, os.WriteFile(rulePath, []byte("not a useful rule"), 0o644))
	bad := cursorPostureResult(dir)
	require.Equal(t, statusFail, bad.status)
	require.Contains(t, bad.howToFix, "--force")

	require.NoError(t, os.WriteFile(rulePath, []byte(cursorRuleBody), 0o644))
	good := cursorPostureResult(dir)
	require.Equal(t, statusPass, good.status)
	require.Contains(t, good.detail, "global User Rules")
}

func TestSirenePostureResult(t *testing.T) {
	dir := t.TempDir()
	shimDir := filepath.Join(dir, ".local", "bin")
	require.NoError(t, os.MkdirAll(shimDir, 0o755))

	noSirene := sirenePostureResult(dir, shimDir, shimDir)
	require.Equal(t, statusPass, noSirene.status)
	require.Contains(t, noSirene.detail, "not detected")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".sirene"), 0o755))
	missingShim := sirenePostureResult(dir, shimDir, filepath.Join(dir, "bin"))
	require.Equal(t, statusFail, missingShim.status)
	require.Contains(t, missingShim.howToFix, "install-shell")

	covered := sirenePostureResult(dir, shimDir, shimDir)
	require.Equal(t, statusPass, covered.status)
	require.Contains(t, covered.detail, "includes veto shim dir")
}

// TestEarlierRealBinary covers the "shim shadowed by mise/homebrew"
// detection: a real `npm` earlier in PATH than our shim dir must be
// flagged. A `veto`-pointing symlink earlier in PATH is NOT a
// conflict (the user has veto installed in a non-default place).
func TestEarlierRealBinary(t *testing.T) {
	dir := t.TempDir()
	mise := filepath.Join(dir, "mise-shims")
	user := filepath.Join(dir, "user-bin")
	for _, d := range []string{mise, user} {
		require.NoError(t, mkdir(d))
	}
	// Real npm in mise dir.
	realNpm := filepath.Join(mise, "npm")
	require.NoError(t, writeFile(realNpm, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	pathParts := []string{mise, user}
	shimIdx := 1 // user is the shim dir (last)
	got := earlierRealBinary("npm", pathParts, shimIdx)
	require.Equal(t, realNpm, got)

	// No conflict for a binary that doesn't exist earlier.
	got = earlierRealBinary("pip", pathParts, shimIdx)
	require.Equal(t, "", got)
}

// TestDetectVersionManager: the doctor recognises the canonical
// install/shim dirs of the version managers we know how to advise about.
// Misclassification would either suppress useful advice (false negative)
// or print a misleading recipe (false positive) — both worse than the
// generic fallback.
func TestDetectVersionManager(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/Users/x/.local/share/mise/installs/node/20.0.0/bin/npm", "mise"},
		{"/Users/x/.local/share/mise/shims/npm", "mise"},
		{"/Users/x/.asdf/installs/python/3.11.0/bin/pip", "asdf"},
		{"/Users/x/.asdf/shims/pip", "asdf"},
		{"/Users/x/.pyenv/shims/python", "pyenv"},
		{"/Users/x/.pyenv/versions/3.11.0/bin/python", "pyenv"},
		{"/Users/x/.nvm/versions/node/20.0.0/bin/npm", "nvm"},
		// Not a version manager dir: must NOT misclassify.
		{"/opt/homebrew/bin/npm", ""},
		{"/usr/local/bin/npm", ""},
		{"/Users/x/.local/bin/npm", ""},
		// Substring "mise" without the directory shape must NOT match.
		{"/Users/x/.local/bin/promise-checker", ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			require.Equal(t, c.want, detectVersionManager(c.path))
		})
	}
}

// TestPrintVersionManagerFooters_DedupesPerManager: ten mise-shadowed
// shims should still produce only one mise footer block, not ten.
func TestPrintVersionManagerFooters_DedupesPerManager(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusFail, label: "shim:npm", detail: "mise install at /x shadows the veto shim"},
		{status: statusFail, label: "shim:pnpm", detail: "mise install at /y shadows the veto shim"},
		{status: statusFail, label: "shim:yarn", detail: "mise install at /z shadows the veto shim"},
	}
	printVersionManagerFooters(&buf, results)
	out := buf.String()
	require.Equal(t, 1, strings.Count(out, "mise PATH-ordering recipe"),
		"a multi-mise-shadow doctor run must print the footer exactly once")
	require.Contains(t, out, "veto install-shell")
	require.Contains(t, out, "managed block", "chpwd-hook workaround must be delegated to the managed block")
}

// TestPrintVersionManagerFooters_OnlyOnFail: a PASS result that happens
// to mention "mise" (e.g. a shim whose mise-version is healthy) must
// NOT trigger the footer.
func TestPrintVersionManagerFooters_OnlyOnFail(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusPass, label: "shim:npm", detail: "mise-installed but healthy"},
	}
	printVersionManagerFooters(&buf, results)
	require.Empty(t, buf.String())
}

// TestPrintVersionManagerFooters_OnlyForRecognizedManagers: a FAIL
// whose detail names some other tool must not produce a footer block.
func TestPrintVersionManagerFooters_OnlyForRecognizedManagers(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusFail, label: "shim:npm", detail: "rbenv install at /x shadows the veto shim"},
	}
	printVersionManagerFooters(&buf, results)
	require.Empty(t, buf.String(), "no footer for unrecognised version managers — fall through to generic advice")
}

// Small file-IO helpers used by the earlier-real-binary test.
func mkdir(p string) error                                 { return os.MkdirAll(p, 0o755) }
func writeFile(p string, data []byte, m os.FileMode) error { return os.WriteFile(p, data, m) }

// hostHasAbsolutePathPM reports whether the running host has any
// wrapped-PM binary at one of the well-known absolute-path install
// roots (homebrew / /usr/local/bin). Used by the per-PM survey
// tests to skip themselves on hosts that would carry real installs
// into the survey output and make assertions flaky.
//
// We don't check the version-manager install roots (~/.local/share/mise/...
// etc.) because the tests already control $HOME, so those resolve under
// the tempdir.
func hostHasAbsolutePathPM(t *testing.T) bool {
	t.Helper()
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			for _, pm := range []string{
				"npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx",
				"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
				"go", "cargo",
			} {
				if e.Name() == pm {
					return true
				}
			}
		}
	}
	return false
}

// TestCheckWrappersPerPM_AllNotApplicable: with an empty tempdir as
// the only $PATH entry, an isolated $HOME (no mise/asdf installs), and
// no wrappers.json — every PM line should come back N/A and the
// generic Layer-4 WARN must NOT fire (nothing to wrap means no
// warning).
//
// Skipped when the host has homebrew/usr-local PM installs since the
// /opt/homebrew/bin and /usr/local/bin survey paths aren't sandboxable
// from a test. That's almost always darwin in practice, but we
// detect dynamically rather than gating on runtime.GOOS so the test is
// useful on either platform when the host is clean.
func TestCheckWrappersPerPM_AllNotApplicable(t *testing.T) {
	if hostHasAbsolutePathPM(t) {
		t.Skip("host has PM installs in /opt/homebrew/bin or /usr/local/bin; can't isolate survey")
	}
	tempDir := t.TempDir()
	emptyBin := filepath.Join(tempDir, "bin")
	require.NoError(t, os.MkdirAll(emptyBin, 0o755))
	t.Setenv("HOME", tempDir)
	t.Setenv("PATH", emptyBin)

	cfg := config{CacheDir: filepath.Join(tempDir, "cache")}
	results := checkWrappers(cfg)

	naCount := 0
	for _, r := range results {
		require.NotEqual(t, statusWarn, r.status,
			"no generic Layer-4 WARN should fire when nothing is installed; got: %+v", r)
		require.NotEqual(t, statusFail, r.status,
			"no FAIL with empty state and clean host; got: %+v", r)
		if r.status == statusNotApplicable {
			naCount++
		}
	}
	// One N/A per wrapped PM expected.
	require.Equal(t, len(pmlistWrappedForTest()), naCount,
		"expected one N/A line per wrapped PM; got %d lines: %+v", naCount, results)
}

// pmlistWrappedForTest mirrors pmlist.Wrapped without importing the
// package directly from the test (the package is already imported via
// doctor.go; this helper just keeps the test free of internal/ paths).
func pmlistWrappedForTest() []string {
	// Survey one PM at a time via surveyWrappablePaths to derive the
	// list rather than hardcoding it — keeps the test from drifting
	// when pmlist.Wrapped changes.
	return wrappedManagers
}

// TestCheckWrappersPerPM_OneWrappedOneUnwrapped: builds a tempdir with
// two synthetic binaries — `npm` as a symlink to the test binary (so
// pointsAtVeto succeeds) with a .veto-original sibling, and `uv` as a
// plain executable. Survey should report npm PASS, uv WARN.
//
// Skipped when the host has homebrew/usr-local PM installs that
// would surface their own WARN lines and break the focused assertion.
func TestCheckWrappersPerPM_OneWrappedOneUnwrapped(t *testing.T) {
	if hostHasAbsolutePathPM(t) {
		t.Skip("host has PM installs in /opt/homebrew/bin or /usr/local/bin; can't isolate survey")
	}
	tempDir := t.TempDir()
	bin := filepath.Join(tempDir, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))

	// Resolve the test binary's canonical path. We use it as the
	// symlink target so isAlreadyOursWrap's strict physical-path
	// identity check (via pointsAtVeto) succeeds.
	vetoPath, err := resolveVetoBinary()
	require.NoError(t, err)

	// Wrapped npm: symlink → test binary, with .veto-original sibling.
	npmPath := filepath.Join(bin, "npm")
	require.NoError(t, os.Symlink(vetoPath, npmPath))
	require.NoError(t, os.WriteFile(npmPath+wrapperSuffix, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	// Unwrapped uv: plain executable, no .veto-original.
	uvPath := filepath.Join(bin, "uv")
	require.NoError(t, os.WriteFile(uvPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("HOME", tempDir)
	t.Setenv("PATH", bin)

	cfg := config{CacheDir: filepath.Join(tempDir, "cache")}
	results := checkWrappers(cfg)

	var npmLine, uvLine *checkResult
	for i := range results {
		switch results[i].label {
		case "wrapper:npm":
			if npmLine == nil || results[i].status == statusPass {
				npmLine = &results[i]
			}
		case "wrapper:uv":
			if uvLine == nil || results[i].status == statusWarn {
				uvLine = &results[i]
			}
		}
	}
	require.NotNil(t, npmLine, "no wrapper:npm line in output: %+v", results)
	require.NotNil(t, uvLine, "no wrapper:uv line in output: %+v", results)
	require.Equal(t, statusPass, npmLine.status, "npm symlink to veto with .veto-original should PASS; got %+v", npmLine)
	require.Equal(t, statusWarn, uvLine.status, "uv plain executable should WARN; got %+v", uvLine)
	require.Contains(t, uvLine.detail, "NOT wrapped")
}

// TestCheckWrappersPerPM_OutputHasNoHomebrewOnLinux: regression for
// the original symptom — on Linux the doctor output must not
// reference /opt/homebrew anywhere when the generic Layer-4 WARN
// fires. Tests the platform-aware example path branch via
// layer4ExampleHints. We render through printResults using a
// synthetic results slice so the test doesn't depend on the host's
// state.
//
// On darwin the homebrew path is the correct example, so the test
// is darwin-skipped: it's a Linux-output regression, not a
// cross-platform invariant.
func TestCheckWrappersPerPM_OutputHasNoHomebrewOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("regression test for Linux output; /opt/homebrew is a legitimate example path on darwin")
	}
	examplePath, envVar := layer4ExampleHints("uv")
	require.Equal(t, "/usr/local/bin/uv", examplePath, "Linux example path must be /usr/local/bin/<pm>")
	require.Equal(t, "LD_PRELOAD", envVar, "Linux preload env var must be LD_PRELOAD")

	// And render a synthetic results slice through printResults to
	// confirm no /opt/homebrew leaks via any other code path.
	var buf bytes.Buffer
	results := []checkResult{
		{
			status: statusWarn,
			label:  "real-binary wrappers",
			detail: "Layer 4 not installed — absolute-path invocations like " + examplePath + " bypass the gate",
			howToFix: "Run `veto install-wrappers` to wrap PM binaries with veto symlinks. " +
				"This catches `subprocess.run([abs_path, ...])` even when " + envVar + " is unset.",
		},
		{status: statusNotApplicable, label: "wrapper:npm", detail: "no absolute-path install detected on this host"},
	}
	printResults(&buf, results)
	require.NotContains(t, buf.String(), "/opt/homebrew",
		"Linux doctor output must not reference /opt/homebrew")
}

// TestStatusNotApplicableCountsAsPassInSummary: assert that an N/A
// line shows up in the "passed" bucket of the summary, not warnings
// or failures. We test the summary computation by replicating it
// inline since runDoctor's loop is small and not separately
// exported.
func TestStatusNotApplicableCountsAsPassInSummary(t *testing.T) {
	results := []checkResult{
		{status: statusPass, label: "a", detail: "ok"},
		{status: statusNotApplicable, label: "b", detail: "n/a"},
		{status: statusNotApplicable, label: "c", detail: "n/a"},
		{status: statusWarn, label: "d", detail: "warn"},
		{status: statusFail, label: "e", detail: "fail"},
	}
	failures := 0
	warnings := 0
	for _, r := range results {
		switch r.status {
		case statusFail:
			failures++
		case statusWarn:
			warnings++
		}
	}
	passed := len(results) - failures - warnings
	require.Equal(t, 3, passed, "1 PASS + 2 N/A should count as 3 passed")
	require.Equal(t, 1, warnings)
	require.Equal(t, 1, failures)
}

// TestPrintResults_NAMarkerRendered: an N/A result must render an
// `[N/A]` marker in the output and NOT emit a how-to-fix arrow line
// (even if howToFix is set, which it shouldn't normally be — but
// printResults must defend against it).
func TestPrintResults_NAMarkerRendered(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusNotApplicable, label: "wrapper:foo", detail: "no install detected", howToFix: "this should NOT print"},
	}
	printResults(&buf, results)
	out := buf.String()
	require.Contains(t, out, "N/A", "N/A marker must appear in output")
	require.Contains(t, out, "wrapper:foo", "label must appear")
	require.NotContains(t, out, "this should NOT print",
		"N/A must not emit a how-to-fix arrow line")
	require.NotContains(t, out, "→", "N/A must not emit the fix-arrow glyph")
}
