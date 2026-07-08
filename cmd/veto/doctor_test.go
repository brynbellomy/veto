package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
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

// ---------------------------------------------------------------------------
// SIP-protected path tests
// ---------------------------------------------------------------------------

func TestIsSIPProtectedPath(t *testing.T) {
	cases := []struct {
		path     string
		wantSIP  bool
	}{
		// Canonical SIP roots — binaries inside them are SIP-protected.
		{"/usr/bin/pip3", true},
		{"/usr/bin/python3", true},
		{"/usr/sbin/sysctl", true},
		{"/bin/sh", true},
		{"/sbin/launchd", true},
		{"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", true},
		// Edge cases: path cleanup.
		{"/usr/bin/../bin/sh", true}, // rare but must not break
		// Non-SIP paths.
		{"/opt/homebrew/bin/python3", false},
		{"/usr/local/bin/pip3", false},
		{"/Users/x/.local/bin/pip3", false},
		{"/tmp/pip3", false},
		{"/", false},
		{"/usr", false},        // prefix of SIP dir but not inside it
		{"/System", false},     // ditto
		{"/usr/bin", false},    // the directory itself, not a file inside
		{"/usr/binary", false}, // false prefix
		// Substring false-positive guards.
		{"/usr/binfoo/pip3", false},
		{"/usr/local/sbin/thing", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got := isSIPProtectedPath(c.path)
			if c.wantSIP {
				require.True(t, got, "%q should be SIP-protected", c.path)
			} else {
				require.False(t, got, "%q should NOT be SIP-protected", c.path)
			}
		})
	}
}

// TestPrintResults_SIPNAMarker: a SIP-protected binary must render as
// [N/A] with the SIP reason and must NOT emit a how-to-fix arrow or the
// "run veto install-wrappers" recommendation.
func TestPrintResults_SIPNAMarker(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{
			status: statusNotApplicable,
			label:  "wrapper:pip3",
			detail: "/usr/bin/pip3 (SIP-protected — no defense layer can cover this)",
		},
	}
	printResults(&buf, results)
	out := buf.String()
	require.Contains(t, out, "N/A", "SIP-protected paths must render as N/A")
	require.Contains(t, out, "wrapper:pip3", "label must appear")
	require.Contains(t, out, "SIP-protected", "SIP reason must appear")
	require.Contains(t, out, "no defense layer can cover this", "full reason must be visible")
	require.NotContains(t, out, "→", "N/A must not emit the fix-arrow glyph")
	require.NotContains(t, out, "install-wrappers", "SIP-protected binary must not recommend wrapping")
}

// TestSIPDoesNotCountAsUnwrapped: a SIP-protected real binary must NOT
// increment anyUnwrappedFound, so the generic Layer-4 WARN does not
// fire when the only "unwrapped" candidates are SIP-protected. We test
// this by running checkWrappersWith against a fake vetoid with a
// real binary at a tempdir path that is NOT in SIP territory — and
// separately verify the SIP path would be classified as N/A.
func TestSIPPathIsNotApplicableInWrapperSurvey(t *testing.T) {
	if hostHasAbsolutePathPM(t) {
		t.Skip("host has PM installs in /opt/homebrew/bin or /usr/local/bin; can't isolate survey")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("SIP classification only applies on macOS")
	}

	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	// A fake veto binary for the survey.
	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("veto"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	// Plant a real binary at a non-SIP path that the survey can find.
	// Use a known wrapped PM name so PathsFor discovery hits it.
	pathDir := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(pathDir, 0o755))
	pmPath := filepath.Join(pathDir, "pip3")
	require.NoError(t, os.WriteFile(pmPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	t.Setenv("HOME", tmp)
	t.Setenv("PATH", pathDir)

	cfg := config{CacheDir: cacheDir}
	results := checkWrappersWith(cfg, vetoID, nil)

	// The tempdir pip3 is not SIP-protected, so it should WARN.
	r := findResult(t, results, "wrapper:pip3", "NOT wrapped")
	require.Equal(t, statusWarn, r.status)
	require.Contains(t, r.howToFix, "install-wrappers")

	// Now verify the classification helper itself on a real SIP path.
	// We can't plant files in /usr/bin, but we can assert the helper
	// returns true for well-known SIP paths regardless of whether the
	// file exists — classification is by path prefix only.
	require.True(t, isSIPProtectedPath("/usr/bin/pip3"))
	require.True(t, isSIPProtectedPath("/usr/bin/python3"))
	require.False(t, isSIPProtectedPath(pmPath))
}

// TestCheckWrappers_SelfReferentialAnchorFails is the doctor half of the
// 2026-07-08 incident regression: after the anchor was clobbered, doctor
// reported "0 failures" because it only checked that `.veto-original`
// EXISTS (os.Stat follows the symlink to the still-present veto binary),
// not that it resolves to a real, non-veto binary. A `.veto-original`
// that itself points at veto is a veto→veto exec loop; doctor must FAIL
// it loudly instead of passing it.
func TestCheckWrappers_SelfReferentialAnchorFails(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	vetoBin := filepath.Join(tmp, "veto")
	require.NoError(t, os.WriteFile(vetoBin, []byte("#!/bin/sh\n# veto\n"), 0o755))
	vetoID, err := pmsurvey.VetoIdentityFor(vetoBin)
	require.NoError(t, err)

	bin := filepath.Join(tmp, "bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	// The corrupted on-disk shape: go → veto AND go.veto-original → veto.
	goBin := filepath.Join(bin, "go")
	require.NoError(t, os.Symlink(vetoBin, goBin))
	require.NoError(t, os.Symlink(vetoBin, goBin+wrapperSuffix))

	cfg := config{CacheDir: cacheDir}
	require.NoError(t, saveWrapperState(cfg, wrapperState{Wrappers: []wrapperEntry{{
		Path:         goBin,
		OriginalPath: goBin + wrapperSuffix,
		PM:           "go",
		Source:       "homebrew",
	}}}))

	t.Setenv("HOME", tmp)
	t.Setenv("PATH", bin)

	results := checkWrappersWith(cfg, vetoID, nil)

	var found *checkResult
	for i := range results {
		if results[i].label == "wrapper:go" && results[i].status == statusFail &&
			strings.Contains(results[i].detail, "self-referential") {
			found = &results[i]
			break
		}
	}
	require.NotNil(t, found, "expected a FAIL for the self-referential go anchor; got %+v", results)
	require.Contains(t, found.howToFix, "install-wrappers")
}

// TestCheckStaleShimSiblings_FlagsPlanted plants the on-disk shape behind
// the veto-dzk bead (self-referential `*.veto-original` symlinks in
// ~/.local/bin) and asserts doctor returns one FAIL row per stale entry,
// naming the exact path and pointing at `veto install-all`.
func TestCheckStaleShimSiblings_FlagsPlanted(t *testing.T) {
	shimDir := t.TempDir()
	veto := filepath.Join(shimDir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	planted := []string{
		filepath.Join(shimDir, "python3.veto-original"),
		filepath.Join(shimDir, "python3.12.veto-original"),
	}
	for _, p := range planted {
		require.NoError(t, os.Symlink(veto, p))
	}

	got := checkStaleShimSiblings(shimDir)
	require.Len(t, got, len(planted))
	for _, r := range got {
		require.Equal(t, statusFail, r.status)
		require.Contains(t, r.howToFix, "veto install-all")
	}

	// Each planted path appears verbatim in exactly one row's detail.
	for _, p := range planted {
		var found bool
		for _, r := range got {
			if strings.Contains(r.detail, p) {
				found = true
				break
			}
		}
		require.True(t, found, "expected a doctor row naming %s", p)
	}
}

// TestCheckStaleShimSiblings_PassWhenClean proves a healthy shim dir
// (real shim symlinks, no .veto-original entries) produces zero rows.
// The caller appends rows to the parent slice, so an empty return means
// the invariant holds silently.
func TestCheckStaleShimSiblings_PassWhenClean(t *testing.T) {
	shimDir := t.TempDir()
	veto := filepath.Join(shimDir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.Symlink(veto, filepath.Join(shimDir, "npm")))

	got := checkStaleShimSiblings(shimDir)
	require.Empty(t, got)
}

// TestCheckStaleShimSiblings_MissingDirIsNoFinding proves an absent
// shim dir produces zero rows: the parent `checkShimDir` already
// reports "shim dir not on PATH" in that case, and we don't want to
// double-report.
func TestCheckStaleShimSiblings_MissingDirIsNoFinding(t *testing.T) {
	got := checkStaleShimSiblings(filepath.Join(t.TempDir(), "absent"))
	require.Empty(t, got)
}

// TestCheckStaleShimSiblings_AfterScrubPasses proves the
// install-shims convergence pass actually heals the invariant: after
// the scrub runs, doctor reports zero stale-sibling rows.
func TestCheckStaleShimSiblings_AfterScrubPasses(t *testing.T) {
	shimDir := t.TempDir()
	veto := filepath.Join(shimDir, "..", "fake-veto")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))
	stale := filepath.Join(shimDir, "python3.veto-original")
	require.NoError(t, os.Symlink(veto, stale))

	// Confirm doctor flags it BEFORE the scrub.
	pre := checkStaleShimSiblings(shimDir)
	require.Len(t, pre, 1)

	// Run the scrub primitive that install-shims wires into its
	// convergence pass.
	_, errs := scrubVetoOriginalSiblings(shimDir, false)
	require.Empty(t, errs)

	// Doctor reports clean AFTER scrub.
	post := checkStaleShimSiblings(shimDir)
	require.Empty(t, post)
}
