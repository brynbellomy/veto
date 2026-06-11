// Claude Code PreToolUse hook entrypoint.
//
// `veto hook claude-code` reads the JSON payload Claude Code sends to a
// PreToolUse command-hook on stdin, runs the analyzer, and writes a JSON
// hook-output decision to stdout. Compiled into the same binary as the
// rest of veto so a missing-python3 shebang failure can never silently
// fail-OPEN — if the veto binary is on PATH the hook is present.
//
// Fail-closed defense in depth:
//
//  1. Recovered panics: convert to a hard "deny" with INTERNAL ERROR.
//  2. Veto binary not resolvable: deny with a hard "do not retry"
//     message so colleagues notice the mis-install instead of seeing
//     veto get silently bypassed.
//  3. Risky command detected: deny with the corrected `veto …` prefix
//     in the message so the agent re-issues correctly.
//
// All three states emit a Claude-Code-shaped JSON envelope and exit 0.
// Exiting non-zero would cause Claude Code to fail-OPEN by default; only
// exit 2 produces a blocking error, used here as a last-resort fallback
// if stdout itself is broken.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/hook/claudecode"
)

// claudeHookInput is the subset of Claude Code's PreToolUse payload we use.
// Documented at https://docs.claude.com/en/docs/claude-code/hooks — we ignore
// anything outside Bash and outside `tool_input.command`.
type claudeHookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// claudeHookOutput matches Claude Code's `hookSpecificOutput.PreToolUse`
// shape. Only `permissionDecision` and `permissionDecisionReason` are
// load-bearing — the schema requires `hookEventName` for routing.
type claudeHookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// runHook dispatches `veto hook <subcommand>`. Only `claude-code` is
// implemented today; others print usage so users see a clear "not wired
// yet" message instead of a silent no-op.
func runHook(logger zerolog.Logger, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "veto hook: missing subcommand. Try `veto hook claude-code`.")
		return exitUsage
	}
	switch args[0] {
	case "claude-code":
		return runClaudeCodeHook(logger, os.Stdin, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "veto hook: unknown subcommand %q. Available: claude-code\n", args[0])
		return exitUsage
	}
}

// runClaudeCodeHook is the inner implementation. Takes io.Reader/Writer so
// tests can drive it without touching stdin/stdout. Always returns 0
// (success path or fail-closed "deny" envelope), unless the JSON envelope
// itself cannot be emitted — then we exit 2, which Claude Code treats as
// a blocking error per its documented contract.
func runClaudeCodeHook(logger zerolog.Logger, stdin io.Reader, stdout io.Writer) (rc int) {
	// Defense layer 1: any panic in the analyzer or transport becomes a
	// hard "deny" with INTERNAL ERROR. Without this, an uncaught panic
	// would exit non-zero, which Claude Code interprets as fail-OPEN.
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Interface("panic", r).Msg("hook panic — emitting fail-closed deny")
			if writeErr := writeDeny(stdout, fmt.Sprintf(
				"veto-hook: INTERNAL ERROR in hook script — install aborted fail-closed.\n\n"+
					"The hook crashed before it could make a routing decision. The agent's command was NOT executed.\n\n"+
					"Underlying error: %v\n\n"+
					"Re-run the original command only after the hook is fixed (or temporarily unwire it from "+
					"~/.claude/settings.json if you accept the risk).",
				r,
			)); writeErr != nil {
				rc = 2 // Claude Code: exit 2 = blocking error.
				return
			}
			rc = exitOK
		}
	}()

	var input claudeHookInput
	if err := json.NewDecoder(stdin).Decode(&input); err != nil {
		// Malformed input is one of the few cases where letting the tool
		// call proceed is the right call — if we can't tell what the tool
		// is, we have no business gating it. Same behavior as the Python
		// original (which returned without emitting anything).
		logger.Debug().Err(err).Msg("decode hook input")
		return exitOK
	}
	if input.ToolName != "Bash" || input.ToolInput.Command == "" {
		return exitOK
	}

	finding, risky := claudecode.Analyze(input.ToolInput.Command)
	if !risky {
		return exitOK
	}

	// Shell-expansion refusal (Phase 1.2 band-aid for $(), backticks,
	// <(), >(), <<<). There's no "prefix with veto" correction — the
	// agent must reissue without the construct. Phase 3.1 (sh/v3
	// AST walker) will replace this with structural detection.
	if finding.PM == "shell-expansion" {
		msg := "veto-hook: refusing to evaluate shell command-substitution / herestring.\n" +
			"The command contains $(...), backticks, <(...), >(...), or <<< — these hide commands from " +
			"veto's analyzer. Reissue the command without the substitution construct, or invoke " +
			"the package manager directly via `veto <pm> ...`."
		return writeDecisionOrFail(stdout, msg)
	}

	// binding.gyp worm check (phantom-gyp / Miasma). This is the earliest
	// layer: an npm-family install in a worm-bearing tree re-runs node-gyp
	// for the whole tree and detonates at install time, prefix or no prefix.
	// The analyzer stays pure (no I/O), so the cwd content scan lives here in
	// the transport. We only scan for npm-family findings — node-gyp is an
	// npm concern. A worm hit denies directly with the worm reason rather
	// than the generic "re-run with veto" nudge, since prefixing with veto
	// would not make this tree safe to install into.
	if isNpmFamilyPM(finding.PM) {
		if reason, found := gypWormReasonForTree(logger, finding.PM, hookPMArgs(finding.Tokens)); found {
			return writeDecisionOrFail(stdout, reason)
		}
	}

	// Hades / Shai-Hulud .pth startup-hook worm check. Symmetrical to the
	// npm-family branch above: site.py loads a .pth at every interpreter
	// startup, so prefixing the command with `veto` would NOT make a
	// poisoned environment safe to install into — the worm fires before
	// the install completes. Deny directly with the worm reason.
	if isPythonFamilyPM(finding.PM) {
		if reason, found := pthWormReasonForTree(logger, finding.PM, hookPMArgs(finding.Tokens)); found {
			return writeDecisionOrFail(stdout, reason)
		}
	}

	// Defense layer 2: if veto itself isn't on PATH at hook time,
	// telling the agent to "prefix with veto" is useless. Fail closed
	// loudly so the mis-install is visible.
	if !vetoReachable() {
		msg := fmt.Sprintf(
			"veto-hook: BLOCKED unguarded `%s` invocation, AND the veto binary itself was not found on PATH.\n\n"+
				"This means the safety gate is not installed correctly. Do NOT retry this command — the agent has no way to "+
				"route a package-manager call through a malware scan right now.\n\n"+
				"To fix:\n"+
				"  1. Build and install veto: `make install` in the veto repo, OR `go install "+
				"github.com/brynbellomy/veto/cmd/veto@latest`\n"+
				"  2. Confirm `which veto` resolves to a real binary\n"+
				"  3. Then retry the original command.",
			finding.PM,
		)
		return writeDecisionOrFail(stdout, msg)
	}

	corrected := "veto " + joinShellQuoted(finding.Tokens)
	msg := fmt.Sprintf(
		"veto-hook: blocked unguarded `%s` invocation.\n"+
			"Reason: veto only protects you when the command is routed through it. Re-run with an explicit "+
			"`veto` prefix so the malware scan runs:\n\n  %s\n\n"+
			"If multiple commands are chained, only the package-manager leaf needs the prefix.",
		finding.PM, corrected,
	)
	return writeDecisionOrFail(stdout, msg)
}

// npmFamilyHookPMs are the package-manager finding names whose installs
// trigger node-gyp, and therefore could detonate a binding.gyp worm.
var npmFamilyHookPMs = map[string]struct{}{
	"npm": {}, "pnpm": {}, "yarn": {}, "bun": {},
	"npx": {}, "pnpx": {}, "bunx": {},
}

// isNpmFamilyPM reports whether a hook finding's PM name resolves npm
// packages (and so could run a binding.gyp at install time).
func isNpmFamilyPM(pm string) bool {
	_, ok := npmFamilyHookPMs[pm]
	return ok
}

// pythonFamilyHookPMs are the package-manager finding names whose installs
// run inside a Python interpreter / venv — i.e. whose target tree has a
// site-packages and could carry a Hades .pth worm.
var pythonFamilyHookPMs = map[string]struct{}{
	"pip": {}, "pip3": {}, "uv": {}, "pipx": {}, "poetry": {}, "pdm": {}, "uvx": {},
}

func isPythonFamilyPM(pm string) bool {
	_, ok := pythonFamilyHookPMs[pm]
	return ok
}

// pthWormReasonForTree scans the target install tree's site-packages dirs
// for a critical .pth worm match and, if found, returns a hook-shaped deny
// reason. found=false means clean (or scan-error / cwd-unresolvable — all
// non-blocking, mirroring gypWormReasonForTree).
func pthWormReasonForTree(logger zerolog.Logger, pmName string, pmArgs []string) (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err).Msg("hook .pth check: resolve cwd failed; skipping")
		return "", false
	}
	var buf strings.Builder
	if !pthPreflightRoots(logger, &buf, pthScanRootsForInstall(pmName, pmArgs, cwd)) {
		return "", false
	}
	return "veto-hook: BLOCKED — " + buf.String(), true
}

func hookPMArgs(tokens []string) []string {
	if len(tokens) <= 1 {
		return nil
	}
	return tokens[1:]
}

// gypWormReasonForTree scans the target install tree's node_modules for a
// critical binding.gyp worm match and, if found, returns a hook-shaped deny
// reason. found=false means the tree is clean (or cwd is unresolvable / the
// scan errored — all non-blocking, because this is an additive heuristic, not
// a fail-closed gate). It reuses the same gypPreflight engine the install
// hot path uses, capturing its output to a buffer for the hook envelope.
func gypWormReasonForTree(logger zerolog.Logger, pmName string, pmArgs []string) (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err).Msg("hook gyp check: resolve cwd failed; skipping")
		return "", false
	}
	var buf strings.Builder
	if !gypPreflightRoots(logger, &buf, gypScanRootsForInstall(pmName, pmArgs, cwd)) {
		return "", false
	}
	return "veto-hook: BLOCKED — " + buf.String(), true
}

// writeDecisionOrFail writes a `deny` envelope or, if even that fails,
// returns exit 2 — the only return value Claude Code documents as a
// blocking error when the hook itself misbehaves.
func writeDecisionOrFail(stdout io.Writer, reason string) int {
	if err := writeDeny(stdout, reason); err != nil {
		return 2
	}
	return exitOK
}

// writeDeny emits the Claude-Code-shaped JSON envelope.
func writeDeny(stdout io.Writer, reason string) error {
	var out claudeHookOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(stdout).Encode(out)
}

// vetoReachable mirrors the Python original's check: confirm that the
// shell can resolve `veto` from PATH, since the agent re-invokes by
// bare name after we tell it to add the prefix. If the hook is wired by
// absolute path but `veto` is not on PATH, the corrected command will
// fail with "command not found" — fail closed loudly instead.
func vetoReachable() bool {
	path, err := exec.LookPath("veto")
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

// joinShellQuoted formats a slice of tokens back into a shell-safe string
// suitable for the corrected command line shown to the agent. We use
// shlex.Join from google/shlex's sibling for symmetry with the analyzer.
//
// Implementation note: google/shlex doesn't expose a Join, so we
// hand-format. The python original used shlex.quote per token; same idea
// here. Tokens with no shell-special characters pass through unquoted;
// anything else gets single-quoted with embedded single-quotes escaped.
func joinShellQuoted(tokens []string) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = shellQuote(t)
	}
	return strings.Join(parts, " ")
}

// shellQuote mirrors Python's `shlex.quote`: returns t unchanged if it only
// contains "safe" characters; otherwise wraps in single quotes and escapes
// embedded single quotes with the standard POSIX close/backslash/open sequence.
func shellQuote(t string) string {
	if t == "" {
		return "''"
	}
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@%+=:,./-_"
	allSafe := true
	for i := 0; i < len(t); i++ {
		if !strings.ContainsRune(safe, rune(t[i])) {
			allSafe = false
			break
		}
	}
	if allSafe {
		return t
	}
	return "'" + strings.ReplaceAll(t, "'", `'\''`) + "'"
}
