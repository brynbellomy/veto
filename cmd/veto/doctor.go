// `veto doctor`: one-stop verification of the gate's defense layers.
//
// The README documents a six-step verification checklist; this command
// runs it. Reading the manual list and copy-pasting commands is the
// kind of friction that lets people quietly run an unguarded install
// and assume veto is in front of it. The doctor closes that gap.
//
// Each check produces one line with a status (PASS/WARN/FAIL) plus a
// short explanation. WARN means coverage is partial but not dangerously
// broken (e.g. one PM shim missing). FAIL means the gate is not in front
// of installs in some meaningful way — the user should fix it before
// trusting veto.
//
// Exit codes: 0 if no FAILs, 1 if any FAIL was emitted. WARN doesn't
// affect the exit code so the command is still usable as a tripwire in
// CI.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

// status is the per-check outcome. PASS = green; WARN = yellow; FAIL =
// red. Strictly speaking PASS could be silent and only WARN/FAIL printed,
// but printing every result makes "did the check even run?" answerable.
type status int

const (
	statusPass status = iota
	statusWarn
	statusFail
	// statusNotApplicable is a presentation-only fourth value: it renders
	// as a cyan `[N/A]` marker, never emits a how-to-fix arrow, and is
	// counted as a "pass" by the summary (it does NOT bump warnings or
	// failures). Use it for per-PM survey lines where the PM is simply
	// not installed on this host — the absence of an install is not a
	// finding, just the answer to "is there anything to wrap here?"
	statusNotApplicable
)

// checkResult is one row in the doctor's output table.
type checkResult struct {
	status   status
	label    string
	detail   string
	howToFix string // shown only on WARN/FAIL
}

// runDoctor implements `veto doctor`. No flags today — the checklist
// is fixed.
func runDoctor(logger zerolog.Logger, cfg config, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "veto doctor: unexpected arguments: %v\n", args)
		return exitUsage
	}

	results := []checkResult{}
	results = append(results, checkVetoOnPath())
	results = append(results, checkShimDir()...)
	results = append(results, checkShellIntegration())
	results = append(results, checkClaudeHook())
	results = append(results, checkCodexPosture())
	results = append(results, checkCursorPosture())
	results = append(results, checkSirenePosture())
	results = append(results, checkInterposer()...)
	results = append(results, checkWrappers(cfg)...)
	intelResults := checkIntel(logger, cfg)
	results = append(results, intelResults...)
	results = append(results, checkIOC(logger, cfg))

	printResults(os.Stdout, results)
	printVersionManagerFooters(os.Stdout, results)

	failures := 0
	warnings := 0
	for _, r := range results {
		switch r.status {
		case statusFail:
			failures++
		case statusWarn:
			warnings++
			// statusPass and statusNotApplicable both roll into
			// "passed" — the latter is presentation-only (a PM not
			// installed on this host is not a finding).
		}
	}
	fmt.Fprintf(os.Stdout, "\nSummary: %d passed, %d warnings, %d failures\n",
		len(results)-failures-warnings, warnings, failures)

	if failures > 0 {
		return exitRefused // exit 1 — same as a malware refusal so the
		// signal is "do not trust this install path"
	}
	return exitOK
}

// checkVetoOnPath: the foundational invariant. If veto itself
// isn't resolvable, every layer below is meaningless.
func checkVetoOnPath() checkResult {
	path, err := exec.LookPath("veto")
	if err != nil {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: "not found",
			howToFix: "Run `make install` in the veto repo, or place the " +
				"veto binary somewhere in PATH (e.g. ~/.local/bin).",
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: fmt.Sprintf("stat %s: %v", path, err),
		}
	}
	if info.Mode()&0o111 == 0 {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: fmt.Sprintf("%s is not executable", path),
		}
	}
	return checkResult{
		status: statusPass,
		label:  "veto on PATH",
		detail: path,
	}
}

// checkShimDir verifies the PATH shim layer. Two facets:
//   - the shim directory itself is on PATH (otherwise none of the shims
//     get reached);
//   - each PM either has a working shim, or doesn't conflict with a real
//     binary earlier in PATH (which would shadow our shim).
//
// We don't refuse to PASS the shim-dir check just because mise/homebrew
// is earlier in PATH for SOME binary — that's per-PM granularity, surfaced
// as per-shim WARN/FAIL.
func checkShimDir() []checkResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return []checkResult{{status: statusFail, label: "shim dir", detail: "cannot resolve home: " + err.Error()}}
	}
	shimDir := filepath.Join(home, ".local", "bin")
	pathParts := filepath.SplitList(os.Getenv("PATH"))

	shimIdx := -1
	for i, p := range pathParts {
		if absEqual(p, shimDir) {
			shimIdx = i
			break
		}
	}
	out := []checkResult{}
	if shimIdx < 0 {
		out = append(out, checkResult{
			status:   statusWarn,
			label:    "shim dir on PATH",
			detail:   shimDir + " is NOT in PATH",
			howToFix: "Run `veto install-shell`, then open a new terminal.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "shim dir on PATH",
			detail: fmt.Sprintf("%s (position %d of %d)", shimDir, shimIdx+1, len(pathParts)),
		})
	}

	// Static-canonical shim names PLUS every `python3.X` shim already
	// installed in the shim dir. The latter is what catches versioned
	// aliases install-shims created on a previous run — we want
	// doctor to confirm they STILL point at the current veto binary,
	// not silently ignore them.
	shimNames := append([]string{}, shimmedManagers...)
	shimNames = append(shimNames, discoverInstalledPythonShims(shimDir)...)
	for _, name := range shimNames {
		shimPath := filepath.Join(shimDir, name)
		info, err := os.Lstat(shimPath)
		if err != nil {
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "shim:" + name,
				detail:   "not installed",
				howToFix: "Run `veto install-shims` to create missing shims.",
			})
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			// A real binary occupies the shim path (uv self-installs
			// into ~/.local/bin/uv). install-shims --force handles this
			// safely: it displaces the real binary to
			// `<name>.veto-displaced`, which findRealBinary resolves at
			// exec time — no manual move-aside needed.
			out = append(out, checkResult{
				status: statusFail,
				label:  "shim:" + name,
				detail: shimPath + " exists but is not a symlink",
				howToFix: "Run `veto install-shims --force` — it displaces the real binary to " +
					shimPath + displacedSuffix + ", which veto resolves when the shim runs.",
			})
			continue
		}
		// Verify the shim points at the veto binary.
		target, err := os.Readlink(shimPath)
		if err != nil || !strings.Contains(target, "veto") {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "shim:" + name,
				detail:   fmt.Sprintf("%s → %s (not a veto shim)", shimPath, target),
				howToFix: "Run `veto install-shims --force` to repoint.",
			})
			continue
		}
		// Earlier-in-PATH conflict: a real PM lives in a dir that comes
		// before the shim dir. The shim never gets reached for this PM.
		if shimIdx >= 0 {
			shadow := earlierRealBinary(name, pathParts, shimIdx)
			if shadow != "" {
				// Mise (and asdf, pyenv, nvm, ...) typically own a
				// version-pinned shim/install dir that the user
				// reasonably wants to keep. Naming the offender lets
				// the user route directly to the recipe footer below
				// instead of guessing what's wrong.
				vm := detectVersionManager(shadow)
				detail := fmt.Sprintf("real %s at %s appears before shim dir; shim is shadowed", name, shadow)
				fix := "Run `veto install-shell`, then open a new terminal."
				if vm != "" {
					detail = fmt.Sprintf("%s install at %s shadows the veto shim", vm, shadow)
					fix = fmt.Sprintf("Run `veto install-shell`. See the %s footer at the end for details.", vm)
				}
				out = append(out, checkResult{
					status:   statusFail,
					label:    "shim:" + name,
					detail:   detail,
					howToFix: fix,
				})
				continue
			}
		}
		// Displacement integrity: install-shims --force moves a real
		// binary occupying the shim path aside to `<name>.veto-displaced`
		// before planting the symlink, and findRealBinary resolves
		// through that sibling at exec time. If the displaced file has
		// itself been clobbered into a veto symlink (or is no longer
		// executable), the shim LOOKS healthy but the real binary is
		// lost — the same class of lie as a self-referential
		// `.veto-original` anchor. Verify before emitting PASS.
		detail := fmt.Sprintf("%s → %s", shimPath, target)
		if fail, displaced := checkDisplacedShimSibling(shimPath); fail != nil {
			out = append(out, *fail)
			continue
		} else if displaced != "" {
			detail += fmt.Sprintf(" (real %s displaced to %s; veto resolves it)", name, displaced)
		}
		out = append(out, checkResult{
			status: statusPass,
			label:  "shim:" + name,
			detail: detail,
		})
	}

	// Layer 2 invariant: no `*.veto-original` siblings allowed in the
	// shim dir. Those belong to Layer 4 wrap sites and would never be
	// registered with this shim dir as their parent. Each stray entry is
	// at minimum a stale artifact; at worst (when it resolves back into
	// veto itself) it can chain into an exec loop or stall when veto is
	// invoked as a `python3` shim from an agent spawn context — the
	// observed veto-dzk symptom.
	out = append(out, checkStaleShimSiblings(shimDir)...)

	return out
}

// checkDisplacedShimSibling validates the `.veto-displaced` sibling of
// a healthy shim symlink, if one exists. Returns (nil, "") when there
// is no sibling, (nil, path) when the sibling is a healthy real binary
// (callers surface it in the PASS detail), and a FAIL row otherwise.
//
// Only install-shims --force writes the suffix (displacing a real
// binary that occupied the shim path), and findRealBinary trusts it as
// the real PM for shim-dir paths — so a sibling that is not executable
// or that resolves back into the running veto binary means the ONLY
// on-disk copy of the real PM is gone. The self-reference test is
// isSelfReferential (main.go), the same identity check the resolver
// applies before exec'ing the sibling: doctor and the resolver must
// agree on which displaced files are trustworthy.
func checkDisplacedShimSibling(shimPath string) (*checkResult, string) {
	displaced := shimPath + displacedSuffix
	if _, err := os.Lstat(displaced); err != nil {
		return nil, "" // no displacement at this shim; nothing to verify
	}
	name := filepath.Base(shimPath)
	if !isExecutableRegularOrSymlink(displaced) {
		return &checkResult{
			status:   statusFail,
			label:    "shim:" + name,
			detail:   displaced + " exists but is not an executable binary — displaced original unusable, real " + name + " unreachable",
			howToFix: "Restore a working " + name + " at " + displaced + " (reinstall the tool), then re-run `veto doctor`.",
		}, ""
	}
	if isSelfReferential(displaced) {
		return &checkResult{
			status:   statusFail,
			label:    "shim:" + name,
			detail:   displaced + " resolves back to the veto binary — real " + name + " lost (resolving it would loop veto into itself)",
			howToFix: "Restore the real " + name + " at " + displaced + " (reinstall the tool), then re-run `veto install-shims --force`.",
		}, ""
	}
	return nil, displaced
}

// checkStaleShimSiblings scans the Layer 2 shim dir for any
// `*.veto-original` entries. Each one produces a FAIL row naming the
// exact path; this matches the severity of other Layer 2 invariants
// (shim-not-a-symlink also FAILs in checkShimDir above). The fix
// suggestion routes through `veto install-all` (or `veto install-shims`)
// because the convergence pass at the top of install-shims scrubs
// these siblings every run — no separate recovery command needed.
func checkStaleShimSiblings(shimDir string) []checkResult {
	entries, err := os.ReadDir(shimDir)
	if err != nil {
		// Missing shim dir is not a finding here; checkShimDir's own
		// PATH check (above) handles "shim dir absent" explicitly.
		// Any other read error means we cannot enforce the invariant —
		// surface it as a WARN with the failure detail so the user
		// can fix permissions, then re-run doctor.
		if os.IsNotExist(err) {
			return nil
		}
		return []checkResult{{
			status:   statusWarn,
			label:    "shim-dir scan",
			detail:   "read " + shimDir + ": " + err.Error(),
			howToFix: "Fix perms on the shim dir, then re-run `veto doctor`.",
		}}
	}
	var out []checkResult
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".veto-original") {
			continue
		}
		full := filepath.Join(shimDir, name)
		out = append(out, checkResult{
			status:   statusFail,
			label:    "shim sibling:" + name,
			detail:   full + " exists but Layer 2 shim dirs must not have .veto-original siblings",
			howToFix: "Run `veto install-all` (or `veto install-shims`) to scrub stale siblings.",
		})
	}
	return out
}

// checkShellIntegration confirms veto's managed shell-rc block is installed
// in the current user's likely interactive shell rc files. This is the block
// that pins ~/.local/bin ahead of mise/asdf/pyenv/nvm and wires shell-only
// pip/uv package-age quarantine wrappers.
func checkShellIntegration() checkResult {
	targets, err := defaultShellIntegrationTargets()
	if err != nil {
		return checkResult{
			status:   statusWarn,
			label:    "shell integration",
			detail:   "could not detect shell rc targets: " + err.Error(),
			howToFix: "Run `veto install-shell --shell-rc PATH` for your shell rc.",
		}
	}

	var missing []string
	var present []string
	for _, target := range targets {
		exists, malformed, err := managedBlockStatus(target.path, shellMarkerStart, shellMarkerEnd)
		if os.IsNotExist(err) {
			missing = append(missing, target.path)
			continue
		}
		if err != nil {
			return checkResult{
				status:   statusFail,
				label:    "shell integration",
				detail:   "read " + target.path + ": " + err.Error(),
				howToFix: "Fix rc file permissions, then run `veto install-shell`.",
			}
		}
		if malformed {
			return checkResult{
				status:   statusFail,
				label:    "shell integration",
				detail:   "managed block markers are incomplete in " + target.path,
				howToFix: "Remove the partial block and run `veto install-shell`.",
			}
		}
		if exists {
			present = append(present, target.path)
		} else {
			missing = append(missing, target.path)
		}
	}
	if len(missing) > 0 {
		return checkResult{
			status:   statusWarn,
			label:    "shell integration",
			detail:   "managed block missing from " + strings.Join(missing, ", "),
			howToFix: "Run `veto install-shell`.",
		}
	}
	return checkResult{
		status: statusPass,
		label:  "shell integration",
		detail: strings.Join(present, ", "),
	}
}

// detectVersionManager classifies a shadowing path by which version
// manager owns it. Returns "" when the path doesn't look like a
// known version-manager dir, in which case the caller falls back to
// the generic reorder advice. Today we name mise explicitly because
// it's the documented motivating case; asdf and pyenv follow the
// same recipe so we recognize them too.
func detectVersionManager(shadowPath string) string {
	// Substring matches catch both shim dirs (.../mise/shims/<pm>) and
	// install dirs (.../mise/installs/<tool>/<v>/bin/<pm>). The user's
	// reported failure was in installs/, but newer mise modes also
	// expose shims/ — handle both with one match.
	switch {
	case strings.Contains(shadowPath, "/mise/installs/"),
		strings.Contains(shadowPath, "/mise/shims/"):
		return "mise"
	case strings.Contains(shadowPath, "/.asdf/installs/"),
		strings.Contains(shadowPath, "/.asdf/shims/"):
		return "asdf"
	case strings.Contains(shadowPath, "/.pyenv/shims/"),
		strings.Contains(shadowPath, "/.pyenv/versions/"):
		return "pyenv"
	case strings.Contains(shadowPath, "/.nvm/versions/"),
		strings.Contains(shadowPath, "/nvm/versions/node/"):
		// `.nvm/` is the home-dir install; some setups use a system-wide
		// nvm install whose path still ends in `versions/node/<v>/bin`.
		return "nvm"
	}
	return ""
}

// earlierRealBinary returns the path of a real `name` binary earlier in
// PATH than the shim dir, or "" if none. Used to detect when a shim is
// silently shadowed by mise/homebrew.
func earlierRealBinary(name string, pathParts []string, shimIdx int) string {
	for i := 0; i < shimIdx; i++ {
		candidate := filepath.Join(pathParts[i], name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		// Don't flag if the earlier entry is itself a veto-pointing
		// symlink (some users wire a system-wide veto outside ~/.local/bin).
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil {
			if strings.Contains(resolved, "veto") {
				continue
			}
		}
		return candidate
	}
	return ""
}

// checkClaudeHook reads ~/.claude/settings.json and confirms a veto
// hook entry exists under PreToolUse[Bash][hooks]. WARN (not FAIL) when
// settings.json itself is missing — the user may legitimately not run
// Claude Code.
func checkClaudeHook() checkResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return checkResult{status: statusWarn, label: "Claude hook", detail: "cannot resolve home: " + err.Error()}
	}
	path := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return checkResult{
			status:   statusWarn,
			label:    "Claude hook",
			detail:   path + " not present (Claude Code not configured?)",
			howToFix: "If you use Claude Code, run `veto install-claude-hook`.",
		}
	}
	if err != nil {
		return checkResult{status: statusFail, label: "Claude hook", detail: "read settings: " + err.Error()}
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return checkResult{
			status:   statusFail,
			label:    "Claude hook",
			detail:   "settings.json failed to parse: " + err.Error(),
			howToFix: "Fix the JSON syntax in " + path + " before running install-claude-hook.",
		}
	}
	if hasVetoClaudeHook(settings) {
		return checkResult{status: statusPass, label: "Claude hook", detail: path}
	}
	return checkResult{
		status:   statusFail,
		label:    "Claude hook",
		detail:   "no veto hook entry in " + path,
		howToFix: "Run `veto install-claude-hook`.",
	}
}

// hasVetoClaudeHook walks the settings tree looking for a Bash
// PreToolUse hook whose command references veto. We match by
// substring rather than exact command shape so old python-shebang
// installs (`/path/veto-hook.py`) and new in-binary installs
// (`/path/veto hook claude-code`) both register as "the gate is wired."
func hasVetoClaudeHook(settings map[string]any) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	pre, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	for _, raw := range pre {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if matcher, _ := entry["matcher"].(string); matcher != "Bash" {
			continue
		}
		inner, _ := entry["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			cmd, _ := hm["command"].(string)
			if isDoctorVetoHookCommand(cmd) {
				return true
			}
		}
	}
	return false
}

// isDoctorVetoHookCommand recognises any command string we'd accept
// as "this hook routes through veto." Kept here (not in a shared
// helper) to avoid a dependency on a sister file that may move during
// the project's ongoing refactoring.
func isDoctorVetoHookCommand(cmd string) bool {
	if cmd == "" {
		return false
	}
	if strings.Contains(cmd, "veto hook claude-code") {
		return true
	}
	if strings.Contains(cmd, "veto-hook.py") {
		return true
	}
	if strings.HasSuffix(cmd, "/veto-hook") {
		return true
	}
	return false
}

// checkCodexPosture confirms Codex agent shells will inherit a PATH that can
// reach veto's shims. Codex has no per-tool hook, so this is the enforceable
// local posture check for that agent.
func checkCodexPosture() checkResult {
	report, err := inspectCodexEnv()
	if err != nil {
		return checkResult{
			status:   statusWarn,
			label:    "Codex PATH policy",
			detail:   "cannot inspect Codex config: " + err.Error(),
			howToFix: "Run `veto install-codex` and confirm Codex agent shells inherit the veto shim PATH.",
		}
	}
	return codexPostureResult(report)
}

func codexPostureResult(report codexEnvReport) checkResult {
	if !report.ConfigExists {
		return checkResult{status: statusPass, label: "Codex PATH policy", detail: "no config; Codex inherits shell PATH by default"}
	}
	if !report.HasShellPolicy {
		return checkResult{status: statusPass, label: "Codex PATH policy", detail: "no shell_environment_policy; Codex inherits shell PATH"}
	}
	switch report.InheritMode {
	case "", "all":
		return checkResult{status: statusPass, label: "Codex PATH policy", detail: "inherit=all; user PATH carries through"}
	case "core":
		if report.HasUserPathEntry {
			return checkResult{
				status:   statusWarn,
				label:    "Codex PATH policy",
				detail:   "inherit=core, but policy mentions PATH; confirm the shim dir is first inside Codex",
				howToFix: "Inside a fresh Codex session, run `which npm`; it should resolve under ~/.local/bin.",
			}
		}
		return checkResult{
			status:   statusFail,
			label:    "Codex PATH policy",
			detail:   "inherit=core strips the user PATH before Codex agent shells run",
			howToFix: "Set `[shell_environment_policy].inherit = \"all\"` or add a PATH policy that prepends ~/.local/bin, then restart Codex.",
		}
	default:
		return checkResult{
			status:   statusWarn,
			label:    "Codex PATH policy",
			detail:   "unrecognized inherit value: " + report.InheritMode,
			howToFix: "Run `veto install-codex`, then verify `which npm` inside a Codex session points at the veto shim dir.",
		}
	}
}

// checkCursorPosture reports whether the current project has veto's Cursor
// rule. Cursor's global user-rule state is stored in private app data, so doctor
// only verifies the project rule it can safely inspect.
func checkCursorPosture() checkResult {
	cwd, err := os.Getwd()
	if err != nil {
		return checkResult{status: statusWarn, label: "Cursor rule", detail: "cannot resolve current project: " + err.Error()}
	}
	return cursorPostureResult(cwd)
}

func cursorPostureResult(projectDir string) checkResult {
	rulePath := filepath.Join(projectDir, ".cursor", "rules", "veto.mdc")
	data, err := os.ReadFile(rulePath)
	if os.IsNotExist(err) {
		return checkResult{
			status:   statusWarn,
			label:    "Cursor rule",
			detail:   "project rule not installed at " + rulePath,
			howToFix: "Run `veto install-cursor --project-dir " + projectDir + "`; add the same rule manually to Cursor User Rules for global coverage.",
		}
	}
	if err != nil {
		return checkResult{status: statusFail, label: "Cursor rule", detail: "read " + rulePath + ": " + err.Error()}
	}
	if !isVetoCursorRule(string(data)) {
		return checkResult{
			status:   statusFail,
			label:    "Cursor rule",
			detail:   rulePath + " exists but does not look like a veto rule",
			howToFix: "Run `veto install-cursor --project-dir " + projectDir + " --force` to replace it.",
		}
	}
	return checkResult{status: statusPass, label: "Cursor rule", detail: rulePath + " installed; global User Rules remain manually inspectable only"}
}

func isVetoCursorRule(text string) bool {
	return strings.Contains(text, "veto") && strings.Contains(text, "package-manager")
}

// checkSirenePosture confirms the current shell environment that would launch
// Sirene can reach veto's shim dir. Sirene inherits its parent process PATH, so
// this is the inspectable local posture check.
func checkSirenePosture() checkResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return checkResult{status: statusWarn, label: "Sirene launch PATH", detail: "cannot resolve home: " + err.Error()}
	}
	shimDir, err := defaultShellShimDir()
	if err != nil {
		return checkResult{status: statusWarn, label: "Sirene launch PATH", detail: "cannot resolve shim dir: " + err.Error()}
	}
	return sirenePostureResult(home, shimDir, os.Getenv("PATH"))
}

func sirenePostureResult(home, shimDir, pathEnv string) checkResult {
	detected := executableOnPath("sirene", pathEnv) != "" || pathExists(filepath.Join(home, ".sirene"))
	if !pathListContains(pathEnv, shimDir) {
		status := statusWarn
		detail := "shim dir is not on current PATH"
		if detected {
			status = statusFail
			detail = "Sirene detected, but shim dir is not on current PATH"
		}
		return checkResult{
			status:   status,
			label:    "Sirene launch PATH",
			detail:   detail,
			howToFix: "Run `veto install-shell`, open a new terminal, and launch Sirene from that shell.",
		}
	}
	if !detected {
		return checkResult{status: statusPass, label: "Sirene launch PATH", detail: "Sirene not detected; current PATH includes veto shim dir if you launch it later"}
	}
	return checkResult{status: statusPass, label: "Sirene launch PATH", detail: "current launch PATH includes veto shim dir"}
}

func executableOnPath(name, pathEnv string) string {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}

func pathListContains(pathEnv, want string) bool {
	for _, p := range filepath.SplitList(pathEnv) {
		if absEqual(p, want) {
			return true
		}
	}
	return false
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// isSIPProtectedPath returns true on macOS when path is under a
// System Integrity Protection root (/usr/bin, /usr/sbin, /bin, /sbin,
// /System/...). dyld strips DYLD_INSERT_LIBRARIES from SIP-protected
// binaries and the directories themselves are read-only, so neither
// Layer 3 (interposer) nor Layer 4 (wrappers) can cover them. On Linux
// this always returns false — SIP does not exist there.
func isSIPProtectedPath(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	clean := filepath.Clean(path)
	for _, prefix := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/System/"} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

// checkInterposer validates the native-interposer layer. Three checks:
//   - the preload env var (DYLD_INSERT_LIBRARIES / LD_PRELOAD) is set;
//   - VETO_PATH is set and points at the veto binary;
//   - the dylib file the env var references actually exists.
//
// These are WARN (not FAIL) because layer 3 is opt-in — users can
// legitimately ship without it and rely on layers 1+2.
func checkInterposer() []checkResult {
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	preload := os.Getenv(envVar)
	vetoPath := os.Getenv("VETO_PATH")

	out := []checkResult{}
	if preload == "" {
		out = append(out, checkResult{
			status:   statusWarn,
			label:    "interposer env",
			detail:   envVar + " is NOT set",
			howToFix: "Run `veto install-preload --lib ./libveto_interpose.* --shell-rc auto` to wire layer 3.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "interposer env",
			detail: envVar + "=" + preload,
		})
		// Library file should exist and be readable.
		if _, err := os.Stat(preload); err != nil {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "interposer library",
				detail:   "stat " + preload + ": " + err.Error(),
				howToFix: "Rebuild with `make interposer` and reinstall.",
			})
		} else {
			out = append(out, checkResult{
				status: statusPass,
				label:  "interposer library",
				detail: preload,
			})
		}
	}
	if preload != "" && vetoPath == "" {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "VETO_PATH env",
			detail:   "interposer is loaded but VETO_PATH is unset; interposer can't reach the gate",
			howToFix: "Re-run `veto install-preload --shell-rc auto`.",
		})
	} else if vetoPath != "" {
		out = append(out, checkResult{
			status: statusPass,
			label:  "VETO_PATH env",
			detail: vetoPath,
		})
	}
	return out
}

// checkWrappers validates the Layer 4 real-binary wrappers as a per-PM
// survey of the actual host, not an all-or-nothing summary line. The
// flow has three phases:
//
//  1. State drift. Walk every entry in wrappers.json: verify the
//     symlink is still present, still points at veto, and the
//     .veto-original sibling still exists. Any drift FAILs the entry
//     individually; healthy entries also emit a per-PM PASS line so
//     wraps in custom --dir locations stay visible. Record paths
//     covered by state for dedup against the host-survey phase.
//
//  2. Per-PM host survey. For each PM in pmlist.Wrapped, look for an
//     install at the well-known absolute-path roots (homebrew prefix,
//     /usr/local/bin, mise installs, asdf installs, ~/.bun/bin) and
//     in $PATH (skipping known shim/version-manager dirs so we
//     don't double-count Layer-2 shims as Layer-4 candidates).
//     Per location:
//
//     - wrapped (symlink → veto + .veto-original sibling): PASS;
//     - real binary or non-veto symlink:                    WARN;
//     - no install of this PM on the host:                  N/A
//     (one N/A line per PM, only when state has no wrap
//     either — otherwise the PASS from state covers it).
//
//  3. Generic Layer-4 WARN. ONLY emitted when state is empty AND
//     the survey found at least one unwrapped install — i.e. there
//     is something worth wrapping but nothing wrapped. The example
//     path/env var in that message is platform-aware (linux:
//     LD_PRELOAD + /usr/local/bin; darwin-arm64: DYLD + /opt/homebrew/bin;
//     darwin-amd64: DYLD + /usr/local/bin) so Linux users never see
//     "/opt/homebrew/bin/npm" misadvice.
//
// Removed: the static "Layer 4 not installed" WARN that fired whenever
// state was empty, regardless of host. That line hardcoded a darwin
// path in Linux output and gave no signal on hosts where no PMs were
// installed in known absolute-path roots.
func checkWrappers(cfg config) []checkResult {
	// Thin shim: resolve the veto identity, then delegate to
	// checkWrappersWith. Tests construct their own VetoIdentity against a
	// planted veto binary in a tempdir and call checkWrappersWith
	// directly — that's why the resolveVetoBinary call lives here, not
	// inside the worker.
	vetoPath, vetoErr := resolveVetoBinary()
	var vetoID *pmsurvey.VetoIdentity
	if vetoErr == nil {
		id, idErr := pmsurvey.VetoIdentityFor(vetoPath)
		if idErr != nil {
			vetoErr = idErr
		} else {
			vetoID = id
		}
	}
	return checkWrappersWith(cfg, vetoID, vetoErr)
}

// checkWrappersWith is the worker. checkWrappers is the production
// entrypoint that constructs vetoID via resolveVetoBinary; tests build
// their own identity against a planted veto binary in a tempdir so
// classifications are deterministic regardless of where the test
// binary lives.
func checkWrappersWith(cfg config, vetoID *pmsurvey.VetoIdentity, vetoErr error) []checkResult {
	state, err := loadWrapperState(cfg)
	if err != nil {
		return []checkResult{{
			status:   statusFail,
			label:    "wrapper state",
			detail:   "load wrapper state: " + err.Error(),
			howToFix: "Inspect " + filepath.Join(cfg.CacheDir, stateFileName) + " — JSON may be corrupted.",
		}}
	}

	out := []checkResult{}
	// Paths already reported by the state-drift phase. The host
	// survey skips any path in this set so we don't get duplicate
	// lines for one binary.
	coveredByState := map[string]bool{}

	// Phase 1: state-drift loop. Preserved semantics from the prior
	// implementation; the new bit is the per-entry PASS line so
	// --dir installs are visible.
	for _, w := range state.Wrappers {
		coveredByState[w.Path] = true
		info, err := os.Lstat(w.Path)
		if err != nil {
			out = append(out, checkResult{
				status: statusFail,
				label:  "wrapper:" + w.PM,
				detail: fmt.Sprintf("%s gone — upgrade may have removed it", w.Path),
				howToFix: "Re-run `veto install-wrappers` to restore. Toolchain upgrades " +
					"(brew, mise install) wipe wrapper symlinks; this is expected.",
			})
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "wrapper:" + w.PM,
				detail:   fmt.Sprintf("%s is no longer a symlink — wrapper has been replaced by a real binary (likely after upgrade)", w.Path),
				howToFix: "Re-run `veto install-wrappers --force` to re-wrap.",
			})
			continue
		}
		// Classifier-driven identity check. The prior version used
		// strings.Contains(target, "veto") which accepted any symlink
		// whose name happened to contain "veto" — so a previous-tool
		// wrapper (the "bouncer" case) read as "subverted" with no
		// actionable detail. ClassifySymlink uses SHA-256 of the target
		// against the running veto binary, distinguishing broken /
		// foreign / ours-by-path / ours-by-hash explicitly.
		if vetoID == nil {
			// Survey degraded due to vetoErr; fall through (the WARN below
			// surfaces it). Leave this entry's healthy-PASS to follow.
		} else {
			class, target, classErr := pmsurvey.ClassifySymlink(w.Path, vetoID)
			if classErr != nil {
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + w.PM,
					detail:   fmt.Sprintf("%s: classify error — %v", w.Path, classErr),
					howToFix: "Re-run `veto doctor` after resolving the I/O error; if the path is on an unusual filesystem, check permissions.",
				})
				continue
			}
			switch class {
			case pmsurvey.ClassOursByPath, pmsurvey.ClassOursByHash:
				// Healthy by classification; fall through to the OriginalPath
				// stat check below.
			case pmsurvey.ClassBrokenSymlink:
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + w.PM,
					detail:   fmt.Sprintf("%s is a broken symlink to %s — wrapper target vanished (likely a previous wrapper tool's leftover)", w.Path, target),
					howToFix: "Delete the broken symlink. If a sibling `<path>.veto-original` exists, restore it to the original name. Then re-run `veto install-wrappers`.",
				})
				continue
			case pmsurvey.ClassForeignWrapper:
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + w.PM,
					detail:   fmt.Sprintf("%s is a symlink to %s, which is not the veto binary — a foreign wrapper from another tool is installed at this path", w.Path, target),
					howToFix: "Delete the symlink. If a sibling `<path>.veto-original` exists (e.g. `.bouncer-original`), restore it to the original name. Then re-run `veto install-wrappers`.",
				})
				continue
			case pmsurvey.ClassPMLayoutSymlink:
				// State says we wrapped this path, but the current
				// symlink resolves to a package-manager install (Cellar,
				// mise, etc.) — almost always the result of a brew /
				// mise upgrade reinstalling the canonical layout on top
				// of our wrap. Routine; install-all heals it.
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + w.PM,
					detail:   fmt.Sprintf("%s now resolves to %s (canonical package-manager install) — wrapper was overwritten, likely by a package upgrade", w.Path, target),
					howToFix: "Run `veto install-all` (or `veto install-wrappers`) to re-wrap.",
				})
				continue
			case pmsurvey.ClassReal:
				// info.Mode()&ModeSymlink == 0 already short-circuited above,
				// so ClassReal should be unreachable here — but defend
				// against future refactors that loosen the early-out.
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + w.PM,
					detail:   fmt.Sprintf("%s is no longer a symlink — wrapper has been replaced by a real binary (likely after upgrade)", w.Path),
					howToFix: "Re-run `veto install-wrappers --force` to re-wrap.",
				})
				continue
			}
		}
		// Self-referential anchor guard. os.Stat below FOLLOWS the symlink,
		// so a `.veto-original` that itself points at the veto binary would
		// resolve to the still-present veto file and PASS — masking a
		// veto→veto exec loop (the real binary is gone). This is exactly the
		// state the 2026-07-08 brew-cleanup incident left behind, and the
		// reason doctor reported "0 failures" while the toolchain was broken.
		// Classify the anchor explicitly: a healthy anchor is a real binary
		// (ClassReal) or a Cellar/mise layout symlink (ClassPMLayoutSymlink),
		// never ours by identity. If it resolves to veto, FAIL loudly.
		if vetoID != nil {
			if aclass, _, aerr := pmsurvey.ClassifySymlink(w.OriginalPath, vetoID); aerr == nil {
				switch aclass {
				case pmsurvey.ClassOursByPath, pmsurvey.ClassOursByHash:
					out = append(out, checkResult{
						status:   statusFail,
						label:    "wrapper:" + w.PM,
						detail:   fmt.Sprintf("%s points at the veto binary itself — self-referential anchor, real binary lost (veto→veto exec loop)", w.OriginalPath),
						howToFix: "Restore the real binary at " + w.OriginalPath + " (reinstall the toolchain, or recreate the symlink to point at the real binary), then re-run `veto install-wrappers`.",
					})
					continue
				}
			}
		}
		if _, err := os.Stat(w.OriginalPath); err != nil {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "wrapper:" + w.PM,
				detail:   fmt.Sprintf("%s missing — wrapper would execute as veto with nothing to delegate to", w.OriginalPath),
				howToFix: "Run `veto install-all` (or `veto install-wrappers`) — the convergence pass at the top of install-wrappers prunes stale entries and re-wraps the live binary on the next run.",
			})
			continue
		}
		// Healthy entry: emit a per-PM PASS line. This matters for
		// --dir installs in custom locations; the prior single-line
		// "N/M healthy" summary hid them entirely.
		out = append(out, checkResult{
			status: statusPass,
			label:  "wrapper:" + w.PM,
			detail: fmt.Sprintf("%s (wrapped, original at %s)", w.Path, w.OriginalPath),
		})
	}

	// If we couldn't resolve the veto binary, the host survey can't
	// run reliably. Emit a single WARN and return whatever the
	// state-drift phase produced.
	if vetoErr != nil {
		out = append(out, checkResult{
			status:   statusWarn,
			label:    "real-binary wrappers",
			detail:   "cannot resolve veto binary for survey: " + vetoErr.Error(),
			howToFix: "Confirm the running veto is on a readable path; re-run `veto doctor`.",
		})
		return out
	}

	// Phase 2: per-PM host survey.
	anyUnwrappedFound := false
	firstUnwrappedPM := ""
	for _, pm := range pmlist.Wrapped {
		locations := pmsurvey.PathsFor(pm)
		seen := map[string]bool{}
		pmHadDiscovery := false
		for _, path := range locations {
			if seen[path] {
				continue
			}
			seen[path] = true
			if inShimDir(path) {
				// Layer-2 territory: the dedicated shim:<pm> checks own
				// this directory (symlink identity, PATH shadowing,
				// `.veto-displaced` validation). Surveying it as a
				// Layer-4 wrap site produced two lies: a PASS with a
				// fabricated "original at <path>.veto-original" detail
				// for a shim that has no such anchor, and a WARN
				// advising `veto install-wrappers` — advice
				// install-wrappers refuses to follow (territory guard,
				// install_wrappers.go). Skip without marking discovery:
				// "no absolute-path install" (N/A) is the truthful
				// Layer-4 verdict for a PM that only exists as a shim.
				continue
			}
			if coveredByState[path] {
				// Already reported by the state-drift phase; don't
				// double-report.
				pmHadDiscovery = true
				continue
			}
			class, target, classErr := pmsurvey.ClassifySymlink(path, vetoID)
			if classErr != nil {
				out = append(out, checkResult{
					status:   statusWarn,
					label:    "wrapper:" + pm,
					detail:   fmt.Sprintf("%s: classify error — %v", path, classErr),
					howToFix: "Re-run `veto doctor` after resolving the I/O error.",
				})
				pmHadDiscovery = true
				continue
			}
			pmHadDiscovery = true
			switch class {
			case pmsurvey.ClassOursByPath:
				if alias := discoveredAliasPassRow(pm, path); alias != nil {
					out = append(out, *alias)
					continue
				}
				if bad := discoveredAnchorFailure(pm, path, vetoID); bad != nil {
					out = append(out, *bad)
					continue
				}
				out = append(out, checkResult{
					status: statusPass,
					label:  "wrapper:" + pm,
					detail: fmt.Sprintf("%s (wrapped, original at %s%s)", path, path, wrapperSuffix),
				})
				continue
			case pmsurvey.ClassOursByHash:
				if alias := discoveredAliasPassRow(pm, path); alias != nil {
					out = append(out, *alias)
					continue
				}
				if bad := discoveredAnchorFailure(pm, path, vetoID); bad != nil {
					out = append(out, *bad)
					continue
				}
				out = append(out, checkResult{
					status: statusPass,
					label:  "wrapper:" + pm,
					detail: fmt.Sprintf("%s (wrapped via hash-identified veto at %s, original at %s%s)", path, target, path, wrapperSuffix),
				})
				continue
			case pmsurvey.ClassBrokenSymlink:
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + pm,
					detail:   fmt.Sprintf("%s is a broken symlink to %s — likely a previous wrapper tool's leftover", path, target),
					howToFix: "Delete the broken symlink. If a sibling `<path>.veto-original` exists, restore it. Then re-run `veto install-wrappers`.",
				})
				continue
			case pmsurvey.ClassForeignWrapper:
				out = append(out, checkResult{
					status:   statusFail,
					label:    "wrapper:" + pm,
					detail:   fmt.Sprintf("%s is a symlink to %s — foreign wrapper, not veto", path, target),
					howToFix: "Delete the symlink. If a sibling `<path>.veto-original` exists, restore it. Then re-run `veto install-wrappers`.",
				})
				continue
			case pmsurvey.ClassPMLayoutSymlink:
				// Symlink into a known package-manager install dir
				// (Homebrew Cellar, mise install tree, npm-cli.js, etc.).
				// Wrappable by default — emit the same "NOT wrapped"
				// WARN as a regular file: install-wrappers will wrap it
				// without --force.
				if !anyUnwrappedFound {
					firstUnwrappedPM = pm
				}
				anyUnwrappedFound = true
				out = append(out, checkResult{
					status:   statusWarn,
					label:    "wrapper:" + pm,
					detail:   fmt.Sprintf("%s (canonical package-manager symlink → %s; NOT wrapped — run veto install-wrappers)", path, target),
					howToFix: "Run `veto install-wrappers` (or `veto install-all`) to wrap this binary so absolute-path invocations route through veto.",
				})
				continue
			case pmsurvey.ClassReal:
				if isSIPProtectedPath(path) {
					out = append(out, checkResult{
						status: statusNotApplicable,
						label:  "wrapper:" + pm,
						detail: fmt.Sprintf("%s (SIP-protected — no defense layer can cover this)", path),
					})
					// SIP paths are not "unwrapped" — they're
					// unwrappable. Don't bump anyUnwrappedFound;
					// the generic Layer-4 WARN must not count them.
					continue
				}
				// Fall through to the WARN "NOT wrapped" emit below.
			}
			// Not wrapped: real binary. The absolute-path invocation skips
			// the gate.
			if !anyUnwrappedFound {
				firstUnwrappedPM = pm
			}
			anyUnwrappedFound = true
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "wrapper:" + pm,
				detail:   fmt.Sprintf("%s (NOT wrapped — run veto install-wrappers)", path),
				howToFix: "Run `veto install-wrappers` to wrap this binary so absolute-path invocations route through veto.",
			})
		}
		// No install of this PM anywhere on the host AND no state
		// entry covering it: emit a single N/A line so the user sees
		// the doctor actually surveyed this PM.
		if !pmHadDiscovery {
			pmCovered := false
			for _, w := range state.Wrappers {
				if w.PM == pm {
					pmCovered = true
					break
				}
			}
			if !pmCovered {
				out = append(out, checkResult{
					status: statusNotApplicable,
					label:  "wrapper:" + pm,
					detail: "no absolute-path install detected on this host",
				})
			}
		}
	}

	// Phase 3: generic Layer-4 WARN. Only when nothing is wrapped
	// (state empty) AND something could be (the survey found at
	// least one unwrapped install). Otherwise the per-PM WARN lines
	// already make the situation visible, and a generic header is
	// noise.
	if len(state.Wrappers) == 0 && anyUnwrappedFound {
		examplePath, envVar := layer4ExampleHints(firstUnwrappedPM)
		out = append(out, checkResult{
			status: statusWarn,
			label:  "real-binary wrappers",
			detail: fmt.Sprintf("Layer 4 not installed — absolute-path invocations like %s bypass the gate", examplePath),
			howToFix: "Run `veto install-wrappers` to wrap PM binaries with veto symlinks. " +
				"This catches `subprocess.run([abs_path, ...])` even when " + envVar + " is unset.",
		})
	}

	return out
}

// discoveredAliasPassRow returns a PASS row when path is a plain alias
// into a wrapped SAME-DIR sibling (pyenv `python -> python3.10`, bun
// `bunx -> /abs/dir/bun`), or nil when path is not such an alias.
//
// These aliases have no `.veto-original` of their own BY DESIGN:
// discovery deliberately keeps them plain (aliasInheritsSiblingWrap —
// wrapping one would manufacture a self-referential anchor), and the
// resolver follows them through the sibling's wrap at runtime
// (findWrappedOriginalViaChain). ClassifySymlink resolves the full
// chain alias -> sibling -> veto, so without this guard the
// discovered-anchor verification reads the alias as an orphaned
// wrapper — the false positive the 2026-07-24 live doctor run
// surfaced on ~/.bun/bin/bunx and pyenv's python/python3 aliases.
//
// The sibling's anchor is deliberately NOT validated here: the sibling
// is itself surveyed (or state-checked) and FAILs on its own row if
// orphaned. One defect, one row — the alias is not independently
// repairable, and duplicating the orphan FAIL onto every alias would
// turn a single broken anchor into N rows naming paths the user must
// not touch.
func discoveredAliasPassRow(pm, path string) *checkResult {
	target, ok := aliasSiblingWrapTarget(path)
	if !ok {
		return nil
	}
	return &checkResult{
		status: statusPass,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s (plain alias into wrapped sibling %s; inherits the wrap — no own anchor by design)", path, target),
	}
}

// discoveredAnchorFailure validates the `.veto-original` anchor behind
// a DISCOVERED veto-pointing symlink — one the Phase-2 host survey
// found but wrappers.json does not cover. Returns nil when the anchor
// holds a healthy real binary; otherwise a FAIL row.
//
// The survey used to emit PASS with a detail string naming
// "<path>.veto-original" WITHOUT ever stat-ing that anchor — trusting
// symlink direction alone. An orphaned wrapper (veto symlink on disk,
// anchor pruned, no registry entry — the live /usr/local/bin/npm case
// from the 2026-07-24 incident) therefore surveyed all-green while the
// real binary was unreachable. This is the discovered-path mirror of
// the state-phase anchor classification in checkWrappersWith: missing
// / non-executable anchors and anchors that classify as veto itself
// (self-referential — a veto→veto exec loop) both mean the wrapper has
// nothing real to delegate to.
//
// Classification errors on an existing, executable anchor are treated
// as healthy, matching the state-phase prior art — an I/O hiccup on
// the hash pass must not convert a working wrapper into a FAIL.
func discoveredAnchorFailure(pm, path string, vetoID *pmsurvey.VetoIdentity) *checkResult {
	anchor := path + wrapperSuffix
	fail := &checkResult{
		status: statusFail,
		label:  "wrapper:" + pm,
		detail: fmt.Sprintf("%s is an orphaned wrapper: points at veto but its .veto-original anchor is missing/self-referential — real binary unreachable", path),
		howToFix: "Restore the real binary (reinstall the toolchain, or recreate " + anchor +
			" pointing at it) or delete the orphaned symlink, then re-run `veto install-wrappers`.",
	}
	if !isExecutableRegularOrSymlink(anchor) {
		return fail
	}
	if vetoID != nil {
		if aclass, _, aerr := pmsurvey.ClassifySymlink(anchor, vetoID); aerr == nil {
			switch aclass {
			case pmsurvey.ClassOursByPath, pmsurvey.ClassOursByHash:
				return fail
			}
		}
	}
	return nil
}

// layer4ExampleHints returns the platform-correct example path and
// preload env var name for the generic Layer-4 WARN. The static
// version of this message hardcoded /opt/homebrew/bin/npm and
// DYLD_INSERT_LIBRARIES, which was both unhelpful and misleading on
// Linux. firstUnwrappedPM is the first PM the survey found a
// real binary for; "" means the survey found nothing (fall back to
// "npm" so the message reads sensibly).
func layer4ExampleHints(firstUnwrappedPM string) (examplePath, envVar string) {
	pm := firstUnwrappedPM
	if pm == "" {
		pm = "npm"
	}
	switch runtime.GOOS {
	case "darwin":
		envVar = "DYLD_INSERT_LIBRARIES"
		if runtime.GOARCH == "arm64" {
			examplePath = "/opt/homebrew/bin/" + pm
		} else {
			examplePath = "/usr/local/bin/" + pm
		}
	default:
		// Linux and everything else: /usr/local/bin + LD_PRELOAD.
		envVar = "LD_PRELOAD"
		examplePath = "/usr/local/bin/" + pm
	}
	return examplePath, envVar
}

// checkIntel validates the malware-intel layer: the store can refresh,
// has data above the sanity floor, and each configured source is
// reachable. We use a short timeout because doctor must feel snappy;
// users running it as part of "did my install work?" expect <30s.
func checkIntel(logger zerolog.Logger, cfg config) []checkResult {
	out := []checkResult{}
	store, err := buildStore(logger, cfg)
	if err != nil {
		return append(out, checkResult{
			status:   statusFail,
			label:    "intel store",
			detail:   "build store: " + err.Error(),
			howToFix: "Check VETO_SOURCES is valid (default: aikido,datadog,openssf,osv,pypa; optional CVE feeds: ghsa, rustsec, govulndb, gemnasium).",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "intel refresh",
			detail:   err.Error(),
			howToFix: "Network connectivity issue? Try `veto sync` and check upstream feeds.",
		})
		return out
	}

	count := store.ReportCount()
	if count < minHealthyReportCount {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "intel store size",
			detail:   fmt.Sprintf("%d reports (floor: %d)", count, minHealthyReportCount),
			howToFix: "Run `veto sync` to rebuild; if it still shows low, upstream feeds may be broken.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "intel store size",
			detail: fmt.Sprintf("%d reports across %d sources", count, len(store.SourceIDs())),
		})
	}
	// Per-source integrity: a damaged (source, ecosystem) bucket means the
	// gate for that ecosystem is missing coverage. doctor is the "did my
	// install work?" entry point, so surface it as a distinct failing row.
	if damaged := store.Damaged(); len(damaged) > 0 {
		details := make([]string, 0, len(damaged))
		for _, d := range damaged {
			details = append(details, fmt.Sprintf("%s/%s: %s (got %d, baseline %d)", d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline))
		}
		out = append(out, checkResult{
			status:   statusFail,
			label:    "intel source integrity",
			detail:   strings.Join(details, "; "),
			howToFix: "Restore network and run `veto sync`. If a feed legitimately shrank, remove the baseline file (~/.cache/veto/intel-baseline.json) and re-sync.",
		})
	} else {
		out = append(out, checkResult{status: statusPass, label: "intel source integrity", detail: "all sources verified"})
	}
	// Cache freshness — each source's cache dir contains files; the
	// newest mtime is "last refreshed." 24h is the staleness window.
	if freshness, ok := newestCacheMtime(cfg.CacheDir); ok {
		age := time.Since(freshness)
		switch {
		case age < 24*time.Hour:
			out = append(out, checkResult{status: statusPass, label: "intel freshness", detail: freshness.Format(time.RFC3339)})
		case age < 7*24*time.Hour:
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "intel freshness",
				detail:   fmt.Sprintf("last refreshed %s (%s ago)", freshness.Format(time.RFC3339), age.Round(time.Hour)),
				howToFix: "Run `veto sync` to pull the latest feeds.",
			})
		default:
			out = append(out, checkResult{
				status:   statusFail,
				label:    "intel freshness",
				detail:   fmt.Sprintf("last refreshed %s — more than a week stale", freshness.Format(time.RFC3339)),
				howToFix: "Run `veto sync`.",
			})
		}
	}
	return out
}

// checkIOC validates the host-level IOC layer. With no ioc_sources configured
// (the default) the layer is inert, so we emit a single informational PASS and
// touch no network. When feeds are configured we refresh and report the
// indicator count. A refresh failure is WARN, not FAIL: IOC matching is a
// supplementary scan-time signal, not part of the install gate, so a degraded
// feed must not make doctor (or a gate) treat the install path as untrusted.
func checkIOC(logger zerolog.Logger, cfg config) checkResult {
	if len(cfg.IOCSources) == 0 {
		return checkResult{
			status: statusPass,
			label:  "ioc feeds",
			detail: "none configured (host-level IOC scanning off)",
		}
	}
	store := buildIOCStore(logger, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		return checkResult{
			status:   statusWarn,
			label:    "ioc refresh",
			detail:   err.Error(),
			howToFix: "Check VETO_IOC_SOURCES and any required key (e.g. VETO_ABUSECH_AUTH_KEY); try `veto sync`.",
		}
	}
	return checkResult{
		status: statusPass,
		label:  "ioc feeds",
		detail: fmt.Sprintf("%d indicators across %v", store.IndicatorCount(), store.SourceIDs()),
	}
}

// newestCacheMtime walks cfg.CacheDir and returns the newest non-dir file
// mtime. Used as the staleness clock — once a source writes its etag
// file or payload, the cache "version" is the time of that write.
func newestCacheMtime(dir string) (time.Time, bool) {
	var newest time.Time
	found := false
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !found || info.ModTime().After(newest) {
			newest = info.ModTime()
			found = true
		}
		return nil
	})
	return newest, found
}

// printVersionManagerFooters emits one recipe block per detected version
// manager whose shims are shadowing veto. Centralizing this here
// keeps the per-shim FAIL lines tight ("mise install at … shadows the
// veto shim") while still giving the user a single copy-pasteable
// fix to follow.
//
// We dedupe by manager: ten shadowed PMs from mise → one mise footer.
func printVersionManagerFooters(w io.Writer, results []checkResult) {
	seen := map[string]bool{}
	for _, r := range results {
		if r.status != statusFail {
			continue
		}
		for _, vm := range []string{"mise", "asdf", "pyenv", "nvm"} {
			if strings.HasPrefix(r.detail, vm+" install") || strings.HasPrefix(r.detail, vm+" shim") {
				if !seen[vm] {
					seen[vm] = true
					fmt.Fprint(w, versionManagerFooter(vm))
				}
			}
		}
	}
}

// versionManagerFooter returns the copy-pasteable recipe for the named
// version manager. Mise has the most detail because that's the one we
// actually field-tested; the others get a short pointer to the same
// pattern.
func versionManagerFooter(vm string) string {
	switch vm {
	case "mise":
		return `
─── mise PATH-ordering recipe ──────────────────────────────────────────

mise prepends its shim/install dir to PATH at ` + "`mise activate`" + ` time.
For veto's shims to win, let veto install its managed shell block after
your version-manager setup:

    veto install-shell

Trace of ` + "`npm install foo`" + `:
  1. shell → ~/.local/bin/npm  (veto shim)
  2. veto gates, allows
  3. veto's findRealBinary walks PATH, skips itself, hits mise's shim
  4. mise's shim resolves the project-pinned npm and exec's it

The managed block also installs the prompt hook that re-pins ~/.local/bin
when mise's chpwd hook re-prepends its own dirs after cd.

Verify with ` + "`veto doctor`" + ` — the shim:* FAIL lines should clear.
`
	case "asdf":
		return `
─── asdf PATH-ordering recipe ──────────────────────────────────────────
asdf prepends ~/.asdf/shims to PATH on activate. Run:
    veto install-shell
The same trace as the mise recipe applies; see that footer for details.
`
	case "pyenv":
		return `
─── pyenv PATH-ordering recipe ─────────────────────────────────────────
pyenv prepends ~/.pyenv/shims via ` + "`pyenv init`" + `. Run:
    veto install-shell
`
	case "nvm":
		return `
─── nvm PATH-ordering recipe ───────────────────────────────────────────
nvm prepends ~/.nvm/versions/node/<v>/bin via ` + "`nvm use`" + `. After every
` + "`nvm use`" + `, veto's shim dir must be re-prepended. Run:
    veto install-shell
`
	}
	return ""
}

// printResults renders the checklist with PASS/WARN/FAIL markers and a
// trailing how-to-fix hint where applicable. Colors are ANSI codes —
// most terminals handle them; piping to a non-TTY just shows the codes,
// which is acceptable (and grep-friendly).
func printResults(w io.Writer, results []checkResult) {
	fmt.Fprintln(w, "veto doctor — verifying defense layers and intel state")
	fmt.Fprintln(w)
	for _, r := range results {
		marker := "[\x1b[32mPASS\x1b[0m]"
		switch r.status {
		case statusWarn:
			marker = "[\x1b[33mWARN\x1b[0m]"
		case statusFail:
			marker = "[\x1b[31mFAIL\x1b[0m]"
		case statusNotApplicable:
			// Cyan [N/A] marker. Same column shape as the other
			// three so a grep -E '\[(PASS|WARN|FAIL|N/A)\]' stays
			// aligned. printResults never renders a fix arrow for
			// N/A — there's nothing to fix, the PM just isn't here.
			marker = "[\x1b[36mN/A\x1b[0m] "
		}
		fmt.Fprintf(w, "  %s  %-26s  %s\n", marker, r.label, r.detail)
		// Only PASS and N/A suppress the how-to-fix arrow. WARN/FAIL
		// always print one when a fix string is present.
		if r.howToFix != "" && r.status != statusPass && r.status != statusNotApplicable {
			fmt.Fprintf(w, "         → %s\n", r.howToFix)
		}
	}
}
