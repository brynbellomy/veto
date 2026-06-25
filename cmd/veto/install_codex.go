// Codex CLI integration.
//
// Codex (codex-cli 0.130.x at time of writing) does not expose a per-tool
// PreToolUse hook protocol — `codex help` confirms there's no analogue
// to Claude Code's hooks. The only integration surface is PATH: the
// agent's spawned shell inherits whatever PATH the user's interactive
// shell exported, plus any modifications from
// `[shell_environment_policy]` in ~/.codex/config.toml.
//
// `veto install-codex` is therefore a guided wrapper around
// install-shims, plus a config inspection that warns when codex's
// `shell_environment_policy.inherit = "core"` would strip the user's
// PATH (which is where our shim dir lives) before the agent shell runs.
//
// We intentionally do NOT auto-edit ~/.codex/config.toml: TOML round-trip
// edits without losing comments require a real parser, and codex itself
// rewrites the file on settings changes. Print actionable instructions
// instead.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// runInstallCodex implements `veto install-codex [--dir DIR] [--force]`.
// Same flag shape as install-shims; we hand them through.
func runInstallCodex(logger zerolog.Logger, cfg config, args []string) int {
	fmt.Println("veto: wiring Codex CLI via PATH shims")
	fmt.Println()
	rc := runInstallShims(logger, cfg, args)
	if rc != exitOK {
		return rc
	}

	fmt.Println()
	fmt.Println("veto: checking Codex environment policy")
	report, err := inspectCodexEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not inspect codex config: %v\n", err)
	} else {
		printCodexReport(os.Stdout, report)
	}

	fmt.Println()
	fmt.Println("Next steps for Codex coverage:")
	fmt.Println("  1. Confirm `which npm` resolves to a path under your shim dir")
	fmt.Println("     (default ~/.local/bin/npm). If it resolves to mise/homebrew,")
	fmt.Println("     your PATH order is wrong — shim dir must come first.")
	fmt.Println("  2. Start a fresh Codex session; codex inherits the parent shell's PATH.")
	fmt.Println("  3. Inside that session run `npm install --version-check-only`")
	fmt.Println("     and confirm veto logs appear on stderr.")
	fmt.Println("  4. For direct child-process invocation coverage")
	fmt.Println("     (e.g. tools that exec /full/path/to/npm), see")
	fmt.Println("     `veto install-preload`.")
	return exitOK
}

// codexEnvReport summarizes the bits of ~/.codex/config.toml that
// determine whether our PATH modifications will reach the agent shell.
type codexEnvReport struct {
	ConfigPath       string
	ConfigExists     bool
	HasShellPolicy   bool
	InheritMode      string // empty when not set; "all"/"core" otherwise
	IgnoreDefaults   bool
	HasUserPathEntry bool // ${PATH} or "PATH" appears in set/include rules
}

// inspectCodexEnv does a best-effort line-level scan of ~/.codex/config.toml
// for the keys that matter. A full TOML parse is overkill — and we
// explicitly do not want to drag in a TOML dep for one config-inspection
// path. If a user has a multi-line or unusual layout, the report just
// shows fewer findings; the human-readable output is still actionable.
func inspectCodexEnv() (codexEnvReport, error) {
	report := codexEnvReport{}
	home, err := os.UserHomeDir()
	if err != nil {
		return report, errors.With(err, "resolve home dir")
	}
	report.ConfigPath = filepath.Join(home, ".codex", "config.toml")
	f, err := os.Open(report.ConfigPath)
	if os.IsNotExist(err) {
		return report, nil
	}
	if err != nil {
		return report, errors.With(err, "open codex config")
	}
	defer f.Close()
	report.ConfigExists = true

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	currentSection := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			if currentSection == "shell_environment_policy" {
				report.HasShellPolicy = true
			}
			continue
		}
		if currentSection != "shell_environment_policy" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "inherit":
			report.InheritMode = strings.Trim(value, `"`)
		case "ignore_default_excludes":
			report.IgnoreDefaults = strings.Contains(value, "true")
		case "set", "include_only":
			if strings.Contains(value, "PATH") {
				report.HasUserPathEntry = true
			}
		}
	}
	return report, scanner.Err()
}

// printCodexReport renders findings + concrete advice. The aim is: a
// colleague reading this output knows whether their codex sessions will
// actually see the veto shims.
func printCodexReport(w *os.File, report codexEnvReport) {
	if !report.ConfigExists {
		fmt.Fprintln(w, "  no ~/.codex/config.toml found — codex will inherit your shell PATH by default. ✓")
		return
	}
	fmt.Fprintf(w, "  found %s\n", report.ConfigPath)
	if !report.HasShellPolicy {
		fmt.Fprintln(w, "  no [shell_environment_policy] section — codex will inherit your shell PATH by default. ✓")
		return
	}
	switch report.InheritMode {
	case "", "all":
		fmt.Fprintln(w, "  shell_environment_policy.inherit = all (or unset) — your PATH carries through. ✓")
	case "core":
		fmt.Fprintln(w, "  ⚠  shell_environment_policy.inherit = \"core\" — codex will strip your PATH.")
		fmt.Fprintln(w, "      Codex starts each agent shell with a minimal PATH, so the shims you just")
		fmt.Fprintln(w, "      installed won't be reached. Either change inherit to \"all\", or set")
		fmt.Fprintln(w, "      a `set.PATH = \"$HOME/.local/bin:$PATH\"` entry under shell_environment_policy.")
	default:
		fmt.Fprintf(w, "  ⚠  shell_environment_policy.inherit = %q — unfamiliar value.\n", report.InheritMode)
		fmt.Fprintln(w, "      Manually confirm `which npm` inside a codex session resolves to your shim dir.")
	}
	if report.HasUserPathEntry {
		fmt.Fprintln(w, "  shell_environment_policy mentions PATH — confirm it points to the shim dir first.")
	}
}
