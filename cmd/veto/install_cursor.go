// Cursor IDE integration.
//
// Cursor does not expose a per-tool PreToolUse hook protocol analogous
// to Claude Code's. Two surfaces remain:
//
//  1. PATH shims (Layer 2). Cursor's agent mode runs shell commands in
//     the user's integrated terminal, which inherits the parent shell's
//     PATH. Once shims are installed, every `npm install foo` issued by
//     Cursor's agent goes through veto exactly as it would from any
//     other shell. Layers 3 and 4 (interposer + wrappers) cover the
//     absolute-path and env-stripped cases the same way they do for any
//     local agent.
//  2. Project rules. Cursor reads `.cursor/rules/*.mdc` files and
//     loads them into the model's context. `install-cursor` writes a
//     veto-aware rule that tells the model to prefix package-manager
//     install verbs with `veto`. This is a behavioral nudge, not
//     enforced — strictly weaker than the Claude Code hook, but the
//     best Cursor exposes today.
//
// We deliberately do NOT auto-edit Cursor's user-level settings.
// Cursor stores user-scope rules in its internal app state (sqlite /
// settings.json under ~/Library/Application Support/Cursor), and the
// schema there is private to Cursor and changes between releases.
// Touching it would be brittle and could corrupt user settings.
// Instead we print a copy-paste blob so the user can install the rule
// at user scope themselves via Cursor Settings → Rules.
//
// Background Agents (Cursor's cloud execution mode) are explicitly out
// of scope: they run in Cursor's containers, not on the user's machine,
// and no veto layer is installed there. The user-facing output flags
// this so colleagues don't assume Background Agent installs are gated.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// runInstallCursor implements install-cursor for project rules and PATH shims.
func runInstallCursor(logger zerolog.Logger, cfg config, args []string) int {
	fs := flag.NewFlagSet("install-cursor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	projectDir := fs.String("project-dir", "", "directory in which to write .cursor/rules/veto.mdc (default: current working directory)")
	skipShims := fs.Bool("skip-shims", false, "do not invoke install-shims (assume already done)")
	shimDir := fs.String("shim-dir", "", "passed through to install-shims as --dir")
	force := fs.Bool("force", false, "overwrite an existing .cursor/rules/veto.mdc and existing shims")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	fmt.Println("veto: wiring Cursor via PATH shims + project rule")
	fmt.Println()

	if !*skipShims {
		var shimArgs []string
		if *shimDir != "" {
			shimArgs = append(shimArgs, "--dir", *shimDir)
		}
		if *force {
			shimArgs = append(shimArgs, "--force")
		}
		if rc := runInstallShims(logger, cfg, shimArgs); rc != exitOK {
			return rc
		}
	} else {
		fmt.Println("  (skipping install-shims per --skip-shims)")
	}

	dir := *projectDir
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto: cannot resolve current working directory: %v\n", err)
			return exitInternal
		}
		dir = cwd
	}
	rulePath := filepath.Join(dir, ".cursor", "rules", "veto.mdc")

	fmt.Println()
	fmt.Printf("veto: writing %s\n", rulePath)
	if err := writeCursorRule(rulePath, *force); err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		fmt.Fprintln(os.Stderr, "  pass --force to overwrite an existing rule file.")
		return exitInternal
	}
	fmt.Println("  ✓ project rule installed")

	fmt.Println()
	fmt.Println("Next steps for Cursor coverage:")
	fmt.Println("  1. Restart Cursor (or reload the project) so the new rule is picked up.")
	fmt.Println("     Verify by running `which npm` in Cursor's integrated terminal — it")
	fmt.Println("     should point at your shim dir (default ~/.local/bin).")
	fmt.Println("  2. For GLOBAL (cross-project) coverage, open Cursor Settings → Rules →")
	fmt.Println("     User Rules and paste the body of the rule you just installed:")
	fmt.Printf("       cat %s\n", rulePath)
	fmt.Println("     Cursor stores user rules in its app settings, not in a file veto")
	fmt.Println("     can safely write to, so this step has to be manual.")
	fmt.Println("  3. For absolute-path / env-stripped subprocess coverage, install")
	fmt.Println("     Layers 3 and 4:")
	fmt.Println("       veto install-preload --lib /path/to/libveto_interpose.dylib")
	fmt.Println("       veto install-wrappers")
	fmt.Println("  4. CAVEAT — Cursor Background Agents run in Cursor's cloud, not on")
	fmt.Println("     your machine. veto does NOT protect Background Agent installs.")
	fmt.Println("     Use local agent mode for any task that may touch dependencies, or")
	fmt.Println("     audit the diff carefully before merging a Background Agent branch.")
	return exitOK
}

// cursorRuleBody is the .mdc rule veto writes into .cursor/rules/.
// Frontmatter follows Cursor's current convention (description / globs /
// alwaysApply). The body is plain markdown.
//
// alwaysApply: true means Cursor loads this rule into every conversation
// in the project, not just when matching a glob. That's what we want — a
// package install verb can show up regardless of which files are open.
const cursorRuleBody = `---
description: Always route package-manager installs through veto's package scan.
globs:
alwaysApply: true
---

# veto — package intelligence scan for installs

This project uses [veto](https://github.com/brynbellomy/veto), a
command-level scanner that checks package names against multiple
supply-chain feeds (Aikido, OpenSSF, OSV, PyPA; optional GHSA) before
allowing an install to run.

**Always** prefix package-manager install commands with ` + "`veto`" + `:

| Don't | Do |
| --- | --- |
| ` + "`npm install foo`" + ` | ` + "`veto npm install foo`" + ` |
| ` + "`yarn add bar`" + ` | ` + "`veto yarn add bar`" + ` |
| ` + "`pnpm add baz`" + ` | ` + "`veto pnpm add baz`" + ` |
| ` + "`bun add qux`" + ` | ` + "`veto bun add qux`" + ` |
| ` + "`pip install requests`" + ` | ` + "`veto pip install requests`" + ` |
| ` + "`uv pip install ...`" + ` | ` + "`veto uv pip install ...`" + ` |
| ` + "`poetry add ...`" + ` | ` + "`veto poetry add ...`" + ` |
| ` + "`pipx install ...`" + ` | ` + "`veto pipx install ...`" + ` |
| ` + "`pdm add ...`" + ` | ` + "`veto pdm add ...`" + ` |

Applies to: npm, pnpm, yarn, bun, npx, pnpx, bunx, pip, pip3, uv, uvx,
poetry, pipx, pdm.

If veto refuses an install, **do not** retry by editing this rule,
removing the shim, invoking the package manager via an alternate path,
or any other workaround. A refusal means the package matches a
known-malicious record. Stop, surface the refusal verbatim to the
user, and wait for explicit direction.

Read-only commands (` + "`npm list`" + `, ` + "`npm run <script>`" + `, ` + "`pip show`" + `,
` + "`yarn info`" + `, etc.) do not need the ` + "`veto`" + ` prefix — only install
verbs (` + "`install`" + `, ` + "`add`" + `, ` + "`i`" + `, ` + "`-g`" + ` global installs, etc.) need
to be gated.

Scripts in package.json that run install verbs internally should also be
gated: prefer ` + "`veto npm run setup`" + ` over ` + "`npm run setup`" + ` when the
script invokes a package manager.
`

// writeCursorRule writes the rule body to path atomically (tmpfile +
// rename), creating the parent .cursor/rules directory if needed. Refuses
// to overwrite an existing file unless force is set.
func writeCursorRule(path string, force bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.With(err, "create .cursor/rules dir")
	}
	if _, err := os.Stat(path); err == nil && !force {
		return errors.WithNew("file already exists").Set("path", path)
	} else if err != nil && !os.IsNotExist(err) {
		return errors.With(err, "stat existing rule")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(cursorRuleBody), 0o644); err != nil {
		return errors.With(err, "write tmp rule")
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.With(err, "rename tmp into place")
	}
	return nil
}
