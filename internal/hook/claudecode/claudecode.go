// Package claudecode is the Go port of the Claude Code PreToolUse hook.
//
// It detects package-manager install commands inside a Bash tool call —
// including invocations wrapped in `timeout`, `xargs`, `env`, `sudo`,
// `bash -c "..."`, and chained with shell separators — and decides whether
// to deny the tool call and ask the agent to re-issue with a `veto`
// prefix.
//
// Why a Go port: the Python original is wired via a shebang. If `python3`
// is missing at hook-invocation time, Claude Code fails OPEN — the
// unguarded command runs. Compiling the analyzer into the same binary that
// the agent must already have for shim/preload defenses removes that
// failure mode entirely.
//
// The analyzer is structured as pure functions so it can be tested without
// hitting stdin/stdout. The transport layer (JSON in, JSON out) lives in
// the cmd/veto subcommand.
package claudecode

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
)

// Finding is the analyzer's verdict on a single Bash command. Empty PM
// means the command did not reach a covered package manager.
type Finding struct {
	PM     string   // package-manager binary name (e.g. "npm")
	Tokens []string // tokens of the leaf command, after wrapper-stripping
}

// isInterposerPM reports whether the basename is a PM name the hook /
// Layer-3 interposer recognises. Backed by pmlist.MatchesInterposer so
// the hook, the C interposer (via the generated pm_names.h + the
// versioned-python regex), the Layer-2 install-shims set, and the
// Layer-4 install-wrappers set all consume one source of truth — see
// internal/packagemanager/pmlist.
//
// The hook's set is a superset of install-shims' (it also recognises
// rush/rushx) because the hook just classifies "is this command
// risky?"; we don't install shims/wrappers for rush, but if a user's
// agent invokes rush directly we still want the install verbs gated.
//
// Versioned python aliases ("python3.10", "python3.12.1", …) match
// through the regex side of MatchesInterposer too — a Claude-issued
// `python3.12 -m pip install foo` must be classified as risky by the
// Layer-1 hook just like a bare `python -m pip install foo`.
func isInterposerPM(name string) bool {
	return pmlist.MatchesInterposer(name)
}

// isPythonInterpreter reports whether name is one of the python
// flavors the hook treats as a `-m <pm>` dispatcher. Includes the
// canonical "python" / "python3" set AND every `python3.X` versioned
// alias. Centralised so isRisky's python branch and the static map
// pythonInterpreters stay consistent.
func isPythonInterpreter(name string) bool {
	if _, ok := pythonInterpreters[name]; ok {
		return true
	}
	return pmlist.IsVersionedPython(name)
}

// pythonDashMTargets is the set of `-m <module>` names that, when
// invoked via `python -m <module> …`, are gated as package-manager
// calls. Bare python invocations (scripts, REPLs, `-c`, `-V`,
// `-m http.server`, `-m venv`, `-m unittest`, …) are not risky and
// pass through unchanged.
//
// Kept in sync with cmd/veto/main.go::pythonDashMTargets.
var pythonDashMTargets = map[string]struct{}{
	"pip": {}, "pip3": {}, "uv": {}, "pipx": {}, "poetry": {}, "pdm": {},
}

// pythonInterpreters is the set of basenames that map to the CPython
// interpreter for `-m` dispatch purposes.
var pythonInterpreters = map[string]struct{}{
	"python": {}, "python3": {},
}

// dangerousVerbs maps each PM to the verbs that resolve and fetch remote
// packages. A non-listed verb (e.g. `npm run`) is not an install and the
// hook lets it through.
var dangerousVerbs = map[string]map[string]struct{}{
	"npm":    setOf("install", "i", "add", "ci", "update", "up", "upgrade", "exec"),
	"yarn":   setOf("install", "add", "upgrade", "up", "dlx"),
	"pnpm":   setOf("install", "i", "add", "update", "up", "upgrade", "dlx"),
	"bun":    setOf("install", "i", "add", "update", "upgrade", "x", "create"),
	"rush":   setOf("install", "add", "update"),
	"pip":    setOf("install", "download"),
	"pip3":   setOf("install", "download"),
	"pipx":   setOf("install", "upgrade", "inject", "run"),
	"uv":     setOf("add", "sync", "install", "tool", "run", "pip"),
	"poetry": setOf("install", "add", "update", "lock"),
	"pdm":    setOf("install", "add", "update", "sync"),
	"cargo":  setOf("add", "update", "fetch", "install", "build", "check", "test", "run", "bench", "clippy"),
}

var goFlagsWithValues = setOf(
	"-C", "-mod", "-modfile", "-overlay", "-tags", "-exec", "-asmflags", "-gcflags",
	"-ldflags", "-gccgoflags", "-toolexec", "-pkgdir", "-p", "-o", "-buildmode",
	"-compiler", "-coverpkg", "-coverprofile", "-run", "-bench", "-benchtime", "-count",
	"-cpu", "-list", "-parallel", "-timeout", "-vet", "-reuse",
)

var cargoFlagsWithValues = setOf(
	"--color", "--config", "-Z", "--manifest-path", "--lockfile-path", "--target",
	"--target-dir", "--package", "-p", "--features", "-F", "--jobs", "-j", "--profile",
	"--message-format", "--example", "--bin", "--test", "--bench", "--index",
	"--registry", "--version", "--vers", "--git", "--tag", "--rev", "--branch",
	"--path", "--root", "--precise", "--aggressive", "--rename",
)

// execPMs are the fetch-and-run binaries: every non-help invocation pulls
// and executes remote code, so any non-trivial argv is treated as risky.
var execPMs = map[string]struct{}{
	"npx": {}, "pnpx": {}, "bunx": {}, "rushx": {}, "uvx": {},
}

// wrappers are programs whose argv pattern is `<wrapper> [flags] <real-cmd>
// [real-args]`. They execvp the inner command, so a shell function aliasing
// the inner command does not engage.
var wrappers = map[string]struct{}{
	"timeout": {}, "env": {}, "sudo": {}, "doas": {}, "nice": {}, "ionice": {},
	"nohup": {}, "time": {}, "command": {}, "builtin": {}, "exec": {},
	"stdbuf": {}, "unbuffer": {}, "watch": {}, "xargs": {}, "chronic": {}, "ts": {},
}

var shellBins = map[string]struct{}{
	"bash": {}, "sh": {}, "zsh": {}, "dash": {}, "ksh": {}, "fish": {},
}

func setOf(items ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, it := range items {
		out[it] = struct{}{}
	}
	return out
}

// Analyze parses a Bash tool command and returns a Finding if the command
// reaches a covered package manager with a dangerous verb. ok=false means
// the command is safe to let through unchanged (or unparseable; we defer
// to the shell in that case, matching the Python original).
//
// The command is parsed into a real shell AST (mvdan.cc/sh) and every
// command node is classified — including ones nested inside command
// substitution ($(...) / backticks), process substitution (<(...), >(...)),
// here-strings / here-docs, `bash -c "..."` payloads, pipelines, and
// separators. This replaces the earlier blanket refusal of any command
// merely containing substitution syntax, which false-positived on harmless
// read-only commands like `go list -m $(git rev-parse HEAD)` while a real
// PM install hidden inside a substitution is still caught precisely (the
// hidden install is a command node the walk visits).
func Analyze(cmd string) (Finding, bool) {
	file, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		// Unparseable as shell. Preserve the prior fail-CLOSED posture for
		// inputs that still look like they hide a command in substitution
		// syntax; otherwise defer to the shell, matching the legacy
		// shlex-failure behavior (e.g. `npm install "unterminated`).
		if containsShellExpansion(cmd) {
			return Finding{PM: "shell-expansion", Tokens: []string{cmd}}, true
		}
		return Finding{}, false
	}

	var finding Finding
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			// `sh <<< 'npm install foo'` / a here-doc feeding a shell: the
			// payload is a redirect word, not a command the parser descends
			// into. If the leading binary is a shell, re-analyze the body.
			if inner, ok := shellStdinScript(n); ok {
				if f, risky := Analyze(inner); risky {
					finding, found = f, true
					return false
				}
			}
		case *syntax.CallExpr:
			if f, risky := analyzeCall(n); risky {
				finding, found = f, true
				return false
			}
		}
		return true
	})
	return finding, found
}

// analyzeCall classifies a single simple-command node. CallExpr.Args holds
// only the command words — env assignments live in Assigns and redirects on
// the enclosing Stmt, both handled natively by the AST — so we resolve the
// words to their literal text, strip known wrappers, and reuse isRisky.
func analyzeCall(ce *syntax.CallExpr) (Finding, bool) {
	words, static := callWords(ce)
	if len(words) == 0 {
		return Finding{}, false // pure assignment / empty
	}
	stripped := stripWrappers(words)
	if len(stripped) == 0 {
		return Finding{}, false
	}
	// `bash -c "<script>"`: the -c argument is opaque shell source the
	// parser does not descend into. Re-analyze it as its own command.
	if inner, ok := shellDashCScript(stripped); ok {
		if f, risky := Analyze(inner); risky {
			return f, true
		}
	}
	if pm, ok := isRisky(stripped); ok {
		return Finding{PM: pm, Tokens: stripped}, true
	}
	// Conservative guard: a known PM whose VERB position is itself a
	// substitution (e.g. `npm $(echo install) foo`) cannot be classified
	// statically — refuse rather than fail open. A dynamic ARGUMENT to an
	// otherwise determinate command (`go list -m $(git rev-parse HEAD)`)
	// does NOT trip this; only the verb slot matters. stripWrappers returns
	// a suffix of words, so the static flags realign by the dropped count.
	off := len(words) - len(stripped)
	if verbSlotDynamic(stripped, static[off:]) {
		b := base(stripped[0])
		if b != "veto" && (isInterposerPM(b) || isPythonInterpreter(b)) {
			return Finding{PM: b, Tokens: stripped}, true
		}
	}
	return Finding{}, false
}

// callWords resolves a CallExpr's argument words to literal text and reports,
// per word, whether the word is fully static (no command / parameter /
// process / arithmetic expansion). A purely dynamic word resolves to "" —
// enough for the verb-slot guard to notice while leaving determinate flags
// and verbs matchable.
func callWords(ce *syntax.CallExpr) (words []string, static []bool) {
	for _, w := range ce.Args {
		text, ok := wordLiteral(w)
		words = append(words, text)
		static = append(static, ok)
	}
	return words, static
}

// wordLiteral concatenates the literal portions of a word and reports
// whether the word was fully static. Single/double-quoted literals are
// static; command/parameter/process/arithmetic expansions are not.
func wordLiteral(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	static := true
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				} else {
					static = false
				}
			}
		default:
			static = false
		}
	}
	return b.String(), static
}

// verbSlotDynamic reports whether the verb position — the first non-flag
// word after argv[0] — is a non-static (substitution-bearing) word.
func verbSlotDynamic(words []string, static []bool) bool {
	for i := 1; i < len(words) && i < len(static); i++ {
		if strings.HasPrefix(words[i], "-") {
			continue
		}
		return !static[i]
	}
	return false
}

// shellDashCScript returns the inline script of a `<shell> -c "<script>"`
// invocation so the caller can re-analyze it. tokens must already be
// wrapper-stripped. Returns ("", false) for non-shell or no-`-c` commands.
func shellDashCScript(tokens []string) (string, bool) {
	if len(tokens) < 3 {
		return "", false
	}
	if _, ok := shellBins[base(tokens[0])]; !ok {
		return "", false
	}
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-c" && i+1 < len(tokens) {
			return tokens[i+1], true
		}
		if !strings.HasPrefix(t, "-") {
			break
		}
	}
	return "", false
}

// shellStdinScript returns the here-string / here-doc body fed to a shell
// command on stdin (`sh <<< 'npm install foo'`, `bash <<EOF … EOF`), which
// the shell executes as a script. Returns ("", false) when the command is
// not a shell or carries no such redirect.
func shellStdinScript(stmt *syntax.Stmt) (string, bool) {
	ce, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Args) == 0 {
		return "", false
	}
	lead, _ := wordLiteral(ce.Args[0])
	if _, ok := shellBins[base(lead)]; !ok {
		return "", false
	}
	for _, r := range stmt.Redirs {
		switch r.Op {
		case syntax.WordHdoc:
			if body, _ := wordLiteral(r.Word); body != "" {
				return body, true
			}
		case syntax.Hdoc, syntax.DashHdoc:
			if body, _ := wordLiteral(r.Hdoc); body != "" {
				return body, true
			}
		}
	}
	return "", false
}

// containsShellExpansion reports whether the raw command string contains
// constructs that hide commands from a token-pipeline parser: command
// substitution ($(...) and backticks), process substitution (<(...),
// >(...)), and herestrings (<<<). Any of these can route a PM call past
// the analyzer; Phase 1.2 refuses them to close the fail-OPEN until
// Phase 3.1 swaps in a real shell AST.
func containsShellExpansion(s string) bool {
	if strings.Contains(s, "$(") {
		return true
	}
	if strings.Contains(s, "`") {
		return true
	}
	if strings.Contains(s, "<(") || strings.Contains(s, ">(") {
		return true
	}
	if strings.Contains(s, "<<<") {
		return true
	}
	return false
}

// base returns the last path component (no directory). Mirrors Python's
// `tok.rsplit('/', 1)[-1]` without requiring filepath semantics.
func base(tok string) string {
	if i := strings.LastIndexByte(tok, '/'); i >= 0 {
		return tok[i+1:]
	}
	return tok
}

// stripWrappers peels off known wrappers and their flags until it reaches
// the underlying binary. Matches the Python version's per-wrapper rules.
func stripWrappers(tokens []string) []string {
	for len(tokens) > 0 {
		b := base(tokens[0])
		if _, isWrapper := wrappers[b]; !isWrapper {
			return tokens
		}
		tokens = tokens[1:]
		switch b {
		case "env":
			for len(tokens) > 0 {
				t := tokens[0]
				if strings.HasPrefix(t, "-") {
					switch t {
					case "-u", "-S", "-C":
						if len(tokens) > 1 {
							tokens = tokens[2:]
						} else {
							tokens = nil
						}
					default:
						tokens = tokens[1:]
					}
					continue
				}
				if strings.Contains(t, "=") {
					tokens = tokens[1:]
					continue
				}
				break
			}
		case "sudo", "doas":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-u", "-g", "-h", "-p", "-C", "-D", "-T", "-U", "-A":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
		case "timeout":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-s", "-k", "--signal", "--kill-after":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
			if len(tokens) > 0 {
				tokens = tokens[1:] // DURATION
			}
		case "nice", "ionice":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-n", "-c", "-p":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
		case "xargs":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-I", "-n", "-P", "-L", "-J", "-d", "-E", "-s",
					"--max-args", "--max-procs", "--max-lines",
					"--delimiter", "--max-chars", "--replace":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
		case "time":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				tokens = tokens[1:]
			}
		case "watch":
			for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
				switch tokens[0] {
				case "-n", "-d":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
		case "stdbuf":
			for len(tokens) > 0 && (strings.HasPrefix(tokens[0], "-") || strings.Contains(tokens[0], "=")) {
				switch tokens[0] {
				case "-i", "-o", "-e":
					if len(tokens) > 1 {
						tokens = tokens[2:]
					} else {
						tokens = nil
					}
				default:
					tokens = tokens[1:]
				}
			}
		}
	}
	return tokens
}

// isRisky returns the PM name if tokens describe a risky invocation,
// otherwise ("", false). The decision rules match the Python original:
//
//   - already prefixed with `veto` → not risky (already guarded)
//   - `python -m <pm> …` where <pm> is one of pythonDashMTargets →
//     unwrap to `<pm> …` and recurse (the canonical install form
//     inside virtualenvs and Dockerfiles). Other python invocations
//     pass through.
//   - exec-style PM (npx/bunx/...) with any non-help argv → risky
//   - regular PM whose first non-flag argv is a dangerous verb → risky
func isRisky(tokens []string) (string, bool) {
	if len(tokens) == 0 {
		return "", false
	}
	b := base(tokens[0])
	if b == "veto" {
		return "", false
	}
	// `python -m <pm> …` — gate when <pm> is a known PM module. We
	// unwrap by re-running isRisky on `<pm> …` so the existing per-PM
	// logic (dangerous-verb lookup, exec-PM rule) decides risk. Other
	// `-m` modules and non-`-m` python invocations are not risky.
	if isPythonInterpreter(b) {
		if len(tokens) >= 3 && tokens[1] == "-m" {
			if _, ok := pythonDashMTargets[tokens[2]]; ok {
				return isRisky(tokens[2:])
			}
		}
		return "", false
	}
	if !isInterposerPM(b) {
		return "", false
	}
	if b == "go" {
		return riskyGo(tokens)
	}
	if b == "cargo" {
		// rustup honors a `+<toolchain>` override (`cargo +nightly install …`)
		// only as the first argument. It is not a flag, so drop it before verb
		// classification — otherwise the override is read as the verb and a
		// dangerous command (e.g. `cargo +nightly install`) slips through ungated.
		toks := tokens
		if len(tokens) > 1 && strings.HasPrefix(tokens[1], "+") {
			toks = append([]string{tokens[0]}, tokens[2:]...)
		}
		return riskyByVerb(toks, b, dangerousVerbs[b], cargoFlagsWithValues)
	}
	if _, exec := execPMs[b]; exec {
		var rest []string
		for _, a := range tokens[1:] {
			if !strings.HasPrefix(a, "-") {
				rest = append(rest, a)
			}
		}
		if len(rest) == 0 {
			return "", false
		}
		switch rest[0] {
		case "help", "--help", "-h", "--version", "-v":
			return "", false
		}
		return b, true
	}
	return riskyByVerb(tokens, b, dangerousVerbs[b], nil)
}

func riskyGo(tokens []string) (string, bool) {
	verbIdx, verb, ok := firstNonFlagWithValues(tokens, 1, goFlagsWithValues)
	if !ok {
		return "", false
	}
	switch verb {
	case "get", "install", "build", "test", "vet":
		return "go", true
	case "run":
		_, a, ok := firstNonFlagWithValues(tokens, verbIdx+1, goFlagsWithValues)
		if !ok {
			return "", false
		}
		if strings.Contains(a, "@") && !strings.HasPrefix(a, "./") && !strings.HasPrefix(a, "../") && !strings.HasPrefix(a, "/") {
			return "go", true
		}
		return "go", true
	case "mod":
		_, a, ok := firstNonFlagWithValues(tokens, verbIdx+1, goFlagsWithValues)
		if !ok {
			return "", false
		}
		switch a {
		case "download", "tidy":
			return "go", true
		default:
			return "", false
		}
	}
	return "", false
}

func riskyByVerb(tokens []string, pm string, verbs map[string]struct{}, flagsWithValues map[string]struct{}) (string, bool) {
	_, verb, ok := firstNonFlagWithValues(tokens, 1, flagsWithValues)
	if !ok {
		return "", false
	}
	if _, hit := verbs[verb]; hit {
		return pm, true
	}
	return "", false
}

func firstNonFlagWithValues(tokens []string, start int, flagsWithValues map[string]struct{}) (int, string, bool) {
	for i := start; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "--" {
			if i+1 < len(tokens) {
				return i + 1, tokens[i+1], true
			}
			return -1, "", false
		}
		if !strings.HasPrefix(tok, "-") {
			return i, tok, true
		}
		if strings.Contains(tok, "=") {
			continue
		}
		if _, takesValue := flagsWithValues[tok]; takesValue && i+1 < len(tokens) {
			i++
		}
	}
	return -1, "", false
}
