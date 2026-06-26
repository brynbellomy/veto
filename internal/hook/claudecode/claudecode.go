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

	"mvdan.cc/sh/v3/expand"
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

// strongInstallVerbs are the unambiguous package-install verbs across PMs,
// used by the dynamic-command-name guard (dynamicCommandHidesInstall) where
// argv[0] is a substitution so the PM is unknown. Deliberately EXCLUDES the
// common English words that are dangerous only for a specific PM (go
// build/test/run/vet) to avoid false-positives when the command name is
// dynamic.
var strongInstallVerbs = setOf(
	"install", "i", "add", "ci", "dlx", "exec", "x",
	"upgrade", "up", "update", "sync", "inject", "download", "fetch", "create",
)

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
func Analyze(cmd string) (Finding, bool) { return analyzeDepth(cmd, 0) }

// Resource bounds. Analyze runs on EVERY Bash tool call. mvdan/sh's
// recursive-descent parser, syntax.Walk, and our own re-analysis of
// `bash -c` / `eval` / here-doc payloads all recurse with input nesting
// depth; a pathologically nested or huge command could exhaust the goroutine
// stack with a runtime fatal error that recover() cannot catch. We bound the
// input fail-CLOSED (treat as a refusal) before doing any of that.
const (
	maxCommandLen     = 128 * 1024
	maxNestingDepth   = 64
	maxReanalyzeDepth = 32
)

func analyzeDepth(cmd string, depth int) (Finding, bool) {
	if depth > maxReanalyzeDepth || len(cmd) > maxCommandLen || parenNestingDepth(cmd) > maxNestingDepth {
		return Finding{PM: "shell-expansion", Tokens: []string{cmd}}, true
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return analyzeUnparseable(cmd, depth)
	}
	return walkFile(file, depth)
}

// walkFile classifies every command node in a parsed shell file, including
// nodes nested inside substitutions, process substitutions, here-docs, and
// pipelines (syntax.Walk descends into all of them).
func walkFile(file *syntax.File, depth int) (Finding, bool) {
	var finding Finding
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			// `sh <<< 'npm install foo'` / a here-doc feeding a shell: the
			// payload is a redirect word the parser does not descend into. A
			// static body is re-analyzed; a substitution-bearing body cannot
			// be resolved, so we fail closed.
			if script, scriptStatic, ok := shellStdinScript(n); ok {
				if !scriptStatic {
					finding, found = Finding{PM: "shell-expansion", Tokens: []string{script}}, true
					return false
				}
				if f, risky := analyzeDepth(script, depth+1); risky {
					finding, found = f, true
					return false
				}
			}
		case *syntax.CallExpr:
			if f, risky := analyzeCall(n, depth); risky {
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
// the enclosing Stmt, both handled natively by the AST.
func analyzeCall(ce *syntax.CallExpr, depth int) (Finding, bool) {
	words, static := callWords(ce)
	if len(words) == 0 {
		return Finding{}, false // pure assignment / empty
	}
	stripped := stripWrappers(words)
	if len(stripped) == 0 {
		return Finding{}, false
	}
	// stripWrappers only ever removes a PREFIX of the tokens, so the per-word
	// static flags and AST words for `stripped` are the trailing len(stripped)
	// entries (callWords is 1:1 with ce.Args).
	sstatic := static[len(static)-len(stripped):]
	strippedArgs := ce.Args[len(ce.Args)-len(stripped):]

	// `eval <words>` / `<shell> -c <script>`: opaque shell source the parser
	// does not descend into. A static payload is re-analyzed; a
	// substitution-bearing one we cannot resolve fails closed.
	if script, scriptStatic, ok := dispatchedScript(stripped, strippedArgs); ok {
		if !scriptStatic {
			return Finding{PM: "shell-expansion", Tokens: stripped}, true
		}
		if f, risky := analyzeDepth(script, depth+1); risky {
			return f, true
		}
	}

	if pm, ok := isRisky(stripped); ok {
		return Finding{PM: pm, Tokens: stripped}, true
	}

	// Fail-closed guards for substitutions that hide the install from static
	// classification — these keep the old blanket rule's conservatism for the
	// cases that genuinely cannot be classified:
	//   (a) argv[0] is itself a substitution (command name unknowable) and a
	//       package-install verb follows (`$(echo npm) install evil`);
	//   (b) a known PM whose verb slot is a substitution
	//       (`npm $(echo install) foo`).
	// A dynamic ARGUMENT to an otherwise determinate command
	// (`go list -m $(git rev-parse HEAD)`) trips neither.
	if dynamicCommandHidesInstall(stripped, sstatic) {
		return Finding{PM: "shell-expansion", Tokens: stripped}, true
	}
	if pm, ok := dynamicVerbOnPM(stripped, sstatic); ok {
		return Finding{PM: pm, Tokens: stripped}, true
	}
	return Finding{}, false
}

// callWords resolves a CallExpr's argument words to literal text and reports,
// per word, whether the word is fully static (no command / parameter /
// process / arithmetic expansion, and no ANSI-C $'...' quoting). A
// non-static word resolves to its static prefix ("" when purely dynamic) —
// enough for the guards to notice while leaving determinate flags and verbs
// matchable.
func callWords(ce *syntax.CallExpr) (words []string, static []bool) {
	for _, w := range ce.Args {
		text, ok := wordLiteral(w)
		words = append(words, text)
		static = append(static, ok)
	}
	return words, static
}

// wordLiteral concatenates the literal portions of a word and reports whether
// the word was fully static. Plain single/double-quoted literals are static;
// command/parameter/process/arithmetic expansions are not. ANSI-C $'...'
// quoting is treated as NON-static: its .Value is the undecoded source
// (e.g. \x69...), not the runtime string, so treating it as a literal would
// both mis-match and let a verb hidden in ANSI-C escapes masquerade as a
// benign static token — failing the conservative guard open.
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
			if p.Dollar { // $'...' ANSI-C quoting — undecoded, treat as dynamic
				static = false
				continue
			}
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

// dispatchedScript returns the shell-source payload a command interprets as a
// nested script — `eval <words>` or `<shell> -c <script>` — so the caller can
// re-analyze it. The payload is decoded from the AST word with
// expand.Literal so quote/escape handling is faithful (a hand-concatenation
// of Lit parts mangles `bash -c "… \"x\" …"`). scriptStatic reports whether
// the payload is fully static (re-analyzable) or substitution-bearing (must
// be refused). present is false for any other command. tokens and args are
// 1:1 (both the wrapper-stripped suffix).
func dispatchedScript(tokens []string, args []*syntax.Word) (script string, scriptStatic, present bool) {
	if len(tokens) == 0 {
		return "", false, false
	}
	if base(tokens[0]) == "eval" {
		var parts []string
		allStatic := true
		for i := 1; i < len(tokens); i++ {
			if strings.HasPrefix(tokens[i], "-") {
				continue // eval's own flags (e.g. `--`)
			}
			val, st := decodeStaticWord(argAt(args, i))
			if !st {
				allStatic = false
			}
			parts = append(parts, val)
		}
		if len(parts) == 0 {
			return "", false, false
		}
		return strings.Join(parts, " "), allStatic, true
	}
	if _, ok := shellBins[base(tokens[0])]; ok {
		for i := 1; i < len(tokens); i++ {
			t := tokens[i]
			if isDashCFlag(t) && i+1 < len(tokens) {
				val, st := decodeStaticWord(argAt(args, i+1))
				return val, st, true
			}
			if !strings.HasPrefix(t, "-") {
				break
			}
		}
	}
	return "", false, false
}

func argAt(args []*syntax.Word, i int) *syntax.Word {
	if i >= 0 && i < len(args) {
		return args[i]
	}
	return nil
}

// decodeStaticWord returns a word's fully-decoded literal value (quotes and
// escapes resolved by mvdan's own expander) and whether the word is static.
// A word containing any command/parameter/process/arithmetic expansion — or
// ANSI-C $'...' quoting — is NOT static; we return ("", false) and the caller
// fails closed rather than guessing at the runtime value.
func decodeStaticWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	if !isStaticWord(w) {
		return "", false
	}
	s, err := expand.Literal(nil, w)
	if err != nil {
		return "", false
	}
	return s, true
}

// isStaticWord reports whether a word is composed entirely of literal text
// (plain literals and ordinary single/double quotes), with no expansion of
// any kind and no ANSI-C $'...' quoting.
func isStaticWord(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
		case *syntax.SglQuoted:
			if p.Dollar {
				return false
			}
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				switch d := dp.(type) {
				case *syntax.Lit:
				case *syntax.SglQuoted:
					if d.Dollar {
						return false
					}
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// isDashCFlag matches `-c` and short-flag clusters whose LAST letter is c
// (`sh -ec "…"`, `sh -xc "…"`), where the next argument is the command string.
func isDashCFlag(t string) bool {
	if t == "-c" {
		return true
	}
	if len(t) >= 2 && t[0] == '-' && t[1] != '-' {
		body := t[1:]
		return isAllLetters(body) && strings.HasSuffix(body, "c")
	}
	return false
}

func isAllLetters(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// dynamicCommandHidesInstall reports whether argv[0] is substitution-bearing
// (so the binary is unknowable) AND a recognizable package-install verb
// follows. The old blanket rule refused such commands; we keep that
// conservatism only where we genuinely cannot classify, still allowing a
// dynamic argv[0] with no install verb (`$(tty)`-style usage).
func dynamicCommandHidesInstall(tokens []string, static []bool) bool {
	if len(static) == 0 || static[0] {
		return false
	}
	for i := 1; i < len(tokens); i++ {
		if i < len(static) && !static[i] {
			continue
		}
		if _, ok := strongInstallVerbs[tokens[i]]; ok {
			return true
		}
	}
	return false
}

// dynamicVerbOnPM reports a known PM whose verb slot is a substitution, which
// cannot be classified statically. It locates the verb slot EXACTLY as the
// isRisky classifier does (same per-PM flag tables, cargo +toolchain skip,
// python -m form), so the guard inspects the same slot the classifier would.
func dynamicVerbOnPM(tokens []string, static []bool) (string, bool) {
	if len(tokens) == 0 {
		return "", false
	}
	b := base(tokens[0])
	if b == "veto" {
		return "", false
	}
	if isPythonInterpreter(b) {
		// `python -m <module>`: the module name is the risky slot.
		if len(tokens) >= 3 && tokens[1] == "-m" && len(static) > 2 && !static[2] {
			return b, true
		}
		return "", false
	}
	if !isInterposerPM(b) {
		return "", false
	}
	idx, ok := classifierVerbIndex(b, tokens)
	if ok && idx < len(static) && !static[idx] {
		return b, true
	}
	return "", false
}

// classifierVerbIndex returns the argv index isRisky treats as the verb,
// mirroring its per-PM flag handling.
func classifierVerbIndex(pm string, tokens []string) (int, bool) {
	switch pm {
	case "go":
		idx, _, ok := firstNonFlagWithValues(tokens, 1, goFlagsWithValues)
		return idx, ok
	case "cargo":
		start := 1
		if len(tokens) > 1 && strings.HasPrefix(tokens[1], "+") {
			start = 2 // skip rustup `+toolchain` override
		}
		idx, _, ok := firstNonFlagWithValues(tokens, start, cargoFlagsWithValues)
		return idx, ok
	default:
		idx, _, ok := firstNonFlagWithValues(tokens, 1, nil)
		return idx, ok
	}
}

// parenNestingDepth returns the maximum paren nesting depth (plus a backtick
// estimate) — a cheap pre-parse proxy for how deep the parser/walk will
// recurse. It over-counts parens inside quotes (a fail-closed bias); real
// commands stay far below the cap.
func parenNestingDepth(s string) int {
	depth, max := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
			if depth > max {
				max = depth
			}
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	if bt := strings.Count(s, "`") / 2; bt > max {
		max = bt
	}
	return max
}

// analyzeUnparseable handles input mvdan/sh rejects. It retries once with
// leading `!` negation runs stripped (a bash-vs-POSIX divergence the parser
// can reject), then preserves the documented posture for what remains: fail
// CLOSED on substitution-bearing input, otherwise defer to the shell (an
// unparseable non-substitution command is a shell syntax error, not ours to
// gate — matches the legacy shlex-failure behavior).
func analyzeUnparseable(cmd string, depth int) (Finding, bool) {
	if trimmed, removed := stripLeadingBang(cmd); removed && depth <= maxReanalyzeDepth {
		if file, err := syntax.NewParser().Parse(strings.NewReader(trimmed), ""); err == nil {
			return walkFile(file, depth+1)
		}
	}
	if containsShellExpansion(cmd) {
		return Finding{PM: "shell-expansion", Tokens: []string{cmd}}, true
	}
	return Finding{}, false
}

// stripLeadingBang removes leading `!` negation tokens (`! ! cmd`).
func stripLeadingBang(cmd string) (string, bool) {
	s := strings.TrimLeft(cmd, " \t")
	removed := false
	for len(s) > 0 && s[0] == '!' && (len(s) == 1 || s[1] == ' ' || s[1] == '\t') {
		s = strings.TrimLeft(s[1:], " \t")
		removed = true
	}
	return s, removed
}

// shellStdinScript returns the here-string / here-doc body fed to a shell
// command on stdin (`sh <<< 'npm install foo'`, `bash <<EOF … EOF`), which the
// shell executes as a script, plus whether that body is fully static. present
// is false when the command is not a shell or carries no such redirect.
func shellStdinScript(stmt *syntax.Stmt) (script string, scriptStatic, present bool) {
	ce, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(ce.Args) == 0 {
		return "", false, false
	}
	lead, _ := wordLiteral(ce.Args[0])
	if _, ok := shellBins[base(lead)]; !ok {
		return "", false, false
	}
	for _, r := range stmt.Redirs {
		var w *syntax.Word
		switch r.Op {
		case syntax.WordHdoc:
			w = r.Word
		case syntax.Hdoc, syntax.DashHdoc:
			w = r.Hdoc
		default:
			continue
		}
		body, st := decodeStaticWord(w)
		return body, st, true
	}
	return "", false, false
}

// containsShellExpansion reports whether the raw command string contains
// command substitution ($(...) / backticks), process substitution (<(...),
// >(...)), or a here-string (<<<). The primary classifier is now the shell
// AST walk in Analyze; this is only a residual fail-CLOSED fallback for input
// the parser REJECTS (analyzeUnparseable) — if we cannot parse it but it
// still hides commands in substitution syntax, we refuse rather than guess.
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
