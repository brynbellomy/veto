// Package gypscan is a content heuristic for the "phantom gyp" / Miasma
// class of npm supply-chain worms (the June 2026 binding.gyp campaign).
//
// The worm defeats veto's name+version intel model entirely: it rides
// trusted package names via maintainer-account-takeover (so the name is
// not in any malware feed yet), keeps package.json `scripts` clean (so
// lifecycle-script inspection sees nothing), and hides arbitrary shell in
// a tiny binding.gyp `sources` array. When npm sees a binding.gyp at a
// package root and no preinstall/install script, it invokes node-gyp to
// "build a native addon" — and node-gyp runs GYP command-expansion
// (`<!(...)`, `<!@(...)`) as a shell during configure. That executes the
// payload at install time EVEN WITH `--ignore-scripts`, because this is
// not a lifecycle hook.
//
// gypscan reads a binding.gyp (and, when available, its sibling
// package.json and a listing of the package's files) and classifies it as
// benign or worm-shaped. It performs no I/O, runs no node-gyp, and never
// executes the package — the analysis is pure inspection of bytes the
// caller already has on disk. Callers (the scan walker, the Claude hook,
// a future install-time tarball prescan) own the file reads and turn a
// Verdict into their own finding/refusal type.
package gypscan

import (
	"regexp"
	"strings"
)

// Severity ranks how confident gypscan is that a binding.gyp is malicious.
type Severity string

const (
	// SeverityNone: nothing suspicious. The binding.gyp looks like an
	// ordinary native-addon build descriptor.
	SeverityNone Severity = "none"

	// SeverityMedium: the binding.gyp is anomalous in a way consistent with
	// the worm but without a confirmed command-expansion payload — e.g. a
	// pure-JS package that has no business shipping a binding.gyp at all, or
	// a `type: "none"` target with no real native sources. Worth surfacing;
	// not on its own proof of execution.
	SeverityMedium Severity = "medium"

	// SeverityCritical: a confirmed install-time code-execution vector — GYP
	// command expansion (`<!(...)` / `<!@(...)`) or embedded shell
	// metacharacters in a position node-gyp will run as a command. This is
	// the phantom-gyp worm's signature. Do not install; treat the package as
	// compromised.
	SeverityCritical Severity = "critical"
)

// Signal is one matched heuristic, carrying a short machine-stable code, a
// human-readable explanation, and the offending excerpt (already truncated
// and single-lined so it is safe to render in a report).
type Signal struct {
	// Code is a stable identifier for the heuristic that fired (e.g.
	// "gyp-command-expansion"). Stable across releases so downstream tooling
	// and tests can match on it.
	Code string

	// Detail explains, in one sentence, why this signal indicates risk.
	Detail string

	// Excerpt is the offending fragment of the binding.gyp, truncated and
	// flattened to a single line. Empty when the signal is structural rather
	// than tied to a specific substring.
	Excerpt string
}

// Verdict is the result of inspecting one binding.gyp. Flagged() is the
// single decision point callers branch on; Signals and Severity drive the
// diagnostics.
type Verdict struct {
	Severity Severity
	Signals  []Signal
}

// Flagged reports whether the binding.gyp is suspicious enough to surface or
// block. True for SeverityMedium and SeverityCritical.
func (v Verdict) Flagged() bool {
	return v.Severity == SeverityMedium || v.Severity == SeverityCritical
}

// Input is everything gypscan needs to classify one binding.gyp. Only
// GypContent is required; the sibling package.json and the package file
// listing sharpen the heuristic (they distinguish a legitimate native
// addon from a pure-JS package that suddenly grew a binding.gyp), but
// gypscan degrades gracefully when they are absent.
type Input struct {
	// GypContent is the raw bytes of the binding.gyp file. Required.
	GypContent []byte

	// IncludedContents holds the raw bytes of every .gyp/.gypi file transitively
	// referenced via GYP `includes:` from the root binding.gyp. node-gyp merges
	// and evaluates these at configure time, so a command expansion in any of
	// them executes at install time exactly as if inline. Optional; callers that
	// cannot resolve includes (e.g. only have the root file) pass nil and the
	// detector degrades to root-only analysis.
	IncludedContents [][]byte

	// PackageJSON is the raw bytes of the sibling package.json, when the
	// caller has it. Optional. Used to check for declared native-build
	// dependencies (node-gyp, node-addon-api, nan, prebuild, ...) and a
	// `gypfile` flag, which legitimize a binding.gyp's presence.
	PackageJSON []byte

	// SiblingFiles is a flat list of file names (base names, not paths)
	// present alongside the binding.gyp in the package root tree, when the
	// caller can cheaply enumerate them. Optional. Used to check whether the
	// package ships any C/C++/native sources at all — a binding.gyp with no
	// native source anywhere is the worm's shape.
	SiblingFiles []string
}

const maxExcerpt = 200

var (
	// commandExpansionRe matches GYP command expansion: <!(cmd) and <!@(cmd).
	// node-gyp evaluates these as a shell during `configure`. This primitive
	// is NOT malicious on its own — legitimate native addons routinely use
	// `<!@(node -p "require('node-addon-api').include")` to locate headers.
	// The worm is distinguished by WHERE the expansion sits (a `sources`
	// entry, which is supposed to be a plain filename) and WHAT it does
	// (chains a payload via shell metacharacters), handled below.
	commandExpansionRe = regexp.MustCompile(`<!@?\s*\(`)

	// payloadShellRe matches shell constructs that betray a command being run
	// for its side effects rather than to print a build path: chaining,
	// redirection, piping into an interpreter, backgrounding, or a direct
	// interpreter / fetch invocation. A legitimate `<!@(node -p "...")` prints
	// a path and uses none of these; the worm's
	// `node index.js >/dev/null 2>&1 && echo stub.c` uses several. This is the
	// signal that turns "uses command expansion" into "is executing a payload".
	payloadShellRe = regexp.MustCompile("\\$\\(|`|>\\s*/|>&|2>&1|&&|\\|\\||;|\\bcurl\\b|\\bwget\\b|/dev/null|\\bbash\\b|\\beval\\b|\\bchild_process\\b")

	// nativeBuildDepRe matches package.json dependency or flag names that
	// legitimize a native build. If any of these is declared, a binding.gyp's
	// presence is expected and gypscan stays quiet about the *structural*
	// "pure-JS package with a gyp" signal (command-expansion is still
	// flagged regardless — a real addon never needs a shell).
	nativeBuildDepRe = regexp.MustCompile(`"(node-gyp|node-addon-api|nan|node-pre-gyp|prebuild|prebuild-install|prebuildify|bindings|cmake-js|node-gyp-build)"|"gypfile"\s*:\s*true`)

	// nativeSourceExtns are the file extensions that indicate a package
	// genuinely ships native code a binding.gyp would legitimately compile.
	nativeSourceExtns = []string{".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".h", ".hpp", ".hh", ".s", ".asm"}
)

// Inspect classifies a single binding.gyp. It never errors: malformed or
// empty content yields a SeverityNone verdict (there is nothing to execute),
// and every positive signal is additive. The most severe matched signal sets
// Verdict.Severity.
//
// Inspect is pure and safe for concurrent use.
func Inspect(in Input) Verdict {
	content := string(in.GypContent)
	if strings.TrimSpace(content) == "" {
		return Verdict{Severity: SeverityNone}
	}

	var signals []Signal
	severity := SeverityNone

	bump := func(s Severity) {
		if severityRank(s) > severityRank(severity) {
			severity = s
		}
	}

	// --- Critical: confirmed install-time payload execution ----------------
	//
	// node-gyp evaluating `<!(...)`/`<!@(...)` as a shell is the mechanism;
	// what makes it a worm rather than a header-path lookup is (a) the
	// expansion appearing in a `sources` array — node-gyp shells out every
	// sources entry, and a real source is a filename, never a command — or
	// (b) payload-shaped shell (chaining, redirection, piping into an
	// interpreter, a curl/wget/eval) inside any expansion. Either is the
	// phantom-gyp signature; a benign `<!@(node -p "...")` in include_dirs
	// trips neither.

	if critical := scanCriticalSignals(content, false); len(critical) > 0 {
		signals = append(signals, critical...)
		bump(SeverityCritical)
	}
	for _, included := range in.IncludedContents {
		if critical := scanCriticalSignals(string(included), true); len(critical) > 0 {
			signals = append(signals, critical...)
			bump(SeverityCritical)
		}
	}

	// --- Medium: structural anomalies consistent with the worm ------------

	// A `type: "none"` target exists purely to trigger an action/command; a
	// legitimate addon target builds something (loadable_module,
	// static_library, executable, shared_library). On its own this is only
	// suspicious, but combined with command expansion above it is the worm.
	if hasNoneTypeTarget(content) {
		signals = append(signals, Signal{
			Code:   "gyp-type-none-target",
			Detail: `binding.gyp declares a target with type "none", which builds nothing — legitimate addons build a library or module; a "none" target's only purpose is to run a command.`,
		})
		bump(SeverityMedium)
	}

	// A binding.gyp in a package that ships no native sources and declares no
	// native-build tooling is the account-takeover tell: a pure-JS package
	// that suddenly grew a build descriptor. Only assert this when we can see
	// enough to be sure (we have a file listing or a package.json), to avoid
	// false positives when the caller hands us the gyp alone.
	if isPureJSPackage(in) {
		signals = append(signals, Signal{
			Code:   "gyp-without-native-code",
			Detail: "binding.gyp present in a package that ships no C/C++/native sources and declares no native-build tooling (node-gyp, node-addon-api, nan, prebuild, gypfile) — a pure-JS package has no legitimate reason to carry one.",
		})
		bump(SeverityMedium)
	}

	return Verdict{Severity: severity, Signals: signals}
}

func scanCriticalSignals(content string, fromInclude bool) []Signal {
	var signals []Signal
	normalized := stripGypComments(content)
	if loc := commandExpansionInSources(normalized); loc >= 0 {
		signals = append(signals, Signal{
			Code:    "gyp-command-in-sources",
			Detail:  criticalDetail(fromInclude, "runs a command (<!(...) / <!@(...)) inside a `sources` array — node-gyp shells out every sources entry at install time, and a real source is a filename, never a command. This is the phantom-gyp worm's install-time execution vector and fires even with --ignore-scripts."),
			Excerpt: excerptAround(content, loc),
		})
	}
	if loc := payloadShellInExpansion(normalized); loc >= 0 {
		signals = append(signals, Signal{
			Code:    "gyp-payload-shell",
			Detail:  criticalDetail(fromInclude, "embeds payload-shaped shell inside a command expansion (chaining, redirection, piping into an interpreter, or a curl/wget/eval call) — a legitimate header-path lookup prints a path and needs none of these."),
			Excerpt: excerptAround(content, loc),
		})
	}
	if loc, excerpt := commandActionArray(normalized); loc >= 0 {
		if excerpt == "" {
			excerpt = excerptAround(content, loc)
		}
		signals = append(signals, Signal{
			Code:    "gyp-action-exec",
			Detail:  criticalDetail(fromInclude, "declares an `action` argv array that invokes an interpreter, shell, package manager, fetch tool, computed command, or payload-shaped shell — node-gyp runs actions/rules during the native build path, so this is install-time command execution."),
			Excerpt: excerpt,
		})
	}
	if loc := commandExpansionInExecKeys(normalized); loc >= 0 {
		signals = append(signals, Signal{
			Code:    "gyp-exec-key-command",
			Detail:  criticalDetail(fromInclude, "runs a non-allowlisted command expansion inside an execution-sensitive build key (`libraries`, `cflags`, `ldflags`, `include_dirs`, or related flags) — node-gyp evaluates these at configure time, so quiet package-local interpreter invocations still execute at install time."),
			Excerpt: excerptAround(content, loc),
		})
	}
	return signals
}

// stripGypComments blanks GYP/Python-style # comments while preserving quoted
// strings and byte offsets. It is a heuristic normalizer for critical regexes,
// not a full GYP parser.
func stripGypComments(content string) string {
	out := []byte(content)
	var quote byte
	escaped := false
	for i := 0; i < len(out); i++ {
		ch := out[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '#':
			for i < len(out) && out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
				i++
			}
			i--
		}
	}
	return string(out)
}

func criticalDetail(fromInclude bool, detail string) string {
	if fromInclude {
		return "included GYP file " + detail
	}
	return "binding.gyp " + detail
}

// sourcesArrayRe matches a `sources` (or `inputs`/`outputs`) key followed by
// its array literal, capturing the array body so we can check whether a
// command expansion hides among what should be plain filenames.
var sourcesArrayRe = regexp.MustCompile(`["'](sources|inputs|outputs)["']\s*:\s*\[([^\]]*)\]`)

// actionArrayRe matches a GYP `action` key followed by its argv array. Both
// `actions[].action` and `rules[].action` use this same key shape.
var actionArrayRe = regexp.MustCompile(`["']action["']\s*:\s*\[([^\]]*)\]`)

// execKeyArrayRe matches GYP arrays whose values are evaluated during
// configure/build setup rather than treated as inert source filenames.
var execKeyArrayRe = regexp.MustCompile(`["'](libraries|cflags|cflags_c|cflags_cc|ldflags|include_dirs|library_dirs)["']\s*:\s*\[([^\]]*)\]`)

var localJSPathRe = regexp.MustCompile(`(?i)(^|[\s"'(=])(?:\.{1,2}/|[A-Za-z0-9_.-]+/)[^\s"')]+\.(?:[cm]?js)\b|(^|[\s"'(=])[^/\s"')]+\.(?:[cm]?js)\b`)

var actionCommandInterpreters = map[string]struct{}{
	"bash":       {},
	"bun":        {},
	"bunx":       {},
	"cmd":        {},
	"curl":       {},
	"dash":       {},
	"eval":       {},
	"node":       {},
	"nodejs":     {},
	"npm":        {},
	"npx":        {},
	"osascript":  {},
	"perl":       {},
	"pnpm":       {},
	"powershell": {},
	"pwsh":       {},
	"python":     {},
	"python2":    {},
	"python3":    {},
	"ruby":       {},
	"sh":         {},
	"wget":       {},
	"yarn":       {},
	"zsh":        {},
}

// commandExpansionInSources returns the index (into content) of a command
// expansion found inside a sources/inputs/outputs array, or -1 if none. These
// arrays are supposed to hold filenames; node-gyp shells out each entry, so a
// `<!(...)` here is direct install-time execution.
func commandExpansionInSources(content string) int {
	for _, m := range sourcesArrayRe.FindAllStringSubmatchIndex(content, -1) {
		// m[4]:m[5] is the captured array body (group 2).
		bodyStart, bodyEnd := m[4], m[5]
		if bodyStart < 0 {
			continue
		}
		body := content[bodyStart:bodyEnd]
		if loc := commandExpansionRe.FindStringIndex(body); loc != nil {
			return bodyStart + loc[0]
		}
	}
	return -1
}

// commandActionArray returns the location and excerpt for a risky
// actions/rules `action` argv array. GYP action arrays are direct build
// commands, so argv0 is high-signal when it is an interpreter/shell/package
// manager/fetch tool, a computed command expansion, or paired with
// payload-shaped shell in any argument.
func commandActionArray(content string) (int, string) {
	for _, m := range actionArrayRe.FindAllStringSubmatchIndex(content, -1) {
		bodyStart, bodyEnd := m[2], m[3]
		if bodyStart < 0 {
			continue
		}
		body := content[bodyStart:bodyEnd]
		args := gypStringLiterals(body)
		if len(args) == 0 {
			continue
		}
		argv0 := args[0]
		loc := bodyStart + argv0.start
		if commandExpansionRe.MatchString(argv0.value) || isActionInterpreter(argv0.value) {
			return loc, excerptAround(content, loc)
		}
		for _, arg := range args {
			if payloadShellRe.MatchString(arg.value) {
				loc := bodyStart + arg.start
				return loc, excerptAround(content, loc)
			}
		}
	}
	return -1, ""
}

// commandExpansionInExecKeys returns the index of a risky command expansion
// inside execution-sensitive GYP keys. The allowlist is limited to common
// print-only header/path lookups such as node-addon-api includes and
// pkg-config queries; package-local interpreter scripts remain Critical even
// when they contain no shell metacharacters.
func commandExpansionInExecKeys(content string) int {
	for _, m := range execKeyArrayRe.FindAllStringSubmatchIndex(content, -1) {
		bodyStart, bodyEnd := m[4], m[5]
		if bodyStart < 0 {
			continue
		}
		body := content[bodyStart:bodyEnd]
		for _, expansion := range expansionBodyRe.FindAllStringSubmatchIndex(body, -1) {
			expansionStart := expansion[0]
			expansionBodyStart, expansionBodyEnd := expansion[2], expansion[3]
			if expansionBodyStart < 0 {
				continue
			}
			expansionBody := body[expansionBodyStart:expansionBodyEnd]
			if allowedExecKeyExpansion(expansionBody) {
				continue
			}
			return bodyStart + expansionStart
		}
	}
	return -1
}

type gypStringLiteral struct {
	value string
	start int
}

func gypStringLiterals(content string) []gypStringLiteral {
	var out []gypStringLiteral
	for i := 0; i < len(content); i++ {
		quote := content[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		start := i
		var b strings.Builder
		escaped := false
		for i++; i < len(content); i++ {
			ch := content[i]
			if escaped {
				b.WriteByte(ch)
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				out = append(out, gypStringLiteral{value: b.String(), start: start})
				break
			}
			b.WriteByte(ch)
		}
	}
	return out
}

func isActionInterpreter(argv0 string) bool {
	name := commandBaseName(argv0)
	if name == "" {
		return false
	}
	_, ok := actionCommandInterpreters[name]
	return ok
}

func commandBaseName(cmd string) string {
	fields := strings.Fields(strings.TrimSpace(cmd))
	if len(fields) == 0 {
		return ""
	}
	cmd = fields[0]
	if idx := strings.LastIndexAny(cmd, `/\`); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	cmd = strings.ToLower(cmd)
	cmd = strings.TrimSuffix(cmd, ".exe")
	return cmd
}

func allowedExecKeyExpansion(body string) bool {
	body = strings.TrimSpace(body)
	if body == "" || payloadShellRe.MatchString(body) {
		return false
	}
	switch commandBaseName(body) {
	case "node", "nodejs":
		return allowedNodePrintExpansion(body)
	case "pkg-config":
		return true
	case "python", "python2", "python3":
		return allowedPythonPrintExpansion(body)
	default:
		return false
	}
}

func allowedNodePrintExpansion(body string) bool {
	if localJSPathRe.MatchString(body) {
		return false
	}
	if hasCommandToken(body, "-p", "--print") {
		return true
	}
	if !hasCommandToken(body, "-e", "--eval") {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "console.log") &&
		(strings.Contains(lower, "node-addon-api") || strings.Contains(lower, ".include"))
}

func allowedPythonPrintExpansion(body string) bool {
	if localJSPathRe.MatchString(body) || !hasCommandToken(body, "-c") {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "print(") || strings.Contains(lower, "sys.stdout.write")
}

func hasCommandToken(body string, tokens ...string) bool {
	fields := strings.Fields(body)
	for _, field := range fields {
		field = strings.Trim(field, `"'`)
		for _, token := range tokens {
			if field == token || strings.HasPrefix(field, token+"=") {
				return true
			}
		}
	}
	return false
}

// expansionBodyRe captures the body of a GYP command expansion
// `<!(...)` / `<!@(...)` up to the closing paren (no nested parens — GYP
// expansions don't nest in practice, and a greedy stop at `)` is sufficient
// to inspect the command text for payload shape).
var expansionBodyRe = regexp.MustCompile(`<!@?\s*\(([^)]*)\)`)

// payloadShellInExpansion returns the index of the first command expansion
// whose body contains payload-shaped shell, or -1. This catches the worm even
// when the expansion is NOT in a sources array (e.g. relocated into an action
// or condition) while leaving a benign `<!@(node -p "...")` alone.
func payloadShellInExpansion(content string) int {
	for _, m := range expansionBodyRe.FindAllStringSubmatchIndex(content, -1) {
		bodyStart, bodyEnd := m[2], m[3]
		if bodyStart < 0 {
			continue
		}
		body := content[bodyStart:bodyEnd]
		if payloadShellRe.MatchString(body) {
			return m[0]
		}
	}
	return -1
}

// hasNoneTypeTarget reports whether the binding.gyp declares a target whose
// `type` is "none". Tolerant of whitespace and quote style; this is a
// heuristic over text, not a GYP parser (GYP is python-ish and not JSON, so
// a strict parse would reject many real files).
func hasNoneTypeTarget(content string) bool {
	re := regexp.MustCompile(`["']type["']\s*:\s*["']none["']`)
	return re.MatchString(content)
}

// isPureJSPackage reports whether the inputs prove the package ships no
// native code and declares no native-build tooling. Returns false (i.e.
// "cannot conclude") when the caller provided neither a file listing nor a
// package.json — absence of evidence is not evidence here, and over-flagging
// a bare gyp would be noisy.
func isPureJSPackage(in Input) bool {
	if len(in.SiblingFiles) == 0 && len(in.PackageJSON) == 0 {
		return false
	}
	if len(in.PackageJSON) > 0 && nativeBuildDepRe.Match(in.PackageJSON) {
		return false
	}
	for _, name := range in.SiblingFiles {
		lower := strings.ToLower(name)
		for _, ext := range nativeSourceExtns {
			if strings.HasSuffix(lower, ext) {
				return false
			}
		}
	}
	// We had at least one evidence source, found no native sources, and no
	// declared native tooling. If we only had SiblingFiles (no package.json)
	// and the listing was non-empty, that's a confident "pure JS". If we only
	// had a package.json, the absence of native deps plus a binding.gyp is
	// itself the signal.
	return true
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityMedium:
		return 2
	case SeverityNone:
		return 1
	default:
		return 0
	}
}

// excerptAround returns a single-line, length-capped window of content
// centered on idx, suitable for display in a finding. Newlines and runs of
// whitespace are collapsed so a multi-line gyp renders on one report line.
func excerptAround(content string, idx int) string {
	const window = maxExcerpt
	start := idx - window/4
	if start < 0 {
		start = 0
	}
	end := start + window
	if end > len(content) {
		end = len(content)
	}
	frag := content[start:end]
	fields := strings.Fields(frag)
	// Drop a leading partial token when we started mid-word, so the excerpt
	// begins at a clean boundary rather than "rget_name".
	if start > 0 && len(fields) > 1 && !isBoundary(content[start-1]) {
		fields = fields[1:]
	}
	frag = strings.Join(fields, " ")
	if len(frag) > maxExcerpt {
		frag = frag[:maxExcerpt] + "…"
	}
	return frag
}

// isBoundary reports whether c is whitespace, i.e. a clean place for an
// excerpt to begin.
func isBoundary(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
