// Package pthscan is a content heuristic for the Hades / Shai-Hulud PyPI
// supply-chain worm (June 2026), the Python branch of the same Miasma
// lineage gypscan fights on npm. The worm ships its payload as a `*-setup.pth`
// file inside a wheel; Python's `site` module evaluates every `*.pth` whose
// first token is `import` at each interpreter startup, so the file detonates
// on the next `python` invocation in a poisoned environment — every time, not
// just at install.
//
// pthscan reads a single `.pth` file's bytes and classifies it as benign,
// structurally anomalous, or worm-shaped. It performs no I/O, runs no
// Python, and never executes the file. Callers (the scan walker, the
// wheel prescan, the Claude Code hook) own the bytes and turn a Verdict
// into their own finding/refusal type.
package pthscan

import (
	"bytes"
	"regexp"
	"strings"
)

// utf8BOM is the leading byte sequence CPython's site.py strips before
// decoding a .pth file. If we don't strip it too, the first executable line
// arrives at the prefix check carrying \xEF\xBB\xBF in front of `import`,
// fails HasPrefix("import "), and the whole payload is treated as inert.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// utf16BOMLE / utf16BOMBE are the UTF-16 byte-order marks. CPython's
// site.py won't actually `exec()` a UTF-16-encoded .pth (it opens the file
// in text mode with the default encoding, which is UTF-8 on every modern
// platform), but an attacker who confuses a future encoding-detection layer
// shouldn't be able to use one of these as a covering blanket. We refuse to
// scan UTF-16 .pth files outright and emit Critical so the install gets
// refused rather than silently green-lit by a scanner that can't see the
// bytes it would need to flag.
var (
	utf16BOMLE = []byte{0xFF, 0xFE}
	utf16BOMBE = []byte{0xFE, 0xFF}
)

// Severity ranks how confident pthscan is that a .pth is malicious.
type Severity string

const (
	// SeverityNone: only inert path lines, or an executable line matching
	// the tightly-anchored known-legit allowlist (distutils-precedence,
	// PEP 660 __editable__*, legacy easy-install).
	SeverityNone Severity = "none"

	// SeverityMedium: an executable .pth line that is neither obviously
	// payload-shaped nor on the allowlist — a structural anomaly worth
	// surfacing in `veto scan`, not on its own enough to block the
	// install hot path.
	SeverityMedium Severity = "medium"

	// SeverityCritical: a confirmed startup-time code-execution payload —
	// an `import`-line carrying network / spawn / dynamic-exec /
	// deobfuscation / runtime-fetch / worm-marker tokens. This is the
	// Hades / Shai-Hulud signature. Do not install; do not run python in
	// this environment.
	SeverityCritical Severity = "critical"
)

// Signal is one matched heuristic.
type Signal struct {
	Code    string
	Detail  string
	Excerpt string
}

// Verdict is the result of inspecting one .pth file.
type Verdict struct {
	Severity Severity
	Signals  []Signal
}

// Flagged reports whether the .pth is suspicious enough to surface or block.
func (v Verdict) Flagged() bool {
	return v.Severity == SeverityMedium || v.Severity == SeverityCritical
}

// Input is everything pthscan needs to classify one .pth.
type Input struct {
	// PthContent is the raw bytes of the .pth file. Required.
	PthContent []byte

	// FileName is the base name (e.g. "evil-setup.pth"). Optional but
	// recommended: a `*-setup.pth` name is a worm marker on its own.
	FileName string

	// SiblingFiles is a flat list of base names alongside the .pth in
	// the same dist. Optional; currently unused but reserved for future
	// "is this distribution shipping anything else?" heuristics.
	SiblingFiles []string

	// Truncated indicates the caller hit its size cap and PthContent
	// holds only a prefix. pthscan treats a truncated .pth as critical
	// (fail-closed: a worm can hide past the cap).
	Truncated bool
}

const maxExcerpt = 200

// Inspect classifies a single .pth file. It never errors: an empty .pth
// yields SeverityNone (Python ignores blank files), and every positive
// signal is additive. Inspect is pure and safe for concurrent use.
func Inspect(in Input) Verdict {
	if in.Truncated {
		return Verdict{
			Severity: SeverityCritical,
			Signals: []Signal{{
				Code:   "pth-file-too-large",
				Detail: ".pth file exceeded the scanner size cap and cannot be fully inspected; treating as unscannable so payloads cannot hide after the read cap.",
			}},
		}
	}
	raw := in.PthContent
	// UTF-16 .pth files are not a CPython-supported shape, but a scanner
	// that can't see import-line bytes shouldn't quietly pass the file as
	// inert. Fail closed.
	if bytes.HasPrefix(raw, utf16BOMLE) || bytes.HasPrefix(raw, utf16BOMBE) {
		return Verdict{
			Severity: SeverityCritical,
			Signals: []Signal{{
				Code:    "pth-unscannable-encoding",
				Detail:  ".pth file begins with a UTF-16 byte-order mark; pthscan only decodes UTF-8 and refuses to scan UTF-16 content rather than green-light a file whose import-lines it can't read.",
				Excerpt: "UTF-16 BOM",
			}},
		}
	}
	// CPython's site.py strips a leading UTF-8 BOM before splitlines();
	// mirror that so the import-prefix check sees the same bytes site.py
	// does. Without this strip the first line is "\xEF\xBB\xBFimport ..."
	// which TrimLeft(" \t") leaves untouched and the prefix check rejects.
	raw = bytes.TrimPrefix(raw, utf8BOM)
	content := string(raw)
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

	for _, line := range executableLines(content) {
		if matchesKnownLegit(line.body) {
			continue
		}
		if payload := scanPayloadSignals(line.body); len(payload) > 0 {
			signals = append(signals, payload...)
			bump(SeverityCritical)
			continue
		}
		signals = append(signals, Signal{
			Code:    "pth-executable-line",
			Detail:  "executable `import …` line in a .pth file with no payload tokens, but not on the known-legit allowlist — site.py exec()'s these at every interpreter startup.",
			Excerpt: excerpt(line.body),
		})
		bump(SeverityMedium)
	}

	if in.FileName != "" && fileNameSetupRe.MatchString(in.FileName) && !allowlistedLegitName.MatchString(in.FileName) {
		signals = append(signals, Signal{
			Code:    "pth-setup-filename",
			Detail:  ".pth filename matches the Hades `*-setup.pth` worm shape — legitimate Python tooling does not ship `-setup.pth` files; the canonical names are distutils-precedence.pth, __editable__.<name>-<ver>.pth, or per-package <name>.pth without a `-setup` suffix.",
			Excerpt: in.FileName,
		})
		bump(SeverityMedium)
	}

	return Verdict{Severity: severity, Signals: signals}
}

// executableLine carries an executable .pth line's body (everything after
// the leading whitespace) plus its 0-based offset in the original content,
// so excerpt rendering and tests can point at exact bytes.
type executableLine struct {
	body   string
	offset int
}

// executableLines walks the .pth using Python's site.py rule: a line is
// executable iff its first non-whitespace token is `import` (case-sensitive,
// matching CPython). Blank lines and lines whose first non-whitespace
// character is `#` are inert. All other lines are inert path entries.
func executableLines(content string) []executableLine {
	var out []executableLine
	start := 0
	for i := 0; i <= len(content); i++ {
		if i < len(content) && content[i] != '\n' {
			continue
		}
		line := strings.TrimSuffix(content[start:i], "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			start = i + 1
			continue
		}
		// Python's site.py treats a line as executable when its first
		// token is `import` followed by any token-separator byte. CPython
		// site.py literally checks `line.startswith(("import ", "import\t"))`,
		// so a tab between `import` and the module name detonates the
		// payload but a naive space-only prefix check misses it. We accept
		// the full set of inter-token whitespace CPython's tokenizer treats
		// as a gap — space, tab, form-feed, vertical tab — plus `(` (the
		// unusual `import(x)` form that still parses) and bare `import`.
		if isImportPrefix(trimmed) {
			out = append(out, executableLine{body: trimmed, offset: start + (len(line) - len(trimmed))})
		}
		start = i + 1
	}
	return out
}

// isImportPrefix reports whether a line (with leading whitespace already
// trimmed) begins with the CPython site.py `import` token. site.py's literal
// check is `line.startswith(("import ", "import\t"))`; we additionally accept
// form-feed and vertical-tab (other ASCII whitespace the CPython tokenizer
// treats as inter-token gap), the `import(x)` shape, and a bare `import` line.
func isImportPrefix(trimmed string) bool {
	const tok = "import"
	if trimmed == tok {
		return true
	}
	if !strings.HasPrefix(trimmed, tok) {
		return false
	}
	switch trimmed[len(tok)] {
	case ' ', '\t', '\f', '\v', '(':
		return true
	}
	return false
}

func excerpt(line string) string {
	flat := strings.Join(strings.Fields(line), " ")
	if len(flat) > maxExcerpt {
		flat = flat[:maxExcerpt] + "…"
	}
	return flat
}

// payloadGroups partitions the Hades payload vocabulary by the *kind* of
// risk so the finding's evidence can name which capability the worm used.
// Group order matters only for diagnostic readability; the first matching
// group wins per signal so the report points at the most specific lens.
var payloadGroups = []struct {
	code  string
	label string
	re    *regexp.Regexp
}{
	{
		code:  "pth-payload-network",
		label: "uses network calls (urllib, requests, socket, http.client, ftplib) — startup-time outbound fetch is the Hades infection pattern.",
		re:    regexp.MustCompile(`\b(?:urllib(?:\.request)?|urlopen|urlretrieve|requests|socket|http\.client|httplib|ftplib)\b`),
	},
	{
		code:  "pth-payload-spawn",
		label: "spawns a process (subprocess, os.system/popen, pty.spawn, os.exec*) at interpreter startup.",
		re:    regexp.MustCompile(`\b(?:subprocess|os\.system|os\.popen|popen|pty\.spawn|os\.(?:exec|spawn)[a-z]*)\b`),
	},
	{
		code:  "pth-payload-dynamic-exec",
		label: "evaluates code dynamically (exec/eval/compile/__import__ on a computed string).",
		re:    regexp.MustCompile(`\b(?:exec|eval|compile|__import__)\s*\(`),
	},
	{
		code:  "pth-payload-deobfuscation",
		label: "decodes or unpacks an embedded blob (base64, marshal, codecs.decode, hex/lzma/zlib) — startup-time decoders are the Hades obfuscation tell.",
		re:    regexp.MustCompile(`\b(?:b64decode|base64|marshal\.loads|codecs\.decode|bytes\.fromhex|zlib\.decompress|lzma)\b|\.decode\(\s*['"]hex['"]\s*\)|(?:\\x[0-9A-Fa-f]{2}){8,}`),
	},
	{
		code:  "pth-payload-runtime-fetch",
		label: "names an external runtime / fetcher (bun, bunx, curl, wget, node, deno) — startup-time downloader for a second-stage payload.",
		re:    regexp.MustCompile(`\b(?:bun|bunx|curl|wget|node|deno)\b`),
	},
	{
		code:  "pth-payload-worm-marker",
		label: "carries a Hades / Shai-Hulud worm marker string.",
		re:    regexp.MustCompile(`\.bun_ran\b|_index\.js\b|\bHades\b|shai-hulud|stygian|tartarean`),
	},
}

// fileNameSetupRe matches the `*-setup.pth` shape Hades-style wheels drop —
// a filename signal independent of body content. Real PyPI ecosystems are
// not known to ship `<name>-setup.pth`; the convention is `distutils-precedence.pth`,
// `__editable__.<name>-<ver>.pth`, `easy-install.pth`, or per-package names
// without a `-setup` suffix.
var fileNameSetupRe = regexp.MustCompile(`(?i)[-_]setup\.pth$`)

// scanPayloadSignals returns the per-group critical signals firing on body
// (an executable line with its leading whitespace already removed).
func scanPayloadSignals(body string) []Signal {
	var out []Signal
	for _, g := range payloadGroups {
		if g.re.MatchString(body) {
			out = append(out, Signal{
				Code:    g.code,
				Detail:  g.label,
				Excerpt: excerpt(body),
			})
		}
	}
	return out
}

// knownLegitLines is the anchored allowlist of executable .pth line shapes
// real Python tooling produces. Each entry is a whole-line regex (after the
// leading whitespace is stripped); a worm that *also* names __editable__ or
// _distutils_hack does NOT match because the regex anchors `^` and `$` and
// covers the entire legitimate body, not a substring.
var knownLegitLines = []*regexp.Regexp{
	// setuptools' distutils-precedence shim. Distros ship variants; the
	// pattern is "import os; <hack-import>".
	regexp.MustCompile(`^import\s+os\s*;\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*os\.environ\.get\(.+?\)\s*;\s*)?__import__\(\s*['"]_distutils_hack['"]\s*\)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\(\s*\))?\s*$`),

	// PEP 660 editable installs — pip writes __editable___<name>_finder.py
	// plus a one-line .pth that imports and installs the finder.
	regexp.MustCompile(`^import\s+__editable___[A-Za-z0-9_]+_finder\s*;\s*__editable___[A-Za-z0-9_]+_finder\.install\(\s*\)\s*$`),
	regexp.MustCompile(`^from\s+__editable___[A-Za-z0-9_]+(?:_finder)?\s+import\s+[A-Za-z_][A-Za-z0-9_]*\s*$`),
	regexp.MustCompile(`^import\s+__editable___[A-Za-z0-9_]+_finder\s*;\s*MapPathFinder\.install\(\s*\)\s*$`),

	// Legacy easy-install.pth path-munge.
	regexp.MustCompile(`^import\s+sys\s*;\s*sys\.__plen\s*=\s*len\(sys\.path\)\s*$`),
	regexp.MustCompile(`^import\s+sys\s*;\s*sys\.__egginsert\s*=\s*0\s*$`),
}

// allowlistedFileName reports whether the .pth's base name is one whose
// known-legit body is allowed by the regex pack above. We don't require this
// — the body regex is the load-bearing check — but a non-matching body that
// nevertheless rides one of these well-known names still gets flagged.
var allowlistedLegitName = regexp.MustCompile(`^(?:distutils-precedence\.pth|__editable__[._-][A-Za-z0-9_.-]+\.pth|easy-install\.pth)$`)

// matchesKnownLegit reports whether trimmed (a single .pth executable line
// with leading whitespace already removed and no trailing newline) matches
// any whole-line legit pattern.
func matchesKnownLegit(trimmed string) bool {
	for _, re := range knownLegitLines {
		if re.MatchString(trimmed) {
			return true
		}
	}
	return false
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
