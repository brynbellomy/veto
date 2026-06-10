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
