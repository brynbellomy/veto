//go:build livegyp

package tarball_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gypscan/tarball"
)

// TestInspectRealTarball inspects a real .tgz pointed to by VETO_TEST_TGZ and
// prints the verdict. Run with: go test -tags livegyp -run TestInspectRealTarball
// -v ./internal/gypscan/tarball/ with VETO_TEST_TGZ set. Used to validate the
// inspector against real-world native packages (no false positives).
func TestInspectRealTarball(t *testing.T) {
	path := os.Getenv("VETO_TEST_TGZ")
	if path == "" {
		t.Skip("set VETO_TEST_TGZ to a .tgz path")
	}
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	v, err := tarball.Inspect(f)
	require.NoError(t, err)
	t.Logf("tarball=%s flagged=%v severity=%s signals=%d", path, v.Flagged(), v.Severity, len(v.Signals))
	for _, s := range v.Signals {
		t.Logf("  signal: %s — %s", s.Code, s.Excerpt)
	}
	require.False(t, v.Flagged(), "real native package should not be flagged")
}
