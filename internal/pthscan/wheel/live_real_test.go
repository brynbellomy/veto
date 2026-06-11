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
