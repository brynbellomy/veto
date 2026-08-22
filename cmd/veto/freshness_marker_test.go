package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// markerCountingSource records how many times the network (Fetch) was consulted.
type markerCountingSource struct {
	hits int
}

func (s *markerCountingSource) ID() string { return "counting-feed" }

func (s *markerCountingSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemNPM {
		return nil, intel.ErrUnsupportedEcosystem
	}
	s.hits++
	reports := make([]intel.MalwareReport, 1200)
	for i := range reports {
		reports[i] = intel.MalwareReport{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: fmt.Sprintf("pkg-%04d", i)},
			SourceID:   "counting-feed",
			Reason:     "MALWARE",
		}
	}
	return reports, nil
}

// TestCacheOnlyRefreshDoesNotSlideFreshnessMarker pins FIX 4: the marker
// means "last successful NETWORK refresh," but it slid on every run —
// including cache-only ones — so an agent loop invoking veto more often
// than the window never contacted the wire at all and never reached the
// fetch paths that heal a damaged cache. The window must measure time
// since the last WIRE contact, not since the last invocation.
func TestCacheOnlyRefreshDoesNotSlideFreshnessMarker(t *testing.T) {
	cfg := config{CacheDir: t.TempDir(), Sources: []string{"counting-feed"}}

	// First (network) refresh writes the marker.
	src := &markerCountingSource{}
	store := intel.NewStore(zerolog.Nop(), src)
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))
	marker := intel.LastRefreshPath(cfg.CacheDir)
	_, err := os.ReadFile(marker)
	require.NoError(t, err, "network refresh must write the marker")
	require.Equal(t, 1, src.hits)

	// Backdate the marker so the next refresh is definitely cache-only
	// (inside the window) but a subsequent one would fall OUTSIDE it.
	backdated := time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	require.NoError(t, os.WriteFile(marker, []byte(backdated), 0o600))

	// Second refresh: marker is 2 minutes old, window is 3 — cache-only
	// (the directive is set; whether the source honors it is the
	// source's business — the property under test is the MARKER).
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))

	// FIX 4: the marker must NOT have slid. It still names the backdated
	// time, so 2 minutes from now the window expires and the next
	// invocation goes to the wire — instead of sliding forever under an
	// invocation loop.
	after, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, backdated, string(after),
		"a cache-only refresh must not slide the freshness marker: the window "+
			"measures time since the last NETWORK refresh")

	// And the guarantee that motivated the fix: let the (un-slid) marker
	// age past the window; the next refresh MUST hit the network.
	expired := time.Now().Add(-4 * time.Minute).UTC().Format(time.RFC3339Nano)
	require.NoError(t, os.WriteFile(marker, []byte(expired), 0o600))
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))

}
