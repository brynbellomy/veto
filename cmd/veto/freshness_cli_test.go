package main

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// countingSource records how many times Fetch ran and whether the context
// carried the cache-only directive.
type countingSource struct {
	fetches       atomic.Int32
	sawCacheOnly  atomic.Bool
	sawNetworkCtx atomic.Bool
}

func (s *countingSource) ID() string { return "counting" }

func (s *countingSource) Fetch(ctx context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemNPM {
		return nil, intel.ErrUnsupportedEcosystem
	}
	s.fetches.Add(1)
	if intel.CacheOnly(ctx) {
		s.sawCacheOnly.Store(true)
	} else {
		s.sawNetworkCtx.Store(true)
	}
	return []intel.MalwareReport{{
		PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"},
		SourceID:   "counting",
		Reason:     "fixture",
	}}, nil
}

// TestRefreshStoreWithFreshnessWindowRecordsMarker: the first refresh runs
// against the network context and writes the marker; the second (inside
// the window) carries the cache-only directive so sources serve from disk.
func TestRefreshStoreWithFreshnessWindowRecordsMarker(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()}
	src := &countingSource{}
	store := intel.NewStore(zerolog.Nop(), src)

	// First refresh: no marker exists, so the directive is absent.
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))
	require.Equal(t, int32(1), src.fetches.Load())
	require.True(t, src.sawNetworkCtx.Load(), "first refresh must run without the cache-only directive")
	require.False(t, src.sawCacheOnly.Load())

	_, fresh := intel.ReadLastRefresh(cfg.CacheDir, time.Now())
	require.True(t, fresh, "marker must be recorded after a successful refresh")

	// Second refresh inside the window: the directive must be set.
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))
	require.Equal(t, int32(2), src.fetches.Load())
	require.True(t, src.sawCacheOnly.Load(), "refresh inside the freshness window must carry the cache-only directive")
}

// TestRefreshStoreWithFreshnessWindowCorruptMarkerStillRefreshes: a
// corrupt marker must fall back to a full (network-context) refresh —
// never suppress one.
func TestRefreshStoreWithFreshnessWindowCorruptMarkerStillRefreshes(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()}
	// Corrupt marker in place.
	require.NoError(t, os.WriteFile(intel.LastRefreshPath(cfg.CacheDir), []byte("garbage-not-a-time"), 0o600))

	src := &countingSource{}
	store := intel.NewStore(zerolog.Nop(), src)
	require.NoError(t, refreshStoreWithFreshnessWindow(zerolog.Nop(), cfg, store))
	require.True(t, src.sawNetworkCtx.Load(), "corrupt marker must fall back to a full refresh")
	require.False(t, src.sawCacheOnly.Load())
}
