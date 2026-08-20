package intel_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestReadLastRefreshMissingMarkerRefreshes: no marker file at all (first
// run, cache wipe) must mean "refresh now."
func TestReadLastRefreshMissingMarkerRefreshes(t *testing.T) {
	dir := t.TempDir()
	_, fresh := intel.ReadLastRefresh(dir, time.Now())
	require.False(t, fresh)
}

// TestReadLastRefreshCorruptMarkerRefreshes: a marker whose contents do not
// parse as RFC3339Nano must NEVER suppress a refresh. A stale security
// decision from a bad cache file is the failure mode this test exists to
// prevent.
func TestReadLastRefreshCorruptMarkerRefreshes(t *testing.T) {
	corruptPayloads := map[string]string{
		"garbage":          "not-a-timestamp",
		"empty":            "",
		"whitespace only":  "  \n\t ",
		"truncated":        "2026-08-19T19:",
		"wrong layout":     "19/08/2026 19:00",
		"unix epoch text":  "1755646800",
		"json-ish":         `{"last_refresh": "2026-08-19T19:00:00Z"}`,
		"double line":      "2026-08-19T19:00:00Z\n2026-08-19T19:01:00Z\n",
		"trailing garbage": "2026-08-19T19:00:00Z garbage",
	}

	for name, payload := range corruptPayloads {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "last-refresh"), []byte(payload), 0o600))
			_, fresh := intel.ReadLastRefresh(dir, time.Now())
			require.False(t, fresh, "corrupt marker %q must force a refresh", payload)
		})
	}
}

// TestReadLastRefreshFutureDatedRefreshes: a marker in the future (clock
// skew, restored backup, NTP correction) must force a refresh — trusting
// it would suppress refreshes until the wall clock caught up.
func TestReadLastRefreshFutureDatedRefreshes(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	future := now.Add(10 * time.Minute)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "last-refresh"),
		[]byte(future.UTC().Format(time.RFC3339Nano)),
		0o600,
	))
	_, fresh := intel.ReadLastRefresh(dir, now)
	require.False(t, fresh)
}

// TestReadLastRefreshInsideWindowSkipsRefresh: a marker younger than the
// freshness window is honored.
func TestReadLastRefreshInsideWindowSkipsRefresh(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for _, age := range []time.Duration{0, 30 * time.Second, intel.RefreshFreshnessWindow - time.Second} {
		last := now.Add(-age)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "last-refresh"),
			[]byte(last.UTC().Format(time.RFC3339Nano)),
			0o600,
		))
		got, fresh := intel.ReadLastRefresh(dir, now)
		require.True(t, fresh, "marker %s ago (window %s) must skip the refresh", age, intel.RefreshFreshnessWindow)
		require.WithinDuration(t, last, got, time.Second)
	}
}

// TestReadLastRefreshOutsideWindowRefreshes: a marker at or past the
// window boundary refreshes. Boundary is inclusive-expired: exactly
// RefreshFreshnessWindow old = refresh.
func TestReadLastRefreshOutsideWindowRefreshes(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for _, age := range []time.Duration{intel.RefreshFreshnessWindow, intel.RefreshFreshnessWindow + time.Second, time.Hour} {
		last := now.Add(-age)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "last-refresh"),
			[]byte(last.UTC().Format(time.RFC3339Nano)),
			0o600,
		))
		_, fresh := intel.ReadLastRefresh(dir, now)
		require.False(t, fresh, "marker %s ago (window %s) must refresh", age, intel.RefreshFreshnessWindow)
	}
}

// TestWriteThenReadRoundTrips: WriteLastRefresh produces a marker that
// ReadLastRefresh accepts as fresh.
func TestWriteThenReadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	require.NoError(t, intel.WriteLastRefresh(dir, now))
	got, fresh := intel.ReadLastRefresh(dir, now.Add(time.Second))
	require.True(t, fresh)
	require.WithinDuration(t, now, got, time.Second)
}

// TestWriteLastRefreshCreatesCacheDir: the marker write must tolerate a
// not-yet-existing cache dir (first-ever run).
func TestWriteLastRefreshCreatesCacheDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "veto-cache")
	require.NoError(t, intel.WriteLastRefresh(dir, time.Now()))
	info, err := os.Stat(filepath.Join(dir, "last-refresh"))
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
}

// TestCacheOnlyContextRoundTrip: the directive flag round-trips through
// context and defaults to false.
func TestCacheOnlyContextRoundTrip(t *testing.T) {
	ctx := t.Context()
	require.False(t, intel.CacheOnly(ctx))
	require.True(t, intel.CacheOnly(intel.WithCacheOnly(ctx)))
}

// TestRefreshFreshnessWindowValue pins the window at the documented 3
// minutes so a drive-by change shows up in review.
func TestRefreshFreshnessWindowValue(t *testing.T) {
	require.Equal(t, 3*time.Minute, intel.RefreshFreshnessWindow)
}
