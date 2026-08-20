package intel

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/brynbellomy/go-utils/errors"
)

// RefreshFreshnessWindow is the short-lived freshness window for the
// advisory cache. When the recorded last-successful-refresh is younger
// than this, callers skip the network refresh entirely and sources serve
// from their on-disk caches. Repeated `veto <pm> install ...` invocations
// in quick succession (agent loops, CI retries) otherwise pay one HTTP
// round-trip per (source, ecosystem) on every run.
//
// Security posture: 3 minutes is far inside every upstream feed's
// publication cadence, and the per-source etag caches already serve
// multi-hour stints on 304s. A bad marker must NEVER suppress a refresh —
// see ReadLastRefresh for the failure rules.
const RefreshFreshnessWindow = 3 * time.Minute

// lastRefreshFilename is the marker file recording when the advisory set
// was last successfully refreshed. It lives in the root of the veto cache
// directory alongside the per-source subdirectories.
const lastRefreshFilename = "last-refresh"

type cacheOnlyCtxKey struct{}

// WithCacheOnly returns a context carrying the cache-only directive:
// intel sources honor it by serving Fetch from their on-disk cache
// without contacting the network. Sources with no usable cache MUST fall
// through to their normal network path — the directive is an
// optimization, never a correctness gate.
func WithCacheOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, cacheOnlyCtxKey{}, true)
}

// CacheOnly reports whether ctx carries the cache-only directive.
func CacheOnly(ctx context.Context) bool {
	v, _ := ctx.Value(cacheOnlyCtxKey{}).(bool)
	return v
}

// LastRefreshPath returns the marker path for a veto cache directory.
func LastRefreshPath(cacheDir string) string {
	return filepath.Join(cacheDir, lastRefreshFilename)
}

// ReadLastRefresh reads the recorded last-successful-refresh time from the
// veto cache directory. fresh=false means "refresh now" — returned when:
//
//   - the marker does not exist (first run, cache wipe),
//   - the marker is empty or unreadable,
//   - the marker's contents do not parse as RFC3339Nano (corrupt — hand
//     edits, partial writes, filesystem damage),
//   - the recorded time is in the future (clock skew, restored backups,
//     NTP corrections; trusting it would suppress refreshes until the
//     wall clock catches up),
//   - the recorded time is at or older than RefreshFreshnessWindow.
//
// The fail-safe direction is always "refresh": a bad marker costs one
// network round-trip, while a wrongly-trusted marker produces a stale
// security decision.
func ReadLastRefresh(cacheDir string, now time.Time) (last time.Time, fresh bool) {
	data, err := os.ReadFile(LastRefreshPath(cacheDir))
	if err != nil || len(data) == 0 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(trimSpaceBytes(data)))
	if err != nil {
		return time.Time{}, false
	}
	if t.After(now) {
		return time.Time{}, false
	}
	if now.Sub(t) >= RefreshFreshnessWindow {
		return t, false
	}
	return t, true
}

// WriteLastRefresh records a successful refresh of the advisory set. The
// write is temp+rename so a crash mid-write leaves either the old marker
// or none at all — never a truncated one that a later ReadLastRefresh
// might misparse (it would fall back to refresh-now anyway, but keeping
// the invariant clean costs nothing).
//
// Errors are returned for the caller's logs but are non-fatal: the worst
// case of a failed marker write is one extra refresh next run.
func WriteLastRefresh(cacheDir string, t time.Time) error {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return errors.With(err, "create cache dir for refresh marker").Set("path", cacheDir)
	}
	dst := LastRefreshPath(cacheDir)
	tmp, err := os.CreateTemp(cacheDir, lastRefreshFilename+".tmp-")
	if err != nil {
		return errors.With(err, "create refresh marker temp")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(t.UTC().Format(time.RFC3339Nano)); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "write refresh marker temp")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close refresh marker temp")
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename refresh marker")
	}
	return nil
}

// trimSpaceBytes strips ASCII whitespace (including a trailing newline)
// from both ends without importing bytes for one call.
func trimSpaceBytes(b []byte) []byte {
	start := 0
	for start < len(b) && isSpaceByte(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
