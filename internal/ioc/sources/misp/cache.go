package misp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/ioc"
)

// cachedEvent is the on-disk extraction for one event: the manifest timestamp
// it was derived from plus the indicators it yielded. A cache hit requires the
// stored Timestamp to equal the current manifest's, which is how the
// unchanged-event short-circuit avoids re-downloading.
type cachedEvent struct {
	Timestamp  int64           `json:"timestamp"`
	Indicators []ioc.Indicator `json:"indicators"`
}

// eventCachePath returns the on-disk path for an event's cached extraction. The
// UUID is sanitized to a bare filename so a hostile manifest key can't escape
// the cache directory via path separators.
func (s *Source) eventCachePath(uuid string) string {
	return filepath.Join(s.cacheDir, "events", sanitizeUUID(uuid)+".json")
}

// readEventCache returns the cached indicators for an event when an on-disk
// extraction exists and its recorded manifest timestamp matches wantTS. A miss
// (absent, unreadable, stale, or malformed) returns ok=false so the caller
// re-downloads.
func (s *Source) readEventCache(uuid string, wantTS int64) ([]ioc.Indicator, bool) {
	data, err := os.ReadFile(s.eventCachePath(uuid))
	if err != nil {
		return nil, false
	}
	var ce cachedEvent
	if err := json.Unmarshal(data, &ce); err != nil {
		return nil, false
	}
	if ce.Timestamp != wantTS {
		return nil, false
	}
	return ce.Indicators, true
}

// writeEventCache persists an event's extraction keyed by its manifest
// timestamp. A write failure is logged and swallowed: the cache is an
// optimization, and a failed write only costs a re-download next time.
func (s *Source) writeEventCache(uuid string, ts int64, indicators []ioc.Indicator) {
	payload, err := json.Marshal(cachedEvent{Timestamp: ts, Indicators: indicators})
	if err != nil {
		s.logger.Debug().Err(err).Str("event", uuid).Msg("marshal event cache")
		return
	}
	if err := writeAtomic(s.eventCachePath(uuid), payload); err != nil {
		s.logger.Debug().Err(err).Str("event", uuid).Msg("write event cache")
	}
}

// sanitizeUUID reduces a manifest key to characters legal in a MISP UUID
// (hex and dashes), neutralizing any path-traversal attempt in a hostile feed.
func sanitizeUUID(uuid string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '-':
			return r
		default:
			return '_'
		}
	}, uuid)
}

// writeAtomic writes payload to dst via a sibling temp file and rename, so a
// crash mid-write leaves either the old file or the new one, never a truncated
// one. The intel sources share an fsutil helper for this, but that package is
// import-restricted to internal/intel/sources/...; the ioc tree carries its own
// copy here.
func writeAtomic(dst string, payload []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-")
	if err != nil {
		return errors.With(err, "create temp")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "write temp")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close temp")
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename temp")
	}
	return nil
}
