package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// orphanTmpMaxAge is how old an orphaned download temp must be before the
// sweep will remove it. This is a SAFETY constant, not a tuning knob: every
// temp file veto writes is created by os.CreateTemp with a process-unique
// name and is renamed or removed within the same fetch — measured in
// seconds, bounded by an HTTP timeout of minutes. A temp file 24 hours old
// was abandoned by a run that died mid-download; no live writer can own
// it. Lower this and you start racing real downloads; the margin above the
// slowest conceivable fetch (hours) is what makes the whole sweep lock-free.
const orphanTmpMaxAge = 24 * time.Hour

// tempMarker is the infix os.CreateTemp leaves between the payload's own
// name and its random suffix: WriteAtomic creates
// filepath.Base(dst)+".tmp-" and the streaming sources pass literal
// patterns like "npm.zip.tmp-". os.CreateTemp then appends a decimal
// string, so a real temp is <payload>.tmp-<digits> with the digits
// TERMINAL. That terminality is what separates a real temp from a gob
// whose etag merely contains ".tmp-" (parsed-abc.tmp-123.gob).
const tempMarker = ".tmp-"

// SweepOrphanTemps removes orphaned download temp files from dir — files
// matching <anything>.tmp-<decimal-digits> whose mtime is older than
// orphanTmpMaxAge — and returns how many were removed.
//
// It exists because every source downloads to a temp file and atomically
// renames it into place; a run that dies before the rename (crash, SIGKILL,
// a cancelled parallel agent) leaves the temp behind forever. On the
// operator machine that accumulated to 126 files / 4.7 GB, with osv's npm
// archive at ~210 MB per orphan.
//
// Safety argument — why no locking is needed. os.CreateTemp generates
// process-unique names and every writer renames or removes its temp within
// one fetch. A live writer's temp file is therefore seconds-to-minutes
// old, never 24 hours. The sweep only touches files older than that, so
// there is no window in which it can race a download in progress: no
// locks, no coordination between concurrent veto processes, no tracked
// state. If a future change makes this need any of those, the property has
// been lost and the design has drifted — reconsider rather than adding a
// lock.
//
// Scope is deliberately ONE flat directory: the caller passes its own
// cache dir and the sweep neither descends into subdirectories nor
// strays outside it, so a bug here can never reach another source's
// cache.
//
// Matching is deliberately narrow. Only a regular file whose base name
// ends in ".tmp-" followed by a non-empty run of decimal digits is
// eligible — exactly the shape os.CreateTemp produces. Real payloads,
// .sha256 sidecars, etags (and their .pending siblings), parsed-*.gob
// layers, intel-baseline.json and last-refresh are never matched, at any
// age. The terminal-digits requirement also protects legitimate files
// that merely contain ".tmp-" mid-name.
//
// Sweep failures are NON-FATAL by contract. A directory that cannot be
// read, or a file that cannot be removed (permissions, read-only
// filesystem), is logged and skipped. Hygiene must never block or fail a
// fetch — this runs on the hot path of every Fetch across nine sources.
func SweepOrphanTemps(dir string, logger zerolog.Logger) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Missing or unreadable cache dir: nothing to sweep, and a sweep
		// that cannot proceed must not proceed loudly. The next fetch's
		// MkdirAll or the fetch itself surfaces real problems.
		logger.Debug().Err(err).Str("dir", dir).Msg("orphan-temp sweep skipped: cannot read cache dir")
		return 0
	}

	cutoff := time.Now().Add(-orphanTmpMaxAge)
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isOrphanTempName(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// Entry vanished between listing and stat — not ours anymore.
			logger.Debug().Err(err).Str("path", filepath.Join(dir, name)).Msg("orphan-temp sweep: stat failed")
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			// Non-fatal by contract: log and keep going. An EROFS mount or
			// a permissions problem is an environment issue, not a reason
			// to fail the fetch this sweep is riding along with.
			logger.Warn().Err(err).
				Str("path", filepath.Join(dir, name)).
				Int64("size_bytes", info.Size()).
				Msg("orphan-temp sweep: could not remove file; leaving it in place")
			continue
		}
		removed++
	}
	if removed > 0 {
		logger.Info().
			Str("dir", dir).
			Int("removed", removed).
			Dur("min_age", orphanTmpMaxAge).
			Msg("orphan-temp sweep: removed abandoned download temps")
	}
	return removed
}

// isOrphanTempName reports whether name is exactly the shape os.CreateTemp
// produces for a veto download temp: a ".tmp-" infix followed, at the very
// END of the name, by a non-empty run of ASCII decimal digits.
//
// The terminality of the digits is load-bearing. A name like
// npm.zip.tmp-123.gob is a real parsed-*.gob cache layer whose etag
// happens to contain ".tmp-" — sweeping it would delete a valid cache
// file. Likewise npm.zip.tmp-12a4 (non-numeric suffix) or npm.zip.tmp-
// (empty suffix) are not os.CreateTemp outputs and are left alone.
func isOrphanTempName(name string) bool {
	i := strings.LastIndex(name, tempMarker)
	if i < 0 {
		return false
	}
	suffix := name[i+len(tempMarker):]
	if suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
