// Package fsutil holds small filesystem helpers shared across the intel
// feed sources. Anything in here is internal-only — the parent
// internal/intel/sources/internal/ path makes that explicit to the Go
// import-path enforcer.
//
// THREAT MODEL (read this before trusting a HashMatch): the content-hash
// sidecars detect CORRUPTION — crash, partial write, disk rot. They are
// NOT an authenticity boundary. A writer that can modify a payload can
// also recompute its sidecar (and rewrite the baseline file), and this
// layer will report HashMatch. That is accepted under veto's
// corruption-only model: anything that can write ~/.cache/veto as your
// UID can also replace the veto binary, so a stronger hash here defends
// nothing. HashMatch means "consistent with whatever last wrote this
// file," not "verified."
package fsutil

import (
	"os"
	"path/filepath"

	"github.com/brynbellomy/go-utils/errors"
)

// WriteAtomic writes payload to dst by renaming a sibling temp file. A
// crash mid-write leaves either the old file or the new file on disk,
// never a truncated one. Used for cached payloads + etag files that fit
// comfortably in memory.
//
// Streaming sources (osv, openssf) that download multi-hundred-MiB bodies
// do tmp+rename inline with their own oversize handling — they're not
// good candidates for this helper because the size-cap error needs to
// surface upward with source-specific context.
func WriteAtomic(dst string, payload []byte) error {
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
