package abusech

import (
	"os"
	"path/filepath"

	"github.com/brynbellomy/go-utils/errors"
)

// writeAtomic writes payload to dst by renaming a sibling temp file. A crash
// mid-write leaves either the old file or the new file on disk, never a
// truncated one. Used for cached payloads and etag files that fit comfortably
// in memory.
//
// This mirrors internal/intel/sources/internal/fsutil.WriteAtomic; it is
// re-implemented here because Go's internal-package rules forbid importing that
// helper across the intel→ioc boundary, and the ioc tree has no shared fsutil.
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
