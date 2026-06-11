// Package wheel inspects a Python wheel (.whl) for the Hades / Shai-Hulud
// .pth startup-hook worm without extracting it to disk and without ever
// invoking Python. A wheel is an inert zip; the .pth file is dropped via
// the data scheme (<dist>-<ver>.data/purelib/*.pth, /platlib/*.pth) or as
// a top-level *.pth listed in RECORD. We enumerate both and run each
// .pth through pthscan.Inspect.
package wheel

import (
	"archive/zip"
	"io"
	"os"
	"path"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/pthscan"
)

// maxPthBytes caps how much of any single .pth we read into memory. Real
// .pth files are tiny — a few hundred bytes; an oversized one is treated
// as unscannable (Critical) rather than trusting a clean prefix.
const maxPthBytes = 256 * 1024

// maxWheelEntries caps wheel-zip entries walked. Real wheels have hundreds
// of entries; pathological wheels with millions are rejected.
const maxWheelEntries = 100_000

// maxWheelDecompressedBytes caps the total bytes decompressed across all
// entries in a single wheel scan. Per-entry reads are already capped at
// maxPthBytes (256 KB); this total cap guards against zip-bomb payloads
// that embed many entries each just below the per-entry limit, or against
// non-.pth entries that are read en-route (e.g. RECORD parsing, if ever
// re-added). 256 MB is orders of magnitude above any legitimate wheel while
// still small enough to bound memory pressure on a DoS-shaped input.
const maxWheelDecompressedBytes = 256 * 1024 * 1024

// Inspect reads a wheel from r (must be a ReaderAt; the *bytes.Reader and
// *os.File from a downloaded wheel both satisfy this) of size and classifies
// every .pth file inside via pthscan.Inspect. Returns the highest-severity
// verdict found, with all firing .pth files' signals concatenated.
//
// A wheel with no .pth files yields SeverityNone (nothing for site.py to
// execute). Errors are returned only on malformed zip / IO; an unparseable
// RECORD is non-fatal (the data-scheme walk catches the .pth too).
func Inspect(r io.ReaderAt, size int64) (pthscan.Verdict, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return pthscan.Verdict{}, errors.With(err, "open wheel zip")
	}
	if len(zr.File) > maxWheelEntries {
		return pthscan.Verdict{}, errors.WithNew("wheel has too many entries").Set("limit", maxWheelEntries)
	}

	pthFiles, err := collectPthEntries(zr)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	if len(pthFiles) == 0 {
		return pthscan.Verdict{Severity: pthscan.SeverityNone}, nil
	}

	worst := pthscan.SeverityNone
	var signals []pthscan.Signal
	for _, p := range pthFiles {
		verdict := pthscan.Inspect(pthscan.Input{
			PthContent: p.content,
			FileName:   path.Base(p.name),
			Truncated:  p.truncated,
		})
		if severityRank(verdict.Severity) > severityRank(worst) {
			worst = verdict.Severity
		}
		signals = append(signals, verdict.Signals...)
	}
	return pthscan.Verdict{Severity: worst, Signals: signals}, nil
}

type pthEntry struct {
	name      string // entry path inside the zip
	content   []byte
	truncated bool
}

// collectPthEntries walks the wheel zip and gathers every .pth file that
// Python's site.py could execute at startup: entries in the data-scheme
// purelib/platlib directories and bare top-level .pth files.
//
// Note: RECORD parsing was considered (to discover .pth files listed in
// RECORD at unusual paths) but removed — the data-scheme zip walk is
// sufficient for all known worm vectors, RECORD parsing had an unsatisfiable
// predicate (base cannot contain '/'), and recordEntries had no consumer.
// If a future wheel layout requires RECORD consultation, add it then with a
// tested consumer. Adversarial wheels that omit/corrupt RECORD are already
// handled correctly by the direct zip walk.
func collectPthEntries(zr *zip.Reader) ([]pthEntry, error) {
	var out []pthEntry
	var totalDecompressed int64
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") {
			continue
		}
		// Defense-in-depth: explicitly skip symlink entries. The scanner
		// never extracts to disk, so symlinks are not currently exploitable,
		// but rejecting them here prevents any future extraction path from
		// accidentally following a wheel-embedded symlink outside the zip.
		if f.Mode()&os.ModeSymlink != 0 {
			continue
		}
		base := path.Base(name)
		if !strings.HasSuffix(base, ".pth") {
			continue
		}
		if !isPthInWheel(name) {
			continue
		}
		content, truncated, err := readZipEntry(f, maxPthBytes)
		if err != nil {
			return nil, errors.With(err, "read wheel .pth entry").Set("path", name)
		}
		totalDecompressed += int64(len(content))
		if totalDecompressed > maxWheelDecompressedBytes {
			return nil, errors.WithNew("wheel decompressed size exceeds limit").
				Set("limit", maxWheelDecompressedBytes, "path", name)
		}
		out = append(out, pthEntry{name: name, content: content, truncated: truncated})
	}
	return out, nil
}

// isPthInWheel reports whether a zip entry path is a position where Python
// will install a .pth at install-time: either the data scheme's purelib /
// platlib directories, or a top-level location alongside the dist-info.
func isPthInWheel(name string) bool {
	if !strings.HasSuffix(name, ".pth") {
		return false
	}
	// Top-level .pth (uncommon but valid).
	if !strings.Contains(name, "/") {
		return true
	}
	// Data scheme: <dist>-<ver>.data/purelib/<...>.pth or .../platlib/<...>.pth
	//
	// Defense-in-depth: split on '/' and match segment positions rather than
	// using strings.Contains. This prevents a crafted name like
	// "malicious_purelib/foo.pth" from matching the ".data/purelib/" substring
	// while not being in a real data-scheme purelib directory. After path.Clean
	// the entry name has no ".." components, so the segment positions are
	// authoritative: we require a segment ending in ".data" immediately followed
	// by a segment that is exactly "purelib" or "platlib".
	segs := strings.Split(name, "/")
	for i := 0; i+2 < len(segs); i++ {
		if strings.HasSuffix(segs[i], ".data") &&
			(segs[i+1] == "purelib" || segs[i+1] == "platlib") {
			return true
		}
	}
	return false
}

func readZipEntry(f *zip.File, limit int64) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

func severityRank(s pthscan.Severity) int {
	switch s {
	case pthscan.SeverityCritical:
		return 3
	case pthscan.SeverityMedium:
		return 2
	case pthscan.SeverityNone:
		return 1
	default:
		return 0
	}
}
