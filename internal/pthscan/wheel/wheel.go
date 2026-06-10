// Package wheel inspects a Python wheel (.whl) for the Hades / Shai-Hulud
// .pth startup-hook worm without extracting it to disk and without ever
// invoking Python. A wheel is an inert zip; the .pth file is dropped via
// the data scheme (<dist>-<ver>.data/purelib/*.pth, /platlib/*.pth) or as
// a top-level *.pth listed in RECORD. We enumerate both and run each
// .pth through pthscan.Inspect.
package wheel

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"io"
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

// collectPthEntries walks the wheel zip and gathers every .pth file via
// either the data scheme or a top-level location. RECORD is consulted as a
// hint but not relied on (some adversarial wheels omit / corrupt RECORD).
func collectPthEntries(zr *zip.Reader) ([]pthEntry, error) {
	var out []pthEntry
	recordEntries := map[string]struct{}{}
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if name == "." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "..") {
			continue
		}
		base := path.Base(name)
		if strings.HasSuffix(base, ".dist-info/RECORD") || strings.HasSuffix(name, "RECORD") && strings.Contains(name, ".dist-info/") {
			// Parse RECORD as a CSV; first column is the entry path. Best-effort.
			content, _, err := readZipEntry(f, maxPthBytes*4)
			if err == nil {
				rd := csv.NewReader(bytes.NewReader(content))
				rd.FieldsPerRecord = -1
				for {
					row, err := rd.Read()
					if err != nil {
						break
					}
					if len(row) == 0 {
						continue
					}
					rel := strings.TrimSpace(row[0])
					if strings.HasSuffix(rel, ".pth") {
						recordEntries[rel] = struct{}{}
					}
				}
			}
			continue
		}
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
		out = append(out, pthEntry{name: name, content: content, truncated: truncated})
	}
	// RECORD entries we haven't seen yet would be a `.pth` in an unusual
	// path. The zip walk above already enumerated every file; recordEntries
	// is informational. (We keep the parse in place because it would matter
	// in a future where a wheel ships a custom installer script that places
	// .pth files outside the data-scheme directories.)
	_ = recordEntries
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
	if strings.Contains(name, ".data/purelib/") || strings.Contains(name, ".data/platlib/") {
		return true
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
