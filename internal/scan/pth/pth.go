// Package pth scans installed Python environment trees for .pth files that
// match the Hades / Shai-Hulud startup-hook worm pattern.
//
// Where the project scanner prunes virtualenvs (it cares only about
// committed manifests), this one descends into them — an installed worm
// lives in site-packages, not in pyproject.toml. The detector lives in
// internal/pthscan; this package owns the file I/O, ctx cancellation, and
// scan.Finding emission.
package pth

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/scan"
)

// maxPthBytes caps how much of a single .pth file we read. Real .pth files
// are tiny; an oversized one is treated as unscannable (Critical).
const maxPthBytes = 256 * 1024

// Options configures a .pth scanner.
type Options struct {
	// Roots are the project roots to walk. The scanner descends into every
	// `site-packages` / `dist-packages` directory beneath each root and
	// inside any venv-shaped subdirectory (.venv, venv, env, ...).
	Roots []string
}

// Scanner walks project trees for worm-shaped .pth files.
type Scanner struct {
	roots []string
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a .pth scanner.
func New(opts Options) *Scanner {
	return &Scanner{roots: append([]string{}, opts.Roots...)}
}

// Scan implements scan.Scanner. It walks each root, finds every .pth file
// inside a site-packages / dist-packages directory, and emits a finding for
// each one pthscan flags.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	for _, root := range s.roots {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		if root == "" {
			continue
		}
		insideSitePackages := false
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk pth scan path").Set("path", path))
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldPruneDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".pth") {
				return nil
			}
			// Only consider .pth files that live under a site-packages or
			// dist-packages directory — those are the ones Python's site
			// module loads at startup. .pth files in other locations (test
			// fixtures, source trees) are not loaded and not interesting.
			if !insideSitePackagesPath(path) {
				return nil
			}
			_ = insideSitePackages
			result.FilesScanned++
			finding, err := s.scanPth(path)
			if err != nil {
				result.Errors = append(result.Errors, err)
				return nil
			}
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk pth scan root").Set("root", root))
		}
	}
	return result
}

// insideSitePackagesPath reports whether path lies inside a site-packages
// or dist-packages directory anywhere along its ancestry.
func insideSitePackagesPath(path string) bool {
	for seg := range strings.SplitSeq(filepath.ToSlash(path), "/") {
		if seg == "site-packages" || seg == "dist-packages" {
			return true
		}
	}
	return false
}

func (s *Scanner) scanPth(path string) (*scan.Finding, error) {
	content, truncated, err := readCapped(path, maxPthBytes)
	if err != nil {
		return nil, errors.With(err, "read .pth").Set("path", path)
	}
	verdict := pthscan.Inspect(pthscan.Input{
		PthContent: content,
		FileName:   filepath.Base(path),
		Truncated:  truncated,
	})
	if !verdict.Flagged() {
		return nil, nil
	}
	severity := scan.SeverityHigh
	if verdict.Severity == pthscan.SeverityCritical {
		severity = scan.SeverityCritical
	}
	evidence := make([]scan.Evidence, 0, len(verdict.Signals))
	for _, sig := range verdict.Signals {
		val := sig.Detail
		if sig.Excerpt != "" {
			val = sig.Detail + " — " + sig.Excerpt
		}
		evidence = append(evidence, scan.Evidence{Label: sig.Code, Value: val})
	}
	return &scan.Finding{
		ID:          "pth:" + string(verdict.Severity) + ":" + path,
		Surface:     scan.SurfaceProject,
		Severity:    severity,
		Path:        path,
		Title:       ".pth file matches startup-hook worm pattern (Hades / Shai-Hulud)",
		Evidence:    evidence,
		Remediation: "Do NOT run python or pip/uv/poetry/pdm in this environment until resolved — site.py executes this .pth at every interpreter startup. Delete the offending package, remove the venv (or clear site-packages), and rotate any credentials reachable from machines that already ran the interpreter in this env.",
	}, nil
}

func readCapped(path string, limit int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// shouldPruneDir skips directory trees that cannot contain an active site
// hierarchy. node_modules, VCS metadata, mypy/pytest caches are not where
// Python loads .pth files from; pruning keeps the walk cheap.
func shouldPruneDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__":
		return true
	default:
		return false
	}
}
