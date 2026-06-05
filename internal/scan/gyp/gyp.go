// Package gyp scans installed npm package trees for binding.gyp files whose
// contents match the phantom-gyp / Miasma worm class (the June 2026
// binding.gyp campaign).
//
// This is veto's existing-exposure surface for a threat the name+version
// intel model cannot see: the worm rides trusted package names via
// account-takeover, so a freshly-compromised version is not in any malware
// feed for hours, and it keeps package.json scripts clean so lifecycle-script
// inspection finds nothing. The only durable signal is the binding.gyp's
// contents — so this scanner walks node_modules trees, reads each
// binding.gyp, and runs it through gypscan.Inspect. Unlike the project
// scanner (which deliberately prunes node_modules because it only cares about
// committed manifests), this scanner descends INTO node_modules: an installed
// worm lives there, not in the manifest.
package gyp

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/gypscan"
	"github.com/brynbellomy/veto/internal/scan"
)

// maxGypBytes caps how much of a binding.gyp we read. A real binding.gyp is a
// few KB; the worm's is ~157 bytes. Anything past this is not a legitimate
// build descriptor and reading it whole would only burn memory — we read the
// cap and let the heuristic run on the prefix.
const maxGypBytes = 256 * 1024

// maxIncludeDepth caps transitive GYP includes to avoid cycles and
// adversarial fan-out.
const maxIncludeDepth = 8

// Options configures a gyp Scanner.
type Options struct {
	// Roots are the project roots to walk. The scanner descends into
	// node_modules beneath each (that is where installed packages, and their
	// binding.gyp files, live).
	Roots []string
}

// Scanner walks project trees for worm-shaped binding.gyp files.
type Scanner struct {
	roots []string
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a gyp scanner.
func New(opts Options) *Scanner {
	return &Scanner{roots: append([]string{}, opts.Roots...)}
}

// Scan implements scan.Scanner. It walks each root, reads every binding.gyp it
// finds (inside node_modules and at project roots), and emits a finding for
// each one gypscan flags. It never executes anything and never mutates the
// host. ctx cancellation is respected at every directory boundary.
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
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk gyp scan path").Set("path", path))
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
			if entry.Name() != "binding.gyp" {
				return nil
			}
			result.FilesScanned++
			finding, err := s.scanGyp(path)
			if err != nil {
				result.Errors = append(result.Errors, err)
				return nil
			}
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk gyp scan root").Set("root", root))
		}
	}
	return result
}

// scanGyp reads one binding.gyp plus the sibling evidence gypscan can use, runs
// the heuristic, and returns a finding when flagged (nil otherwise). I/O errors
// reading the gyp are returned so the caller can surface them as non-fatal scan
// errors; a binding.gyp that cannot be read is reported, not silently skipped.
func (s *Scanner) scanGyp(path string) (*scan.Finding, error) {
	content, err := readCapped(path, maxGypBytes)
	if err != nil {
		return nil, errors.With(err, "read binding.gyp").Set("path", path)
	}

	dir := filepath.Dir(path)
	pkgJSON, _ := readCapped(filepath.Join(dir, "package.json"), maxGypBytes) // best-effort; absence is fine
	siblings := listSiblings(dir)
	includedContents := resolveIncludedContents(dir, content)

	verdict := gypscan.Inspect(gypscan.Input{
		GypContent:       content,
		IncludedContents: includedContents,
		PackageJSON:      pkgJSON,
		SiblingFiles:     siblings,
	})
	if !verdict.Flagged() {
		return nil, nil
	}

	severity := scan.SeverityHigh
	if verdict.Severity == gypscan.SeverityCritical {
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
		ID:          "gyp:" + string(verdict.Severity) + ":" + path,
		Surface:     scan.SurfaceProject,
		Severity:    severity,
		Path:        path,
		Title:       "binding.gyp matches install-time worm pattern (phantom-gyp / Miasma)",
		Evidence:    evidence,
		Remediation: "Do NOT run npm install/update in this tree until resolved — node-gyp executes this binding.gyp at install time even with --ignore-scripts. Delete the package, clear node_modules and the lockfile entry, and rotate any credentials reachable from machines that already installed it.",
	}, nil
}

func resolveIncludedContents(packageRoot string, rootContent []byte) [][]byte {
	rootAbs, err := filepath.Abs(packageRoot)
	if err != nil {
		return nil
	}
	rootAbs = filepath.Clean(rootAbs)

	seen := map[string]struct{}{}
	var out [][]byte
	var walk func(baseDir string, content []byte, depth int)
	walk = func(baseDir string, content []byte, depth int) {
		if depth >= maxIncludeDepth {
			return
		}
		for _, includePath := range gypscan.ParseIncludePaths(content) {
			candidate := filepath.Clean(filepath.Join(baseDir, filepath.FromSlash(includePath)))
			candidateAbs, err := filepath.Abs(candidate)
			if err != nil {
				continue
			}
			candidateAbs = filepath.Clean(candidateAbs)
			if !pathWithinRoot(rootAbs, candidateAbs) {
				continue
			}
			if _, ok := seen[candidateAbs]; ok {
				continue
			}
			seen[candidateAbs] = struct{}{}
			included, err := readCapped(candidateAbs, maxGypBytes)
			if err != nil || included == nil {
				continue
			}
			out = append(out, included)
			walk(filepath.Dir(candidateAbs), included, depth+1)
		}
	}
	walk(rootAbs, rootContent, 0)
	return out
}

func pathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// readCapped reads up to limit bytes from path. Returns (nil, nil) when the
// file does not exist so optional siblings (package.json) degrade quietly;
// other errors are returned.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		// EOF on empty file reads as (0, io.EOF); treat as empty content.
		return []byte{}, nil
	}
	return buf[:n], nil
}

// listSiblings returns the base names of the files (not dirs) directly inside
// dir, so gypscan can decide whether the package ships any native source. Best
// effort: an unreadable directory yields an empty list (gypscan then declines
// to assert the pure-JS signal rather than guessing).
func listSiblings(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// shouldPruneDir skips directory trees that never contain a package's own
// binding.gyp worth scanning. Crucially this does NOT prune node_modules —
// that is exactly where installed packages live. It prunes VCS metadata and
// build-output dirs to keep the walk cheap.
func shouldPruneDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".turbo", ".cache", ".bin":
		return true
	default:
		return false
	}
}
