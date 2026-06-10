// Package wsglob expands workspace-member glob patterns. It wraps
// filepath.Glob to additionally support the doublestar token (`**`),
// which matches zero or more path components and which workspace
// members across uv / npm / cargo monorepos commonly use
// (e.g. `packages/**`, `apps/**/web`).
//
// Stdlib filepath.Glob supports only single-component wildcards
// (`*`, `?`, `[…]`). A `packages/**` pattern handed to it matches
// nothing, which would silently drop every workspace member —
// fail-OPEN for a tool whose job is closing fail-opens.
//
// Scope is deliberately narrow: one `**` per pattern, splitting it
// into a literal-or-shell-glob prefix and a literal-or-shell-glob
// suffix. The supported shapes cover real-world workspace patterns
// (`packages/**`, `**/pkg`, `packages/**/src`). Multi-`**` patterns
// like `a/**/b/**/c` are not supported and are detected at the call
// site (Match returns an error).
package wsglob

import (
	"io/fs"
	"path/filepath"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"
)

// Match is a drop-in replacement for filepath.Glob that also expands
// the doublestar token `**`. It returns absolute or relative paths
// matching pattern, sorted in lexical order (mirroring filepath.Glob).
// Patterns with no `**` are delegated unchanged to filepath.Glob, so
// existing behavior is preserved bit-for-bit for the common cases.
//
// For patterns with one `**`: the pattern is split at that token into
// `prefix**suffix`. The walker descends from the longest literal
// directory prefix of `prefix`, visits each directory, joins the
// per-directory path with `suffix`, and feeds the result through
// filepath.Glob — so any wildcards in `suffix` keep working. Empty
// suffix means "emit every visited directory under the prefix."
//
// Patterns with two or more `**` tokens return an error rather than
// silently mis-matching. Workspace schemas don't require them in
// practice, and supporting them correctly would substantially expand
// the surface for parsing bugs.
func Match(pattern string) ([]string, error) {
	if !strings.Contains(pattern, "**") {
		return filepath.Glob(pattern)
	}
	if strings.Count(pattern, "**") > 1 {
		return nil, vetoerrors.WithNew("workspace glob supports at most one `**` token").
			Set("pattern", pattern)
	}

	idx := strings.Index(pattern, "**")
	prefix := strings.TrimSuffix(pattern[:idx], "/")
	suffix := strings.TrimPrefix(pattern[idx+2:], "/")

	// Walk-root selection. The walker needs a real directory to start
	// from; if `prefix` itself contains wildcards (e.g. `apps/*/`)
	// we first expand it via filepath.Glob and walk each resulting
	// directory in turn. Empty prefix walks from the CWD.
	roots, err := expandPrefixRoots(prefix)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var matches []string
	add := func(p string) {
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		matches = append(matches, p)
	}

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			// Tolerate unreadable subdirs: workspace patterns commonly
			// sit alongside dirs the current user can't read (system
			// caches, other users' files); aborting the whole walk on
			// one EACCES would fail-open the whole expansion.
			if walkErr != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if suffix == "" {
				add(path)
				return nil
			}
			candidates, gErr := filepath.Glob(filepath.Join(path, suffix))
			if gErr != nil {
				return gErr
			}
			for _, c := range candidates {
				add(c)
			}
			return nil
		})
		if err != nil {
			return nil, vetoerrors.With(err, "walk workspace glob root").Set("root", root, "pattern", pattern)
		}
	}
	return matches, nil
}

// expandPrefixRoots returns the directories that the `**` walker
// should descend from. An empty prefix means "the current directory".
// A prefix with no wildcards returns itself (if it exists). A prefix
// with wildcards is expanded via filepath.Glob and each matching
// directory becomes a root.
func expandPrefixRoots(prefix string) ([]string, error) {
	if prefix == "" {
		return []string{"."}, nil
	}
	if !strings.ContainsAny(prefix, "*?[") {
		return []string{prefix}, nil
	}
	return filepath.Glob(prefix)
}
