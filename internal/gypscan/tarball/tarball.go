// Package tarball inspects an npm package tarball (.tgz) for the phantom-gyp
// / Miasma binding.gyp worm without extracting it to a runnable tree and
// without ever invoking node-gyp.
//
// This is the install-time complement to the scan/gyp walker: the npm
// resolver pre-scan runs `--package-lock-only`, so a freshly-resolved (and
// possibly freshly-compromised) package's files never land on disk for the
// walker to see. To gate a brand-new worm version BEFORE the real install
// extracts and node-gyp executes it, the caller fetches the tarball (e.g. via
// `npm pack --ignore-scripts`, which downloads but runs nothing) and hands the
// bytes here. We read the gzip+tar stream in memory, pull out
// `package/binding.gyp` (and package.json + the file listing for context),
// and run gypscan.Inspect. Nothing is written to disk; nothing is executed.
package tarball

import (
	"archive/tar"
	"compress/gzip"
	stderrors "errors"
	"io"
	"path"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/gypscan"
)

// maxEntryBytes caps how much of any single tar entry we read into memory. A
// binding.gyp is a few KB and a package.json rarely exceeds a few hundred KB;
// the cap stops a malicious tarball from ballooning memory via a giant entry
// while still letting the heuristic see enough to fire.
const maxEntryBytes = 1 << 20 // 1 MiB

// maxTarEntries caps how many entries we walk, so a tarball with millions of
// tiny entries cannot wedge the scan. npm packages are small; this is a
// pathological-input guard, not a real limit.
const maxTarEntries = 100_000

// maxGypByteBudget caps aggregate buffered .gyp/.gypi content so an
// adversarial tarball cannot force unbounded memory while include resolution
// waits for the single forward pass to finish.
const maxGypByteBudget = 8 << 20 // 8 MiB

const maxIncludeDepth = 8

// Inspect reads an npm package tarball from r and classifies its binding.gyp
// (if any) via gypscan. It returns a SeverityNone verdict (no signals) when
// the tarball contains no binding.gyp — there is nothing for node-gyp to run.
//
// npm tarballs prefix every path with `package/`; Inspect strips that single
// leading component so the sibling-file heuristic sees clean base names.
//
// r is consumed but not closed — the caller owns the reader's lifecycle.
// Returns a wrapped error only on a malformed/truncated stream; a tarball with
// no binding.gyp is a clean, error-free SeverityNone result.
func Inspect(r io.Reader) (gypscan.Verdict, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return gypscan.Verdict{}, errors.With(err, "open gzip stream")
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	var (
		gypContent  []byte
		rootGypSeen bool
		gypFiles    = map[string][]byte{}
		gypTooLarge = map[string]struct{}{}
		gypBytes    int64
		pkgJSON     []byte
		siblings    []string
		entriesSeen int
	)

	for {
		hdr, err := tr.Next()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return gypscan.Verdict{}, errors.With(err, "read tar entry")
		}
		entriesSeen++
		if entriesSeen > maxTarEntries {
			return gypscan.Verdict{}, errors.WithNew("tarball has too many entries").Set("limit", maxTarEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		rel := stripPackagePrefix(hdr.Name)
		if rel == "" {
			continue
		}
		base := path.Base(rel)
		dir := path.Dir(rel)

		switch {
		case isGypFile(rel) && rel == "binding.gyp":
			// Only the ROOT binding.gyp drives analysis: node-gyp runs the
			// package-root binding.gyp at install time. Nested/vendored
			// binding.gyp files are buffered only as possible explicit include
			// targets, never as separate package-root descriptors.
			rootGypSeen = true
			var truncated bool
			gypContent, truncated, err = readCapped(tr, maxEntryBytes)
			if err != nil {
				return gypscan.Verdict{}, errors.With(err, "read binding.gyp from tarball")
			}
			if truncated {
				return gypFileTooLargeVerdict("binding.gyp"), nil
			}
		case isGypFile(rel):
			if gypBytes >= maxGypByteBudget {
				gypTooLarge[rel] = struct{}{}
				continue
			}
			var limit int64 = maxEntryBytes
			if remaining := maxGypByteBudget - gypBytes; remaining < limit {
				limit = remaining
			}
			content, truncated, err := readCapped(tr, limit)
			if err != nil {
				return gypscan.Verdict{}, errors.With(err, "read gyp include from tarball").Set("path", rel)
			}
			gypFiles[rel] = content
			gypBytes += int64(len(content))
			if truncated {
				gypTooLarge[rel] = struct{}{}
			}
		case rel == "package.json":
			pkgJSON, _, err = readCapped(tr, maxEntryBytes)
			if err != nil {
				return gypscan.Verdict{}, errors.With(err, "read package.json from tarball")
			}
		}

		// Record root-level base names for the pure-JS / native-source
		// heuristic. Only the package root (dir == ".") is relevant — a
		// native source buried in a subdir does not legitimize a root
		// binding.gyp in the way gypscan reasons about it.
		if dir == "." {
			siblings = append(siblings, base)
		}
	}

	if !rootGypSeen {
		// No binding.gyp → nothing node-gyp would run. Clean.
		return gypscan.Verdict{Severity: gypscan.SeverityNone}, nil
	}

	includedContents, tooLargeInclude := resolveIncludedContents("binding.gyp", gypContent, gypFiles, gypTooLarge)
	if tooLargeInclude != "" {
		return gypFileTooLargeVerdict(tooLargeInclude), nil
	}
	return gypscan.Inspect(gypscan.Input{
		GypContent:       gypContent,
		IncludedContents: includedContents,
		PackageJSON:      pkgJSON,
		SiblingFiles:     siblings,
	}), nil
}

func isGypFile(rel string) bool {
	return strings.HasSuffix(rel, ".gyp") || strings.HasSuffix(rel, ".gypi")
}

func gypFileTooLargeVerdict(rel string) gypscan.Verdict {
	detail := "binding.gyp exceeded the tarball scanner size cap and cannot be fully inspected; treating the package as unscannable so payloads cannot hide after the read cap."
	if rel != "binding.gyp" {
		detail = "included GYP file exceeded the tarball scanner size cap or aggregate GYP byte budget and cannot be fully inspected: " + rel
	}
	return gypscan.Verdict{
		Severity: gypscan.SeverityCritical,
		Signals: []gypscan.Signal{{
			Code:   "gyp-file-too-large",
			Detail: detail,
		}},
	}
}

func resolveIncludedContents(rootRel string, rootContent []byte, files map[string][]byte, tooLarge map[string]struct{}) ([][]byte, string) {
	seen := map[string]struct{}{rootRel: {}}
	var out [][]byte
	var tooLargeInclude string
	var walk func(currentRel string, content []byte, depth int)
	walk = func(currentRel string, content []byte, depth int) {
		if depth >= maxIncludeDepth || tooLargeInclude != "" {
			return
		}
		baseDir := path.Dir(currentRel)
		for _, includePath := range gypscan.ParseIncludePaths(content) {
			if tooLargeInclude != "" {
				return
			}
			candidate := path.Clean(path.Join(baseDir, includePath))
			if !tarPathWithinRoot(candidate) {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			if _, ok := tooLarge[candidate]; ok {
				tooLargeInclude = candidate
				return
			}
			included, ok := files[candidate]
			if !ok {
				continue
			}
			out = append(out, included)
			walk(candidate, included, depth+1)
		}
	}
	walk(rootRel, rootContent, 0)
	return out, tooLargeInclude
}

func tarPathWithinRoot(rel string) bool {
	return rel != "." && !path.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, "../")
}

// stripPackagePrefix removes npm's conventional single leading `package/`
// path component. Tarballs that don't use it (rare, non-npm) are returned with
// their path cleaned. Returns "" for directory-only or empty names.
func stripPackagePrefix(name string) string {
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	if clean == "." || clean == "/" {
		return ""
	}
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) == 2 && parts[0] == "package" {
		return parts[1]
	}
	return clean
}

// readCapped reads up to limit bytes from r and reports whether more content
// existed past the cap.
func readCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}
