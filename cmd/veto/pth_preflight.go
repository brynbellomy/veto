package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/pth"
)

// pthPreflightTimeout bounds the existing-tree .pth scan. Walking a project's
// virtualenvs is typically sub-second; the cap stops a pathological tree from
// stalling an install.
const pthPreflightTimeout = 30 * time.Second

// isPythonFamily reports whether an ecosystem resolves PyPI packages — i.e.
// whether site.py could load a .pth at interpreter startup.
func isPythonFamily(eco intel.Ecosystem) bool {
	return eco == intel.EcosystemPyPI
}

// pthPreflightRoots scans the given roots' venvs for the Hades / Shai-Hulud
// startup-hook worm before a Python-family install runs. Fail-OPEN on its own
// errors (walk error / unreadable file): this is an additive heuristic, not a
// fail-closed gate. Critical findings always refuse.
func pthPreflightRoots(logger zerolog.Logger, w io.Writer, roots []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), pthPreflightTimeout)
	defer cancel()

	result := pth.New(pth.Options{Roots: roots}).Scan(ctx)
	for _, err := range result.Errors {
		logger.Warn().Err(err).Msg(".pth preflight scan error (non-fatal; continuing)")
	}

	critical := dedupePthFindings(criticalPthFindings(result.Findings))
	if len(critical) == 0 {
		return false
	}
	printPthRefusal(w, critical)
	return true
}

func criticalPthFindings(findings []scan.Finding) []scan.Finding {
	var out []scan.Finding
	for _, f := range findings {
		if f.Severity == scan.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}

func dedupePthFindings(findings []scan.Finding) []scan.Finding {
	seen := map[string]struct{}{}
	out := make([]scan.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Path
		if key == "" {
			key = f.ID
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func printPthRefusal(w io.Writer, findings []scan.Finding) {
	fmt.Fprintln(w, "veto: install refused — .pth startup-hook worm detected (Hades / Shai-Hulud):")
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", f.Path)
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "      [%s] %s\n", ev.Label, ev.Value)
		}
	}
	fmt.Fprintln(w, "\nThis .pth is exec()'d by Python at every interpreter startup, so a pip/uv/poetry/pdm")
	fmt.Fprintln(w, "install in this environment would detonate the worm before the install completes.")
	fmt.Fprintln(w, "Delete the package, remove the venv (or clear site-packages), and rotate any credentials")
	fmt.Fprintln(w, "reachable from machines that already ran python here.")
}

// runPthPreflightIfPythonFamily runs the .pth preflight when the package
// manager resolves PyPI packages. Returns true when the install must refuse.
func runPthPreflightIfPythonFamily(logger zerolog.Logger, pm packagemanager.PackageManager, pmArgs []string) bool {
	if !isPythonFamily(pm.Ecosystem()) {
		return false
	}
	cwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err).Msg(".pth preflight: resolve cwd failed; skipping")
		return false
	}
	return pthPreflightRoots(logger, os.Stderr, pthScanRootsForInstall(pm.Name(), pmArgs, cwd))
}

// pthScanRootsForInstall picks the venvs the install will affect: the
// argv-named target dir (e.g. `pip install --target ./vendor`) if present,
// plus cwd. The walker descends into any .venv/venv beneath these.
func pthScanRootsForInstall(pmName string, pmArgs []string, cwd string) []string {
	seen := map[string]struct{}{}
	roots := make([]string, 0, 2)
	add := func(root string) {
		if root == "" {
			return
		}
		clean := filepath.Clean(root)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		roots = append(roots, clean)
	}
	add(installTargetDir(pmName, pmArgs, cwd))
	add(cwd)
	return roots
}
