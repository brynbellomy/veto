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
	"github.com/brynbellomy/veto/internal/scan/gyp"
)

// gypPreflightTimeout bounds the binding.gyp content scan over the current
// project tree. The scan is pure file I/O over node_modules and is normally
// sub-second; the cap keeps a pathological tree from stalling an install.
const gypPreflightTimeout = 30 * time.Second

// isNpmFamily reports whether an ecosystem resolves npm packages, i.e. whether
// `node-gyp` could run a binding.gyp at install time. Only npm-family installs
// trigger node-gyp, so the gyp preflight is scoped to them.
func isNpmFamily(eco intel.Ecosystem) bool {
	return eco == intel.EcosystemNPM
}

// gypPreflight scans the current project tree's already-present binding.gyp
// files for the phantom-gyp / Miasma worm before an npm-family install or `ci`
// runs. It exists because an `npm install` re-triggers `node-gyp` for the
// ENTIRE dependency tree, not just the package being added — so a worm already
// sitting in node_modules (from an earlier install, or pulled in as a
// transitive of something installed moments ago) fires its install-time
// payload on the very next, unrelated install. Intel feeds can't see it (it
// rides a trusted name); only the binding.gyp's contents give it away.
//
// It returns true when the install must be refused. cwd is the directory the
// real package manager will run in; the scan walks node_modules beneath it.
// The scan is read-only and runs no node-gyp.
//
// Fail-open by design on its OWN errors: a walk error or an unreadable file
// makes gypPreflight log and allow, because this is an ADDITIONAL heuristic
// layer on top of the intel gate, not a fail-closed gate itself. A false
// "abort the install because we couldn't read a file" would punish every
// install for a permissions quirk. Critical findings — the actual worm
// signature — always refuse.
func gypPreflight(logger zerolog.Logger, w io.Writer, cwd string) bool {
	return gypPreflightRoots(logger, w, []string{cwd})
}

func gypPreflightRoots(logger zerolog.Logger, w io.Writer, roots []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), gypPreflightTimeout)
	defer cancel()

	result := gyp.New(gyp.Options{Roots: roots}).Scan(ctx)
	for _, err := range result.Errors {
		logger.Warn().Err(err).Msg("gyp preflight scan error (non-fatal; continuing)")
	}

	critical := dedupeGypFindings(criticalGypFindings(result.Findings))
	if len(critical) == 0 {
		return false
	}
	printGypRefusal(w, critical)
	return true
}

// criticalGypFindings filters scan findings to the critical binding.gyp
// matches — the confirmed install-time execution vectors. Medium-severity
// structural anomalies are surfaced by `veto scan` but do NOT block an
// install on their own: blocking every `type:"none"` target or every pure-JS
// package that ships a gyp would be too aggressive for the hot path, where a
// false refusal stops real work. The critical signal (command-in-sources /
// payload-shell) is specific enough to block on.
func criticalGypFindings(findings []scan.Finding) []scan.Finding {
	var out []scan.Finding
	for _, f := range findings {
		if f.Severity == scan.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}

func dedupeGypFindings(findings []scan.Finding) []scan.Finding {
	seen := map[string]struct{}{}
	out := make([]scan.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Path
		if key == "" {
			key = finding.ID
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

// printGypRefusal renders a binding.gyp worm refusal in the same shape as the
// intel-driven printRefusal, but names the gyp finding and its evidence so the
// operator can see exactly which package and which signal triggered the block.
func printGypRefusal(w io.Writer, findings []scan.Finding) {
	fmt.Fprintln(w, "veto: install refused — binding.gyp worm pattern detected (phantom-gyp / Miasma):")
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", f.Path)
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "      [%s] %s\n", ev.Label, ev.Value)
		}
	}
	fmt.Fprintln(w, "\nAn `npm install` re-runs node-gyp for the whole tree, so this binding.gyp would")
	fmt.Fprintln(w, "execute at install time even with --ignore-scripts. Remove the offending package,")
	fmt.Fprintln(w, "clear node_modules and the lockfile entry, and rotate any credentials reachable from")
	fmt.Fprintln(w, "machines that already installed it before retrying.")
}

// runGypPreflightIfNpmFamily runs the gyp preflight when the package manager
// resolves npm packages. Returns true when the install must be refused. cwd is
// the process working directory.
func runGypPreflightIfNpmFamily(logger zerolog.Logger, pm packagemanager.PackageManager, pmArgs []string) bool {
	if !isNpmFamily(pm.Ecosystem()) {
		return false
	}
	cwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err).Msg("gyp preflight: resolve cwd failed; skipping")
		return false
	}
	return gypPreflightRoots(logger, os.Stderr, gypScanRootsForInstall(pm.Name(), pmArgs, cwd))
}

func gypScanRootsForInstall(pmName string, pmArgs []string, cwd string) []string {
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
