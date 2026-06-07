package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/agentsurface"
	"github.com/brynbellomy/veto/internal/scan/cache"
	"github.com/brynbellomy/veto/internal/scan/gyp"
	"github.com/brynbellomy/veto/internal/scan/project"
)

type scanOpts struct {
	roots          []string
	json           bool
	projects       bool
	caches         bool
	agentSurface   bool
	quarantineMode bool
	purge          bool
}

func defaultScanOpts() scanOpts {
	return scanOpts{projects: true, caches: true, agentSurface: true}
}

func runScan(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseScanFlags(args, defaultScanOpts())
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto scan: %v\n", err)
		return exitUsage
	}
	return runScanWithOpts(logger, cfg, opts)
}

func runAuditAgentSurface(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseScanFlags(args, scanOpts{agentSurface: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto audit-agent-surface: %v\n", err)
		return exitUsage
	}
	opts.projects = false
	opts.caches = false
	opts.agentSurface = true
	return runScanWithOpts(logger, cfg, opts)
}

func runQuarantineCache(logger zerolog.Logger, cfg config, args []string) int {
	opts := scanOpts{caches: true, quarantineMode: true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--dry-run":
			opts.purge = false
		case "--purge":
			opts.purge = true
		case "--json":
			opts.json = true
		default:
			return unknownScanArg("veto quarantine-cache", a)
		}
	}
	return runScanWithOpts(logger, cfg, opts)
}

func parseScanFlags(args []string, defaults scanOpts) (scanOpts, error) {
	opts := defaults
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--root":
			if i+1 >= len(args) {
				return opts, errors.New("--root requires a path")
			}
			opts.roots = append(opts.roots, args[i+1])
			i++
		case strings.HasPrefix(a, "--root="):
			opts.roots = append(opts.roots, strings.TrimPrefix(a, "--root="))
		case a == "--json":
			opts.json = true
		case a == "--no-projects":
			opts.projects = false
		case a == "--no-caches":
			opts.caches = false
		case a == "--no-agent-surface":
			opts.agentSurface = false
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	if !opts.projects && !opts.caches && !opts.agentSurface {
		return opts, errors.New("at least one scan surface must be enabled")
	}
	return opts, nil
}

func runScanWithOpts(logger zerolog.Logger, cfg config, opts scanOpts) int {
	started := time.Now().UTC()
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto scan: resolve home: %v\n", err)
		return exitInternal
	}
	if len(opts.roots) == 0 && opts.projects {
		opts.roots = []string{filepath.Join(home, "projects")}
	}
	roots, err := cleanExistingRoots(opts.roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto scan: %v\n", err)
		return exitInternal
	}

	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()

	needsIntel := opts.projects || opts.caches
	var store intel.Store
	if needsIntel {
		var err error
		store, err = buildStore(logger, cfg)
		if err != nil {
			logger.Error().Err(err).Msg("build intel store")
			return exitInternal
		}
		if err := store.Refresh(ctx); err != nil {
			logger.Error().Err(err).Msg("intel refresh failed during scan")
			fmt.Fprintln(os.Stderr, "veto: INTERNAL ERROR — intel refresh failed; scan aborted fail-closed.")
			return exitInternal
		}
		if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
			logger.Error().Int("reports", reportCount).Int("floor", minHealthyReportCount).Msg("intel store below sanity floor during scan")
			fmt.Fprintf(os.Stderr, "veto: INTERNAL ERROR — intel store has only %d reports (expected at least %d); scan aborted fail-closed.\n", reportCount, minHealthyReportCount)
			return exitInternal
		}
	}

	results := []scan.Result{}
	if opts.projects {
		results = append(results, project.New(project.Options{Roots: roots, Store: store, Expander: newCompoundExpander()}).Scan(ctx))
		// The gyp scanner is a content heuristic, not an intel lookup, so it
		// runs alongside the project scanner without needing the store. It
		// descends into node_modules (which the project scanner prunes) to
		// catch installed phantom-gyp / Miasma worms the name+version feeds
		// cannot see.
		results = append(results, gyp.New(gyp.Options{Roots: roots}).Scan(ctx))
	}
	cacheRootEntries := cache.DefaultRootEntries(home)
	cacheRoots := cachePaths(cacheRootEntries)
	if opts.caches {
		// Build and refresh the host-level IOC store so cache artifacts can be
		// matched against known-malicious file hashes. With no feeds configured
		// (the default) this is ioc.NopStore{}, the refresh is a no-op, and the
		// cache scanner skips hashing entirely. IOC refresh failures are
		// non-fatal: hash-matching supplements the intel name+version lookup
		// rather than gating, so a degraded IOC feed must not abort the scan.
		iocStore := buildIOCStore(logger, cfg)
		if err := iocStore.Refresh(ctx); err != nil {
			logger.Warn().Err(err).Msg("ioc refresh failed during scan; continuing without hash-matching")
		}
		results = append(results, cache.New(cache.Options{RootEntries: cacheRootEntries, Store: store, IOCStore: iocStore}).Scan(ctx))
	}
	if opts.agentSurface {
		results = append(results, agentsurface.New(agentsurface.Options{Home: home, ProjectRoots: roots}).Scan(ctx))
	}
	report := scan.NewReport(started, roots, results...)
	var purgeActions []scan.PurgeAction
	if opts.quarantineMode {
		purgeActions = cache.PlanPurge(report.Findings, cacheRoots, opts.purge)
		report.PurgeActions = purgeActions
	}
	if opts.json {
		if err := scan.WriteJSON(os.Stdout, report); err != nil {
			logger.Error().Err(err).Msg("write scan json")
			return exitInternal
		}
	} else {
		scan.WriteText(os.Stdout, report)
		if opts.quarantineMode {
			printPurgeActions(os.Stdout, purgeActions, opts.purge)
		}
	}
	if report.Summary.Errors > 0 {
		return exitInternal
	}
	if opts.quarantineMode && opts.purge {
		return quarantinePurgeExitCode(report, purgeActions)
	}
	if report.Summary.Actionable > 0 {
		return exitRefused
	}
	return exitOK
}

func cachePaths(entries []cache.Root) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Path)
	}
	return out
}

func printPurgeActions(w io.Writer, actions []scan.PurgeAction, purge bool) {
	if len(actions) == 0 {
		fmt.Fprintln(w, "\nCache quarantine: no confirmed malicious cache artifacts eligible for purge")
		return
	}
	mode := "dry-run"
	if purge {
		mode = "purge"
	}
	fmt.Fprintf(w, "\nCache quarantine (%s):\n", mode)
	for _, action := range actions {
		fmt.Fprintf(w, "  - [%s] %s\n", action.Status, action.Path)
		fmt.Fprintf(w, "      reason: %s\n", action.Reason)
		if action.Error != "" {
			fmt.Fprintf(w, "      error: %s\n", action.Error)
		}
	}
}

func quarantinePurgeExitCode(report scan.Report, actions []scan.PurgeAction) int {
	if report.Summary.Actionable == 0 {
		return exitOK
	}
	deleted := map[string]struct{}{}
	for _, action := range actions {
		if action.Status == "deleted" {
			deleted[action.FindingID] = struct{}{}
		}
	}
	for _, finding := range report.Findings {
		if !scan.IsActionable(finding.Severity) {
			continue
		}
		if _, ok := deleted[finding.ID]; !ok {
			return exitRefused
		}
	}
	return exitOK
}

func cleanExistingRoots(roots []string) ([]string, error) {
	out := []string{}
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		clean := expandHome(filepath.Clean(root))
		abs, err := filepath.Abs(clean)
		if err != nil {
			return nil, errors.With(err, "resolve scan root").Set("root", root)
		}
		if _, dup := seen[abs]; dup {
			continue
		}
		seen[abs] = struct{}{}
		info, err := os.Stat(abs)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errors.With(err, "stat scan root").Set("root", abs)
		}
		if !info.IsDir() {
			continue
		}
		out = append(out, abs)
	}
	return out, nil
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func unknownScanArg(prefix, arg string) int {
	fmt.Fprintf(os.Stderr, "%s: unknown argument: %s\n", prefix, arg)
	return exitUsage
}
