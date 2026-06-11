// Layer 4: real-binary wrappers.
//
// PATH shims (Layer 2) only engage when the caller resolves the PM by
// bare name. `subprocess.run(["/opt/homebrew/bin/npm", ...])` and
// `/.local/share/mise/installs/node/24.7.0/bin/npm install …` both skip
// PATH lookup entirely. The interposer (Layer 3) closes most of that
// hole — but it depends on the calling process inheriting
// DYLD_INSERT_LIBRARIES / LD_PRELOAD, which an agent can strip.
//
// Layer 4 closes the absolute-path hole without depending on env vars
// at all: for each known PM at a known install dir, we
//
//   1. atomically move the real binary to `<bin>.veto-original`, and
//   2. replace `<bin>` with a symlink to the veto binary.
//
// Any caller naming the original absolute path — bare-name, full-path,
// `subprocess.run` with no env, `os.execvp` from inside an LSP — hits
// veto. The gate runs, then execReal's resolver (in main.go) finds
// the `.veto-original` sibling and exec's it.
//
// Tradeoffs documented for users:
//
//   - Brew / mise / asdf upgrades will overwrite our symlink. Re-run
//     `veto install-wrappers` after upgrading toolchain versions.
//     `veto doctor` flags unwrapped install dirs so a stale state
//     is visible, not silent.
//   - SIP-protected binaries (`/usr/bin/pip3`) can't be wrapped — the
//     dirs are read-only even to root. Layer 3 hits the same wall.
//   - Wrapping requires write access to the candidate dirs. Homebrew
//     and mise install dirs are user-owned by default; `/usr/local/bin`
//     on Intel Macs may need sudo.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

// wrapperSuffix is the rename target. `.veto-original` is verbose on
// purpose — a colleague who finds it during debugging needs to see
// what made it instead of guessing.
const wrapperSuffix = ".veto-original"

// stateFileName is the JSON registry of every wrapper veto has
// installed. Kept alongside the intel cache so a single
// VETO_CACHE_DIR override moves both. uninstall-wrappers replays
// this list in reverse; install-wrappers adds to it idempotently.
const stateFileName = "wrappers.json"

// wrapperState is what we serialise into stateFileName. Each entry is
// one wrapped PM binary. Stored as a list (not a map) so JSON output
// is stable for diffing.
type wrapperState struct {
	Wrappers []wrapperEntry `json:"wrappers"`
}

// wrapperEntry records one wrapper installation. We persist enough
// information to fully reverse the operation without re-discovering the
// system.
type wrapperEntry struct {
	// Path is the absolute path where the veto symlink lives.
	Path string `json:"path"`
	// OriginalPath is Path + wrapperSuffix — the moved-aside real
	// binary. Kept explicit so a future suffix rename doesn't strand
	// old entries.
	OriginalPath string `json:"original_path"`
	// PM is the basename (e.g. "npm"). Useful for doctor output.
	PM string `json:"pm"`
	// Source identifies what kind of install dir this came from
	// ("homebrew", "mise", "asdf", "user"). Cosmetic — used only in
	// the per-wrapper status line.
	Source string `json:"source"`
}

// wrappedManagers is an alias for the canonical pmlist.Wrapped slice.
// A near-mirror of pmlist.Shimmed — the deliberate divergence is
// `python` and `python3`: they're shimmed (Layer 2) so the canonical
// `python -m pip install …` form is caught, but NOT wrapped (Layer 4)
// because Layer 4 replaces the real interpreter on disk, which would
// route EVERY python invocation (every script run, every REPL) through
// veto. That's an unacceptable hot path for a tool whose value sits on
// install-style verbs only. main()'s dispatch fast-paths non-`-m {pm}`
// python calls to the real interpreter, so Layer 2 alone gets full
// install coverage without the per-script overhead.
//
// The divergence is encoded in pmlist (Shimmed has python/python3,
// Wrapped does not). See internal/packagemanager/pmlist for why one
// canonical source kills the drift hazard that used to live across
// five hand-edited lists.
var wrappedManagers = pmlist.Wrapped

// runInstallWrappers implements `veto install-wrappers [--dry-run] [--force]`.
//
// Default behavior: discover candidate dirs (homebrew, mise installs,
// asdf installs, user-specified --dir flags), find every PM in our
// wrappedManagers list living in those dirs, and wrap each one. Paths
// that are already wrapped (symlink-to-veto + `.veto-original` sibling)
// but missing from wrappers.json are reconciled into state — this
// self-heals after a cache wipe, manual symlinking, or an install run
// under a different VETO_CACHE_DIR.
//
//	--dry-run        list the changes that would be made without making them.
//	--force          re-link entries we previously wrapped — useful after an
//	                 upgrade re-installed the real binary, OR to repoint
//	                 already-correct symlinks at the current veto path
//	                 (e.g. after moving the veto binary).
//	--dir DIR        add an additional discovery dir. Can be repeated.
//	--only PM        only wrap this PM. Can be repeated.
func runInstallWrappers(logger zerolog.Logger, cfg config, args []string) int {
	rc, _ := runInstallWrappersWithStats(logger, cfg, args)
	return rc
}

// runInstallWrappersWithStats is the install-wrappers worker exposed so
// install-all can route exit codes based on whether failures were genuine
// vs. just unwritable-dir skips. The public runInstallWrappers wraps this
// and discards the stats — preserves the existing standalone-command exit
// contract (non-zero only on stats.failed > 0, per the original logic).
//
// Thin shim: resolves the veto binary identity then delegates to
// runInstallWrappersWith. Tests plant their own veto binary in a tempdir
// and call the *With variant directly.
func runInstallWrappersWithStats(logger zerolog.Logger, cfg config, args []string) (int, wrapperStats) {
	opts, err := parseWrapperFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-wrappers: %v\n", err)
		return exitUsage, wrapperStats{}
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal, wrapperStats{}
	}
	vetoID, err := pmsurvey.VetoIdentityFor(vetoPath)
	if err != nil {
		logger.Error().Err(err).Msg("build veto identity")
		return exitInternal, wrapperStats{}
	}
	return runInstallWrappersWith(logger, cfg, opts, vetoPath, vetoID)
}

// runInstallWrappersWith is the install-wrappers worker. It takes a
// pre-built VetoIdentity so tests can drive it against a planted veto
// binary in a tempdir without going through os.Executable.
func runInstallWrappersWith(logger zerolog.Logger, cfg config, opts wrapperFlags, vetoPath string, vetoID *pmsurvey.VetoIdentity) (int, wrapperStats) {
	candidates, err := discoverWrapCandidatesWith(opts, vetoID)
	if err != nil {
		logger.Error().Err(err).Msg("discover wrap candidates")
		return exitInternal, wrapperStats{}
	}

	// Phase 1.5: propagate load errors so a corrupt wrappers.json fails
	// loudly instead of being silently truncated by the next save.
	// loadWrapperState already treats "missing file" as (empty, nil), so
	// any error here means the registry exists and is malformed.
	state, err := loadWrapperState(cfg)
	if err != nil {
		logger.Error().Err(err).
			Str("path", filepath.Join(cfg.CacheDir, "wrappers.json")).
			Msg("wrappers.json is malformed; refusing to overwrite a load-bearing registry. Inspect or move the file aside and re-run.")
		return exitInternal, wrapperStats{}
	}

	// Discovery includes already-ours paths, so empty candidates now
	// genuinely means nothing on disk — no PMs in known dirs at all.
	if len(candidates) == 0 {
		fmt.Fprintln(os.Stderr, "veto install-wrappers: no candidate PM binaries found in known dirs.")
		fmt.Fprintln(os.Stderr, "Checked: /opt/homebrew/bin, /usr/local/bin, ~/.local/share/mise/installs/*/*/bin,")
		fmt.Fprintln(os.Stderr, "         ~/.asdf/installs/*/*/bin, ~/.bun/bin.")
		fmt.Fprintln(os.Stderr, "Pass --dir to add more discovery roots, or skip Layer 4 if no PMs are installed locally.")
		return exitOK, wrapperStats{}
	}

	stats := wrapperStats{}
	var skipped []wrapCandidate // read-only-dir candidates, for the sudo hint
	for _, c := range candidates {
		entry := wrapperEntry{
			Path:         c.path,
			OriginalPath: c.path + wrapperSuffix,
			PM:           c.pm,
			Source:       c.source,
		}
		// Phase 1.5 write-ahead-log order: speculatively register the
		// entry and persist BEFORE the FS mutation. If applyWrapper
		// succeeds, the registry already records reality. If it fails
		// (or is a skip), we adjust below. This closes the L4 reviewer's
		// finding that a mid-loop crash left wrappers on-disk with no
		// registry entry, making the PM unfindable until manual
		// recovery.
		//
		// Reconciliation-via-discovery still works because the
		// `pointsAtVeto + state.has` check in applyWrapper detects the
		// already-ours case; the WAL just ensures that for newly-wrapped
		// candidates the registry is durable BEFORE the symlink lands.
		preWrapState := state // shallow copy for rollback comparison
		_ = preWrapState
		needPersist := false
		alreadyHad := state.has(c.path)
		if !opts.dryRun && !alreadyHad {
			state.add(entry)
			if err := saveWrapperState(cfg, state); err != nil {
				logger.Error().Err(err).Msg("save wrapper state (WAL pre-write)")
				state.remove(c.path)
				stats.failed++
				fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", c.pm, c.path, err)
				continue
			}
		}
		switch action, err := applyWrapper(c, vetoPath, opts.dryRun, opts.force); {
		case err != nil:
			stats.failed++
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", c.pm, c.path, err)
			if !alreadyHad && !opts.dryRun {
				// Roll back the speculative registry entry. Best-effort:
				// if THIS save also fails, log but don't double-error;
				// the next install-wrappers reconcile will heal.
				state.remove(c.path)
				if rbErr := saveWrapperState(cfg, state); rbErr != nil {
					logger.Warn().Err(rbErr).Str("path", c.path).
						Msg("WAL rollback save failed; re-run install-wrappers to reconcile")
				}
			}
		case action == wrapperActionSkipUnwritable:
			stats.skippedUnwritable++
			skipped = append(skipped, c)
			fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — read-only dir (needs sudo)\n", c.pm, c.path)
			if !alreadyHad && !opts.dryRun {
				// Same WAL rollback as the failure case above: the entry was
				// speculatively recorded before applyWrapper, but the dir is
				// read-only so nothing was wrapped. Drop it so state never
				// claims a wrap that isn't on disk (doctor would otherwise
				// flag it as drift). The user re-runs under sudo, which
				// records its own entry.
				state.remove(c.path)
				if rbErr := saveWrapperState(cfg, state); rbErr != nil {
					logger.Warn().Err(rbErr).Str("path", c.path).
						Msg("WAL rollback save failed; re-run install-wrappers to reconcile")
				}
			}
		case action == wrapperActionSkipBrokenSymlink:
			stats.skippedBroken++
			fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — broken symlink to %s (likely a previous wrapper tool's leftover; restore `<path>.veto-original` if present, then re-run)\n",
				c.pm, c.path, c.target)
			if !alreadyHad && !opts.dryRun {
				state.remove(c.path)
				if rbErr := saveWrapperState(cfg, state); rbErr != nil {
					logger.Warn().Err(rbErr).Str("path", c.path).Msg("WAL rollback save failed")
				}
			}
		case action == wrapperActionSkipForeignWrapper:
			stats.skippedForeign++
			fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — symlink to %s, which is not the veto binary (foreign wrapper; pass --force to overwrite)\n",
				c.pm, c.path, c.target)
			if !alreadyHad && !opts.dryRun {
				state.remove(c.path)
				if rbErr := saveWrapperState(cfg, state); rbErr != nil {
					logger.Warn().Err(rbErr).Str("path", c.path).Msg("WAL rollback save failed")
				}
			}
		case action == wrapperActionSkipAlreadyOurs:
			// The filesystem says this is wrapped. If state agrees, silent
			// no-op. If state doesn't know about it (alreadyHad was false
			// AND we didn't WAL-add above due to dryRun), reconcile.
			if alreadyHad {
				stats.alreadyOurs++
				if opts.verbose {
					fmt.Printf("  %-10s  ok    already wrapped: %s\n", c.pm, c.path)
				}
			} else {
				stats.reconciled++
				fmt.Printf("  %-10s  ok    reconciled (already wrapped, registering in state): %s\n", c.pm, c.path)
				if opts.dryRun {
					state.add(entry)
				}
				needPersist = true
			}
		case action == wrapperActionSkipDryRun:
			stats.wouldWrap++
			fmt.Printf("  %-10s  ok    would wrap: %s\n", c.pm, c.path)
		case action == wrapperActionWrapped:
			stats.wrapped++
			fmt.Printf("  %-10s  ok    wrapped: %s\n", c.pm, c.path)
			// Already persisted via WAL above; nothing more to do.
		}
		_ = needPersist
	}

	// Final reconcile-state save covers the dry-run paths that need
	// state writes (none, since dry-run is idempotent) and the
	// already-ours-but-not-in-state reconciliation that happened
	// above. The WAL pre-writes covered every wrapped candidate.
	if !opts.dryRun && (stats.reconciled > 0 || stats.failed > 0) {
		if err := saveWrapperState(cfg, state); err != nil {
			logger.Error().Err(err).Msg("save wrapper state (final reconcile)")
			return exitInternal, stats
		}
	}

	fmt.Printf("\nSummary: %d wrapped, %d reconciled, %d already-ours, %d would-wrap, %d skipped (needs sudo), %d skipped (broken symlink), %d skipped (foreign wrapper), %d failed\n",
		stats.wrapped, stats.reconciled, stats.alreadyOurs, stats.wouldWrap, stats.skippedUnwritable,
		stats.skippedBroken, stats.skippedForeign, stats.failed)
	printUnwritableRemediation(skipped)
	if stats.failed > 0 {
		return exitInternal, stats
	}
	return exitOK, stats
}

// printUnwritableRemediation prints one copy-pasteable command per
// read-only dir that held skipped candidates, so the user can finish
// wrapping those paths under sudo and keep full protection. We don't
// fail the run for these — they're an environmental constraint, not a
// bug — but we make the gap and its fix loud.
func printUnwritableRemediation(skipped []wrapCandidate) {
	cmds := unwritableRemediationCommands(skipped)
	if len(cmds) == 0 {
		return
	}
	subject := "path needs"
	if len(skipped) > 1 {
		subject = "paths need"
	}
	fmt.Fprintf(os.Stderr, "\n%d %s elevated permissions to wrap. To finish (keeps full protection):\n",
		len(skipped), subject)
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "  %s\n", cmd)
	}
}

// unwritableRemediationCommands builds one self-contained `sudo veto
// install-wrappers` command per read-only dir, grouping the skipped pms
// under each. The explicit --dir makes the command work even for a dir
// that isn't a default scan root; for a default dir it just re-wraps
// (already-ours paths are harmless no-ops). Dir order is first-seen so
// output is stable across runs.
func unwritableRemediationCommands(skipped []wrapCandidate) []string {
	if len(skipped) == 0 {
		return nil
	}
	dirOrder := []string{}
	pmsByDir := map[string][]string{}
	for _, c := range skipped {
		dir := filepath.Dir(c.path)
		if _, seen := pmsByDir[dir]; !seen {
			dirOrder = append(dirOrder, dir)
		}
		pmsByDir[dir] = append(pmsByDir[dir], c.pm)
	}
	cmds := make([]string, 0, len(dirOrder))
	for _, dir := range dirOrder {
		var b strings.Builder
		b.WriteString("sudo veto install-wrappers --dir ")
		b.WriteString(dir)
		for _, pm := range pmsByDir[dir] {
			b.WriteString(" --only ")
			b.WriteString(pm)
		}
		cmds = append(cmds, b.String())
	}
	return cmds
}

// runUninstallWrappers reverses every wrapper recorded in state. Files
// not recorded in state are left untouched — symmetric with how
// install-shims refuses to clobber things it didn't install.
func runUninstallWrappers(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseWrapperFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-wrappers: %v\n", err)
		return exitUsage
	}

	state, err := loadWrapperState(cfg)
	if err != nil {
		logger.Error().Err(err).Msg("load wrapper state")
		return exitInternal
	}
	if len(state.Wrappers) == 0 {
		fmt.Println("veto uninstall-wrappers: no wrappers recorded; nothing to do.")
		return exitOK
	}

	// Resolve the current veto binary once so unwrap can do strict
	// physical-path identity checks against it for every entry.
	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	remaining := []wrapperEntry{}
	failed := 0
	removed := 0
	for _, w := range state.Wrappers {
		switch err := unwrap(w, vetoPath, opts.dryRun); {
		case err != nil:
			failed++
			remaining = append(remaining, w)
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", w.PM, w.Path, err)
		case opts.dryRun:
			fmt.Printf("  %-10s  ok    would unwrap: %s\n", w.PM, w.Path)
			remaining = append(remaining, w)
		default:
			removed++
			fmt.Printf("  %-10s  ok    unwrapped: %s\n", w.PM, w.Path)
		}
	}
	if !opts.dryRun {
		state.Wrappers = remaining
		if err := saveWrapperState(cfg, state); err != nil {
			logger.Error().Err(err).Msg("save wrapper state")
			return exitInternal
		}
	}
	fmt.Printf("\nSummary: %d unwrapped, %d failed, %d remaining\n", removed, failed, len(remaining))
	if failed > 0 {
		return exitInternal
	}
	return exitOK
}

// wrapperFlags captures parsed CLI args for both install/uninstall.
type wrapperFlags struct {
	dirs    []string
	only    map[string]struct{}
	dryRun  bool
	force   bool
	verbose bool
}

type wrapperStats struct {
	wrapped           int
	reconciled        int
	alreadyOurs       int
	wouldWrap         int
	skippedUnwritable int
	skippedBroken     int
	skippedForeign    int
	failed            int
}

type wrapAction int

const (
	wrapperActionSkipAlreadyOurs wrapAction = iota
	wrapperActionSkipDryRun
	// wrapperActionSkipUnwritable: the candidate dir isn't writable by
	// the current user (e.g. a stray pip3 in root-owned /usr/local/bin on
	// Apple Silicon). This is an environmental constraint, not a failure —
	// the user can finish under sudo. Reported as a skip with a
	// copy-pasteable remediation command rather than aborting install-all.
	wrapperActionSkipUnwritable
	// wrapperActionSkipBrokenSymlink: discovery found a symlink whose
	// target does not exist (typically a leftover from a previous
	// wrapper tool whose binary was uninstalled). install-wrappers
	// emits a visible SKIP line so the user can decide whether to
	// delete the orphan rather than silently dropping the candidate.
	wrapperActionSkipBrokenSymlink
	// wrapperActionSkipForeignWrapper: discovery found a symlink to a
	// binary whose SHA-256 does not match the running veto. Without
	// --force, install-wrappers emits a visible SKIP line and leaves
	// the symlink in place — overwriting could break whatever tool
	// installed it. With --force, applyWrapper falls through to the
	// regular wrap path.
	wrapperActionSkipForeignWrapper
	wrapperActionWrapped
)

func parseWrapperFlags(args []string) (wrapperFlags, error) {
	opts := wrapperFlags{only: map[string]struct{}{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dry-run":
			opts.dryRun = true
		case a == "--force":
			opts.force = true
		case a == "--verbose", a == "-v":
			opts.verbose = true
		case a == "--dir":
			if i+1 >= len(args) {
				return opts, errors.New("--dir requires a path argument")
			}
			opts.dirs = append(opts.dirs, args[i+1])
			i++
		case strings.HasPrefix(a, "--dir="):
			opts.dirs = append(opts.dirs, strings.TrimPrefix(a, "--dir="))
		case a == "--only":
			if i+1 >= len(args) {
				return opts, errors.New("--only requires a PM name")
			}
			opts.only[args[i+1]] = struct{}{}
			i++
		case strings.HasPrefix(a, "--only="):
			opts.only[strings.TrimPrefix(a, "--only=")] = struct{}{}
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

// wrapCandidate is one (dir, pm) pair discovery surfaced.
type wrapCandidate struct {
	path   string                  // absolute path to the existing PM file
	pm     string                  // basename (e.g. "npm")
	source string                  // "homebrew", "mise", "asdf", "user"
	class  pmsurvey.Classification // result of pmsurvey.ClassifySymlink at discovery time
	target string                  // resolved symlink target when class != ClassReal; "" otherwise
}

// discoverWrapCandidates walks the well-known install-dir patterns
// AND $PATH looking for files whose basename matches one of
// wrappedManagers. Thin shim over discoverWrapCandidatesWith; tests use
// the latter directly with a pre-built VetoIdentity.
func discoverWrapCandidates(opts wrapperFlags, vetoPath string) ([]wrapCandidate, error) {
	id, err := pmsurvey.VetoIdentityFor(vetoPath)
	if err != nil {
		return nil, errors.With(err, "discover wrap candidates")
	}
	return discoverWrapCandidatesWith(opts, id)
}

// discoverWrapCandidatesWith uses pmsurvey.PathsFor to enumerate every
// absolute path on this host where each wrapped PM could live
// (well-known roots plus $PATH minus shim dirs) and pmsurvey.ClassifySymlink
// to pre-classify each candidate so applyWrapper can dispatch on
// broken / foreign / ours without re-walking the disk.
func discoverWrapCandidatesWith(opts wrapperFlags, id *pmsurvey.VetoIdentity) ([]wrapCandidate, error) {
	candidates := []wrapCandidate{}
	pmFilter := func(name string) bool {
		if len(opts.only) == 0 {
			return true
		}
		_, ok := opts.only[name]
		return ok
	}

	seen := map[string]struct{}{}
	add := func(c wrapCandidate) {
		if _, dup := seen[c.path]; dup {
			return
		}
		seen[c.path] = struct{}{}
		candidates = append(candidates, c)
	}

	for _, pm := range wrappedManagers {
		if !pmFilter(pm) {
			continue
		}
		for _, path := range pmsurvey.PathsFor(pm) {
			class, target, classErr := pmsurvey.ClassifySymlink(path, id)
			if classErr != nil {
				// I/O failure on a candidate is not a discovery error —
				// applyWrapper will surface it per-candidate. Include
				// the path with ClassReal so the regular path runs and
				// the FAIL line emits if rename fails.
				add(wrapCandidate{path: path, pm: pm, source: sourceFor(path), class: pmsurvey.ClassReal, target: ""})
				continue
			}
			add(wrapCandidate{path: path, pm: pm, source: sourceFor(path), class: class, target: target})
		}
	}

	// User-supplied --dir entries. These are NOT discovered via
	// pmsurvey (the user knows where they live), but they still
	// benefit from classification so applyWrapper handles broken /
	// foreign cases uniformly.
	for _, dir := range opts.dirs {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			class, target, classErr := pmsurvey.ClassifySymlink(p, id)
			if classErr != nil {
				// A --dir entry that doesn't exist is a no-op, not an error.
				continue
			}
			add(wrapCandidate{path: p, pm: pm, source: "user", class: class, target: target})
		}
	}

	return candidates, nil
}

// sourceFor returns a short label describing where a path was
// discovered, used for diagnostic output ("homebrew" / "mise" / etc.).
// Heuristic based on path substrings — exact match is impossible since
// pmsurvey returns flat paths.
func sourceFor(path string) string {
	switch {
	case strings.HasPrefix(path, "/opt/homebrew/"), strings.HasPrefix(path, "/usr/local/bin/"):
		return "homebrew"
	case strings.Contains(path, "/.local/share/mise/installs/"):
		return "mise"
	case strings.Contains(path, "/.asdf/installs/"):
		return "asdf"
	case strings.Contains(path, "/.pyenv/versions/"):
		return "pyenv"
	case strings.Contains(path, "/.nvm/versions/node/"):
		return "nvm"
	case strings.Contains(path, "/.bun/bin"):
		return "bun"
	case strings.Contains(path, "/.cargo/bin"):
		return "cargo"
	case strings.HasPrefix(path, "/usr/bin/"), strings.HasPrefix(path, "/usr/sbin/"):
		return "system"
	default:
		return "path"
	}
}

// pointsAtVeto reports whether linkPath (a symlink) resolves to the
// same physical file as vetoPath. Both sides are fully evaluated via
// filepath.EvalSymlinks so a symlink chain that ends at the canonical
// veto binary is recognized regardless of how many hops it takes.
//
// Why a strict identity check matters: the prior version used
// strings.Contains(target, "veto"), which would accept ANY symlink
// whose target string contained the substring "veto" — including an
// attacker-planted /opt/homebrew/bin/npm → /tmp/veto-malware that
// merely uses our name. Once accepted as "already ours," the wrap
// step skips and the attacker's shadow stays in place. Resolving and
// comparing physical paths closes that hole.
//
// Returns false (not error) on any I/O failure: a symlink we cannot
// resolve is, by definition, not provably ours.
func pointsAtVeto(linkPath, vetoPath string) bool {
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return false
	}
	canonicalVeto, err := filepath.EvalSymlinks(vetoPath)
	if err != nil {
		return false
	}
	return resolved == canonicalVeto
}

// isAlreadyOursWrap reports whether p is an existing veto wrapper:
// a symlink that resolves to vetoPath AND has a sibling
// `<p>.veto-original` on disk. Mirrors applyWrapper's "already ours"
// detection so discovery can include these paths and runInstallWrappers
// can reconcile them into wrappers.json when the state file has drifted
// from filesystem reality (cache wipe, install run under a different
// VETO_CACHE_DIR, manual symlinking). Strict physical-path identity via
// pointsAtVeto — see that helper for the impostor-rejection rationale.
func isAlreadyOursWrap(p, vetoPath string) bool {
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	if !pointsAtVeto(p, vetoPath) {
		return false
	}
	_, err = os.Lstat(p + wrapperSuffix)
	return err == nil
}

// isWrappableTarget reports whether the path is something we should
// wrap: it exists, is not a directory, is executable, and is not
// already our own veto wrapper.
//
// "Already ours" is decided by pointsAtVeto (strict physical-path
// identity), NOT by name substring matching — see that helper for the
// rationale.
func isWrappableTarget(p, vetoPath string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Existing symlink. If it provably points at veto, skip — we
		// installed it. Otherwise it's a real-binary alias (homebrew's
		// canonical layout, mise's shim, etc.) and is wrappable.
		if pointsAtVeto(p, vetoPath) {
			return false
		}
		// Verify the symlink resolves to something we can exec.
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return false
		}
		info2, err := os.Stat(resolved)
		if err != nil || info2.IsDir() || info2.Mode()&0o111 == 0 {
			return false
		}
		return true
	}
	// Regular file. Must be executable.
	return info.Mode()&0o111 != 0
}

// applyWrapper does the rename + symlink dance for one candidate.
// Idempotent against already-installed wrappers (returns
// wrapperActionSkipAlreadyOurs); refuses to clobber an existing
// non-veto file unless --force was passed.
//
// Atomicity: we rename the original BEFORE creating the symlink. If
// the symlink-create step fails we've still left the system in a
// recoverable state: the user can move .veto-original back manually,
// or re-run install-wrappers to retry.
func applyWrapper(c wrapCandidate, vetoPath string, dryRun, force bool) (wrapAction, error) {
	// Classification-driven short-circuits for the broken / foreign
	// cases. Discovery (discoverWrapCandidatesWith) pre-classifies
	// every candidate via pmsurvey.ClassifySymlink, so applyWrapper
	// can dispatch without re-walking the disk.
	switch c.class {
	case pmsurvey.ClassBrokenSymlink:
		return wrapperActionSkipBrokenSymlink, nil
	case pmsurvey.ClassForeignWrapper:
		// Without --force, leave foreign wrappers in place — overwriting
		// them silently could break whatever installed them. The skip
		// emits a visible line with the target so the user can decide.
		// With --force, fall through to the regular wrap path; the
		// existing rename dance moves the foreign symlink to
		// .veto-original.
		if !force {
			return wrapperActionSkipForeignWrapper, nil
		}
	}

	original := c.path + wrapperSuffix

	// Already wrapped? `c.path` is a symlink that resolves to the SAME
	// physical file as vetoPath AND `<c.path>.veto-original` exists.
	// Strict physical-path identity (not name substring) — see
	// pointsAtVeto for rationale.
	//
	// With --force the user is asking us to re-link even when nothing
	// is broken: useful after moving the veto binary, or to recover
	// confidence that nothing has rewritten the symlink. We delete the
	// symlink and recreate it pointing at the current vetoPath.
	if existing, err := os.Lstat(c.path); err == nil && existing.Mode()&os.ModeSymlink != 0 {
		if pointsAtVeto(c.path, vetoPath) {
			if _, err := os.Lstat(original); err == nil {
				if !force {
					return wrapperActionSkipAlreadyOurs, nil
				}
				if dryRun {
					return wrapperActionSkipDryRun, nil
				}
				if err := os.Remove(c.path); err != nil {
					if os.IsPermission(err) {
						return wrapperActionSkipUnwritable, nil
					}
					return wrapperActionWrapped, errors.With(err, "remove existing veto symlink for --force relink").Set("path", c.path)
				}
				if err := os.Symlink(vetoPath, c.path); err != nil {
					if os.IsPermission(err) {
						return wrapperActionSkipUnwritable, nil
					}
					return wrapperActionWrapped, errors.With(err, "recreate veto symlink").Set("path", c.path)
				}
				return wrapperActionWrapped, nil
			}
		}
	}

	// Refuse to clobber if `.veto-original` already exists and we
	// didn't ask for --force. This protects against the partial-state
	// case where a previous wrap moved the original but failed to
	// install the symlink.
	if _, err := os.Lstat(original); err == nil && !force {
		return wrapperActionWrapped, errors.WithNew(".veto-original already exists; pass --force to overwrite").
			Set("path", original)
	}

	if dryRun {
		return wrapperActionSkipDryRun, nil
	}

	// 1) Move the real binary aside. A permission error here means the
	// candidate dir is read-only to this user — classify it as a skip
	// (not a failure) so the caller can emit a sudo remediation and
	// install-all keeps going. Check the raw os error: os.IsPermission
	// does not see through the errors.With wrapper.
	if err := os.Rename(c.path, original); err != nil {
		if os.IsPermission(err) {
			return wrapperActionSkipUnwritable, nil
		}
		return wrapperActionWrapped, errors.With(err, "rename real binary aside").Set("from", c.path, "to", original)
	}
	// 2) Install the symlink at the original path.
	if err := os.Symlink(vetoPath, c.path); err != nil {
		// Best-effort rollback so we don't strand the user with a
		// PM that's invisible.
		_ = os.Rename(original, c.path)
		if os.IsPermission(err) {
			return wrapperActionSkipUnwritable, nil
		}
		return wrapperActionWrapped, errors.With(err, "create veto symlink").Set("path", c.path)
	}
	return wrapperActionWrapped, nil
}

// unwrap reverses one wrapper entry. Symmetric with applyWrapper: it
// removes the veto symlink at Path, then renames the
// `.veto-original` sibling back to Path. Errors short-circuit;
// dry-run skips the actual filesystem operations.
//
// vetoPath is the current location of the veto binary, resolved once
// by the caller. We require strict physical-path identity (via
// pointsAtVeto) before removing — if the symlink at w.Path has been
// replaced by a brew upgrade or by a third party, we bail out rather
// than clobber it. Name-substring matching (the prior pattern) would
// have accepted an attacker-planted symlink to /tmp/veto-evil.
func unwrap(w wrapperEntry, vetoPath string, dryRun bool) error {
	if dryRun {
		return nil
	}
	// Confirm Path is still a veto symlink before touching it.
	info, err := os.Lstat(w.Path)
	if err != nil {
		// Path is gone (maybe an upgrade reinstalled it). If the
		// `.veto-original` is also gone we have nothing to do; if
		// it exists we leave it for the user.
		if os.IsNotExist(err) {
			return nil
		}
		return errors.With(err, "lstat").Set("path", w.Path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !pointsAtVeto(w.Path, vetoPath) {
			// The symlink no longer resolves to our veto binary —
			// either an upgrade replaced it with a real binary
			// (homebrew/mise's reinstall behavior) or a third party
			// swapped in a same-named target. Either way, we don't own
			// it anymore — refuse to remove.
			current, _ := os.Readlink(w.Path)
			return errors.WithNew("path no longer points at veto; refusing to overwrite").
				Set("path", w.Path, "current_target", current, "expected_veto", vetoPath)
		}
		// Phase 1.5 atomic-unwrap: stage the .veto-original to a
		// transient sibling BEFORE removing the veto symlink, so a
		// failure at any step leaves the user with either the
		// original at target, the original at .veto-restoring (manual
		// recovery), or — only briefly — both. The prior order
		// (remove → rename .veto-original → target) could leave
		// target missing if the final rename failed.
		restoring := w.Path + ".veto-restoring"
		hasOriginal := false
		if _, err := os.Lstat(w.OriginalPath); err == nil {
			hasOriginal = true
			if err := os.Rename(w.OriginalPath, restoring); err != nil {
				return errors.With(err, "stage .veto-original to .veto-restoring").
					Set("original", w.OriginalPath, "restoring", restoring)
			}
		}
		// TOCTOU note: see commentary above on Remove-on-symlink safety.
		if err := os.Remove(w.Path); err != nil {
			if hasOriginal {
				// Best-effort rollback: put the original back.
				_ = os.Rename(restoring, w.OriginalPath)
			}
			return errors.With(err, "remove veto symlink").Set("path", w.Path)
		}
		if hasOriginal {
			if err := os.Rename(restoring, w.Path); err != nil {
				return errors.With(err, "rename .veto-restoring into place").
					Set("restoring", restoring, "target", w.Path)
			}
		}
		return nil
	}
	// Non-symlink at w.Path (e.g. upgrade put a real binary back).
	// Restore the .veto-original only if it's still around AND the
	// target is no longer a symlink to leave the upgrade in place.
	if _, err := os.Lstat(w.OriginalPath); err == nil {
		if err := os.Rename(w.OriginalPath, w.Path); err != nil {
			return errors.With(err, "restore real binary").Set("from", w.OriginalPath, "to", w.Path)
		}
	}
	return nil
}

// add inserts entry into state if no record with the same Path
// already exists (idempotent re-install).
func (s *wrapperState) add(entry wrapperEntry) {
	for i, w := range s.Wrappers {
		if w.Path == entry.Path {
			s.Wrappers[i] = entry
			return
		}
	}
	s.Wrappers = append(s.Wrappers, entry)
}

// remove deletes any entry matching path. Used by the WAL rollback
// path in runInstallWrappers when a per-candidate FS mutation fails
// after the registry entry has been persisted.
func (s *wrapperState) remove(path string) {
	for i, w := range s.Wrappers {
		if w.Path == path {
			s.Wrappers = append(s.Wrappers[:i], s.Wrappers[i+1:]...)
			return
		}
	}
}

// has reports whether state already has a record at the given path.
// Used by reconciliation to distinguish "already in sync" from
// "filesystem-only, needs registering".
func (s *wrapperState) has(path string) bool {
	for _, w := range s.Wrappers {
		if w.Path == path {
			return true
		}
	}
	return false
}

// loadWrapperState reads the state file. Missing file is not an error;
// it just means no wrappers have been installed yet.
func loadWrapperState(cfg config) (wrapperState, error) {
	path := filepath.Join(cfg.CacheDir, stateFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return wrapperState{}, nil
	}
	if err != nil {
		return wrapperState{}, errors.With(err, "read wrapper state").Set("path", path)
	}
	var state wrapperState
	if err := json.Unmarshal(data, &state); err != nil {
		return wrapperState{}, errors.With(err, "parse wrapper state").Set("path", path)
	}
	return state, nil
}

// saveWrapperState writes state atomically (tmp + rename) so a crash
// can't strand a half-written JSON.
func saveWrapperState(cfg config, state wrapperState) error {
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return errors.With(err, "mkdir cache dir")
	}
	if err := os.Chmod(cfg.CacheDir, 0o700); err != nil {
		return errors.With(err, "tighten cache dir perms")
	}
	path := filepath.Join(cfg.CacheDir, stateFileName)
	buf, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.With(err, "marshal state")
	}
	buf = append(buf, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), "wrappers.json.tmp.")
	if err != nil {
		return errors.With(err, "tmpfile")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return errors.With(err, "write tmpfile")
	}
	// Phase 1.5: fsync tmpfile + chmod 0o600 + fsync parent dir so an
	// unclean shutdown can't produce a zero-byte registry on disk and
	// the registry isn't world-readable on shared hosts.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.With(err, "fsync tmpfile")
	}
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close tmpfile")
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return errors.With(err, "chmod tmpfile to 0o600")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return errors.With(err, "rename into place")
	}
	// fsync the parent dir so the rename survives an unclean shutdown.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
