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
	opts, err := parseWrapperFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-wrappers: %v\n", err)
		return exitUsage
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	candidates, err := discoverWrapCandidates(opts, vetoPath)
	if err != nil {
		logger.Error().Err(err).Msg("discover wrap candidates")
		return exitInternal
	}

	state, _ := loadWrapperState(cfg) // empty state is fine

	// Discovery includes already-ours paths, so empty candidates now
	// genuinely means nothing on disk — no PMs in known dirs at all.
	if len(candidates) == 0 {
		fmt.Fprintln(os.Stderr, "veto install-wrappers: no candidate PM binaries found in known dirs.")
		fmt.Fprintln(os.Stderr, "Checked: /opt/homebrew/bin, /usr/local/bin, ~/.local/share/mise/installs/*/*/bin,")
		fmt.Fprintln(os.Stderr, "         ~/.asdf/installs/*/*/bin, ~/.bun/bin.")
		fmt.Fprintln(os.Stderr, "Pass --dir to add more discovery roots, or skip Layer 4 if no PMs are installed locally.")
		return exitOK
	}

	stats := wrapperStats{}
	var skipped []wrapCandidate // read-only-dir candidates, for the sudo hint
	for _, c := range candidates {
		switch action, err := applyWrapper(c, vetoPath, opts.dryRun, opts.force); {
		case err != nil:
			stats.failed++
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", c.pm, c.path, err)
		case action == wrapperActionSkipUnwritable:
			stats.skippedUnwritable++
			skipped = append(skipped, c)
			fmt.Fprintf(os.Stderr, "  %-10s  SKIP  %s — read-only dir (needs sudo)\n", c.pm, c.path)
		case action == wrapperActionSkipAlreadyOurs:
			// The filesystem says this is wrapped. If state agrees,
			// silent no-op. If state doesn't know about it, reconcile —
			// register the entry so future uninstall-wrappers can
			// reverse it. Idempotent because state.add replaces by Path.
			if state.has(c.path) {
				stats.alreadyOurs++
				if opts.verbose {
					fmt.Printf("  %-10s  ok    already wrapped: %s\n", c.pm, c.path)
				}
			} else {
				stats.reconciled++
				fmt.Printf("  %-10s  ok    reconciled (already wrapped, registering in state): %s\n", c.pm, c.path)
				state.add(wrapperEntry{
					Path:         c.path,
					OriginalPath: c.path + wrapperSuffix,
					PM:           c.pm,
					Source:       c.source,
				})
			}
		case action == wrapperActionSkipDryRun:
			stats.wouldWrap++
			fmt.Printf("  %-10s  ok    would wrap: %s\n", c.pm, c.path)
		case action == wrapperActionWrapped:
			stats.wrapped++
			fmt.Printf("  %-10s  ok    wrapped: %s\n", c.pm, c.path)
			state.add(wrapperEntry{
				Path:         c.path,
				OriginalPath: c.path + wrapperSuffix,
				PM:           c.pm,
				Source:       c.source,
			})
		}
	}

	if !opts.dryRun && (stats.wrapped > 0 || stats.reconciled > 0 || stats.failed > 0) {
		if err := saveWrapperState(cfg, state); err != nil {
			logger.Error().Err(err).Msg("save wrapper state")
			return exitInternal
		}
	}

	fmt.Printf("\nSummary: %d wrapped, %d reconciled, %d already-ours, %d would-wrap, %d skipped (needs sudo), %d failed\n",
		stats.wrapped, stats.reconciled, stats.alreadyOurs, stats.wouldWrap, stats.skippedUnwritable, stats.failed)
	printUnwritableRemediation(skipped)
	if stats.failed > 0 {
		return exitInternal
	}
	return exitOK
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
	path   string // absolute path to the existing PM file
	pm     string // basename (e.g. "npm")
	source string // "homebrew", "mise", "asdf", "user"
}

// discoverWrapCandidates walks the well-known install-dir patterns
// looking for files whose basename matches one of wrappedManagers. We
// emit a candidate for any path that is either (a) wrappable
// (executable real binary, not yet ours) or (b) already a veto wrapper
// (symlink-to-veto with a `.veto-original` sibling). The latter look
// like no-ops to applyWrapper but let runInstallWrappers reconcile them
// into wrappers.json when state has drifted from filesystem reality.
func discoverWrapCandidates(opts wrapperFlags, vetoPath string) ([]wrapCandidate, error) {
	candidates := []wrapCandidate{}
	pmFilter := func(name string) bool {
		if len(opts.only) == 0 {
			return true
		}
		_, ok := opts.only[name]
		return ok
	}
	include := func(p string) bool {
		return isWrappableTarget(p, vetoPath) || isAlreadyOursWrap(p, vetoPath)
	}

	// 1) Homebrew prefix dirs. On Apple Silicon, /opt/homebrew/bin; on
	//    Intel, /usr/local/bin. We check both — the wrong one will be
	//    a no-op rather than a failure.
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin"} {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			if include(p) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "homebrew"})
			}
		}
	}

	// 2) mise install dirs: ~/.local/share/mise/installs/<tool>/<v>/bin/<pm>.
	if home, err := os.UserHomeDir(); err == nil {
		miseRoot := filepath.Join(home, ".local", "share", "mise", "installs")
		for _, binDir := range globMiseBinDirs(miseRoot) {
			for _, pm := range wrappedManagers {
				if !pmFilter(pm) {
					continue
				}
				p := filepath.Join(binDir, pm)
				if include(p) {
					candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "mise"})
				}
			}
		}
		// 3) asdf: ~/.asdf/installs/<tool>/<v>/bin/<pm>.
		asdfRoot := filepath.Join(home, ".asdf", "installs")
		for _, binDir := range globMiseBinDirs(asdfRoot) {
			for _, pm := range wrappedManagers {
				if !pmFilter(pm) {
					continue
				}
				p := filepath.Join(binDir, pm)
				if include(p) {
					candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "asdf"})
				}
			}
		}
		// 4) Direct bun install: ~/.bun/bin
		bunDir := filepath.Join(home, ".bun", "bin")
		for _, pm := range []string{"bun", "bunx"} {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(bunDir, pm)
			if include(p) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "bun"})
			}
		}
	}

	// 5) User-supplied --dir entries.
	for _, dir := range opts.dirs {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			if include(p) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "user"})
			}
		}
	}

	return candidates, nil
}

// globMiseBinDirs returns every `<tool>/<version>/bin` directory under
// the given root (mise's installs root, or asdf's). We do this by
// listing the two intermediate levels rather than using filepath.Glob
// so we get reasonable behavior when the tree is empty or partial.
func globMiseBinDirs(root string) []string {
	out := []string{}
	tools, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, tool := range tools {
		if !tool.IsDir() {
			continue
		}
		toolDir := filepath.Join(root, tool.Name())
		versions, err := os.ReadDir(toolDir)
		if err != nil {
			continue
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			binDir := filepath.Join(toolDir, v.Name(), "bin")
			if info, err := os.Stat(binDir); err == nil && info.IsDir() {
				out = append(out, binDir)
			}
		}
	}
	return out
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
		// TOCTOU note: there's a window between pointsAtVeto and Remove
		// where a same-UID attacker could repoint w.Path elsewhere. That's
		// safe here: os.Remove on a symlink unlinks the symlink inode
		// itself, not the target it points at — the attacker is only
		// cleaning up their own swap, not tricking us into deleting
		// something we wouldn't have. The check is "is this our state?"
		// not "is this safe to unlink?", and unlinking a symlink is
		// always safe.
		if err := os.Remove(w.Path); err != nil {
			return errors.With(err, "remove veto symlink").Set("path", w.Path)
		}
	}
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
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close tmpfile")
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return errors.With(err, "chmod tmpfile")
	}
	return os.Rename(tmpPath, path)
}

