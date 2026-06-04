// PATH-shim management.
//
// The shim subsystem is the integration path for any agent or shell that
// doesn't expose a per-tool hook protocol (Codex CLI, Sirene, generic CI
// runners, ad-hoc terminals). The mechanism:
//
//  1. `veto install-shims [--dir DIR]` creates a symlink for each
//     supported package manager binary inside DIR (default ~/.local/bin):
//     DIR/npm   → /absolute/path/to/veto
//     DIR/pnpm  → /absolute/path/to/veto
//     ...
//  2. When the user runs `npm install foo`, the shell resolves `npm` to
//     DIR/npm, which is the veto binary. veto's main() detects the
//     shim invocation via `filepath.Base(os.Args[0]) == "npm"` and
//     prepends "npm" to args, so the rest of the code sees the same
//     shape as `veto npm install foo`.
//
// For this to work, DIR must come BEFORE the directories holding the real
// npm/pnpm/... binaries in $PATH. install-shims prints a warning if the
// ordering looks wrong.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/packagemanager/pmlist"
)

// shimmedManagers is an alias for the canonical pmlist.Shimmed slice.
// Kept as a package-local name so the existing call sites read
// naturally; the source of truth lives in
// internal/packagemanager/pmlist so isShimName, install-shims,
// install-wrappers, the claudecode hook, and the C interposer all
// consume the same list.
//
// python/python3 are part of the canonical list to close the
// `python -m pip install …` hole. Layer 4 wrappers deliberately DO NOT
// cover python (see wrappedManagers in install_wrappers.go): wrapping
// the real interpreter would route every script execution through
// veto, an unacceptable hot path. Layer 2 shims are fine because
// main()'s dispatch fast-paths every non-`-m {pm}` python invocation
// straight to the real interpreter.
var shimmedManagers = pmlist.Shimmed

// runInstallShims implements `veto install-shims [--dir DIR] [--force]`.
//
// Idempotency:
//   - If DIR/<pm> doesn't exist: create a symlink to the veto binary.
//   - If DIR/<pm> is already a symlink pointing at the same veto binary:
//     leave it (silent no-op).
//   - If DIR/<pm> is a symlink to a DIFFERENT path (an older veto, a
//     mise shim, anything): update only if --force is set. Otherwise refuse
//     so users don't accidentally shadow tooling they meant to keep.
//   - If DIR/<pm> is a regular file (e.g. a real npm binary): refuse unless
//     --force. Replacing real binaries silently is exactly the kind of
//     surprise a security tool should not cause.
func runInstallShims(logger zerolog.Logger, args []string) int {
	dir, force, err := parseShimFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto: %v\n", err)
		return exitUsage
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error().Err(err).Str("dir", dir).Msg("create shim dir")
		return exitInternal
	}

	var hadFailure, hadAction bool
	for _, name := range shimmedManagers {
		target := filepath.Join(dir, name)
		action, err := ensureShim(target, vetoPath, force)
		switch {
		case err != nil:
			hadFailure = true
			fmt.Fprintf(os.Stderr, "  %-8s  FAILED  %v\n", name, err)
		case action == "":
			// no-op; already correct
			fmt.Fprintf(os.Stdout, "  %-8s  ok      already installed\n", name)
		default:
			hadAction = true
			fmt.Fprintf(os.Stdout, "  %-8s  ok      %s\n", name, action)
		}
	}

	if hadAction {
		printPathOrderingHint(os.Stdout, dir)
	}
	if hadFailure {
		fmt.Fprintln(os.Stderr, "\nveto: one or more shims failed; re-run with --force to overwrite existing files, or move them out of the way first.")
		return exitInternal
	}
	return exitOK
}

// runUninstallShims removes veto-managed symlinks from DIR. It leaves
// untouched anything that isn't a symlink pointing at the veto binary
// — symmetric with install-shims's refusal to clobber.
func runUninstallShims(logger zerolog.Logger, args []string) int {
	dir, _, err := parseShimFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto: %v\n", err)
		return exitUsage
	}
	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	for _, name := range shimmedManagers {
		target := filepath.Join(dir, name)
		removed, err := removeShim(target, vetoPath)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "  %-8s  FAILED  %v\n", name, err)
		case removed:
			fmt.Fprintf(os.Stdout, "  %-8s  ok      removed\n", name)
		default:
			fmt.Fprintf(os.Stdout, "  %-8s  skip    not a veto shim\n", name)
		}
	}
	return exitOK
}

// ensureShim creates or updates a symlink at target pointing to vetoPath.
// Returns a short human-readable description of what happened (e.g. "created",
// "updated"), or "" if no change was needed. Returns an error when target
// exists, is not a veto shim, and force is false.
func ensureShim(target, vetoPath string, force bool) (string, error) {
	info, err := os.Lstat(target)
	if err != nil && !os.IsNotExist(err) {
		return "", errors.With(err, "lstat").Set("path", target)
	}

	if err == nil {
		// Something exists at target. Decide whether to leave it, replace it,
		// or refuse.
		if info.Mode()&os.ModeSymlink != 0 {
			existing, lerr := os.Readlink(target)
			if lerr != nil {
				return "", errors.With(lerr, "readlink").Set("path", target)
			}
			if existing == vetoPath {
				return "", nil // already correct
			}
			if !force {
				return "", errors.WithNew("symlink points elsewhere; pass --force to overwrite").
					Set("path", target, "current_target", existing)
			}
		} else {
			// Regular file. Refuse unless forced. Phase 1.3: instead of
			// deleting the user's pre-existing real binary, rename it to
			// <target>.veto-displaced so uninstall-shims can restore it.
			if !force {
				return "", errors.WithNew("file exists and is not a symlink; pass --force to overwrite").
					Set("path", target)
			}
			displaced := target + ".veto-displaced"
			if err := os.Rename(target, displaced); err != nil {
				return "", errors.With(err, "rename pre-existing real binary to .veto-displaced").
					Set("path", target, "displaced", displaced)
			}
		}
		// Symlink replacement path: a different-pointing symlink can be
		// removed safely (no user data to preserve).
		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(target); err != nil {
				return "", errors.With(err, "remove existing symlink").Set("path", target)
			}
		}
	}

	if err := os.Symlink(vetoPath, target); err != nil {
		// Roll back the displacement on symlink failure so the user
		// isn't left with a missing binary.
		displaced := target + ".veto-displaced"
		if _, derr := os.Lstat(displaced); derr == nil {
			_ = os.Rename(displaced, target)
		}
		return "", errors.With(err, "create symlink").Set("path", target)
	}
	if info != nil {
		return "updated -> " + vetoPath, nil
	}
	return "created -> " + vetoPath, nil
}

// removeShim deletes target if it's a symlink to vetoPath. Returns
// (true, nil) on removal, (false, nil) if target doesn't exist or isn't ours.
func removeShim(target, vetoPath string) (bool, error) {
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, errors.With(err, "lstat").Set("path", target)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}
	existing, err := os.Readlink(target)
	if err != nil {
		return false, errors.With(err, "readlink").Set("path", target)
	}
	if existing != vetoPath {
		return false, nil
	}
	if err := os.Remove(target); err != nil {
		return false, errors.With(err, "remove").Set("path", target)
	}
	// Phase 1.3: restore any pre-existing real binary that install-shims
	// --force displaced to <target>.veto-displaced.
	displaced := target + ".veto-displaced"
	if _, derr := os.Lstat(displaced); derr == nil {
		if err := os.Rename(displaced, target); err != nil {
			return true, errors.With(err, "restore .veto-displaced after removing shim").
				Set("path", target, "displaced", displaced)
		}
	}
	return true, nil
}

// resolveVetoBinary returns the canonical absolute path to the running
// veto binary. We follow any symlinks so the shim targets the real file,
// not the symlink that launched us.
func resolveVetoBinary() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", errors.With(err, "os.Executable")
	}
	resolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		// Fall back to the unresolved path — better than failing entirely.
		return self, nil
	}
	return resolved, nil
}

// parseShimFlags accepts `--dir PATH` and `--force` in any order.
func parseShimFlags(args []string) (string, bool, error) {
	dir := defaultShimDir()
	force := false
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--dir":
			if i+1 >= len(args) {
				return "", false, errors.New("--dir requires a path argument")
			}
			dir = args[i+1]
			i += 2
		case "--force":
			force = true
			i++
		default:
			if v, ok := strings.CutPrefix(args[i], "--dir="); ok {
				dir = v
				i++
				continue
			}
			return "", false, errors.WithNew("unknown argument").Set("arg", args[i])
		}
	}
	if dir == "" {
		return "", false, errors.New("shim directory resolved empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false, errors.With(err, "resolve shim dir")
	}
	return abs, force, nil
}

// defaultShimDir mirrors defaultCacheDir's spirit: prefer XDG, fall back to
// the conventional ~/.local/bin. We do NOT honor $XDG_BIN_HOME (no widely
// adopted spec); users who want a different dir pass --dir.
func defaultShimDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "veto-bin")
	}
	return filepath.Join(home, ".local", "bin")
}

// printPathOrderingHint warns when the shim directory comes AFTER a
// directory that already contains one of the PMs we just shimmed. In that
// case the user's shell would resolve to the real binary before reaching
// our shim, and the install is essentially silent.
func printPathOrderingHint(w io.Writer, shimDir string) {
	pathEnv := os.Getenv("PATH")
	parts := filepath.SplitList(pathEnv)
	shimIdx := -1
	for i, p := range parts {
		if absEqual(p, shimDir) {
			shimIdx = i
			break
		}
	}
	if shimIdx < 0 {
		fmt.Fprintf(w, "\nhint: %s is not in your PATH. Add it (in front of other PM directories) for the shims to take effect:\n  export PATH=%s:$PATH\n", shimDir, shimDir)
		return
	}

	for _, name := range shimmedManagers {
		for i := 0; i < shimIdx; i++ {
			candidate := filepath.Join(parts[i], name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				// A real binary sits earlier in PATH than our shim.
				fmt.Fprintf(w, "\nhint: a real %s exists at %s, which appears in PATH BEFORE the shim dir %s.\n  Reorder your PATH so %s comes first, or the shim won't be reached for %s.\n",
					name, candidate, shimDir, shimDir, name)
				return
			}
		}
	}
}

// absEqual compares two paths after symlink resolution and absolutization,
// so "/Users/x/.local/bin" and "/Users/x/.local/bin/" match.
func absEqual(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		return false
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}
