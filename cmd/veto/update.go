// update.go: `veto update` — self-update the veto binary in place.
//
// Why this exists: veto ships no prebuilt release binaries, so the only
// way to move to a newer version is to have a Go toolchain, clone the
// source, and run the multi-step `make install` + `install-shims` +
// `make interposer` + `install-preload` dance documented in the README.
// That friction means installs drift and stay on old, sometimes-buggy
// builds. `veto update` collapses the common case into one command.
//
// Design: build the requested ref with `go install <module>@<ref>` into a
// throwaway GOBIN (checksum-verified through the module proxy / go.sum,
// no opaque binary download), then atomically replace the managed veto
// binary. Because every Layer 2 shim is a symlink to that binary path and
// the Layer 3 interposer routes execs to $VETO_PATH (the same path), the
// replace alone makes all layers use the new binary immediately — no
// re-source, no shim churn. The only artifact that can go stale is the
// compiled interposer .so, and only when the *set* of shadowed package
// managers changed; `--full` rebuilds it (via `install-all`) for that
// rare case. By default we also run the new binary's `install-shims
// --force`, which is cheap and picks up any newly-shadowed PM names.
//
// go install is invoked against the REAL go (not veto's own shim) with
// VETO_PATH stripped from the child env, so the update neither re-enters
// veto's gate nor trips the interposer recursion guard.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

const (
	// defaultUpdateModule is the `go install`-able main package.
	defaultUpdateModule = "github.com/brynbellomy/veto/cmd/veto"
	// defaultUpdateRepo is the git remote consulted by `--check`.
	defaultUpdateRepo = "https://github.com/brynbellomy/veto"
	// defaultUpdateRef is the ref to install. The repo publishes no
	// semver tags, so `@latest` would fail to resolve — default to the
	// default branch instead.
	defaultUpdateRef = "main"

	// goInstallTimeout bounds the build. Generous: a cold module cache
	// plus a GOTOOLCHAIN auto-download of the go.mod-required toolchain
	// can take a while on a fresh machine.
	goInstallTimeout = 10 * time.Minute
	// lsRemoteTimeout bounds the read-only `--check` probe.
	lsRemoteTimeout = 30 * time.Second
)

type updateOpts struct {
	check      bool   // report current vs latest, change nothing
	full       bool   // after replacing, run `install-all` (rebuilds interposer)
	binaryOnly bool   // replace the binary only; touch no other layer
	ref        string // git ref / module query to install (branch, tag, sha)
	repo       string // git remote for --check
	module     string // go install path
}

// parseUpdateFlags mirrors the manual, dependency-free arg parsing the
// other veto subcommands use (see parseInstallAllFlags).
func parseUpdateFlags(args []string) (updateOpts, error) {
	opts := updateOpts{ref: defaultUpdateRef, repo: defaultUpdateRepo, module: defaultUpdateModule}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--check":
			opts.check = true
		case a == "--full":
			opts.full = true
		case a == "--binary-only":
			opts.binaryOnly = true
		case a == "--ref":
			if i+1 >= len(args) {
				return opts, errors.New("--ref requires a value (branch, tag, or commit)")
			}
			opts.ref = args[i+1]
			i++
		case strings.HasPrefix(a, "--ref="):
			opts.ref = strings.TrimPrefix(a, "--ref=")
		case a == "--repo":
			if i+1 >= len(args) {
				return opts, errors.New("--repo requires a URL")
			}
			opts.repo = args[i+1]
			i++
		case strings.HasPrefix(a, "--repo="):
			opts.repo = strings.TrimPrefix(a, "--repo=")
		case a == "--module":
			if i+1 >= len(args) {
				return opts, errors.New("--module requires a go install path")
			}
			opts.module = args[i+1]
			i++
		case strings.HasPrefix(a, "--module="):
			opts.module = strings.TrimPrefix(a, "--module=")
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	if opts.ref == "" {
		return opts, errors.New("--ref may not be empty")
	}
	if opts.full && opts.binaryOnly {
		return opts, errors.New("--full and --binary-only are mutually exclusive")
	}
	return opts, nil
}

// installSpec returns the `module@ref` argument for `go install`.
func installSpec(module, ref string) string { return module + "@" + ref }

// currentCommit returns the running build's best-effort git short sha,
// preferring the ldflags-injected commit and falling back to a sha parsed
// out of the (possibly pseudo-)version. Returns "" when neither is usable.
func currentCommit() string {
	v, c, _ := resolveVersionInfo()
	if c != "" && c != "untagged" && c != "unknown" {
		return c
	}
	return extractCommit(v)
}

// extractCommit pulls a git sha out of a version string: a bare sha
// ("2b28d87", with an optional "-dirty" suffix) or the trailing sha of a
// go pseudo-version ("v0.0.0-<utc>-<12-hex>"). Returns "" if none is found.
func extractCommit(v string) string {
	v = strings.TrimSpace(strings.TrimSuffix(v, "-dirty"))
	if v == "" || v == "dev" {
		return ""
	}
	if i := strings.LastIndex(v, "-"); i >= 0 {
		if tail := v[i+1:]; looksHex(tail) {
			return tail
		}
	}
	if looksHex(v) {
		return v
	}
	return ""
}

// commitsMatch reports whether a current short sha and a full target sha
// name the same commit, by case-insensitive prefix (the shorter is a
// prefix of the longer). Empty inputs never match.
func commitsMatch(current, target string) bool {
	current, target = strings.ToLower(strings.TrimSpace(current)), strings.ToLower(strings.TrimSpace(target))
	if current == "" || target == "" {
		return false
	}
	if len(current) > len(target) {
		current, target = target, current
	}
	return strings.HasPrefix(target, current)
}

// looksHex reports whether s is a non-empty run of lowercase-or-uppercase
// hex digits at least 7 long — the shape of a git short sha or the 12-hex
// tail of a go pseudo-version. The length floor avoids misreading a
// numeric version segment ("2", "31") as a commit.
func looksHex(s string) bool {
	if len(s) < 7 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// runUpdate implements `veto update`.
func runUpdate(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseUpdateFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto update: %v\n", err)
		return exitUsage
	}

	curVer, curCommit, _ := resolveVersionInfo()

	if opts.check {
		return runUpdateCheck(logger, cfg, opts, curVer, curCommit)
	}

	// Locate the REAL go, skipping veto's own `go` shim so we don't
	// recurse into the gate.
	realGo, err := findRealBinary("go", wrapperRegisteredFunc(cfg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "veto update: no Go toolchain found on PATH.")
		fmt.Fprintln(os.Stderr, "  veto ships no prebuilt binaries, so self-update builds from source with `go install`.")
		fmt.Fprintln(os.Stderr, "  Install Go (https://go.dev/dl/), then re-run `veto update`.")
		return exitInternal
	}

	gobin, err := os.MkdirTemp("", "veto-update-*")
	if err != nil {
		logger.Error().Err(err).Msg("mkdir temp GOBIN")
		return exitInternal
	}
	defer os.RemoveAll(gobin)

	spec := installSpec(opts.module, opts.ref)
	fmt.Printf("veto update: building %s (go install; this can take a minute)...\n", spec)

	ctx, cancel := context.WithTimeout(context.Background(), goInstallTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, realGo, "install", spec)
	// GOBIN steers the artifact into our tempdir. sanitizedEnv strips
	// VETO_PATH so the interposer loaded in the go child short-circuits
	// instead of rewriting go's own tool execs back into veto.
	cmd.Env = append(sanitizedEnv(os.Environ()), "GOBIN="+gobin)
	cmd.Stdout = os.Stderr // build chatter → stderr, keep stdout clean
	cmd.Stderr = os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "veto update: build timed out after %s.\n", goInstallTimeout)
		}
		logger.Error().Err(runErr).Str("spec", spec).Msg("go install failed")
		fmt.Fprintln(os.Stderr, "veto update: go install failed (see output above). Nothing was changed.")
		return exitInternal
	}

	built := filepath.Join(gobin, "veto")
	if _, statErr := os.Stat(built); statErr != nil {
		logger.Error().Err(statErr).Str("path", built).Msg("go install produced no binary")
		fmt.Fprintln(os.Stderr, "veto update: go install reported success but produced no `veto` binary. Nothing was changed.")
		return exitInternal
	}

	target, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate installed veto binary")
		return exitInternal
	}

	if err := replaceBinary(built, target); err != nil {
		logger.Error().Err(err).Str("target", target).Msg("replace veto binary")
		fmt.Fprintf(os.Stderr, "veto update: could not replace %s: %v\n", target, err)
		return exitInternal
	}
	fmt.Printf("veto update: installed new binary → %s\n", target)

	if !opts.binaryOnly {
		if opts.full {
			fmt.Println("veto update: refreshing all layers (install-all)...")
			if rc := execManaged(target, "install-all", "--force"); rc != exitOK {
				fmt.Fprintln(os.Stderr, "veto update: WARN — `install-all` returned non-zero; the new binary is installed, but re-run `veto install-all` to finish refreshing layers.")
			}
		} else {
			// Cheap, idempotent: re-point shims and add any newly-shadowed
			// PM names the new binary knows about.
			if rc := execManaged(target, "install-shims", "--force"); rc != exitOK {
				fmt.Fprintln(os.Stderr, "veto update: WARN — `install-shims --force` returned non-zero; run it manually to finish.")
			}
			fmt.Fprintln(os.Stderr, "veto update: the Layer 3 interposer routes via VETO_PATH and now points at the new binary.")
			fmt.Fprintln(os.Stderr, "  If this release changed which package managers are shadowed, run `veto update --full` to rebuild it.")
		}
	}

	fmt.Print("veto update: now running ")
	_ = execManaged(target, "version")
	return exitOK
}

// runUpdateCheck reports current vs latest without changing anything.
func runUpdateCheck(logger zerolog.Logger, cfg config, opts updateOpts, curVer, curCommit string) int {
	target, err := remoteCommit(cfg, opts.repo, opts.ref)
	if err != nil {
		logger.Error().Err(err).Msg("resolve remote ref")
		fmt.Fprintf(os.Stderr, "veto update --check: could not resolve %s@%s: %v\n", opts.repo, opts.ref, err)
		return exitInternal
	}
	fmt.Printf("veto update: current  %s (commit %s)\n", curVer, curCommit)
	fmt.Printf("veto update: %s@%s → %s\n", opts.repo, opts.ref, shortSha(target))
	if commitsMatch(currentCommit(), target) {
		fmt.Println("veto update: already up to date.")
	} else {
		fmt.Println("veto update: an update is available — run `veto update` to install it.")
	}
	return exitOK
}

// remoteCommit resolves ref at repo to a commit sha via `git ls-remote`,
// using the real git (skipping veto's shim).
func remoteCommit(cfg config, repo, ref string) (string, error) {
	git, err := findRealBinary("git", wrapperRegisteredFunc(cfg))
	if err != nil {
		return "", errors.With(err, "git not found on PATH (needed for --check)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), lsRemoteTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, "ls-remote", repo, ref)
	cmd.Env = sanitizedEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return "", errors.With(err, "git ls-remote").Set("repo", repo, "ref", ref)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", errors.WithNew("ref not found on remote").Set("repo", repo, "ref", ref)
	}
	// First whitespace-delimited token of the first line is the sha.
	fields := strings.Fields(strings.SplitN(line, "\n", 2)[0])
	if len(fields) == 0 || !looksHex(fields[0]) {
		return "", errors.WithNew("unexpected ls-remote output").Set("output", truncateForError(line, 200))
	}
	return fields[0], nil
}

// replaceBinary atomically installs src's contents at dst. It writes a
// sibling temp file in dst's directory (so the final rename is same-
// filesystem and atomic) with mode 0755, then renames it over dst.
// Replacing a running executable this way is safe on Unix: in-flight
// processes keep the old inode; the next exec picks up the new one.
func replaceBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return errors.With(err, "open new binary").Set("src", src)
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".veto-update-*")
	if err != nil {
		return errors.With(err, "create temp in target dir").Set("dir", dir)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return errors.With(err, "copy new binary into place")
	}
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close temp binary")
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return errors.With(err, "chmod temp binary")
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return errors.With(err, "rename temp binary over target").Set("target", dst)
	}
	committed = true
	return nil
}

// execManaged runs an already-installed veto subcommand (the freshly
// replaced binary) with veto's control env stripped, wiring the child's
// stdio to ours. Returns the child's exit code.
func execManaged(bin string, args ...string) int {
	cmd := exec.Command(bin, args...)
	cmd.Env = sanitizedEnv(os.Environ())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return exitInternal
	}
	return exitOK
}

// shortSha truncates a full sha to 7 chars for display. Non-sha strings
// pass through unchanged.
func shortSha(s string) string {
	if looksHex(s) && len(s) > 7 {
		return s[:7]
	}
	return s
}
