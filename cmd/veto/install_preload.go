// install-preload: wire the native execve interposer.
//
// Coverage layers, from least to most invasive:
//
//   1. Claude Code hook + PATH shims (covers shell-mediated invocations).
//   2. install-preload (covers direct child-process spawns: subprocess.run,
//      Popen with shell=False, full-path execve calls).
//
// Layer 2 is opt-in because it requires a shell-rc edit (the env vars
// have to be exported by the parent process tree of any agent we want
// covered). Auto-editing dotfiles without consent is the kind of surprise
// a security tool absolutely cannot afford, so we default to printing
// the export lines and require an explicit --shell-rc to mutate.
//
// The interposer .dylib/.so is built out-of-tree (`make interposer`).
// install-preload locates the artifact, copies it into the user's lib
// dir, and either writes or prints the shell-rc snippet.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// markerStart/markerEnd bracket the block we manage inside a shell rc.
// Idempotent updates re-write the entire block; uninstall strips it.
// Anything outside the markers is preserved verbatim.
const (
	preloadMarkerStart = "# >>> veto preload (managed) >>>"
	preloadMarkerEnd   = "# <<< veto preload (managed) <<<"
)

type preloadOpts struct {
	libPath   string // path to the prebuilt .dylib/.so
	installTo string // dir to copy the library into (default ~/.local/lib)
	shellRC   string // path to shell rc to edit (default: print only)
	autoRC    bool   // if true, auto-detect $SHELL and pick the matching rc
	print     bool   // when true, write export lines to stdout instead of a file
}

// runInstallPreload implements `veto install-preload`.
//
// Required flag: --lib PATH (the path to the prebuilt interposer). We
// don't try to build it inline — that would require a CC on the user's
// machine to live inside the veto binary, which conflicts with the
// "single static Go binary" shape this project optimizes for. Build is
// `make interposer`, install is this subcommand, and they're separate
// steps in the onboarding doc.
func runInstallPreload(logger zerolog.Logger, args []string) int {
	opts, err := parsePreloadFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-preload: %v\n", err)
		return exitUsage
	}

	if opts.libPath == "" {
		fmt.Fprintln(os.Stderr, "veto install-preload: --lib PATH is required.")
		fmt.Fprintln(os.Stderr, "Run `make interposer` first, then pass the resulting libveto_interpose.* path.")
		return exitUsage
	}
	if err := assertInterposerArtifact(opts.libPath); err != nil {
		fmt.Fprintf(os.Stderr, "veto install-preload: %v\n", err)
		return exitUsage
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	// Verify dyld accepts the SOURCE dylib before copying it into place.
	// If we copied first then verified, a bad dylib would overwrite the
	// user's existing (good) install at the same path — and since their
	// shell rc already points at that path, every new terminal would
	// abort with a dyld error. Verifying first means a failure leaves
	// both the installed copy AND the shell rc untouched.
	if err := verifyInterposerLoads(opts.libPath, vetoPath); err != nil {
		logger.Error().Err(err).Msg("interposer load check")
		fmt.Fprintln(os.Stderr, "veto: ERROR — dyld rejected the interposer.")
		fmt.Fprintf(os.Stderr, "  underlying error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Possible causes: arch mismatch (try `make clean && make interposer`),")
		fmt.Fprintln(os.Stderr, "corrupted dylib, or a macOS code-signing policy blocking it.")
		fmt.Fprintln(os.Stderr, "Nothing was modified — your previous Layer 3 install (if any) is intact.")
		return exitInternal
	}
	fmt.Println("veto: verified — dyld accepted the interposer in a test process.")

	installedLibPath, err := copyInterposer(opts.libPath, opts.installTo)
	if err != nil {
		logger.Error().Err(err).Msg("copy interposer")
		return exitInternal
	}
	fmt.Printf("veto: installed interposer to %s\n", installedLibPath)

	envBlock := renderPreloadEnvBlock(installedLibPath, vetoPath)

	if opts.print {
		fmt.Println()
		fmt.Println(envBlock)
		return exitOK
	}

	rcPaths, err := preloadShellRCTargets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-preload: %v\n", err)
		fmt.Fprintln(os.Stderr, "Pass --shell-rc PATH explicitly, or use --print to dump the export lines.")
		return exitUsage
	}

	if len(rcPaths) == 0 {
		// No file edit requested — print the block plus a clear note.
		fmt.Println()
		fmt.Println("# Add the block below to your shell rc (~/.zshrc, ~/.bashrc, …)")
		fmt.Println("# or re-run with --shell-rc PATH (or --shell-rc auto) to edit it for you.")
		fmt.Println()
		fmt.Println(envBlock)
		return exitOK
	}

	for _, rcPath := range rcPaths {
		if err := upsertShellRCBlock(rcPath, envBlock); err != nil {
			logger.Error().Err(err).Str("rc", rcPath).Msg("update shell rc")
			return exitInternal
		}
		fmt.Printf("veto: wrote preload block to %s\n", rcPath)
	}
	fmt.Println("         Open a new terminal (or source your shell rc), then run `veto doctor` —")
	fmt.Println("         the 'interposer env' check should go from WARN to PASS.")
	fmt.Println()
	printSIPCaveat(os.Stdout)
	return exitOK
}

// preloadShellRCTargets returns the list of rc files to write the preload
// block to. Semantics mirror shellIntegrationTargets: an explicit
// --shell-rc PATH wins (single file), --shell-rc auto fans out to the
// auto-detected interactive rc PLUS the bash family (.bashrc,
// .bash_profile, .profile) when bash is on disk, and no flag at all
// returns an empty list (caller prints the block instead of writing).
//
// Why fan out: the env-export block (DYLD_INSERT_LIBRARIES /
// LD_PRELOAD / VETO_PATH) needs to be set in whatever shell ends up
// running the user's package-manager commands. A zsh user who drops
// into bash for a script, or an agent runner that sources .profile
// for non-interactive login, will otherwise silently lose Layer 3.
// Shell integration already fans out for the same reason; preload had
// drifted out of parity (zsh-only by default), and this aligns them.
func preloadShellRCTargets(opts preloadOpts) ([]string, error) {
	if opts.shellRC != "" {
		return []string{opts.shellRC}, nil
	}
	if !opts.autoRC {
		return nil, nil
	}
	targets, err := defaultShellIntegrationTargets()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(targets))
	for _, t := range targets {
		paths = append(paths, t.path)
	}
	return paths, nil
}

// verifyInterposerLoads spawns a quick test subprocess with the
// preload env var set, exec'ing the veto binary itself with `help`.
// If dyld can't load the dylib, the child aborts with a stderr message
// starting "dyld[…]: terminating because inserted dylib '…' could not
// be loaded". We surface that as an error so install-preload can roll
// back before touching the user's shell rc.
//
// We exec the veto binary specifically because (a) we just installed
// it and know it exists, (b) it's user-installed, not SIP-protected,
// so DYLD_INSERT_LIBRARIES actually applies, and (c) `veto help`
// completes in milliseconds without doing any I/O.
func verifyInterposerLoads(libPath, vetoPath string) error {
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, vetoPath, "help")
	cmd.Env = []string{
		envVar + "=" + libPath,
		"VETO_PATH=" + vetoPath,
		"PATH=/usr/bin:/bin",
		"HOME=" + os.Getenv("HOME"),
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	err := cmd.Run()
	// Two failure modes worth catching:
	//   1. exec failed (binary doesn't exist, permissions, etc.) — wrapped.
	//   2. dyld error message in stderr — surface it directly.
	if msg := stderr.String(); strings.Contains(msg, "could not be loaded") ||
		strings.Contains(msg, "cannot be preloaded") {
		// First line is usually the most useful — drop anything after.
		firstLine := msg
		if idx := strings.IndexByte(msg, '\n'); idx > 0 {
			firstLine = msg[:idx]
		}
		return errors.WithNew(strings.TrimSpace(firstLine))
	}
	if err != nil {
		// Distinguish "process exited non-zero" from "process aborted by
		// signal" — the second is what dyld does on a load failure. We
		// don't strictly need this branch (the stderr scan above covers
		// the common case), but it catches truncated-stderr edge cases.
		return errors.With(err, "verification subprocess failed").Set(
			"stderr_excerpt", truncateForError(stderr.String(), 200),
		)
	}
	return nil
}

// truncateForError caps a stderr capture for inclusion in an error
// message, so a multi-line dyld trace doesn't explode the output.
func truncateForError(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// runUninstallPreload removes the managed block from the shell rc and
// removes the installed library file. We leave the source dylib in the
// build dir alone — that's the user's working copy.
func runUninstallPreload(logger zerolog.Logger, args []string) int {
	opts, err := parsePreloadFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-preload: %v\n", err)
		return exitUsage
	}

	rcPaths, err := preloadShellRCTargets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-preload: %v\n", err)
		return exitUsage
	}
	for _, rcPath := range rcPaths {
		if removed, err := removeShellRCBlock(rcPath); err != nil {
			logger.Error().Err(err).Str("rc", rcPath).Msg("strip rc block")
			return exitInternal
		} else if removed {
			fmt.Printf("veto: removed preload block from %s\n", rcPath)
		} else {
			fmt.Printf("veto: no managed block found in %s\n", rcPath)
		}
	}

	installedLib := installedInterposerPath(opts.installTo)
	if err := os.Remove(installedLib); err == nil {
		fmt.Printf("veto: removed %s\n", installedLib)
	} else if !os.IsNotExist(err) {
		logger.Warn().Err(err).Str("path", installedLib).Msg("remove interposer")
	}
	fmt.Println("         Start a fresh shell so the env vars stop being exported.")
	return exitOK
}

func parsePreloadFlags(args []string) (preloadOpts, error) {
	opts := preloadOpts{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lib":
			if i+1 >= len(args) {
				return opts, errors.New("--lib requires a path argument")
			}
			opts.libPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--lib="):
			opts.libPath = strings.TrimPrefix(a, "--lib=")
		case a == "--install-to":
			if i+1 >= len(args) {
				return opts, errors.New("--install-to requires a path argument")
			}
			opts.installTo = args[i+1]
			i++
		case strings.HasPrefix(a, "--install-to="):
			opts.installTo = strings.TrimPrefix(a, "--install-to=")
		case a == "--shell-rc":
			if i+1 >= len(args) {
				return opts, errors.New("--shell-rc requires a path argument (or 'auto')")
			}
			v := args[i+1]
			if v == "auto" {
				opts.autoRC = true
			} else {
				opts.shellRC = v
			}
			i++
		case strings.HasPrefix(a, "--shell-rc="):
			v := strings.TrimPrefix(a, "--shell-rc=")
			if v == "auto" {
				opts.autoRC = true
			} else {
				opts.shellRC = v
			}
		case a == "--print":
			opts.print = true
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

func assertInterposerArtifact(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.With(err, "stat").Set("path", path)
	}
	if info.IsDir() {
		return errors.WithNew("not a regular file").Set("path", path)
	}
	expectedSuffix := ".dylib"
	if runtime.GOOS != "darwin" {
		expectedSuffix = ".so"
	}
	if !strings.HasSuffix(path, expectedSuffix) {
		return errors.WithNew("interposer artifact has unexpected suffix").
			Set("path", path, "expected", expectedSuffix)
	}
	return nil
}

func copyInterposer(src, installTo string) (string, error) {
	dst := installedInterposerPath(installTo)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", errors.With(err, "mkdir lib dir")
	}
	in, err := os.Open(src)
	if err != nil {
		return "", errors.With(err, "open source")
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(dst), ".interposer.")
	if err != nil {
		return "", errors.With(err, "tmpfile")
	}
	tmpPath := out.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", errors.With(err, "copy contents")
	}
	if err := out.Close(); err != nil {
		return "", errors.With(err, "close tmpfile")
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return "", errors.With(err, "chmod")
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return "", errors.With(err, "rename")
	}
	return dst, nil
}

// installedInterposerPath returns the canonical install location for the
// interposer library — ~/.local/lib/libveto_interpose.<ext> by default.
func installedInterposerPath(override string) string {
	dir := override
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			dir = filepath.Join(os.TempDir(), "veto-lib")
		} else {
			dir = filepath.Join(home, ".local", "lib")
		}
	}
	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}
	return filepath.Join(dir, name)
}

// renderPreloadEnvBlock returns the shell-rc snippet that exports the
// interposer env vars. We emit VETO_PATH so the interposer can find
// the veto binary even when PATH varies between sessions.
func renderPreloadEnvBlock(libPath, vetoPath string) string {
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	var b strings.Builder
	b.WriteString(preloadMarkerStart + "\n")
	fmt.Fprintf(&b, "export %s=%q\n", envVar, libPath)
	fmt.Fprintf(&b, "export VETO_PATH=%q\n", vetoPath)
	b.WriteString(preloadMarkerEnd + "\n")
	return b.String()
}

// upsertShellRCBlock writes the managed env block into rcPath, replacing
// any previous managed block. Anything outside the marker bounds is
// preserved verbatim, including comments and trailing newlines. Atomic
// via a sibling tmp + rename.
func upsertShellRCBlock(rcPath, block string) error {
	existing, err := os.ReadFile(rcPath)
	if err != nil && !os.IsNotExist(err) {
		return errors.With(err, "read rc")
	}
	rewritten := upsertManagedBlock(string(existing), block)
	return atomicWrite(rcPath, []byte(rewritten), 0o644)
}

// upsertManagedBlock replaces the (start..end) section in src with the
// provided block, or appends the block (preceded by one blank line) if
// no managed section exists yet.
func upsertManagedBlock(src, block string) string {
	return upsertManagedBlockWithMarkers(src, block, preloadMarkerStart, preloadMarkerEnd)
}

// upsertManagedBlockWithMarkers replaces the (start..end) section in src with
// the provided block, or appends the block when the marker pair is absent.
func upsertManagedBlockWithMarkers(src, block, startMarker, endMarker string) string {
	startIdx := strings.Index(src, startMarker)
	endIdx := strings.Index(src, endMarker)
	if startIdx >= 0 && endIdx > startIdx {
		// Replace the entire span including the end-marker line and its newline.
		after := endIdx + len(endMarker)
		if after < len(src) && src[after] == '\n' {
			after++
		}
		return src[:startIdx] + block + src[after:]
	}
	// No managed block yet. Append, separating with a blank line if the
	// file isn't empty.
	if src == "" {
		return block
	}
	sep := ""
	if !strings.HasSuffix(src, "\n") {
		sep = "\n"
	}
	return src + sep + "\n" + block
}

// removeShellRCBlock strips the managed block from rcPath. Returns
// (changed, error). No file write occurs when nothing was matched.
func removeShellRCBlock(rcPath string) (bool, error) {
	return removeShellRCBlockWithMarkers(rcPath, preloadMarkerStart, preloadMarkerEnd)
}

// removeShellRCBlockWithMarkers strips a managed block from rcPath. Returns
// (changed, error). No file write occurs when nothing was matched.
func removeShellRCBlockWithMarkers(rcPath, startMarker, endMarker string) (bool, error) {
	existing, err := os.ReadFile(rcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.With(err, "read rc")
	}
	src := string(existing)
	startIdx := strings.Index(src, startMarker)
	endIdx := strings.Index(src, endMarker)
	if startIdx < 0 || endIdx <= startIdx {
		return false, nil
	}
	after := endIdx + len(endMarker)
	if after < len(src) && src[after] == '\n' {
		after++
	}
	// Trim any leading-blank-line separator we inserted on append.
	if startIdx > 0 && src[startIdx-1] == '\n' && startIdx >= 2 && src[startIdx-2] == '\n' {
		startIdx--
	}
	rewritten := src[:startIdx] + src[after:]
	if err := atomicWrite(rcPath, []byte(rewritten), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// managedBlockStatus reports whether rcPath contains a complete marker pair.
func managedBlockStatus(rcPath, startMarker, endMarker string) (exists bool, malformed bool, err error) {
	data, err := os.ReadFile(rcPath)
	if err != nil {
		return false, false, err
	}
	src := string(data)
	startIdx := strings.Index(src, startMarker)
	endIdx := strings.Index(src, endMarker)
	switch {
	case startIdx >= 0 && endIdx > startIdx:
		return true, false, nil
	case startIdx >= 0 || endIdx >= 0:
		return false, true, nil
	default:
		return false, false, nil
	}
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.With(err, "mkdir parent")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return errors.With(err, "tmpfile")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.With(err, "write tmpfile")
	}
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close tmpfile")
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return errors.With(err, "chmod tmpfile")
	}
	return os.Rename(tmpPath, path)
}

// autoDetectShellRC picks the shell rc that the user's $SHELL is most
// likely to read at start-up. We bias toward the interactive-shell rc
// (.zshrc / .bashrc) rather than the login rc (.zprofile / .bash_profile)
// because non-interactive agent shells often skip the login rc.
func autoDetectShellRC() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.With(err, "resolve home")
	}
	sh := os.Getenv("SHELL")
	switch {
	case strings.HasSuffix(sh, "/zsh"):
		return filepath.Join(home, ".zshrc"), nil
	case strings.HasSuffix(sh, "/bash"):
		return filepath.Join(home, ".bashrc"), nil
	case strings.HasSuffix(sh, "/fish"):
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	}
	return "", errors.WithNew("could not detect shell rc from $SHELL").Set("shell", sh)
}

// printSIPCaveat surfaces the macOS-specific gotcha so colleagues
// configuring the interposer know what won't be covered AND what
// closes most of the gap. Linux users see nothing — LD_PRELOAD has
// fewer gotchas.
func printSIPCaveat(w io.Writer) {
	if runtime.GOOS != "darwin" {
		return
	}
	fmt.Fprintln(w, "macOS note: DYLD_INSERT_LIBRARIES is stripped by dyld for SIP-protected")
	fmt.Fprintln(w, "binaries (/usr/bin, /usr/sbin, /System/...). Layer 3 will not load")
	fmt.Fprintln(w, "into those processes.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Layer 4 (`veto install-wrappers`) closes most of the gap: it replaces")
	fmt.Fprintln(w, "the actual binary bytes at homebrew/mise install paths, so the gate fires")
	fmt.Fprintln(w, "even when DYLD_INSERT_LIBRARIES is stripped or never inherited (e.g. a")
	fmt.Fprintln(w, "Python subprocess.run with shell=False and env={}). SIP-protected binaries")
	fmt.Fprintln(w, "themselves remain out of reach — those dirs are read-only by macOS design.")
}
