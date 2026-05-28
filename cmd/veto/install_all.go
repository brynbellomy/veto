package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

type installAllOpts struct {
	libPath      string
	shellRC      string
	autoRC       bool
	force        bool
	skipInterpos bool
	skipWrappers bool
}

// installAllStep is one named subcommand executed by install-all. Each
// step closes over its own arg-building logic; the slice it lives in is
// composed by buildInstallAllSteps so callers (including tests) can
// inspect the composition without running anything.
type installAllStep struct {
	name string
	run  func() int
	// kind classifies the step for exit-code routing.
	// - "layer": failure surfaces as exitInstallAllLayerFail (10).
	// - "wrappers": failure goes through classifyWrappersResult to
	//   distinguish needs-root (20) from genuine failure (30).
	kind string
}

const (
	installAllStepKindLayer    = "layer"
	installAllStepKindWrappers = "wrappers"
)

// runInstallAll installs every veto protection layer in one guided command.
//
// Exit-code contract (see main.go for the constants):
//   - 0  every requested step succeeded.
//   - 10 a user-scoped layer (shims/shell/hook/preload/intel/doctor) failed.
//   - 20 the wrappers step couldn't touch one or more candidate dirs
//        because the current user lacks write access (non-root); caller
//        can retry under sudo without re-running layers 1–4.
//   - 30 the wrappers step had write access (or we are root) and still
//        failed — caller has a real bug, not a permissions one.
func runInstallAll(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseInstallAllFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-all: %v\n", err)
		return exitUsage
	}
	if opts.shellRC == "" && !opts.autoRC {
		opts.autoRC = true
	}

	var (
		libPath        string
		libPathCleanup = func() {}
	)
	// Cleanup runs after every step finishes. The interposer-build path
	// returns a tempdir that lives only long enough for runInstallPreload
	// to copy the .dylib/.so into ~/.local/lib; running cleanup any
	// earlier would delete the artifact before the install step reads it.
	defer func() { libPathCleanup() }()
	if !opts.skipInterpos {
		libPath, libPathCleanup, err = ensureInterposerArtifact(logger, opts.libPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto install-all: %v\n", err)
			fmt.Fprintln(os.Stderr, "Pass `--lib /path/to/libveto_interpose.*`, ensure a C compiler is on PATH (CC env var), or use `--skip-interposer`.")
			return exitUsage
		}
	}

	steps := buildInstallAllSteps(opts, cfg, libPath, logger)

	for _, step := range steps {
		fmt.Printf("\n==> veto: %s\n", step.name)
		switch step.kind {
		case installAllStepKindWrappers:
			rc, stats := runInstallWrappersWithStats(logger, cfg, wrapperStepArgs(opts))
			code := classifyWrappersResult(rc, stats, os.Geteuid())
			if code != exitOK {
				fmt.Fprintf(os.Stderr, "veto install-all: step failed: %s\n", step.name)
				return code
			}
		default:
			if rc := step.run(); rc != exitOK {
				fmt.Fprintf(os.Stderr, "veto install-all: step failed: %s\n", step.name)
				return exitInstallAllLayerFail
			}
		}
	}
	return exitOK
}

// buildInstallAllSteps composes the ordered list of steps install-all
// will execute. Pulled out so unit tests can assert composition without
// running anything. The wrappers step closure is still wired here for
// shape consistency, but runInstallAll invokes the stats-bearing helper
// directly so it can route the exit code.
func buildInstallAllSteps(opts installAllOpts, cfg config, libPath string, logger zerolog.Logger) []installAllStep {
	steps := []installAllStep{
		{name: "install shims", kind: installAllStepKindLayer, run: func() int {
			shimArgs := []string{}
			if opts.force {
				shimArgs = append(shimArgs, "--force")
			}
			return runInstallShims(logger, shimArgs)
		}},
		{name: "install shell integration", kind: installAllStepKindLayer, run: func() int {
			return runInstallShell(logger, shellRCArgs(opts))
		}},
		{name: "install Claude Code hook", kind: installAllStepKindLayer, run: func() int {
			return runInstallClaudeHook(logger, nil)
		}},
	}
	if !opts.skipInterpos {
		steps = append(steps, installAllStep{
			name: "install preload interposer",
			kind: installAllStepKindLayer,
			run: func() int {
				preloadArgs := append([]string{"--lib", libPath}, shellRCArgs(opts)...)
				return runInstallPreload(logger, preloadArgs)
			},
		})
	}
	if !opts.skipWrappers {
		steps = append(steps, installAllStep{
			name: "install real-binary wrappers",
			kind: installAllStepKindWrappers,
			run: func() int {
				return runInstallWrappers(logger, cfg, wrapperStepArgs(opts))
			},
		})
	}
	steps = append(steps,
		installAllStep{name: "sync intel", kind: installAllStepKindLayer, run: func() int {
			return runSync(logger, cfg)
		}},
		installAllStep{name: "doctor", kind: installAllStepKindLayer, run: func() int {
			prepareInstallAllDoctorEnv(logger, opts)
			return runDoctor(logger, cfg, nil)
		}},
	)
	return steps
}

// wrapperStepArgs builds the argv install-all hands to the wrappers
// step. Today only --force is forwarded; kept as a helper so both the
// closure (for shape) and the direct call site stay in sync.
func wrapperStepArgs(opts installAllOpts) []string {
	args := []string{}
	if opts.force {
		args = append(args, "--force")
	}
	return args
}

// classifyWrappersResult maps the (rc, stats, euid) tuple returned by
// runInstallWrappersWithStats onto the install-all exit-code contract.
// Pure (no I/O, no globals) so it can be unit tested exhaustively.
//
//   - stats.failed > 0  → genuine wrappers failure (30), regardless of euid.
//                         If we are root and still hit a hard failure, it's
//                         not a permissions problem.
//   - stats.failed == 0 && stats.skippedUnwritable > 0:
//       - euid != 0 → needs-root (20). User can retry under sudo.
//       - euid == 0 → wrappers fail (30). We ARE root and still can't
//                     write; the dir is read-only at the OS level
//                     (SIP-protected, immutable flag, etc.) so
//                     elevation will not help.
//   - rc != 0 (no skipped, no failed) → wrappers fail (30). Defensive:
//     install-wrappers should only return non-zero when stats.failed > 0,
//     but if a future change adds another non-zero path we surface it
//     loudly rather than silently treating it as success.
//   - otherwise → success (0).
func classifyWrappersResult(rc int, stats wrapperStats, euid int) int {
	if stats.failed > 0 {
		return exitInstallAllWrappersFail
	}
	if stats.skippedUnwritable > 0 {
		if euid != 0 {
			return exitInstallAllNeedsRoot
		}
		return exitInstallAllWrappersFail
	}
	if rc != exitOK {
		return exitInstallAllWrappersFail
	}
	return exitOK
}

func parseInstallAllFlags(args []string) (installAllOpts, error) {
	opts := installAllOpts{}
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
		case a == "--force":
			opts.force = true
		case a == "--skip-interposer":
			opts.skipInterpos = true
		case a == "--skip-wrappers":
			opts.skipWrappers = true
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

// ensureInterposerArtifact resolves a path to a usable interposer
// library, building from the embedded C source if none exists on disk.
//
// Returns (path, cleanup, error). cleanup is always safe to call
// exactly once; defer it at the call site. For the explicit-path and
// found-on-disk branches cleanup is a no-op; for the build-from-embed
// branch it removes the tempdir holding the freshly-compiled artifact,
// so the caller MUST consume `path` before allowing cleanup to run.
func ensureInterposerArtifact(logger zerolog.Logger, explicit string) (string, func(), error) {
	noop := func() {}

	path, err := findInterposerArtifact(explicit)
	if err == nil || explicit != "" {
		return path, noop, err
	}

	// No prebuilt artifact on disk and no explicit path. Compile the
	// embedded C source on the fly. This used to require the veto source
	// tree on disk (we'd shell out to `make interposer`); now we ship the
	// .c + .h inside the veto binary via go:embed, so any CWD works.
	fmt.Println("veto: interposer artifact not found; compiling from embedded source...")
	builtPath, cleanup, buildErr := buildInterposerFromEmbed(logger)
	if buildErr != nil {
		logger.Error().Err(buildErr).Msg("build interposer from embed")
		return "", noop, errors.With(buildErr, "build interposer from embedded source")
	}
	fmt.Printf("veto: built interposer at %s\n", builtPath)
	return builtPath, cleanup, nil
}

func shellRCArgs(opts installAllOpts) []string {
	if opts.shellRC != "" {
		return []string{"--shell-rc", opts.shellRC}
	}
	if opts.autoRC {
		return []string{"--shell-rc", "auto"}
	}
	return nil
}

func prepareInstallAllDoctorEnv(logger zerolog.Logger, opts installAllOpts) {
	shimDir, err := defaultShellShimDir()
	if err != nil {
		logger.Warn().Err(err).Msg("resolve shim dir for install-all doctor")
	} else {
		_ = os.Setenv("PATH", pinPathEnv(os.Getenv("PATH"), shimDir))
	}

	if opts.skipInterpos {
		return
	}
	installedLib := installedInterposerPath("")
	if _, err := os.Stat(installedLib); err != nil {
		logger.Warn().Err(err).Str("path", installedLib).Msg("stat installed interposer for install-all doctor")
		return
	}
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	_ = os.Setenv(envVar, installedLib)
	if vetoPath, err := resolveVetoBinary(); err != nil {
		logger.Warn().Err(err).Msg("resolve veto binary for install-all doctor")
	} else {
		_ = os.Setenv("VETO_PATH", vetoPath)
	}
}

func pinPathEnv(pathEnv, shimDir string) string {
	parts := filepath.SplitList(pathEnv)
	out := []string{shimDir}
	for _, p := range parts {
		if p != "" && absEqual(p, shimDir) {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, string(os.PathListSeparator))
}

func findInterposerArtifact(explicit string) (string, error) {
	if explicit != "" {
		if err := assertInterposerArtifact(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}

	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}

	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, name))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), name))
	}
	candidates = append(candidates, installedInterposerPath(""))

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			if err := assertInterposerArtifact(c); err != nil {
				return "", err
			}
			return c, nil
		}
	}
	return "", errors.WithNew("interposer artifact not found").Set("searched", candidates)
}
