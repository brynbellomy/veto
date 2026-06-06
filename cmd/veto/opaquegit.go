package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// filterRegistryInstalls keeps only intel-eligible (registry) installs from a
// clone-scan's expanded lockfile, dropping LocalPath and OpaqueRemote nodes —
// the git root crate and any nested git dependencies. Those are the code the
// user explicitly chose to install; per the "registry deps only" scope they
// are accepted without a name lookup, and the registry crates they pull are
// what gets gated.
func filterRegistryInstalls(in []packagemanager.Install) []packagemanager.Install {
	out := make([]packagemanager.Install, 0, len(in))
	for _, ins := range in {
		if ins.LocalPath || ins.OpaqueRemote || ins.Ref.Name == "" {
			continue
		}
		out = append(out, ins)
	}
	return out
}

// cloneAndCaptureCommit clones plan.GitURL into a fresh temp dir, checks out
// the requested ref, and returns the clone's working-tree dir, the exact HEAD
// commit SHA that was checked out, and a cleanup func the caller MUST invoke.
// cleanup is always non-nil. `git clone` runs no remote hooks and we never
// recurse submodules, so the clone itself executes no project code.
func cloneAndCaptureCommit(ctx context.Context, gitPath string, plan packagemanager.OpaqueRemoteResolvePlan) (srcDir, sha string, cleanup func(), err error) {
	root, err := os.MkdirTemp("", "veto-cargo-git-*")
	if err != nil {
		return "", "", func() {}, errors.With(err, "create clone workdir")
	}
	cleanup = func() { _ = os.RemoveAll(root) }
	src := filepath.Join(root, "src")

	var cloneArgs []string
	switch {
	case plan.RefIsRevision:
		// A bare commit-ish is not reachable by --branch; full-clone then check out.
		cloneArgs = []string{"clone", plan.GitURL, src}
	case plan.Ref != "":
		cloneArgs = []string{"clone", "--depth", "1", "--branch", plan.Ref, plan.GitURL, src}
	default:
		cloneArgs = []string{"clone", "--depth", "1", plan.GitURL, src}
	}
	if err := runGitHardened(ctx, gitPath, "", cloneArgs); err != nil {
		cleanup()
		return "", "", func() {}, errors.With(err, "git clone").Set("url", plan.GitURL)
	}

	if plan.RefIsRevision {
		if err := runGitHardened(ctx, gitPath, src, []string{"checkout", "--detach", plan.Ref}); err != nil {
			cleanup()
			return "", "", func() {}, errors.With(err, "git checkout revision").Set("rev", plan.Ref)
		}
	}

	out, err := runGitOutput(ctx, gitPath, src, []string{"rev-parse", "HEAD"})
	if err != nil {
		cleanup()
		return "", "", func() {}, errors.With(err, "git rev-parse HEAD")
	}
	sha = strings.TrimSpace(out)
	if sha == "" {
		cleanup()
		return "", "", func() {}, errors.WithNew("git rev-parse produced an empty commit")
	}
	return src, sha, cleanup, nil
}

// gitHardenedEnv returns a sanitized environment for git invocations that fails
// fast on credential prompts instead of hanging on a private-repo auth challenge.
func gitHardenedEnv() []string {
	return append(sanitizedEnv(os.Environ()), "GIT_TERMINAL_PROMPT=0")
}

func runGitHardened(ctx context.Context, gitPath, dir string, args []string) error {
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Dir = dir
	cmd.Env = gitHardenedEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.With(err, "git command failed").Set("output", truncateForError(string(out), 800))
	}
	return nil
}

func runGitOutput(ctx context.Context, gitPath, dir string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, gitPath, args...)
	cmd.Dir = dir
	cmd.Env = gitHardenedEnv()
	out, err := cmd.Output()
	return string(out), err
}

// opaqueResolveTimeout bounds the clone + resolve of an opaque git crate. The
// clone touches the network and the resolve touches the registry index, but
// neither compiles the crate nor runs build scripts.
const opaqueResolveTimeout = 2 * time.Minute

// opaqueGitDeps bundles the externalities of an opaque-git resolution so the
// orchestration logic is testable with an injected stub cargo. The clone +
// resolve deadline is carried by the context the caller passes in.
type opaqueGitDeps struct {
	gitPath   string
	cargoPath string
	expander  gate.ManifestExpander
}

// resolveOpaqueGitInstalls clones the git crate, regenerates or validates its
// lockfile with the real cargo (without compiling it), expands the lockfile,
// and returns the registry-eligible installs plus the exact commit SHA that was
// scanned. Any failure is returned as an error so the caller can fail closed.
func resolveOpaqueGitInstalls(ctx context.Context, logger zerolog.Logger, deps opaqueGitDeps, plan packagemanager.OpaqueRemoteResolvePlan) ([]packagemanager.Install, string, error) {
	src, sha, cleanup, err := cloneAndCaptureCommit(ctx, deps.gitPath, plan)
	defer cleanup()
	if err != nil {
		return nil, "", err
	}

	cmd := exec.CommandContext(ctx, deps.cargoPath, plan.ResolveArgs...)
	cmd.Dir = src
	cmd.Env = sanitizedEnv(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Debug().Str("output", truncateForError(string(out), 800)).Msg("cargo resolve output")
		return nil, "", errors.With(err, "cargo resolve for opaque git crate failed").Set("args", strings.Join(plan.ResolveArgs, " "))
	}
	if ctx.Err() != nil {
		return nil, "", errors.With(ctx.Err(), "cargo resolve timed out")
	}

	var installs []packagemanager.Install
	foundLock := false
	for _, ref := range plan.ManifestRefs {
		ref.Path = filepath.Join(src, ref.Path)
		if _, statErr := os.Stat(ref.Path); statErr != nil {
			continue
		}
		foundLock = true
		extra, err := deps.expander.Expand(ref)
		if err != nil {
			return nil, "", errors.With(err, "expand resolved lockfile").Set("path", ref.Path)
		}
		installs = append(installs, extra...)
	}
	if !foundLock {
		return nil, "", errors.WithNew("cargo resolve produced no lockfile to scan")
	}

	return filterRegistryInstalls(installs), sha, nil
}

// opaqueGitResolution is the outcome the gate orchestrator consumes.
type opaqueGitResolution struct {
	Installs []packagemanager.Install // installs to gate (opaque entries replaced by registry deps)
	ExecArgs []string                 // argv to exec on the allow path, pinned to Commit
	Commit   string                   // the scanned commit SHA
	Scanned  int                      // number of registry deps scanned (for the success note)
	Applied  bool                     // whether a clone-scan ran
}

// applyOpaqueGitResolution clones+scans opaque git installs the package manager
// can resolve, replaces them with their registry deps, and pins the argv to the
// scanned commit. When the PM is not an OpaqueRemoteResolver, or no install is
// an unresolvable git spec, it returns Applied=false with the inputs unchanged.
// A non-nil error means the caller must fail closed.
func applyOpaqueGitResolution(
	ctx context.Context,
	logger zerolog.Logger,
	cfg config,
	pm packagemanager.PackageManager,
	pmArgs []string,
	installs []packagemanager.Install,
	expander gate.ManifestExpander,
) (opaqueGitResolution, error) {
	resolver, ok := pm.(packagemanager.OpaqueRemoteResolver)
	if !ok || !hasOpaqueInstall(installs) {
		return opaqueGitResolution{Installs: installs, ExecArgs: pmArgs}, nil
	}
	plan, ok := resolver.OpaqueRemoteResolve(pmArgs)
	if !ok {
		// PM cannot resolve this opaque spec (e.g. a tarball URL); leave it for
		// the gate to refuse as before.
		return opaqueGitResolution{Installs: installs, ExecArgs: pmArgs}, nil
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return opaqueGitResolution{}, errors.With(err, "git is required to scan a git crate but was not found on PATH")
	}
	cargoPath, err := findRealBinary(pm.Name(), wrapperRegisteredFunc(cfg))
	if err != nil {
		return opaqueGitResolution{}, errors.With(err, "locate real cargo for opaque git resolve")
	}

	rctx, cancel := context.WithTimeout(ctx, opaqueResolveTimeout)
	defer cancel()
	registry, sha, err := resolveOpaqueGitInstalls(rctx, logger, opaqueGitDeps{
		gitPath:   gitPath,
		cargoPath: cargoPath,
		expander:  expander,
	}, plan)
	if err != nil {
		return opaqueGitResolution{}, err
	}

	// Replace every opaque install with the scanned registry deps; keep any
	// non-opaque installs the PM also parsed (e.g. cargo add's project refs).
	kept := make([]packagemanager.Install, 0, len(installs)+len(registry))
	for _, ins := range installs {
		if !ins.OpaqueRemote {
			kept = append(kept, ins)
		}
	}
	kept = append(kept, registry...)

	return opaqueGitResolution{
		Installs: kept,
		ExecArgs: resolver.PinResolvedRevision(pmArgs, sha),
		Commit:   sha,
		Scanned:  len(registry),
		Applied:  true,
	}, nil
}

// hasOpaqueInstall reports whether any install is an opaque remote spec.
func hasOpaqueInstall(installs []packagemanager.Install) bool {
	for _, ins := range installs {
		if ins.OpaqueRemote {
			return true
		}
	}
	return false
}
