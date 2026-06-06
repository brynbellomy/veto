package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

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
