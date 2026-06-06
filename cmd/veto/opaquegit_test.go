package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func TestFilterRegistryInstalls(t *testing.T) {
	in := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "serde", Version: "1.0.0"}},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "rootcrate", Version: "0.1.0"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evilgit", Version: "0.0.1"}, OpaqueRemote: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "", Version: ""}},
	}
	out := filterRegistryInstalls(in)
	require.Len(t, out, 1)
	require.Equal(t, "serde", out[0].Ref.Name)
}

// gitRun runs git in dir and fails the test on error.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

// newTestCrateRepo creates a local git repo with a minimal Cargo.toml (no
// committed Cargo.lock) and returns its path (usable as a clone URL) and its
// HEAD commit SHA.
func newTestCrateRepo(t *testing.T) (repoPath, headSHA string) {
	t.Helper()
	repoPath = t.TempDir()
	gitRun(t, repoPath, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "Cargo.toml"),
		[]byte("[package]\nname = \"rootcrate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), 0o644))
	gitRun(t, repoPath, "add", ".")
	gitRun(t, repoPath, "commit", "-q", "-m", "init")
	headSHA = gitRun(t, repoPath, "rev-parse", "HEAD")
	return repoPath, headSHA
}

func TestCloneAndCaptureCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo, sha := newTestCrateRepo(t)

	plan := packagemanager.OpaqueRemoteResolvePlan{GitURL: repo}
	src, got, cleanup, err := cloneAndCaptureCommit(context.Background(), "git", plan)
	defer cleanup()
	require.NoError(t, err)
	require.Equal(t, sha, got)

	_, statErr := os.Stat(filepath.Join(src, "Cargo.toml"))
	require.NoError(t, statErr, "cloned working tree should contain Cargo.toml")
}
