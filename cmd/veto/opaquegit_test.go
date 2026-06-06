package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
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

// writeStubCargo writes a fake `cargo` executable that, for any args, writes a
// fixed Cargo.lock into its working directory (the clone dir). Returns the
// stub's path. Skips on Windows (shell-script stub).
func writeStubCargo(t *testing.T, lockBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub cargo uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cargo")
	script := "#!/bin/sh\ncat > Cargo.lock <<'LOCK'\n" + lockBody + "\nLOCK\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

const stubLock = `[[package]]
name = "rootcrate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "evilgit"
version = "0.0.1"
source = "git+https://example.com/evil#deadbeef"`

func TestResolveOpaqueGitInstalls(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo, sha := newTestCrateRepo(t)

	deps := opaqueGitDeps{
		gitPath:   "git",
		cargoPath: writeStubCargo(t, stubLock),
		expander:  newCompoundExpander(),
	}
	plan := packagemanager.OpaqueRemoteResolvePlan{
		GitURL:       repo,
		ResolveArgs:  []string{"generate-lockfile"},
		ManifestRefs: []packagemanager.ManifestRef{{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock}},
	}

	installs, gotSHA, err := resolveOpaqueGitInstalls(context.Background(), zerolog.Nop(), deps, plan)
	require.NoError(t, err)
	require.Equal(t, sha, gotSHA)
	require.Len(t, installs, 1, "only the registry dep survives the filter")
	require.Equal(t, "serde", installs[0].Ref.Name)
	require.Equal(t, "1.0.200", installs[0].Ref.Version)
}

func TestResolveOpaqueGitInstallsFailsClosedOnResolveError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if runtime.GOOS == "windows" {
		t.Skip("stub cargo uses a POSIX shell script")
	}
	repo, _ := newTestCrateRepo(t)

	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "cargo")
	require.NoError(t, os.WriteFile(stub, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	deps := opaqueGitDeps{gitPath: "git", cargoPath: stub, expander: newCompoundExpander()}
	plan := packagemanager.OpaqueRemoteResolvePlan{
		GitURL:       repo,
		ResolveArgs:  []string{"generate-lockfile"},
		ManifestRefs: []packagemanager.ManifestRef{{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock}},
	}
	_, _, err := resolveOpaqueGitInstalls(context.Background(), zerolog.Nop(), deps, plan)
	require.Error(t, err)
}
