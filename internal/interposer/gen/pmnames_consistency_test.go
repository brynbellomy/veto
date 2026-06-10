package gen

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPMNamesHeaderUpToDate guards the M1 invariant: pm_names.h on
// disk must equal the output of `go generate`. If a contributor adds a
// PM to internal/packagemanager/pmlist but forgets to rerun
// `go generate` (or `make interposer`, which does it for them), this
// test fails loudly — closing the drift hazard that originally
// motivated the canonical-list refactor.
//
// We run the generator into a temp file and diff against the
// checked-in header. The Makefile's `interposer` target also
// regenerates before compiling, so even a forgotten test failure
// can't produce a stale dylib in `make install`.
func TestPMNamesHeaderUpToDate(t *testing.T) {
	// Resolve the repo root from this test's working directory.
	// internal/interposer/gen → ../../.. is the repo root.
	pkgDir, err := os.Getwd()
	require.NoError(t, err)
	repoRoot := filepath.Clean(filepath.Join(pkgDir, "..", "..", ".."))
	headerOnDisk := filepath.Join(repoRoot, "internal", "interposer", "csrc", "pm_names.h")

	tmpDir := t.TempDir()
	tmpHeader := filepath.Join(tmpDir, "pm_names.h")

	cmd := exec.Command("go", "run", "./internal/interposer/cmd/genpmlist", "-o", tmpHeader)
	cmd.Dir = repoRoot
	out, runErr := cmd.CombinedOutput()
	require.NoError(t, runErr, "go run genpmlist failed: %s", string(out))

	want, err := os.ReadFile(tmpHeader)
	require.NoError(t, err)

	got, err := os.ReadFile(headerOnDisk)
	require.NoError(t, err, "pm_names.h not found at %s; run `go generate ./internal/interposer/gen/...`", headerOnDisk)

	if !bytes.Equal(got, want) {
		t.Fatalf("pm_names.h is stale; run `go generate ./internal/interposer/gen/...` (or `make interposer`).\n\n--- on disk ---\n%s\n--- generated ---\n%s\n",
			string(got), string(want))
	}
}
