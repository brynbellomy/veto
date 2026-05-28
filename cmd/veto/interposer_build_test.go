package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestBuildInterposerFromEmbedProducesArtifact is the end-to-end gate for
// the source-free install-all path: extract the embedded C, compile it,
// confirm the .dylib/.so lands in the tempdir, and check the file magic
// so a future regression that writes a 0-byte file or the wrong format
// is caught immediately.
//
// Skipped when:
//   - the platform isn't supported (we only ship darwin/linux flags);
//   - no `cc` is on PATH (CI containers without build-essential, etc.).
//
// The CC probe matches buildInterposerFromEmbed's own probe so the skip
// reason is honest — we never claim "test passed" on a host that can't
// actually exercise the build path.
func TestBuildInterposerFromEmbedProducesArtifact(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("interposer build unsupported on GOOS=%s", runtime.GOOS)
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler on PATH (%s); skipping embed-build test", cc)
	}

	logger := zerolog.Nop()
	artifact, cleanup, err := buildInterposerFromEmbed(logger)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	defer cleanup()

	// File exists and is non-empty.
	info, err := os.Stat(artifact)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	require.Greater(t, info.Size(), int64(0))

	// Correct per-OS extension.
	switch runtime.GOOS {
	case "darwin":
		require.True(t, strings.HasSuffix(artifact, ".dylib"),
			"expected .dylib suffix, got %s", artifact)
	case "linux":
		require.True(t, strings.HasSuffix(artifact, ".so"),
			"expected .so suffix, got %s", artifact)
	}

	// File magic. We only sanity-check the leading bytes — full
	// Mach-O/ELF validation is dyld's job, and assertInterposerArtifact
	// + verifyInterposerLoads cover that in the install path.
	head, err := os.ReadFile(artifact)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(head), 4)
	switch runtime.GOOS {
	case "linux":
		// ELF: 0x7f 'E' 'L' 'F'
		require.Equal(t, []byte{0x7f, 'E', 'L', 'F'}, head[:4],
			"output is not an ELF object")
	case "darwin":
		// On arm64 we build a fat dylib (-arch arm64 -arch arm64e), which
		// has the fat-header magic 0xCAFEBABE / 0xCAFEBABF. On other
		// macOS arches we produce a plain Mach-O (0xFEEDFACE/0xFEEDFACF).
		got := string(head[:4])
		validMagic := map[string]bool{
			// fat magic (32/64-bit, big-endian)
			"\xca\xfe\xba\xbe": true,
			"\xca\xfe\xba\xbf": true,
			// thin Mach-O (32/64-bit, little-endian — modern macOS)
			"\xce\xfa\xed\xfe": true,
			"\xcf\xfa\xed\xfe": true,
		}
		require.True(t, validMagic[got],
			"output magic %x is not a Mach-O / fat-Mach-O", head[:4])
	}
}

// TestBuildInterposerFromEmbedCleansUpTempdir asserts that the cleanup
// callback removes the build tempdir. We grab the tempdir from the
// artifact path (which lives inside it) before calling cleanup, then
// verify the dir is gone afterwards. Catches a regression where the
// cleanup closure captures the wrong path or where we leak tempdirs
// across install-all invocations.
func TestBuildInterposerFromEmbedCleansUpTempdir(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("interposer build unsupported on GOOS=%s", runtime.GOOS)
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler on PATH (%s); skipping embed-build cleanup test", cc)
	}

	logger := zerolog.Nop()
	artifact, cleanup, err := buildInterposerFromEmbed(logger)
	require.NoError(t, err)

	tempDir := filepath.Dir(artifact)
	_, err = os.Stat(tempDir)
	require.NoError(t, err, "tempdir should exist before cleanup")

	cleanup()
	_, err = os.Stat(tempDir)
	require.True(t, os.IsNotExist(err), "tempdir should be removed after cleanup, stat err=%v", err)
}
