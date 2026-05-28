package interposer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSourceFSContainsExpectedFiles guards the embed: if either filename
// goes missing or is renamed, the install-time build path (which extracts
// these files to a tempdir and feeds them to $(CC)) breaks silently —
// dyld would then reject an artifact that was never produced. We assert
// non-empty contents so an accidentally-truncated header is caught too.
//
// The embed FS preserves the on-disk layout under the package directory,
// so the C and header land under "csrc/" — matching where SourceFS roots.
func TestSourceFSContainsExpectedFiles(t *testing.T) {
	c, err := SourceFS.ReadFile("csrc/veto_interpose.c")
	require.NoError(t, err)
	require.NotEmpty(t, c)

	h, err := SourceFS.ReadFile("csrc/pm_names.h")
	require.NoError(t, err)
	require.NotEmpty(t, h)

	// Sanity-check the header guards / generator marker so we catch the
	// case where a future generator change emits an empty stub.
	require.Contains(t, string(h), "VETO_PM_NAMES_H",
		"pm_names.h is missing its header guard — generator likely broken")
	require.True(t,
		strings.Contains(string(c), "#include \"pm_names.h\""),
		"veto_interpose.c no longer includes pm_names.h; embed pair is incoherent")
}
