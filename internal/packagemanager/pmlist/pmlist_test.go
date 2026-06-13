package pmlist

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWrappedIsSubsetOfShimmed pins the documented invariant: every
// wrapped binary is also shimmed. Wrapping a PM that isn't shimmed
// would be incoherent — main()'s dispatch wouldn't recognise the
// resulting symlink as a shim.
func TestWrappedIsSubsetOfShimmed(t *testing.T) {
	for _, w := range Wrapped {
		require.True(t, IsShimmed(w),
			"%q is in Wrapped but not in Shimmed; install-wrappers would create a symlink shim-dispatch cannot route",
			w)
	}
}

// TestShimmedIsSubsetOfInterposer pins the documented invariant: every
// shimmed binary is also recognised by the Layer-3 interposer / Layer-1
// hook. If a PM is shimmed but the interposer doesn't classify it,
// `subprocess.run(["/abs/path/<pm>", ...])` from a process with the
// interposer loaded would silently bypass the gate.
func TestShimmedIsSubsetOfInterposer(t *testing.T) {
	for _, s := range Shimmed {
		require.True(t, IsInterposerPM(s),
			"%q is in Shimmed but not in InterposerPMs; Layer 3 / Layer 1 would miss direct spawns of this PM",
			s)
	}
}

// TestMembershipHelpers spot-checks the IsX helpers against the
// expected outcomes for a few representative PMs.
func TestMembershipHelpers(t *testing.T) {
	require.True(t, IsShimmed("npm"))
	require.True(t, IsShimmed("go"))
	require.True(t, IsShimmed("cargo"))
	require.True(t, IsShimmed("python"))
	require.True(t, IsShimmed("python3"))
	require.False(t, IsShimmed("rush"), "rush is NOT shimmed; install-shims does not wire it up")
	require.False(t, IsShimmed("veto"))
	require.False(t, IsShimmed(""))

	require.True(t, IsWrapped("npm"))
	require.True(t, IsWrapped("go"))
	require.True(t, IsWrapped("cargo"))
	// python and python3 ARE wrapped now (closing the uv-venv bypass);
	// see Wrapped's doc comment for the cost rationale.
	require.True(t, IsWrapped("python"))
	require.True(t, IsWrapped("python3"))
	require.False(t, IsWrapped("rush"))

	require.True(t, IsInterposerPM("npm"))
	require.True(t, IsInterposerPM("go"))
	require.True(t, IsInterposerPM("cargo"))
	require.True(t, IsInterposerPM("python"))
	require.True(t, IsInterposerPM("rush"), "rush is recognised by Layer 3 / Layer 1 even though we don't shim it")
	require.True(t, IsInterposerPM("rushx"))
	require.False(t, IsInterposerPM("veto"))
	require.False(t, IsInterposerPM(""))
}

// TestNoDuplicates guards against accidentally appending a name twice
// to one of the canonical slices. The membership sets would silently
// absorb the duplicate; the install-output side would print the name
// twice.
func TestNoDuplicates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slice []string
	}{
		{"Shimmed", Shimmed},
		{"Wrapped", Wrapped},
		{"InterposerPMs", InterposerPMs},
	} {
		seen := map[string]bool{}
		for _, n := range tc.slice {
			require.False(t, seen[n], "%s contains duplicate %q", tc.name, n)
			seen[n] = true
		}
	}
}

// TestVersionedPythonPattern pins the strict regex semantics for the
// dynamic python3.X alias matcher. Versioned aliases must match;
// adjacent shapes that AREN'T conventional python version aliases must
// not (so we don't accidentally hijack `python3-config`, `python4`,
// `python3.X-foo`, etc.).
func TestVersionedPythonPattern(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Conventional versioned aliases — must match.
		{"python3.8", true},
		{"python3.9", true},
		{"python3.10", true},
		{"python3.11", true},
		{"python3.12", true},
		{"python3.13", true},
		// Patch-level alias (uv ships some of these).
		{"python3.11.2", true},
		{"python3.12.0", true},
		// Plain python / python3 — covered by the static slices, NOT
		// the regex (avoids two truths for the same string).
		{"python", false},
		{"python3", false},
		// Adjacent shapes that look pythonic but aren't versioned aliases.
		{"python3a", false},
		{"python3-config", false},
		{"python3.X-foo", false},
		{"python3.10-config", false},
		{"python3.", false},
		{"python3.10.", false},
		// Triple-dotted is not a conventional alias.
		{"python3.10.2.4", false},
		// Wrong major.
		{"python4", false},
		{"python4.0", false},
		{"python2.7", false},
		// Non-python.
		{"npm", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsVersionedPython(tc.name),
				"IsVersionedPython(%q): want %v", tc.name, tc.want)
		})
	}
}

// TestMatchesShim verifies the pattern-aware shim matcher: static-list
// members AND versioned aliases both match; nothing else does.
func TestMatchesShim(t *testing.T) {
	// Static-list members.
	require.True(t, MatchesShim("npm"))
	require.True(t, MatchesShim("python"))
	require.True(t, MatchesShim("python3"))
	// Versioned aliases.
	require.True(t, MatchesShim("python3.10"))
	require.True(t, MatchesShim("python3.11.2"))
	// Non-matches.
	require.False(t, MatchesShim("python3-config"))
	require.False(t, MatchesShim("python3.X-foo"))
	require.False(t, MatchesShim("python4"))
	require.False(t, MatchesShim("rush"), "rush is NOT shimmed even with pattern matching")
	require.False(t, MatchesShim("veto"))
	require.False(t, MatchesShim(""))
}

// TestMatchesWrapped verifies the pattern-aware wrap matcher.
func TestMatchesWrapped(t *testing.T) {
	require.True(t, MatchesWrapped("npm"))
	require.True(t, MatchesWrapped("python"))
	require.True(t, MatchesWrapped("python3"))
	require.True(t, MatchesWrapped("python3.10"))
	require.True(t, MatchesWrapped("python3.11.2"))
	require.False(t, MatchesWrapped("python3-config"))
	require.False(t, MatchesWrapped("python4"))
	require.False(t, MatchesWrapped("rush"))
	require.False(t, MatchesWrapped(""))
}

// TestMatchesInterposer verifies the pattern-aware interposer/hook
// matcher.
func TestMatchesInterposer(t *testing.T) {
	require.True(t, MatchesInterposer("npm"))
	require.True(t, MatchesInterposer("rush"))
	require.True(t, MatchesInterposer("python"))
	require.True(t, MatchesInterposer("python3"))
	require.True(t, MatchesInterposer("python3.10"))
	require.True(t, MatchesInterposer("python3.11.2"))
	require.False(t, MatchesInterposer("python3-config"))
	require.False(t, MatchesInterposer("python4"))
	require.False(t, MatchesInterposer("veto"))
	require.False(t, MatchesInterposer(""))
}
