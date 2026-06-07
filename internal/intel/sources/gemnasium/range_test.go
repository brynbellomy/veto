package gemnasium

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestTranslateAffectedRange is the table-driven core of the gemnasium feed:
// every affected_range shape we claim to support has a row here, and every
// shape we deliberately refuse (strict `>` lower bound, caret/tilde sugar)
// asserts Skipped without emitting a guessed interval.
func TestTranslateAffectedRange(t *testing.T) {
	cases := []struct {
		name       string
		eco        intel.Ecosystem
		expr       string
		wantRanges []intel.VersionRange
		wantExact  []string
		wantSkip   bool
	}{
		{
			name:       "npm exclusive upper only",
			eco:        intel.EcosystemNPM,
			expr:       "<4.17.12",
			wantRanges: []intel.VersionRange{{Fixed: "4.17.12"}},
		},
		{
			name:       "npm inclusive lower and exclusive upper",
			eco:        intel.EcosystemNPM,
			expr:       ">=1.0.0,<2.0.0",
			wantRanges: []intel.VersionRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
		},
		{
			name: "pypi three OR-alternatives",
			eco:  intel.EcosystemPyPI,
			expr: ">=2.2a1,<2.2.25||>=3.0a1,<3.1.14||>=3.2a1,<3.2.10",
			wantRanges: []intel.VersionRange{
				{Introduced: "2.2a1", Fixed: "2.2.25"},
				{Introduced: "3.0a1", Fixed: "3.1.14"},
				{Introduced: "3.2a1", Fixed: "3.2.10"},
			},
		},
		{
			name:       "go v-prefixed upper bound is normalized",
			eco:        intel.EcosystemGo,
			expr:       "<v1.7.0",
			wantRanges: []intel.VersionRange{{Fixed: "1.7.0"}},
		},
		{
			name:       "cargo bounded interval",
			eco:        intel.EcosystemCrates,
			expr:       ">=0.5.0,<1.0.4",
			wantRanges: []intel.VersionRange{{Introduced: "0.5.0", Fixed: "1.0.4"}},
		},
		{
			name:       "inclusive upper bound maps to LastAffected",
			eco:        intel.EcosystemNPM,
			expr:       "<=1.2.3",
			wantRanges: []intel.VersionRange{{LastAffected: "1.2.3"}},
		},
		{
			name:       "lower bound only is open-ended",
			eco:        intel.EcosystemNPM,
			expr:       ">=2.0.0",
			wantRanges: []intel.VersionRange{{Introduced: "2.0.0"}},
		},
		{
			name:      "exact pin via equals",
			eco:       intel.EcosystemNPM,
			expr:      "=1.4.2",
			wantExact: []string{"1.4.2"},
		},
		{
			name:      "bare version is an exact pin",
			eco:       intel.EcosystemNPM,
			expr:      "1.4.2",
			wantExact: []string{"1.4.2"},
		},
		{
			name:       "empty expression over-blocks as unbounded",
			eco:        intel.EcosystemNPM,
			expr:       "",
			wantRanges: []intel.VersionRange{{Introduced: "0"}},
		},
		{
			name:     "strict greater-than lower bound is dropped, not guessed",
			eco:      intel.EcosystemNPM,
			expr:     ">1.0.0,<2.0.0",
			wantSkip: true,
		},
		{
			name:       "partial OR: keep the clean alternative, drop the strict one",
			eco:        intel.EcosystemNPM,
			expr:       ">1.0.0,<2.0.0||>=3.0.0,<3.5.0",
			wantRanges: []intel.VersionRange{{Introduced: "3.0.0", Fixed: "3.5.0"}},
			wantSkip:   true,
		},
		{
			name:     "caret range sugar is refused",
			eco:      intel.EcosystemNPM,
			expr:     "^1.2.3",
			wantSkip: true,
		},
		{
			name:     "tilde range sugar is refused",
			eco:      intel.EcosystemNPM,
			expr:     "~1.2.3",
			wantSkip: true,
		},
		{
			name:     "contradictory double upper bound is dropped",
			eco:      intel.EcosystemNPM,
			expr:     "<2.0.0,<3.0.0",
			wantSkip: true,
		},
		{
			name:      "mixing exact with a bound is refused",
			eco:       intel.EcosystemNPM,
			expr:      "=1.0.0,<2.0.0",
			wantSkip:  true,
			wantExact: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := translateAffectedRange(c.eco, c.expr)
			require.Equal(t, c.wantRanges, got.Ranges, "ranges")
			require.Equal(t, c.wantExact, got.ExactVersions, "exact versions")
			require.Equal(t, c.wantSkip, got.Skipped, "skipped flag")
		})
	}
}

// TestTranslatedRanges_MembershipSemantics confirms the intervals we emit are
// interpreted by intel.InRange the way a reader of the affected_range would
// expect — the translation is only correct if the downstream comparator
// agrees on the boundaries.
func TestTranslatedRanges_MembershipSemantics(t *testing.T) {
	// npm "<4.17.12": everything below is in range, the fix and above are out.
	res := translateAffectedRange(intel.EcosystemNPM, "<4.17.12")
	require.Len(t, res.Ranges, 1)
	rng := res.Ranges[0]
	require.True(t, intel.InRange(intel.EcosystemNPM, "4.17.11", rng), "version below fix is affected")
	require.False(t, intel.InRange(intel.EcosystemNPM, "4.17.12", rng), "the fixed version is not affected (exclusive upper)")
	require.False(t, intel.InRange(intel.EcosystemNPM, "4.18.0", rng), "above fix is not affected")

	// go "<v1.7.0": the normalized bound must compare against an un-prefixed
	// query version the same way.
	resGo := translateAffectedRange(intel.EcosystemGo, "<v1.7.0")
	require.Len(t, resGo.Ranges, 1)
	rngGo := resGo.Ranges[0]
	require.True(t, intel.InRange(intel.EcosystemGo, "v1.6.0", rngGo), "go version below fix is affected")
	require.False(t, intel.InRange(intel.EcosystemGo, "v1.7.0", rngGo), "go fixed version is not affected")

	// pypi bounded interval with a pre-release lower bound.
	resPy := translateAffectedRange(intel.EcosystemPyPI, ">=2.2a1,<2.2.25")
	require.Len(t, resPy.Ranges, 1)
	rngPy := resPy.Ranges[0]
	require.True(t, intel.InRange(intel.EcosystemPyPI, "2.2.10", rngPy), "version inside interval is affected")
	require.False(t, intel.InRange(intel.EcosystemPyPI, "2.2.25", rngPy), "the fixed version is not affected")
	require.False(t, intel.InRange(intel.EcosystemPyPI, "2.1.0", rngPy), "version below introduced is not affected")
}

// TestSplitComparator exercises the operator tokenizer directly so each
// operator form (and the rejections) is pinned independently of the higher
// level interval logic.
func TestSplitComparator(t *testing.T) {
	cases := []struct {
		raw     string
		wantOp  comparatorOp
		wantVer string
		wantOK  bool
	}{
		{">=1.0.0", opGE, "1.0.0", true},
		{"<=1.0.0", opLE, "1.0.0", true},
		{">1.0.0", opGT, "1.0.0", true},
		{"<1.0.0", opLT, "1.0.0", true},
		{"==1.0.0", opEQ, "1.0.0", true},
		{"=1.0.0", opEQ, "1.0.0", true},
		{"1.0.0", opEQ, "1.0.0", true},
		{"  >= 1.0.0 ", opGE, "1.0.0", true},
		{"", opNone, "", false},
		{">=", opGE, "", false},
		{"^1.0.0", opNone, "", false},
		{"~1.0.0", opNone, "", false},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			op, ver, ok := splitComparator(c.raw)
			require.Equal(t, c.wantOK, ok)
			if !ok {
				return
			}
			require.Equal(t, c.wantOp, op)
			require.Equal(t, c.wantVer, ver)
		})
	}
}
