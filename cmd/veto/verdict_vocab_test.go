package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
)

// TestNormalizeOutcomeEnforcesVocabulary pins FIX 6b: the verdict JSON's
// "decision" field carries exactly the four-value vocabulary (allow,
// refuse, passthrough, abort). codeForOutcome already maps unknowns to
// exit 70, but the JSON used to emit the raw outcome string — a consumer
// branching on "decision" would see an unknown token and fall through to
// its default (often allow). Unknown outcomes must normalize to abort so
// the JSON and the exit code can never disagree.
func TestNormalizeOutcomeEnforcesVocabulary(t *testing.T) {
	for _, o := range []gate.Outcome{gate.OutcomeAllow, gate.OutcomeRefuse, gate.OutcomePassThrough, gate.OutcomeAbort} {
		require.Equal(t, string(o), normalizeOutcome(o), "known outcomes pass through verbatim")
		require.Equal(t, codeForOutcome(o), codeForOutcome(gate.Outcome(normalizeOutcome(o))),
			"exit code and JSON decision agree for %s", o)
	}

	unknown := gate.Outcome("nonsense-new-outcome")
	require.Equal(t, string(gate.OutcomeAbort), normalizeOutcome(unknown),
		"an unknown outcome must normalize to abort, not leak into the JSON")
	require.Equal(t, exitInternal, codeForOutcome(unknown))
}
