package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
)

// evaluateAgainstFakeStore runs the same gate.Evaluate call the verdict
// path uses, against fixture intel, and maps it through verdictFromDecision
// — the exact code path runVerdict consumes after gateInputsFor.
func evaluateAgainstFakeStore(t *testing.T, reports []intel.MalwareReport, pmArgs []string) commandVerdict {
	t.Helper()
	pm := npm.New()
	installs := pm.ParseInstalls(pmArgs)
	manifestRefs := pm.ManifestRefs(pmArgs)
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = newCompoundExpander()
	d := gate.New(storeWithFakeReports(t, reports), policy, zerolog.Nop()).Evaluate(installs, manifestRefs...)
	return verdictFromDecision("npm", pmArgs, &d)
}

func TestVerdictBenignCommandAllows(t *testing.T) {
	v := evaluateAgainstFakeStore(t, nil, []string{"install", "lodash"})

	require.Equal(t, string(gate.OutcomeAllow), v.Decision)
	require.Equal(t, "npm", v.PM)
	require.Equal(t, []string{"install", "lodash"}, v.Args)
	require.Equal(t, exitOK, codeForOutcome(gate.Outcome(v.Decision)))
	require.NotEmpty(t, v.Installs)
	for _, ins := range v.Installs {
		require.False(t, ins.Flagged, "benign package must not be flagged: %s", ins.Name)
		require.Empty(t, ins.Sources)
	}
}

func TestVerdictMaliciousCommandRefuses(t *testing.T) {
	reports := []intel.MalwareReport{
		{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "chai-as-upgraded"},
			SourceID:   "aikido",
			Reason:     "MALWARE",
			AdvisoryID: "MAL-2024-0001",
		},
	}
	v := evaluateAgainstFakeStore(t, reports, []string{"install", "chai-as-upgraded"})

	require.Equal(t, string(gate.OutcomeRefuse), v.Decision)
	require.Equal(t, exitRefused, codeForOutcome(gate.Outcome(v.Decision)))
	require.Contains(t, v.Reason, "chai-as-upgraded")
	require.Contains(t, v.Reason, "aikido")

	require.Len(t, v.Installs, 1)
	ins := v.Installs[0]
	require.True(t, ins.Flagged)
	require.Equal(t, "chai-as-upgraded", ins.Name)
	require.Equal(t, "npm", ins.Ecosystem)
	require.Equal(t, []string{"aikido"}, ins.Sources)
	require.Len(t, ins.Reasons, 1)
	require.Contains(t, ins.Reasons[0], "MAL-2024-0001")
	require.Contains(t, ins.Reasons[0], "MALWARE")
}

func TestVerdictMixedInstallsRefusesOnTheFlaggedOne(t *testing.T) {
	reports := []intel.MalwareReport{
		{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg", Version: "9.9.9"},
			SourceID:   "test-feed",
			Reason:     "known malicious",
		},
	}
	v := evaluateAgainstFakeStore(t, reports, []string{"install", "lodash", "evil-pkg@9.9.9"})

	require.Equal(t, string(gate.OutcomeRefuse), v.Decision)
	var flagged, clean int
	for _, ins := range v.Installs {
		if ins.Flagged {
			flagged++
			require.Equal(t, "evil-pkg", ins.Name)
		} else {
			clean++
		}
	}
	require.Equal(t, 1, flagged)
	require.GreaterOrEqual(t, clean, 1)
}

func TestVerdictOpaqueRemoteSpecRefusesUnconditionally(t *testing.T) {
	// URL/git/tarball specs bypass the registry name lookup; the gate
	// refuses them under any intel state, even an empty store.
	v := evaluateAgainstFakeStore(t, nil, []string{"install", "https://evil.com/pkg.tgz"})

	require.Equal(t, string(gate.OutcomeRefuse), v.Decision)
	require.Equal(t, exitRefused, codeForOutcome(gate.Outcome(v.Decision)))
	require.Len(t, v.Installs, 1)
	require.True(t, v.Installs[0].Flagged)
	require.Equal(t, []string{"veto-policy"}, v.Installs[0].Sources)
	require.Contains(t, v.Installs[0].Reasons[0], "opaque-spec install refused")
}

func TestVerdictNonInstallCommandPassesThrough(t *testing.T) {
	// `npm view lodash` neither installs nor executes project code:
	// ParseInstalls returns nil, ManifestRefs returns nil, and npm's
	// ProjectPreflight does not claim it — so the gate layer is never
	// consulted and veto passes the command through.
	pm := npm.New()
	args := []string{"view", "lodash"}
	require.Nil(t, pm.ParseInstalls(args))
	require.Nil(t, pm.ManifestRefs(args))
	_, claims := pm.ProjectPreflight(args)
	require.False(t, claims)

	// The verdict path maps this to OutcomePassThrough without a store.
	v := commandVerdict{
		PM:       "npm",
		Args:     args,
		Decision: string(gate.OutcomePassThrough),
		Reason:   "not an install command; veto would pass it through",
	}
	require.Equal(t, exitOK, codeForOutcome(gate.Outcome(v.Decision)))
	require.Empty(t, v.Installs)
}

func TestVerdictAbortMapsToExitInternal(t *testing.T) {
	d := gate.Decision{Outcome: gate.OutcomeAbort, Errors: []error{errors.New("boom")}}
	v := verdictFromDecision("npm", []string{"install"}, &d)

	require.Equal(t, string(gate.OutcomeAbort), v.Decision)
	require.Equal(t, exitInternal, codeForOutcome(gate.Outcome(v.Decision)))
	require.Len(t, v.Errors, 1)
	require.NotEmpty(t, v.Reason)
}

// TestVerdictScopeExcludesEnforcementOnlyLayers pins the documented scope
// of the verdict path: it evaluates the intel+policy gate over argv and
// on-disk manifests, and must NOT acquire the enforcement-only layers
// (which execute commands or fetch beyond the intel cache — wiring them in
// would silently break this mode's "executes nothing" contract). The check
// parses verdict.go with go/ast and looks for any IDENTIFIER reference —
// call, var, or assignment — outside comments, so the scope documentation
// may name the layers while any real use trips the test.
func TestVerdictScopeExcludesEnforcementOnlyLayers(t *testing.T) {
	enforcementOnly := []string{
		"runResolverPreScanIfAvailable",
		"runResolverPreScan",
		"gypTarballPreflight",
		"runGypPreflightIfNpmFamily",
		"pthWheelPreflight",
		"runPthPreflightIfPythonFamily",
		"applyOpaqueGitResolution",
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "verdict.go", nil, 0)
	require.NoError(t, err)
	used := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			used[id.Name] = true
		}
		return true
	})
	for _, sym := range enforcementOnly {
		require.False(t, used[sym],
			"verdict path references enforcement-only layer %s (see scope comment in evaluateCommandLine)", sym)
	}

	// And the enforcement path must still CALL them — if runGate loses
	// one, the verdict scope comment ("enforcement runs these after the
	// gate") becomes false in the other direction.
	gateSrc, err := os.ReadFile("main.go")
	require.NoError(t, err)
	for _, sym := range enforcementOnly {
		require.Contains(t, string(gateSrc), sym+"(",
			"enforcement path lost layer %s; the verdict scope comment now misdescribes it", sym)
	}
}

func TestCodeForOutcomeContract(t *testing.T) {
	require.Equal(t, exitOK, codeForOutcome(gate.OutcomeAllow))
	require.Equal(t, exitOK, codeForOutcome(gate.OutcomePassThrough))
	require.Equal(t, exitRefused, codeForOutcome(gate.OutcomeRefuse))
	require.Equal(t, exitInternal, codeForOutcome(gate.OutcomeAbort))
}

func TestVerdictReasonDescribesEachOutcome(t *testing.T) {
	require.NotEmpty(t, verdictReason(&gate.Decision{Outcome: gate.OutcomeAllow}))
	require.NotEmpty(t, verdictReason(&gate.Decision{Outcome: gate.OutcomePassThrough}))
	require.NotEmpty(t, verdictReason(&gate.Decision{Outcome: gate.OutcomeAbort}))

	refuse := gate.Decision{
		Outcome: gate.OutcomeRefuse,
		Verdicts: []intel.Verdict{{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil"},
			Reports: []intel.MalwareReport{{SourceID: "aikido"}},
		}},
	}
	require.Contains(t, verdictReason(&refuse), "evil")
	require.Contains(t, verdictReason(&refuse), "aikido")
}

// TestRunVerdictUsageErrors asserts the CLI contract for malformed
// invocations: missing command line and unknown --format values are usage
// errors (exit 64), not internal failures.
func TestRunVerdictUsageErrors(t *testing.T) {
	cfg := config{CacheDir: t.TempDir(), Sources: []string{}}

	require.Equal(t, exitUsage, runVerdict(zerolog.Nop(), cfg, nil))
	require.Equal(t, exitUsage, runVerdict(zerolog.Nop(), cfg, []string{"--format", "yaml", "npm", "install", "lodash"}))
	require.Equal(t, exitUsage, runVerdict(zerolog.Nop(), cfg, []string{"--format"}))
}
