package main

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
)

// damageTestSource serves a controllable report count for npm so a test
// can collapse the bucket between refreshes — the gutted-manifest damage
// shape — while a filler source keeps the aggregate healthy.
type damageTestSource struct {
	id  string
	npm int
}

func (s *damageTestSource) ID() string { return s.id }

func (s *damageTestSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemNPM {
		return nil, intel.ErrUnsupportedEcosystem
	}
	reports := make([]intel.MalwareReport, s.npm)
	for i := range reports {
		reports[i] = intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      fmt.Sprintf("pkg-%04d", i),
			},
			SourceID: s.id,
			Reason:   "MALWARE",
		}
	}
	return reports, nil
}

// fillerSource keeps the sanity floor satisfied with a large, healthy
// PyPI bucket while the npm bucket under test rots. This mirrors the
// real-world shape the regression lived in: aggregate counts look fine,
// one ecosystem's coverage has silently collapsed.
type fillerSource struct{}

func (fillerSource) ID() string { return "filler-feed" }

func (fillerSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemPyPI {
		return nil, intel.ErrUnsupportedEcosystem
	}
	reports := make([]intel.MalwareReport, 1500)
	for i := range reports {
		reports[i] = intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: intel.EcosystemPyPI,
				Name:      fmt.Sprintf("filler-%04d", i),
			},
			SourceID: "filler-feed",
			Reason:   "MALWARE",
		}
	}
	return reports, nil
}

// withDamagedNpmStore injects a store whose npm bucket is damaged — warm
// refresh records a 1200-report npm baseline, the source collapses to 2
// (the gutted manifest), a COLD refresh rejects the bucket and reports
// it via Damaged() — and evaluates an npm install through the full
// production verdict path (gateInputsFor → damage branch). The healthy
// pypi filler keeps ReportCount() above the sanity floor so the damage
// branch, not the floor, is what runs: the exact multi-source shape the
// regression lived in.
func withDamagedNpmStore(t *testing.T) commandVerdict {
	t.Helper()
	cacheDir := t.TempDir()
	baselinePath := filepath.Join(cacheDir, "intel-baseline.json")

	src := &damageTestSource{id: "damage-test-feed", npm: 1200}
	warm := intel.NewStoreWithBaseline(zerolog.Nop(), baselinePath, src, fillerSource{})
	require.NoError(t, warm.Refresh(context.Background()))
	require.Empty(t, warm.Damaged(), "warm refresh must be healthy")

	src.npm = 2 // the gutted manifest
	cold := intel.NewStoreWithBaseline(zerolog.Nop(), baselinePath, src, fillerSource{})
	require.NoError(t, cold.Refresh(context.Background()))
	require.Len(t, cold.Damaged(), 1, "the collapsed npm bucket must be reported as damaged")
	require.GreaterOrEqual(t, cold.ReportCount(), minHealthyReportCount,
		"fixture sanity: the healthy filler keeps the aggregate above the sanity floor")

	// Inject the damaged cold store into the production path via the
	// buildStoreFn seam; gateInputsFor refreshes it again (same collapsed
	// source → still damaged) and computes damageRefusals.
	orig := buildStoreFn
	buildStoreFn = func(zerolog.Logger, config) (intel.Store, error) { return cold, nil }
	t.Cleanup(func() { buildStoreFn = orig })

	cfg := config{CacheDir: cacheDir, Sources: []string{"damage-test-feed"}}
	v, code := evaluateCommandLine(zerolog.Nop(), cfg, []string{"npm", "install", "pkg-0001"})
	require.Equal(t, exitInternal, code)
	return v
}

// TestVerdictDamagedBucketMustNotAllow is the behavioral pin: a damaged
// intel bucket in an ecosystem the command touches must NOT produce an
// "allow" verdict. The regression: the damage refusal lived only in
// runGate, so `veto test npm install ...` answered {"decision":"allow"}
// over a store whose npm coverage had collapsed — a machine-readable
// allow on the exact state the integrity layer exists to catch.
func TestVerdictDamagedBucketMustNotAllow(t *testing.T) {
	v := withDamagedNpmStore(t)

	require.Equal(t, string(gate.OutcomeAbort), v.Decision,
		"a damaged bucket must abort, never allow")
	require.Equal(t, exitInternal, codeForOutcome(gate.Outcome(v.Decision)))
	require.Len(t, v.Damage, 1, "the damaged bucket must be enumerated in the JSON")
	require.Equal(t, "damage-test-feed", v.Damage[0].Source)
	require.Equal(t, string(intel.EcosystemNPM), v.Damage[0].Eco)
	require.Equal(t, 2, v.Damage[0].Got)
	require.Equal(t, 1200, v.Damage[0].Baseline)
	require.Contains(t, v.Reason, "damage-test-feed")
	require.Contains(t, v.Reason, "npm")
	require.NotEmpty(t, v.Errors, "the damage must also appear in errors for log-scraping consumers")
	require.Empty(t, v.Installs, "no per-install verdicts are meaningful when coverage is damaged")
}

// TestVerdictDamageReasonNamesSourceAndEcosystem pins the JSON contract:
// a machine consumer must be able to surface remediation without parsing
// prose — the reason names the source and the ecosystem.
func TestVerdictDamageReasonNamesSourceAndEcosystem(t *testing.T) {
	r := verdictDamageReason([]intel.SourceDamage{
		{SourceID: "datadog", Ecosystem: intel.EcosystemNPM, Reason: "collapsed vs baseline", Got: 696390, Baseline: 747370},
	})
	require.Contains(t, r, "datadog")
	require.Contains(t, r, "npm")
	require.Contains(t, r, "696390")
	require.Contains(t, r, "747370")

	multi := verdictDamageReason([]intel.SourceDamage{
		{SourceID: "a", Ecosystem: intel.EcosystemNPM, Reason: "r"},
		{SourceID: "b", Ecosystem: intel.EcosystemNPM, Reason: "r"},
	})
	require.Contains(t, multi, "(+1 more)")
}

// TestVerdictOutOfScopeDamageDoesNotBlock pins the ecosystem scoping:
// damage in an ecosystem the command does NOT touch must not abort the
// verdict (an npm install must not wedge because the crates feed is
// rotting). runGate prints those as WARNs; the verdict stays silent.
func TestVerdictOutOfScopeDamageDoesNotBlock(t *testing.T) {
	damaged := []intel.SourceDamage{
		{SourceID: "rustsec", Ecosystem: intel.EcosystemCrates, Reason: "collapsed", Got: 0, Baseline: 500},
	}
	refusals := damagedRefusals(damaged, intel.EcosystemNPM,
		npm.New().ParseInstalls([]string{"install", "lodash"}))
	require.Empty(t, refusals,
		"out-of-scope damage must not block; warn-only in runGate, invisible to the verdict")
}
