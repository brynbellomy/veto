package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// scanDamageSource reports a damaged npm bucket on every refresh, with
// enough healthy pypi reports to clear the sanity floor.
type scanDamageSource struct{}

func (scanDamageSource) ID() string { return "scan-damage-feed" }

func (scanDamageSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemPyPI {
		return nil, intel.ErrUnsupportedEcosystem
	}
	reports := make([]intel.MalwareReport, 1500)
	for i := range reports {
		reports[i] = intel.MalwareReport{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: fmt.Sprintf("filler-%04d", i)},
			SourceID:   "scan-damage-feed",
			Reason:     "MALWARE",
		}
	}
	return reports, nil
}

// TestScanAbortsOnDamagedIntel is the FIX 3 regression: `veto scan` built
// and refreshed the same intel store the gate uses but never consulted
// store.Damaged(), so a scan against a damaged index walked the tree with
// silently degraded coverage and reported clean. Damage in ANY ecosystem
// matters to a scan (unlike an npm install, a scan covers every
// ecosystem), so scan fails closed on any reported damage.
func TestScanAbortsOnDamagedIntel(t *testing.T) {
	// A real (empty) project root so the scan reaches the intel stage
	// instead of dying on root validation.
	root := t.TempDir()

	// Control: the same scan with a HEALTHY store must exit 0 — proving
	// the exit code below is attributable to damage, not to fixture
	// accident.
	healthy := &stubDamagedStore{damage: nil}
	orig := buildStoreFn
	buildStoreFn = func(zerolog.Logger, config) (intel.Store, error) { return healthy, nil }
	cfg := config{CacheDir: t.TempDir(), Sources: []string{"scan-damage-feed"}}
	code := runScanWithOpts(zerolog.Nop(), cfg, scanOpts{projects: true, roots: []string{root}})
	require.NotEqual(t, exitInternal, code,
		"control: a healthy store must not hit exitInternal (fixture sanity)")

	// Damaged store: Damaged() reports one npm bucket (any ecosystem — a
	// scan covers them all, unlike a single-ecosystem install).
	damagedStore := &stubDamagedStore{damage: []intel.SourceDamage{{
		SourceID:  "datadog",
		Ecosystem: intel.EcosystemNPM,
		Reason:    "report count collapsed below recorded baseline",
		Got:       2,
		Baseline:  747370,
	}}}
	buildStoreFn = func(zerolog.Logger, config) (intel.Store, error) { return damagedStore, nil }
	t.Cleanup(func() { buildStoreFn = orig })

	code = runScanWithOpts(zerolog.Nop(), cfg, scanOpts{projects: true, roots: []string{root}})
	require.Equal(t, exitInternal, code,
		"a scan against a damaged intel index must abort fail-closed, not report clean")
}

// stubDamagedStore is an intel.Store reporting a fixed damage set and a
// healthy report count (so the sanity floor does not fire first).
type stubDamagedStore struct {
	damage []intel.SourceDamage
}

func (s *stubDamagedStore) ReportCount() int                { return 1500 }
func (s *stubDamagedStore) Damaged() []intel.SourceDamage   { return s.damage }
func (s *stubDamagedStore) Refresh(_ context.Context) error { return nil }
func (s *stubDamagedStore) Lookup(_ intel.PackageRef) intel.Verdict {
	return intel.Verdict{Ref: intel.PackageRef{}}
}
func (s *stubDamagedStore) SourceIDs() []string { return []string{"scan-damage-feed"} }
