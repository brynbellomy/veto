package intel_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// baselineTestSource serves a per-ecosystem report count that the test can
// change between Refresh calls, simulating a feed that collapses. It also
// lets the test inject an error (e.g. intel.ErrDamagedCache wrapped) to
// exercise the damaged-cache routing. Refresh fans out one goroutine per
// ecosystem, so all mutable state is mutex-guarded.
type baselineTestSource struct {
	id  string
	mu  sync.Mutex
	per map[intel.Ecosystem][]intel.MalwareReport
	err map[intel.Ecosystem]error
}

func (s *baselineTestSource) ID() string { return s.id }

func (s *baselineTestSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil && s.err[eco] != nil {
		return nil, s.err[eco]
	}
	return s.per[eco], nil
}

// makeReports builds n distinct npm reports.
func makeBaselineReports(n int) []intel.MalwareReport {
	out := make([]intel.MalwareReport, n)
	for i := range out {
		out[i] = intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: intel.EcosystemNPM,
				Name:      "evil-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
				Version:   "1",
			},
			SourceID: "alpha",
		}
	}
	return out
}

// TestBaselineStoreColdStartRejectsCollapsedFetch is the store-level
// regression for the gutted-manifest vulnerability: a fresh process (no
// in-process previous data) whose fetch returns drastically fewer reports
// than the recorded baseline must NOT serve the collapsed data. The
// bucket is rejected and reported via Damaged().
func TestBaselineStoreColdStartRejectsCollapsedFetch(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(100),
		},
	}

	// First invocation: records the baseline (100 reports).
	first := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, first.Refresh(context.Background()))
	require.Equal(t, 100, first.ReportCount())
	require.Empty(t, first.Damaged())

	// Second invocation, fresh process shape: the fetch now returns 2
	// reports (the gutted manifest). In-process retention can't help —
	// this store has no previous slice. The persistent baseline must
	// reject the collapse.
	src.per[intel.EcosystemNPM] = makeBaselineReports(2)
	second := intel.NewStoreWithBaseline(logger, baselinePath, src)
	err := second.Refresh(context.Background())
	require.NoError(t, err, "a damaged bucket must not fail the whole refresh while others are healthy")

	damaged := second.Damaged()
	require.Len(t, damaged, 1, "the collapsed bucket must be reported as damaged")
	require.Equal(t, "alpha", damaged[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, damaged[0].Ecosystem)
	require.Equal(t, 2, damaged[0].Got)
	require.Equal(t, 100, damaged[0].Baseline)

	require.Equal(t, 0, second.ReportCount(),
		"the collapsed data must not be served")
}

// TestBaselineStoreColdStartAcceptsGrowth: a feed that GROWS (or shrinks
// modestly) must be accepted and the baseline updated upward. Guards
// against a criterion so tight it trips on ordinary feed churn.
func TestBaselineStoreColdStartAcceptsGrowth(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(100),
		},
	}

	first := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, first.Refresh(context.Background()))

	// Grow to 500 — accepted, baseline updated.
	src.per[intel.EcosystemNPM] = makeBaselineReports(500)
	second := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, second.Refresh(context.Background()))
	require.Empty(t, second.Damaged())
	require.Equal(t, 500, second.ReportCount())

	// Shrink modestly to 300 (60% of 500, above the 50% threshold) —
	// accepted; ordinary churn must not trip the check.
	src.per[intel.EcosystemNPM] = makeBaselineReports(300)
	third := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, third.Refresh(context.Background()))
	require.Empty(t, third.Damaged(), "a shrink above the threshold is ordinary churn, not damage")
	require.Equal(t, 300, third.ReportCount())
}

// TestBaselineStoreRejectsCollapsedFetchTwice: the rejection must persist
// across invocations. If the baseline were rebuilt from the rejected
// (collapsed) state, the second invocation would accept the gutted data —
// the vulnerability, one run later. The baseline must carry the rejected
// bucket's entry forward.
func TestBaselineStoreRejectsCollapsedFetchTwice(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(100),
		},
	}

	first := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, first.Refresh(context.Background()))

	// Collapse to 2 and refresh across THREE fresh store instances.
	src.per[intel.EcosystemNPM] = makeBaselineReports(2)
	for i := 0; i < 3; i++ {
		store := intel.NewStoreWithBaseline(logger, baselinePath, src)
		require.NoError(t, store.Refresh(context.Background()), "iteration %d", i)
		damaged := store.Damaged()
		require.Len(t, damaged, 1, "iteration %d: the collapse must stay rejected", i)
		require.Equal(t, 100, damaged[0].Baseline,
			"iteration %d: the baseline entry must carry forward, not ratchet down", i)
		require.Equal(t, 0, store.ReportCount(), "iteration %d", i)
	}
}

// TestBaselineStoreRoutesDamagedCacheError: a source that returns an
// error wrapping intel.ErrDamagedCache on a cold start must surface in
// Damaged() (with the recorded baseline count for context), not just as
// an ordinary fetch failure.
func TestBaselineStoreRoutesDamagedCacheError(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(100),
		},
	}

	// Record the baseline.
	first := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, first.Refresh(context.Background()))

	// Cold start with the source refusing its damaged cache.
	src.per[intel.EcosystemNPM] = nil
	src.err = map[intel.Ecosystem]error{
		intel.EcosystemNPM: errors.Join(intel.ErrDamagedCache),
	}

	second := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, second.Refresh(context.Background()))

	damaged := second.Damaged()
	require.Len(t, damaged, 1)
	require.Equal(t, "alpha", damaged[0].SourceID)
	require.Equal(t, 100, damaged[0].Baseline)
	require.Equal(t, 0, damaged[0].Got)
	require.Contains(t, damaged[0].Reason, "content-hash")
}

// TestBaselineStoreMissingFileIsGrandfathered: no baseline file → first
// refresh records one and accepts whatever it reads. The upgrade path
// must not brick every pre-existing installation.
func TestBaselineStoreMissingFileIsGrandfathered(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(2),
		},
	}
	store := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Empty(t, store.Damaged(), "no baseline file → no comparison, no damage")
	require.Equal(t, 2, store.ReportCount())
	require.FileExists(t, baselinePath, "first refresh must record the baseline")
}

// TestBaselineStoreCorruptFileIsIgnored: a corrupt baseline file degrades
// to no-baseline behavior (record on next refresh) rather than bricking
// the gate. The baseline is an integrity signal; a corrupt signal must
// not refuse healthy installs.
func TestBaselineStoreCorruptFileIsIgnored(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")
	require.NoError(t, os.WriteFile(baselinePath, []byte("{not json"), 0o600))

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(50),
		},
	}
	store := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Empty(t, store.Damaged())
	require.Equal(t, 50, store.ReportCount())
}

// TestBaselineStoreInProcessRetentionStillWorks: with a baseline store,
// the second Refresh WITHIN one process (warm in-process previous data)
// retains against a collapse via the in-process layer, and reports it as
// damage with the retained count as baseline context.
func TestBaselineStoreInProcessRetentionStillWorks(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "alpha",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(100),
		},
	}

	store := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, store.Refresh(context.Background()))

	// Collapse within the same process: the in-process layer retains the
	// previous 100 reports (coverage intact).
	src.per[intel.EcosystemNPM] = makeBaselineReports(2)
	require.NoError(t, store.Refresh(context.Background()))

	require.Equal(t, 100, store.ReportCount(),
		"in-process retention must keep the previous slice when available")
	damaged := store.Damaged()
	require.Empty(t, damaged,
		"a below-threshold collapse with retention available is the pre-existing partial-drop path, not new damage")
}
