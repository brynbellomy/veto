package intel_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestBaselineDoesNotRatchetDownOnCacheOnlyRun pins FIX 2: a bucket whose
// on-disk payload is damaged-but-above-threshold (e.g. a partial write
// retaining 60% of entries) is ACCEPTED by the retention check, and the
// naive mergeBaseline then records the lower count as the new anchor.
// The next cold start compares against the degraded anchor, so the damage
// becomes permanent and invisible — "accept poisoned and the poison
// becomes the anchor." A cache-only run has NO wire basis (nothing was
// fetched from upstream), so it must never move an anchor downward: the
// old anchor is kept and only wire-verified runs may re-anchor.
func TestBaselineDoesNotRatchetDownOnCacheOnlyRun(t *testing.T) {
	logger := zerolog.Nop()
	baselinePath := filepath.Join(t.TempDir(), "intel-baseline.json")

	src := &baselineTestSource{
		id: "ratchet",
		per: map[intel.Ecosystem][]intel.MalwareReport{
			intel.EcosystemNPM: makeBaselineReports(1000),
		},
	}

	// Run 1 (network): healthy 1000-report bucket; anchor = 1000.
	first := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, first.Refresh(context.Background()))
	require.Equal(t, 1000, first.ReportCount())
	require.Empty(t, first.Damaged())

	// Run 2 (NETWORK, source now serves 600 — a damaged-but-above-50%
	// payload): the retention check ACCEPTS it (600 >= 500). The wire
	// basis is real (upstream really served 600), so re-anchoring at 600
	// is legitimate shrinkage — feeds do shrink.
	src.per[intel.EcosystemNPM] = makeBaselineReports(600)
	second := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, second.Refresh(context.Background()))
	require.Empty(t, second.Damaged())
	require.Equal(t, 600, second.ReportCount())

	// Run 3 (CACHE-ONLY, source now serves 200 — further rot): with the
	// in-process retention layer blind (fresh store) and the anchor at
	// 600, 200 < 300 → the bucket is REJECTED as damaged. Good. But the
	// property under test is subtler: even if the rot kept the count
	// above the threshold (say 400 >= 300 → accepted), a cache-only run
	// must NOT re-anchor at 400 — nothing upstream confirmed 400.
	src.per[intel.EcosystemNPM] = makeBaselineReports(400)
	third := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, third.Refresh(intel.WithCacheOnly(context.Background())))
	require.Empty(t, third.Damaged(), "400 >= 300 passes the ratio check; accepted")
	require.Equal(t, 400, third.ReportCount(), "the accepted disk data is served")

	// Run 4 (NETWORK, healthy again — 1000 reports): the anchor must
	// still be 600 (the last wire-verified count), NOT 400 (the
	// cache-only count). If run 3 re-anchored at 400, this healthy fetch
	// would look like growth and a LATER collapse to 300 would pass the
	// check against the poisoned 400 anchor while being well under the
	// honest 600. Assert the anchor survived the cache-only run.
	src.per[intel.EcosystemNPM] = makeBaselineReports(200)
	fourth := intel.NewStoreWithBaseline(logger, baselinePath, src)
	require.NoError(t, fourth.Refresh(context.Background()))
	damaged := fourth.Damaged()
	require.NotEmpty(t, damaged,
		"200 reports against the wire-verified anchor of 600 must be rejected; "+
			"if the cache-only run re-anchored at 400, this check passes and the "+
			"poison became the anchor — the FIX 2 defect")
	require.Equal(t, 600, damaged[0].Baseline,
		"the anchor must be the last WIRE-VERIFIED count (600), never the "+
			"cache-only count (400)")
}
