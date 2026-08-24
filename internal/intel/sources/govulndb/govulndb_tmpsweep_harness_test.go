package govulndb

import (
	"testing"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/tmpsweeptest"
)

// Plug govulndb into the shared orphan-temp sweep harness.
func TestSweepHarnessRemovesOrphansOnFirstFetch(t *testing.T) {
	tmpsweeptest.RunSweepsOrphansOnFirstFetch(t, govulndbCacheOnlyCase(t))
}

func TestSweepHarnessSweepFailureNeverFailsFetch(t *testing.T) {
	tmpsweeptest.RunSweepFailureNeverFailsFetch(t, govulndbCacheOnlyCase(t))
}
