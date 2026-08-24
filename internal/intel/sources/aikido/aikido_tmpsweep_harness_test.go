package aikido_test

import (
	"testing"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/tmpsweeptest"
)

// Plug aikido into the shared orphan-temp sweep harness.
func TestSweepHarnessRemovesOrphansOnFirstFetch(t *testing.T) {
	tmpsweeptest.RunSweepsOrphansOnFirstFetch(t, aikidoCacheOnlyCase(t))
}

func TestSweepHarnessSweepFailureNeverFailsFetch(t *testing.T) {
	tmpsweeptest.RunSweepFailureNeverFailsFetch(t, aikidoCacheOnlyCase(t))
}
