package pypa_test

import (
	"testing"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/tmpsweeptest"
)

// Plug pypa into the shared orphan-temp sweep harness.
func TestSweepHarnessRemovesOrphansOnFirstFetch(t *testing.T) {
	tmpsweeptest.RunSweepsOrphansOnFirstFetch(t, pypaCacheOnlyCase(t))
}

func TestSweepHarnessSweepFailureNeverFailsFetch(t *testing.T) {
	tmpsweeptest.RunSweepFailureNeverFailsFetch(t, pypaCacheOnlyCase(t))
}
