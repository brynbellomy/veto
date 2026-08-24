package rustsec

import (
	"testing"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/tmpsweeptest"
)

// Plug rustsec into the shared orphan-temp sweep harness.
func TestSweepHarnessRemovesOrphansOnFirstFetch(t *testing.T) {
	tmpsweeptest.RunSweepsOrphansOnFirstFetch(t, rustsecCacheOnlyCase(t))
}

func TestSweepHarnessSweepFailureNeverFailsFetch(t *testing.T) {
	tmpsweeptest.RunSweepFailureNeverFailsFetch(t, rustsecCacheOnlyCase(t))
}
