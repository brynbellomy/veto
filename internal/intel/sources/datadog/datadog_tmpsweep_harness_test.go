package datadog_test

import (
	"testing"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/tmpsweeptest"
)

// Plug datadog into the shared orphan-temp sweep harness.
func TestSweepHarnessRemovesOrphansOnFirstFetch(t *testing.T) {
	tmpsweeptest.RunSweepsOrphansOnFirstFetch(t, datadogCacheOnlyCase(t))
}

func TestSweepHarnessSweepFailureNeverFailsFetch(t *testing.T) {
	tmpsweeptest.RunSweepFailureNeverFailsFetch(t, datadogCacheOnlyCase(t))
}
