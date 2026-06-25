package hades_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/hades"
)

func TestSourceID(t *testing.T) {
	require.Equal(t, "hades", hades.New().ID())
}

func TestFetchPyPIReturnsCuratedSet(t *testing.T) {
	reports, err := hades.New().Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	names := map[string]struct{}{}
	for _, r := range reports {
		require.Equal(t, intel.EcosystemPyPI, r.PackageRef.Ecosystem)
		require.NotEmpty(t, r.PackageRef.Name)
		require.NotEmpty(t, r.PackageRef.Version)
		names[r.PackageRef.Name] = struct{}{}
	}
	_, hasEnsmallen := names["ensmallen"]
	require.True(t, hasEnsmallen)
}

func TestFetchNonPyPIIsSkipped(t *testing.T) {
	_, err := hades.New().Fetch(context.Background(), intel.EcosystemNPM)
	require.ErrorIs(t, err, intel.ErrUnsupportedEcosystem)
}

// TestFetchVersionsArePEP440Canonical verifies that all hades entries store
// their versions in PEP 440 canonical form (no alternate separators) so they
// round-trip cleanly through NormalizeVersion and land in the index under the
// same key that NormalizeVersion(installVersion) would produce.
func TestFetchVersionsArePEP440Canonical(t *testing.T) {
	reports, err := hades.New().Fetch(context.Background(), intel.EcosystemPyPI)
	require.NoError(t, err)
	for _, r := range reports {
		got := intel.NormalizeVersion(intel.EcosystemPyPI, r.PackageRef.Version)
		require.Equal(t, r.PackageRef.Version, got,
			"hades entry %s@%s is not PEP 440 canonical; normalize returns %q",
			r.PackageRef.Name, r.PackageRef.Version, got)
	}
}
