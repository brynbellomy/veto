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
