package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func TestFilterRegistryInstalls(t *testing.T) {
	in := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "serde", Version: "1.0.0"}},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "rootcrate", Version: "0.1.0"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "evilgit", Version: "0.0.1"}, OpaqueRemote: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: "", Version: ""}},
	}
	out := filterRegistryInstalls(in)
	require.Len(t, out, 1)
	require.Equal(t, "serde", out[0].Ref.Name)
}
