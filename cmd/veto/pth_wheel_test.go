package main

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func ins(name, version string, eco intel.Ecosystem) packagemanager.Install {
	return packagemanager.Install{Ref: intel.PackageRef{Ecosystem: eco, Name: name, Version: version}}
}

func zerologNop() zerolog.Logger { return zerolog.Nop() }

func TestPthWheelScanModeDefaults(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "")
	enabled, full := pthWheelScanMode()
	require.True(t, enabled)
	require.False(t, full)
}

func TestPthWheelScanModeOff(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	enabled, _ := pthWheelScanMode()
	require.False(t, enabled)
}

func TestPthWheelScanModeFull(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "full")
	enabled, full := pthWheelScanMode()
	require.True(t, enabled)
	require.True(t, full)
}

func TestSelectWheelTargetsDirectOnly(t *testing.T) {
	direct := []packagemanager.Install{ins("ensmallen", "", intel.EcosystemPyPI)}
	resolved := []packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI), ins("transitive", "1.0", intel.EcosystemPyPI)}
	got := selectWheelTargets(direct, resolved, false)
	require.Len(t, got, 1)
	require.Equal(t, "ensmallen==0.8.6", got[0].spec()) // resolver version upgrade applied
}

func TestSelectWheelTargetsFull(t *testing.T) {
	direct := []packagemanager.Install{ins("ensmallen", "", intel.EcosystemPyPI)}
	resolved := []packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI), ins("transitive", "1.0", intel.EcosystemPyPI)}
	got := selectWheelTargets(direct, resolved, true)
	require.Len(t, got, 2)
}

func TestSelectWheelTargetsSkipsNonPyPI(t *testing.T) {
	direct := []packagemanager.Install{ins("evil", "", intel.EcosystemNPM)}
	got := selectWheelTargets(direct, nil, false)
	require.Empty(t, got)
}

func TestSelectWheelTargetsSkipsLocalAndOpaque(t *testing.T) {
	direct := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "./local"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "https://evil/foo.whl"}, OpaqueRemote: true},
	}
	got := selectWheelTargets(direct, nil, false)
	require.Empty(t, got)
}

func TestPthWheelPreflightDisabledShortCircuits(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	refused := pthWheelPreflight(
		zerologNop(), os.Stderr, config{},
		[]packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI)}, nil,
	)
	require.False(t, refused)
}
