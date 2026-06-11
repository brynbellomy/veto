package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
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
	enabled, full, raw := pthWheelScanMode()
	require.True(t, enabled)
	require.False(t, full)
	require.Equal(t, "", raw)
}

func TestPthWheelScanModeOff(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	enabled, _, raw := pthWheelScanMode()
	require.False(t, enabled)
	require.Equal(t, "off", raw)
}

func TestPthWheelScanModeFull(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "full")
	enabled, full, _ := pthWheelScanMode()
	require.True(t, enabled)
	require.True(t, full)
}

// TestPthWheelScanModeOnlyOffDisables verifies that legacy boolean-ish values
// ("0", "false", "no") are no longer treated as disable — they fall through to
// the default (enabled, argv-direct) and log an unrecognised-value warning.
// Only the literal string "off" turns the scan off.
func TestPthWheelScanModeOnlyOffDisables(t *testing.T) {
	for _, v := range []string{"0", "false", "no"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("VETO_PTH_WHEEL_SCAN", v)
			enabled, _, _ := pthWheelScanMode()
			require.True(t, enabled, "expected %q NOT to disable the scan (only 'off' should)", v)
		})
	}
}

// TestPthWheelPreflightDisabledLogsAndWarns verifies that setting
// VETO_PTH_WHEEL_SCAN=off causes pthWheelPreflight to:
//  1. return false (no refusal — prescan skipped)
//  2. write a visible WARNING to the output writer
func TestPthWheelPreflightDisabledLogsAndWarns(t *testing.T) {
	t.Setenv("VETO_PTH_WHEEL_SCAN", "off")
	var buf bytes.Buffer

	// Use a real zerolog logger pointing at buf so we can check it logged.
	log := zerolog.New(&buf)

	refused := pthWheelPreflight(
		log, &buf, config{},
		[]packagemanager.Install{ins("ensmallen", "0.8.6", intel.EcosystemPyPI)}, nil,
	)
	require.False(t, refused)

	out := buf.String()
	require.True(t, strings.Contains(out, "DISABLED") || strings.Contains(out, "disabled"),
		"expected output to mention 'DISABLED', got: %q", out)
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

// -- sdist-only sentinel tests (veto-3w1.3) -----------------------------------

func TestErrSdistOnlyError(t *testing.T) {
	err := &errSdistOnly{spec: "evil==1.0", detail: "No matching distribution found for evil==1.0"}
	require.Contains(t, err.Error(), "evil==1.0")
	require.Contains(t, err.Error(), "sdist-only")
}

func TestErrSdistOnlyErrorNilDetail(t *testing.T) {
	err := &errSdistOnly{spec: "foo"}
	require.Contains(t, err.Error(), "foo")
}

func TestIsErrSdistOnly(t *testing.T) {
	var target *errSdistOnly

	// nil → false
	require.False(t, isErrSdistOnly(nil, &target))

	// wrong type → false
	require.False(t, isErrSdistOnly(fmt.Errorf("other error"), &target))

	// correct type → true + target populated
	orig := &errSdistOnly{spec: "pkg==1"}
	require.True(t, isErrSdistOnly(orig, &target))
	require.Equal(t, "pkg==1", target.spec)
}

func TestPipOutputIndicatesSdistOnly(t *testing.T) {
	cases := []struct {
		output string
		want   bool
	}{
		// pip 22+ canonical messages
		{"ERROR: No matching distribution found for evil==1.0.0", true},
		{"Could not find a version that satisfies the requirement evil==1.0.0", true},
		// pip --only-binary hint
		{"Note: This would have installed a sdist (source distribution)", true},
		// transient / unrelated
		{"ERROR: pip's dependency resolver does not currently take into account all the packages", false},
		{"Collecting evil==1.0.0\n  Downloading evil-1.0.0-py3-none-any.whl\nSuccessfully downloaded evil", false},
		{"", false},
	}
	for _, tc := range cases {
		got := pipOutputIndicatesSdistOnly(tc.output)
		require.Equal(t, tc.want, got, "input: %q", tc.output)
	}
}
