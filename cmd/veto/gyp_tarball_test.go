package main

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gypscan"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

func npmInstall(name, version string) packagemanager.Install {
	return packagemanager.Install{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version}}
}

func TestGypTarballScanModeDefault(t *testing.T) {
	t.Setenv("VETO_GYP_TARBALL_SCAN", "")
	enabled, full := gypTarballScanMode()
	require.True(t, enabled, "tarball scan should default ON")
	require.False(t, full, "full mode should default OFF")
}

func TestGypTarballScanModeDisabled(t *testing.T) {
	for _, v := range []string{"0", "off", "false", "no"} {
		t.Setenv("VETO_GYP_TARBALL_SCAN", v)
		enabled, _ := gypTarballScanMode()
		require.False(t, enabled, "VETO_GYP_TARBALL_SCAN=%s should disable", v)
	}
}

func TestGypTarballScanModeFull(t *testing.T) {
	for _, v := range []string{"full", "all", "transitive"} {
		t.Setenv("VETO_GYP_TARBALL_SCAN", v)
		enabled, full := gypTarballScanMode()
		require.True(t, enabled)
		require.True(t, full, "VETO_GYP_TARBALL_SCAN=%s should enable full mode", v)
	}
}

func TestSelectTarballTargetsDirectOnly(t *testing.T) {
	direct := []packagemanager.Install{npmInstall("lodash", "")}
	resolved := []packagemanager.Install{
		npmInstall("lodash", "4.17.21"),
		npmInstall("some-transitive", "1.0.0"),
	}
	targets := selectTarballTargets(direct, resolved, false)

	require.Len(t, targets, 1)
	// Direct install's empty version is upgraded to the resolved concrete one.
	require.Equal(t, "lodash@4.17.21", targets[0].spec())
}

func TestSelectTarballTargetsFullIncludesTransitives(t *testing.T) {
	direct := []packagemanager.Install{npmInstall("lodash", "")}
	resolved := []packagemanager.Install{
		npmInstall("lodash", "4.17.21"),
		npmInstall("some-transitive", "1.0.0"),
	}
	targets := selectTarballTargets(direct, resolved, true)

	specs := map[string]bool{}
	for _, tg := range targets {
		specs[tg.spec()] = true
	}
	require.True(t, specs["lodash@4.17.21"])
	require.True(t, specs["some-transitive@1.0.0"])
	require.Len(t, targets, 2)
}

func TestSelectTarballTargetsSkipsLocalAndOpaque(t *testing.T) {
	direct := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "local"}, LocalPath: true},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "remote"}, OpaqueRemote: true},
		npmInstall("good", "1.0.0"),
	}
	targets := selectTarballTargets(direct, nil, false)
	require.Len(t, targets, 1)
	require.Equal(t, "good@1.0.0", targets[0].spec())
}

func TestSelectTarballTargetsSkipsNonNpm(t *testing.T) {
	direct := []packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "requests", Version: "2.0"}},
	}
	require.Empty(t, selectTarballTargets(direct, nil, false))
}

func TestSelectTarballTargetsDeduplicates(t *testing.T) {
	direct := []packagemanager.Install{npmInstall("lodash", "4.17.21"), npmInstall("lodash", "4.17.21")}
	require.Len(t, selectTarballTargets(direct, nil, false), 1)
}

func TestPrintTarballRefusal(t *testing.T) {
	var buf bytes.Buffer
	printTarballRefusal(&buf, []tarballFinding{{
		spec: "innocent-util@1.2.4",
		verdict: gypscan.Verdict{
			Severity: gypscan.SeverityCritical,
			Signals:  []gypscan.Signal{{Code: "gyp-command-in-sources", Detail: "runs a command in sources", Excerpt: "node index.js"}},
		},
	}})
	out := buf.String()
	require.Contains(t, out, "innocent-util@1.2.4")
	require.Contains(t, out, "gyp-command-in-sources")
	require.Contains(t, out, "never run")
}

func TestGypTarballPreflightDisabledShortCircuits(t *testing.T) {
	t.Setenv("VETO_GYP_TARBALL_SCAN", "off")
	var buf bytes.Buffer
	// With the scan disabled, it must return false without touching npm.
	refused := gypTarballPreflight(zerolog.Nop(), &buf, config{}, []packagemanager.Install{npmInstall("x", "1.0.0")}, nil)
	require.False(t, refused)
	require.Empty(t, buf.String())
}
