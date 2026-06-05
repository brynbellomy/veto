package golang_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/golang"
)

func TestParseInstalls(t *testing.T) {
	m := golang.New()

	t.Run("go get gates module specs and skips removals", func(t *testing.T) {
		out := m.ParseInstalls([]string{"get", "github.com/evil/module@v1.2.3", "golang.org/x/sys@latest", "github.com/old/module@none"})
		requireContains(t, out, "github.com/evil/module", "v1.2.3", false, false)
		requireContains(t, out, "golang.org/x/sys", "", false, false)
		require.Len(t, out, 2)
	})

	t.Run("go install gates remote package forms", func(t *testing.T) {
		out := m.ParseInstalls([]string{"install", "github.com/evil/cmd@v0.2.0"})
		requireContains(t, out, "github.com/evil/cmd", "v0.2.0", false, false)
	})

	t.Run("go run only gates remote versioned package form", func(t *testing.T) {
		out := m.ParseInstalls([]string{"run", "github.com/evil/cmd@v0.2.0", "--arg"})
		requireContains(t, out, "github.com/evil/cmd", "v0.2.0", false, false)

		out = m.ParseInstalls([]string{"run", "github.com/evil/cmd@latest"})
		requireContains(t, out, "github.com/evil/cmd", "", false, false)

		require.Nil(t, m.ParseInstalls([]string{"run", "./cmd/app"}))
		require.Nil(t, m.ParseInstalls([]string{"run", "main.go"}))
	})

	t.Run("go mod download gates explicit modules", func(t *testing.T) {
		out := m.ParseInstalls([]string{"mod", "download", "github.com/evil/module@v1.2.3"})
		requireContains(t, out, "github.com/evil/module", "v1.2.3", false, false)
	})

	t.Run("go mod tidy gates manifest refs only", func(t *testing.T) {
		out := m.ParseInstalls([]string{"mod", "tidy"})
		require.Empty(t, out)
	})

	t.Run("non dependency-fetching commands parse no installs", func(t *testing.T) {
		require.Nil(t, m.ParseInstalls([]string{"build", "./..."}))
		require.Nil(t, m.ParseInstalls([]string{"test", "./..."}))
		require.Nil(t, m.ParseInstalls([]string{"version"}))
	})
}

func TestManifestRefs(t *testing.T) {
	m := golang.New()

	for _, args := range [][]string{
		{"get", "github.com/evil/module@v1.2.3"},
		{"mod", "download"},
		{"mod", "tidy"},
	} {
		refs := m.ManifestRefs(args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "go.mod", Kind: packagemanager.ManifestKindGoMod},
			{Path: "go.sum", Kind: packagemanager.ManifestKindGoSum},
		}, refs)
	}

	require.Nil(t, m.ManifestRefs([]string{"get", "github.com/old/module@none"}))
	// Phase 1.8: `go get` with no positionals must gate go.mod's
	// transitive set — `go get -u` walks the existing graph.
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: "go.mod", Kind: packagemanager.ManifestKindGoMod},
		{Path: "go.sum", Kind: packagemanager.ManifestKindGoSum},
	}, m.ManifestRefs([]string{"get"}))
	require.Nil(t, m.ManifestRefs([]string{"install", "github.com/evil/cmd@v0.2.0"}))
	require.Nil(t, m.ManifestRefs([]string{"run", "github.com/evil/cmd@v0.2.0"}))
	require.Nil(t, m.ManifestRefs([]string{"build", "./..."}))
}

func TestProjectPreflight(t *testing.T) {
	m := golang.New()

	for _, args := range [][]string{
		{"build", "./..."},
		{"test", "./..."},
		{"vet", "./..."},
		{"run", "./cmd/app"},
		{"run", "main.go"},
	} {
		plan, ok := m.ProjectPreflight(args)
		require.True(t, ok, "expected project preflight for %v", args)
		require.Equal(t, []packagemanager.ManifestRef{
			{Path: "go.mod", Kind: packagemanager.ManifestKindGoMod},
			{Path: "go.sum", Kind: packagemanager.ManifestKindGoSum},
		}, plan.ManifestRefs)
	}

	plan, ok := m.ProjectPreflight([]string{"-C", "nested", "test", "./..."})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join("nested", "go.mod"), Kind: packagemanager.ManifestKindGoMod},
		{Path: filepath.Join("nested", "go.sum"), Kind: packagemanager.ManifestKindGoSum},
	}, plan.ManifestRefs)

	plan, ok = m.ProjectPreflight([]string{"-modfile", "alt.mod", "build", "./..."})
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: "alt.mod", Kind: packagemanager.ManifestKindGoMod},
		{Path: "alt.sum", Kind: packagemanager.ManifestKindGoSum},
	}, plan.ManifestRefs)

	_, ok = m.ProjectPreflight([]string{"run", "github.com/evil/cmd@v0.2.0"})
	require.False(t, ok, "remote versioned go run stays install-style gating")
	_, ok = m.ProjectPreflight([]string{"run"})
	require.False(t, ok, "go run without a local target should not force project preflight")
	_, ok = m.ProjectPreflight([]string{"version"})
	require.False(t, ok)
	_, ok = m.ProjectPreflight([]string{"env"})
	require.False(t, ok)
}

func TestEnvRecursionRisk_Go(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want packagemanager.EnvRecursionRiskLevel
	}{
		{"go run", []string{"run", "./cmd/foo"}, packagemanager.RecursionRiskLow},
		{"go build", []string{"build", "./..."}, packagemanager.RecursionRiskLow},
		{"go test", []string{"test", "./..."}, packagemanager.RecursionRiskLow},
		{"go vet", []string{"vet", "./..."}, packagemanager.RecursionRiskLow},
		{"go get modern", []string{"get", "./..."}, packagemanager.RecursionRiskLow},
		{"go mod tidy", []string{"mod", "tidy"}, packagemanager.RecursionRiskLow},
		{"go mod download", []string{"mod", "download"}, packagemanager.RecursionRiskLow},
		{"go work sync", []string{"work", "sync"}, packagemanager.RecursionRiskLow},
		{"go list", []string{"list", "./..."}, packagemanager.RecursionRiskLow},
		{"go bug", []string{"bug"}, packagemanager.RecursionRiskLow},
		{"go install", []string{"install", "pkg@latest"}, packagemanager.RecursionRiskHigh},
		{"go install local", []string{"install", "./cmd/foo"}, packagemanager.RecursionRiskHigh},
		{"go generate", []string{"generate", "./..."}, packagemanager.RecursionRiskHigh},
		{"go tool", []string{"tool", "dist", "list"}, packagemanager.RecursionRiskHigh},
		{"unknown verb", []string{"someNewVerb", "arg"}, packagemanager.RecursionRiskUnknown},
		{"no verb", []string{}, packagemanager.RecursionRiskLow},
		{"-C dir run", []string{"-C", "/tmp", "run", "./x"}, packagemanager.RecursionRiskLow},
		{"-C dir install", []string{"-C", "/tmp", "install", "pkg@v1"}, packagemanager.RecursionRiskHigh},
		{"-ldflags then install", []string{"-ldflags=-X main.x=run", "install", "./..."}, packagemanager.RecursionRiskHigh},
	}

	m := golang.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.EnvRecursionRisk(tc.args)
			require.Equal(t, tc.want, got)
		})
	}
}

func requireContains(t *testing.T, installs []packagemanager.Install, name, version string, localPath, opaque bool) {
	t.Helper()
	for _, ins := range installs {
		if ins.Ref.Ecosystem == intel.EcosystemGo && ins.Ref.Name == name && ins.Ref.Version == version && ins.LocalPath == localPath && ins.OpaqueRemote == opaque {
			return
		}
	}
	t.Fatalf("expected %s@%s local=%t opaque=%t in:\n%v", name, version, localPath, opaque, installs)
}
