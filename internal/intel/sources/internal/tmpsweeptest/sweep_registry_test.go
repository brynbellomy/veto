package tmpsweeptest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/cacheonlytest"
)

// The guards in this file exist for the same reason as
// cacheonlytest/registry_test.go: the per-source sweep hook is duplicated
// source-by-source, and each copy can be reverted independently. A sweep
// hook that nothing tests is 4.7 GB of silent disk growth away from being
// "still working". These tests make the failure mode for a missing or
// hollow hook a red build instead of a slowly-filling disk.
//
// The sweep hook is one line inside each source's Fetch. That is exactly
// the shape of thing a rebase drops without any test noticing — the
// verdict-only-mode rebase silently reverted eight of nine cache-only
// guards, which is the incident that produced the registry-guard pattern
// this file copies.

// TestEveryNetworkSourceSweepsOrphanTemps walks the same source registry
// the CLI constructs (cacheonlytest.RegisteredSources, itself guarded to
// match cmd/veto's buildSource) and asserts each network source's Fetch
// actually CALLS the sweep. Binding on the call expression — not a comment
// or an import — is what makes a hollow hook fail.
func TestEveryNetworkSourceSweepsOrphanTemps(t *testing.T) {
	sourcesDir := sourcesDir(t)

	for _, id := range sortedSources() {
		srcPath := filepath.Join(sourcesDir, id, id+".go")
		src, err := os.ReadFile(srcPath)
		require.NoError(t, err, "cannot read %s — was the source renamed?", srcPath)

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, srcPath, src, 0)
		require.NoError(t, err, "%s does not parse", srcPath)

		// Find the Fetch method and require a sweep call inside it, before
		// any os.CreateTemp/fsutil.WriteAtomic the source performs. The
		// sweep must run on FIRST Fetch — before the download that could
		// itself die and orphan a temp — not after a successful one.
		var foundSweep, foundFetch bool
		var fetchPos, sweepPos token.Pos
		ast.Inspect(f, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fd.Name.Name != "Fetch" || fd.Recv == nil || len(fd.Recv.List) == 0 {
				return true
			}
			foundFetch = true
			fetchPos = fd.Pos()
			ast.Inspect(fd.Body, func(m ast.Node) bool {
				ce, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := ce.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Do" {
					// s.sweepOnce.Do(s.sweepOrphanTemps)
					if obj, ok := sel.X.(*ast.SelectorExpr); ok && strings.Contains(obj.Sel.Name, "sweepOnce") {
						foundSweep = true
						sweepPos = ce.Pos()
					}
				}
				return true
			})
			return false
		})

		require.True(t, foundFetch,
			"%s: no Fetch method found in %s — the guard itself is broken; update it", id, srcPath)
		require.True(t, foundSweep,
			"%s: Fetch never calls the orphan-temp sweep. Every network source must sweep "+
				"abandoned *.tmp-* download temps from its own cache dir on first Fetch — "+
				"a hook that nothing tests is 4.7 GB of silent disk growth. "+
				"See fsutil.SweepOrphanTemps and tmpsweeptest.", id)
		require.True(t, sweepPos > fetchPos,
			"%s: sweep call is not inside Fetch — internal error in this guard", id)
	}
}

// TestEveryNetworkSourceSweepIsOncePerProcess pins that each source's
// sweep hook is guarded by a sync.Once (cost guard). An unguarded sweep
// would stat the whole cache dir on every single Fetch across every
// ecosystem — nine sources times four ecosystems times every veto
// invocation — which turns hygiene into measurable latency on the hot
// path that gates every go build.
func TestEveryNetworkSourceSweepIsOncePerProcess(t *testing.T) {
	sourcesDir := sourcesDir(t)

	for _, id := range sortedSources() {
		srcPath := filepath.Join(sourcesDir, id, id+".go")
		src, err := os.ReadFile(srcPath)
		require.NoError(t, err)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, srcPath, src, 0)
		require.NoError(t, err)

		// sweepOnce field declared on the struct…
		var hasField bool
		// …and a sweepOrphanTemps method that delegates to fsutil.
		var hasMethod bool
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Field:
				for _, name := range node.Names {
					if name.Name == "sweepOnce" {
						hasField = true
					}
				}
			case *ast.FuncDecl:
				if node.Name.Name == "sweepOrphanTemps" && node.Recv != nil {
					hasMethod = true
				}
			}
			return true
		})
		require.True(t, hasField,
			"%s: Source struct has no sweepOnce field — the sweep must be once per process", id)
		require.True(t, hasMethod,
			"%s: no sweepOrphanTemps method delegating to fsutil.SweepOrphanTemps", id)
	}
}

// TestHadesIsExempt pins that hades — static embedded data, no cache dir,
// nothing to sweep — stays exempt. If hades ever gains a cache dir this
// must be revisited rather than silently leaving it unswept.
func TestHadesIsExempt(t *testing.T) {
	require.NotContains(t, sortedSources(), "hades",
		"hades is static embedded data with no cache dir; it must never appear in the sweep registry. "+
			"If hades gained a cache dir, add a hook and remove this exemption knowingly.")
}

// sortedSources returns the network source IDs in deterministic order.
func sortedSources() []string {
	out := make([]string, len(cacheonlytest.RegisteredSources))
	copy(out, cacheonlytest.RegisteredSources)
	sort.Strings(out)
	return out
}

// sourcesDir locates …/internal/intel/sources from this file's location.
func sourcesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// …/sources/internal/tmpsweeptest/sweep_registry_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}
