package cacheonlytest

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
)

// The guards in this file exist because the per-source cache-only guard is
// duplicated source-by-source, and each copy can be reverted
// independently — exactly what the verdict-only-mode rebase did, silently,
// in eight of the nine. Enumerating the family by hand is how a tenth
// source ships with no coverage at all. These tests make the failure mode
// for source #10 a red build instead of a silent hole.

// TestRegisteredSourcesMatchBuildSource parses cmd/veto's buildSource
// switch — the registry the CLI actually uses to construct sources — and
// asserts every NETWORK source in it is registered in the harness, and
// every registered source is still constructed. hades is exempt: it is
// static embedded data with no network cache to damage.
func TestRegisteredSourcesMatchBuildSource(t *testing.T) {
	registered := make(map[string]bool)
	for _, id := range RegisteredSources {
		require.False(t, registered[id], "duplicate harness registration: %s", id)
		registered[id] = true
	}

	network := networkSourceIDs(t)
	require.NotEmpty(t, network,
		"parsing buildSource found no sources; the registry guard itself is broken "+
			"(was buildSource renamed or moved?) — update this test, do not delete it")

	for _, id := range network {
		require.True(t, registered[id],
			"source %q is constructed by buildSource but is NOT registered in "+
				"cacheonlytest.RegisteredSources. Every network source must run the "+
				"cache-only integrity harness — a guard that nothing tests is a guard "+
				"on a timer. Add a *_cacheonly_harness_test.go to the source package "+
				"and add the ID to RegisteredSources.", id)
	}
	for id := range registered {
		require.Contains(t, network, id,
			"harness registers %q but buildSource does not construct it; stale registration", id)
	}
}

// TestEveryRegisteredSourceHasPlugIn closes the hole where a source is
// registered but its plug-in file is missing or hollow: each registered
// ID must have a *_cacheonly_harness_test.go that actually invokes both
// harness scenarios. Registration without a plug-in compiles fine and
// fails nothing otherwise.
func TestEveryRegisteredSourceHasPlugIn(t *testing.T) {
	for _, id := range RegisteredSources {
		plugDir := filepath.Join(filepath.Dir(repoRootForID()), "sources", id)
		matches, err := filepath.Glob(filepath.Join(plugDir, "*_cacheonly_harness_test.go"))
		require.NoError(t, err)
		require.NotEmpty(t, matches,
			"source %q is registered but has no *_cacheonly_harness_test.go plug-in; "+
				"the registration is lying", id)

		// FIX 6: bind on real CALL EXPRESSIONS, not substrings — a
		// commented-out call or a doc-comment mention satisfied the old
		// require.Contains check. Parse each plug-in file and require an
		// actual call to every scenario runner.
		track := map[string]bool{
			"RunGuttedUnderCacheOnly":                  false,
			"RunUnrecordedMustNotAdopt":                false,
			"Run304UnrecordedGuttedMustRebindFromWire": false,
		}
		for _, m := range matches {
			fset := token.NewFileSet()
			af, err := parser.ParseFile(fset, m, nil, 0)
			if err != nil {
				t.Errorf("source %q: plug-in %s does not parse: %v", id, m, err)
				continue
			}
			ast.Inspect(af, func(n ast.Node) bool {
				if ce, ok := n.(*ast.CallExpr); ok {
					if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
						if _, tracked := track[sel.Sel.Name]; tracked || track[sel.Sel.Name] == false {
							if _, ok := track[sel.Sel.Name]; ok {
								track[sel.Sel.Name] = true
							}
						}
					}
				}
				return true
			})
		}
		for name, seen := range track {
			if !seen {
				t.Errorf("source %q: plug-in never CALLS cacheonlytest.%s (a comment or "+
					"doc mention does not count)", id, name)
			}
		}
	}
}

// repoRootForID returns the intel sources directory (the parent of both
// this package's internal/ dir and the per-source packages).
func repoRootForID() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// networkSourceIDs parses cmd/veto/main.go's buildSource switch and
// returns every case value except the known non-network sources.
func networkSourceIDs(t *testing.T) []string {
	t.Helper()

	// Locate the repo root from this file's location: …/<repo>/internal/
	// intel/sources/internal/cacheonlytest/registry_test.go
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	cacheDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(cacheDir)))))
	mainPath := filepath.Join(repoRoot, "cmd", "veto", "main.go")

	src, err := os.ReadFile(mainPath)
	require.NoError(t, err, "cannot read cmd/veto/main.go from %s", mainPath)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mainPath, src, 0)
	require.NoError(t, err)

	// nonNetwork sources: static embedded data, no fetch, no cache.
	nonNetwork := map[string]bool{"hades": true}

	var ids []string
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "buildSource" {
			return true
		}
		found = true
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			sw, ok := m.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			for _, c := range sw.Body.List {
				cc, ok := c.(*ast.CaseClause)
				if !ok || cc.List == nil {
					continue // default clause
				}
				for _, e := range cc.List {
					bl, ok := e.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					v := strings.Trim(bl.Value, `"`)
					if nonNetwork[v] {
						continue
					}
					ids = append(ids, v)
				}
			}
			return false
		})
		return false
	})
	require.True(t, found, "buildSource function not found in cmd/veto/main.go")
	sort.Strings(ids)
	return ids
}
