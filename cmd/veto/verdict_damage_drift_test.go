package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBothEntrypointsConsultDamage is the structural drift guard for the
// damaged-intel check. The regression it prevents: the damage refusal was
// wired into runGate AFTER the verdict path was extracted from it, and
// for the entire life of this branch `veto test` answered
// {"decision":"allow"} over a damaged store while `veto <pm> install`
// aborted — the same vulnerability in a new surface. Behavioral tests
// pin today's wiring; this pins the STRUCTURE that makes divergence
// hard: the damage decision must be computed in gateInputsFor (the one
// site both paths flow through), and both entrypoints must consume the
// computed field rather than re-deriving or skipping it.
func TestBothEntrypointsConsultDamage(t *testing.T) {
	// 1. gateInputsFor computes the damage refusals. (Identifier-level
	// check: the field must be assigned and the computed helper must be
	// called inside gateInputsFor specifically, not merely exist in the
	// package.)
	verdictFset := token.NewFileSet()
	verdictFile, err := parser.ParseFile(verdictFset, "verdict.go", nil, 0)
	require.NoError(t, err)

	computes := func() (assignsField bool, callsHelper bool) {
		var inGateInputsFor bool
		ast.Inspect(verdictFile, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok {
				inGateInputsFor = fd.Name.Name == "gateInputsFor"
				return true
			}
			if !inGateInputsFor {
				return true
			}
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == "damageRefusals" {
						assignsField = true
					}
				}
			}
			if ce, ok := n.(*ast.CallExpr); ok {
				if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "damagedRefusals" {
					callsHelper = true
				}
			}
			return true
		})
		return
	}
	assignsField, callsHelper := computes()
	require.True(t, assignsField,
		"gateInputsFor must compute damageRefusals — this is the single shared site that "+
			"prevents the enforcement and verdict paths from diverging on whether damage blocks")
	require.True(t, callsHelper,
		"gateInputsFor must call damagedRefusals(store.Damaged(), ...) — recomputing "+
			"the scoped damage there is the fix for the verdict-path allow-over-damage bug")

	// 2. gateInputs carries the field.
	hasField := func() bool {
		found := false
		ast.Inspect(verdictFile, func(n ast.Node) bool {
			if st, ok := n.(*ast.StructType); ok {
				for _, f := range st.Fields.List {
					for _, name := range f.Names {
						if name.Name == "damageRefusals" {
							found = true
						}
					}
				}
			}
			return true
		})
		return found
	}()
	require.True(t, hasField, "gateInputs must carry damageRefusals so both callers consume one computation")

	// 3. The verdict path consumes it before any allow can be returned.
	//    (evaluateCommandLine must reference the field; a path that never
	//    reads it is the regression.)
	foundVerdictConsume := false
	var inEval bool
	ast.Inspect(verdictFile, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok {
			inEval = fd.Name.Name == "evaluateCommandLine"
			return true
		}
		if !inEval {
			return true
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "in" && sel.Sel.Name == "damageRefusals" {
				foundVerdictConsume = true
			}
		}
		return true
	})
	require.True(t, foundVerdictConsume,
		"evaluateCommandLine must consult in.damageRefusals — the verdict path answering "+
			"\"allow\" over a damaged bucket is the exact bug this guards")

	// 4. The enforcement path (runGate) consumes the SAME field, not a
	//    re-derivation. If runGate recomputes damagedRefusals itself, the
	//    two sites can diverge again (different scoping inputs, ordering,
	//    or a future edit to one and not the other).
	mainFset := token.NewFileSet()
	mainFile, err := parser.ParseFile(mainFset, "main.go", nil, 0)
	require.NoError(t, err)

	var inRunGate, runGateConsumes, runGateRecomputes bool
	ast.Inspect(mainFile, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok {
			inRunGate = fd.Name.Name == "runGate"
			return true
		}
		if !inRunGate {
			return true
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "in" && sel.Sel.Name == "damageRefusals" {
				runGateConsumes = true
			}
		}
		if ce, ok := n.(*ast.CallExpr); ok {
			if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "damagedRefusals" {
				runGateRecomputes = true
			}
		}
		return true
	})
	require.True(t, runGateConsumes,
		"runGate must consume in.damageRefusals (the shared computation) rather than "+
			"re-deriving damage")
	require.False(t, runGateRecomputes,
		"runGate must not recompute damagedRefusals itself — a second call site is a "+
			"second chance for the paths to diverge (and double-logs the damage)")
}

// TestEveryStoreConsumerConsultsDamage is the STRUCTURAL, enumerated form
// of the drift guard (FIX 3): instead of listing entrypoints by name —
// which is exactly how `veto scan` escaped the first guard — it parses
// every non-test file in cmd/veto, finds every function that obtains an
// intel.Store (via a buildStore/buildStoreFn call or an intel.Store-typed
// declaration), and asserts each consults .Damaged(). A future entrypoint
// that builds a store, checks the sanity floor, and stops — without the
// damage check — fails this test by construction, not by omission from a
// list of names. This guard was lost once to a mutation-restore wipe and
// caught a real fourth consumer (runStatus) the first time it ran.
func TestEveryStoreConsumerConsultsDamage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files, "no .go files found in cmd/veto; the guard is broken")

	// Producers/consumers exempt from the Damaged() requirement:
	//   - buildStore: constructs the store; it has nothing to consult.
	//   - refreshStoreWithFreshnessWindow: shared plumbing every consumer
	//     calls (refresh + marker); not a decision-maker. Its callers are
	//     each guarded individually.
	// This list is reviewable surface: adding a name here must justify
	// why that consumer may ignore damage.
	exempt := map[string]bool{
		"buildStore":                      true,
		"refreshStoreWithFreshnessWindow": true,
	}

	type consumer struct {
		file string
		fn   string
	}
	var consumers []consumer

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Errorf("%s does not parse: %v", f, err)
			continue
		}

		var currentFn string
		var fnGetsStore, fnConsultsDamage, hasRefreshBasis bool

		// Helpers that receive an already-refreshed store from their
		// callers (gateInputsFor: both call sites refresh first).
		helperWithRefreshedCallers := map[string]bool{
			"gateInputsFor": true,
		}
		flush := func() {
			if fnGetsStore && currentFn != "" && !exempt[currentFn] {
				consumers = append(consumers, consumer{file: f, fn: currentFn})
				if !fnConsultsDamage {
					t.Errorf("%s: %s obtains an intel.Store but never consults Damaged() — "+
						"a consumer over a damaged index silently degrades coverage (FIX 3: "+
						"this is how `veto scan` escaped the named-entrypoint guard)", f, currentFn)
				}
				// grok round-3 finding: consulting Damaged() on a store that was
				// never refreshed is a dead consult — Damaged() reports the
				// last refresh, so a consumer that builds and reads without
				// refreshing always sees nil and the check is theater. Every
				// consumer must have a refresh basis: its own Refresh/
				// refreshStoreWithFreshnessWindow call, or helper status
				// (gateInputsFor — its callers refresh before calling).
				if !fnConsultsDamage || !hasRefreshBasis {
					if !hasRefreshBasis && helperWithRefreshedCallers[currentFn] {
						// ok: helper of a refreshing caller
					} else if !hasRefreshBasis {
						t.Errorf("%s: %s consults Damaged() but never refreshes — "+
							"a dead consult on a never-refreshed store always sees nil "+
							"(grok round-3: runStatus reported a clean store over damage)", f, currentFn)
					}
				}
			}
			fnGetsStore, fnConsultsDamage, hasRefreshBasis = false, false, false
		}

		ast.Inspect(af, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok {
				flush()
				currentFn = fd.Name.Name
				return true
			}
			if currentFn == "" {
				return true
			}
			// Obtains a store: calls a producer (in an assignment or a
			// declaration), or declares an intel.Store-typed variable.
			if ce, ok := n.(*ast.CallExpr); ok {
				if id, ok := ce.Fun.(*ast.Ident); ok && (id.Name == "buildStore" || id.Name == "buildStoreFn") {
					fnGetsStore = true
				}
			}
			if vs, ok := n.(*ast.ValueSpec); ok {
				for _, v := range vs.Values {
					if id, ok := v.(*ast.Ident); ok && (id.Name == "buildStore" || id.Name == "buildStoreFn") {
						fnGetsStore = true
					}
				}
				if sel, ok := vs.Type.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "intel" && sel.Sel.Name == "Store" {
						fnGetsStore = true
					}
				}
			}
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, r := range as.Rhs {
					if id, ok := r.(*ast.Ident); ok && (id.Name == "buildStore" || id.Name == "buildStoreFn") {
						fnGetsStore = true
					}
					if ce, ok := r.(*ast.CallExpr); ok {
						if id, ok := ce.Fun.(*ast.Ident); ok && (id.Name == "buildStore" || id.Name == "buildStoreFn") {
							fnGetsStore = true
						}
					}
				}
			}
			// Consults damage.
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Damaged" {
					// Receiver-bind the consult: it must be a method on a store
					// variable (e.g. store.Damaged()), not any selector named
					// Damaged on an unrelated receiver. The receiver just has
					// to be an identifier here; the consumer detection above
					// already established this function holds an intel.Store.
					if _, ok := sel.X.(*ast.Ident); ok {
						fnConsultsDamage = true
					}
				}
				if sel.Sel.Name == "Refresh" {
					hasRefreshBasis = true
				}
			}
			if ce, ok := n.(*ast.CallExpr); ok {
				if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "refreshStoreWithFreshnessWindow" {
					hasRefreshBasis = true
				}
			}
			return true
		})
		flush()
	}

	require.NotEmpty(t, consumers,
		"the guard found no store consumers; it is broken and must be fixed, not deleted")
	t.Logf("guard covered %d store consumers across cmd/veto", len(consumers))
}
