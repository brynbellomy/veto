package main

import (
	"go/ast"
	"go/parser"
	"go/token"
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
