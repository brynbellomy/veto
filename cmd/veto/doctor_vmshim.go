package main

import (
	"fmt"
	"os"

	"github.com/brynbellomy/veto/internal/vmshim"
)

// checkVersionManagerShims reports, per shimmed PM, what the real-binary
// resolver does when its PATH walk lands on a version-manager shim
// (mise, asdf, pyenv) from the current directory.
//
// The resolver hands off to such a shim only after the manager confirms
// it can name a real binary for the tool here; otherwise the shim is
// skipped, because a manager that cannot resolve falls back to a PATH
// search of its own, finds veto's shim again, and the two exec-loop
// forever. That skip keeps commands working but silently runs whatever
// `<pm>` comes next on PATH — usually a different version than the one
// the project pins — so it is surfaced here as a WARN with the
// manager's own remediation command. This check is cwd-sensitive by
// design: the project config that pins the tool lives in the tree
// doctor is run from.
//
// Rows appear only for PMs whose walk actually met a version-manager
// shim; a PM resolved straight to a real binary or a Layer-4 anchor is
// already covered by the shim:* and wrapper:* rows.
func checkVersionManagerShims(cfg config) []checkResult {
	shimDir := defaultShimDir()
	names := append([]string{}, shimmedManagers...)
	names = append(names, discoverInstalledPythonShims(shimDir)...)
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	return checkVersionManagerShimsWith(names, cwd, wrapperRegisteredFunc(cfg), defaultVMShims())
}

func checkVersionManagerShimsWith(names []string, cwd string, registered func(string) bool, vms vmshim.Registry) []checkResult {
	out := []checkResult{}
	for _, name := range names {
		res, err := resolveRealBinary(name, registered, vms)
		if res.Probed == nil && len(res.Skipped) == 0 {
			continue
		}
		for _, s := range res.Skipped {
			fallback := fmt.Sprintf("veto now runs %s instead", res.Path)
			if err != nil {
				fallback = fmt.Sprintf("no other %s exists on PATH, so the command fails with \"cannot find real %s\"", name, name)
			}
			fix := fmt.Sprintf("Until %s can resolve %s from %s, %s.", s.Manager, name, cwd, fallback)
			if s.Hint != "" {
				fix = fmt.Sprintf("Run `%s` (from %s) so %s can serve %s again; until then %s.", s.Hint, cwd, s.Manager, name, fallback)
			}
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "vm-shim:" + name,
				detail:   fmt.Sprintf("%s shim %s: %s", s.Manager, s.Candidate, s.Reason),
				howToFix: fix,
			})
		}
		if p := res.Probed; p != nil {
			out = append(out, checkResult{
				status: statusPass,
				label:  "vm-shim:" + name,
				detail: fmt.Sprintf("%s shim %s resolves %s to %s here", p.Manager, p.Candidate, name, p.RealPath),
			})
		}
	}
	return out
}
