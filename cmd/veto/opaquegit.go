package main

import (
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// filterRegistryInstalls keeps only intel-eligible (registry) installs from a
// clone-scan's expanded lockfile, dropping LocalPath and OpaqueRemote nodes —
// the git root crate and any nested git dependencies. Those are the code the
// user explicitly chose to install; per the "registry deps only" scope they
// are accepted without a name lookup, and the registry crates they pull are
// what gets gated.
func filterRegistryInstalls(in []packagemanager.Install) []packagemanager.Install {
	out := make([]packagemanager.Install, 0, len(in))
	for _, ins := range in {
		if ins.LocalPath || ins.OpaqueRemote || ins.Ref.Name == "" {
			continue
		}
		out = append(out, ins)
	}
	return out
}
