package main

import (
	"github.com/brynbellomy/veto/internal/vmshim"
	"github.com/brynbellomy/veto/internal/vmshim/asdf"
	"github.com/brynbellomy/veto/internal/vmshim/mise"
	"github.com/brynbellomy/veto/internal/vmshim/pyenv"
)

// defaultVMShims is the version-manager registry the real-binary
// resolver and `veto doctor` consult. This is the only place the
// concrete managers are wired; everything else speaks vmshim.Registry.
func defaultVMShims() vmshim.Registry {
	return vmshim.Registry{mise.New(), asdf.New(), pyenv.New()}
}
