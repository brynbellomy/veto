// Package mise implements vmshim.Manager for mise (https://mise.jdx.dev).
//
// mise shims are symlinks from `$MISE_DATA_DIR/shims/<tool>` to the mise
// binary itself; mise reads argv[0] to learn which tool to dispatch. The
// dispatcher we probe is therefore the resolved shim target whenever it
// is named `mise`, so a host with several mise binaries on PATH is probed
// with the one that would actually have run.
package mise

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/veto/internal/vmshim"
)

// Manager is the mise shim protocol.
type Manager struct {
	shimsDir   string // explicit shims dir; "" = derive from env/home
	dispatcher string // explicit mise binary; "" = derive from the shim
}

var _ vmshim.Manager = (*Manager)(nil)

// Options tunes where the manager looks. Both fields default to the
// conventional mise layout when empty.
type Options struct {
	// ShimsDir is the directory holding mise's shims. Empty derives it
	// from $MISE_DATA_DIR (or ~/.local/share/mise) + "/shims".
	ShimsDir string
	// Dispatcher is the mise binary to probe. Empty uses the shim's own
	// resolved target when that is a `mise` binary, else `mise` on PATH.
	Dispatcher string
}

// New returns a Manager using the conventional mise layout.
func New() *Manager { return NewWithOptions(Options{}) }

// NewWithOptions returns a Manager with explicit locations.
func NewWithOptions(opts Options) *Manager {
	return &Manager{shimsDir: opts.ShimsDir, dispatcher: opts.Dispatcher}
}

// Name implements vmshim.Manager.
func (m *Manager) Name() string { return "mise" }

// OwnsShim implements vmshim.Manager. A candidate is a mise shim when it
// lives in the shims dir or when it resolves to a binary named `mise`
// (the shims are symlinks to the mise executable).
func (m *Manager) OwnsShim(candidate, resolved string) bool {
	if filepath.Base(resolved) == "mise" {
		return true
	}
	if dir := m.shimsDirOrDefault(); dir != "" && filepath.Dir(filepath.Clean(candidate)) == filepath.Clean(dir) {
		return true
	}
	return strings.Contains(candidate, "/mise/shims/")
}

// Which implements vmshim.Manager via `mise which <name>`, which mirrors
// the shim's own resolution: it loads the config files visible from dir
// and names the pinned tool's executable, exiting non-zero when the
// installed version does not provide it.
func (m *Manager) Which(ctx context.Context, candidate, name, dir string, env []string) (string, error) {
	return vmshim.RunWhich(ctx, m.Name(), m.dispatcherFor(candidate), []string{"which", name}, name, dir, env)
}

func (m *Manager) shimsDirOrDefault() string {
	if m.shimsDir != "" {
		return m.shimsDir
	}
	if data := os.Getenv("MISE_DATA_DIR"); data != "" {
		return filepath.Join(data, "shims")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "mise", "shims")
}

// dispatcherFor picks the mise binary to probe: the explicit option, else
// the shim's resolved target when it is mise itself, else `mise` on PATH.
func (m *Manager) dispatcherFor(candidate string) string {
	if m.dispatcher != "" {
		return m.dispatcher
	}
	if resolved, err := filepath.EvalSymlinks(candidate); err == nil && filepath.Base(resolved) == "mise" {
		return resolved
	}
	if p, err := exec.LookPath("mise"); err == nil {
		return p
	}
	return ""
}
