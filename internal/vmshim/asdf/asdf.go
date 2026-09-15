// Package asdf implements vmshim.Manager for asdf (https://asdf-vm.com).
//
// asdf shims are small shell scripts under `$ASDF_DATA_DIR/shims` that
// `exec asdf exec <tool>`; `asdf which <tool>` reports the binary that
// exec would run from the current directory's `.tool-versions`, exiting
// non-zero ("No version is set for command …") when none applies.
package asdf

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/veto/internal/vmshim"
)

// Manager is the asdf shim protocol.
type Manager struct {
	shimsDir   string
	dispatcher string
}

var _ vmshim.Manager = (*Manager)(nil)

// Options tunes where the manager looks; empty fields use the
// conventional asdf layout.
type Options struct {
	// ShimsDir is the directory holding asdf's shims. Empty derives it
	// from $ASDF_DATA_DIR (or ~/.asdf) + "/shims".
	ShimsDir string
	// Dispatcher is the asdf binary to probe. Empty uses `asdf` on PATH.
	Dispatcher string
}

// New returns a Manager using the conventional asdf layout.
func New() *Manager { return NewWithOptions(Options{}) }

// NewWithOptions returns a Manager with explicit locations.
func NewWithOptions(opts Options) *Manager {
	return &Manager{shimsDir: opts.ShimsDir, dispatcher: opts.Dispatcher}
}

// Name implements vmshim.Manager.
func (m *Manager) Name() string { return "asdf" }

// OwnsShim implements vmshim.Manager: the candidate lives in asdf's
// shims dir.
func (m *Manager) OwnsShim(candidate, _ string) bool {
	if dir := m.shimsDirOrDefault(); dir != "" && filepath.Dir(filepath.Clean(candidate)) == filepath.Clean(dir) {
		return true
	}
	return strings.Contains(candidate, "/.asdf/shims/")
}

// Which implements vmshim.Manager via `asdf which <name>`.
func (m *Manager) Which(ctx context.Context, _ string, name, dir string, env []string) (string, error) {
	return vmshim.RunWhich(ctx, m.Name(), m.dispatcherPath(), []string{"which", name}, name, dir, env)
}

func (m *Manager) shimsDirOrDefault() string {
	if m.shimsDir != "" {
		return m.shimsDir
	}
	if data := os.Getenv("ASDF_DATA_DIR"); data != "" {
		return filepath.Join(data, "shims")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".asdf", "shims")
}

func (m *Manager) dispatcherPath() string {
	if m.dispatcher != "" {
		return m.dispatcher
	}
	if p, err := exec.LookPath("asdf"); err == nil {
		return p
	}
	return ""
}
