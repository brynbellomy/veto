// Package pyenv implements vmshim.Manager for pyenv
// (https://github.com/pyenv/pyenv).
//
// pyenv shims are shell scripts under `$PYENV_ROOT/shims` that `exec
// pyenv exec <tool>`; `pyenv which <tool>` names the interpreter the
// selected version provides, exiting non-zero ("pyenv: <tool>: command
// not found") when no selected version has it.
package pyenv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/veto/internal/vmshim"
)

// Manager is the pyenv shim protocol.
type Manager struct {
	shimsDir   string
	dispatcher string
}

var _ vmshim.Manager = (*Manager)(nil)

// Options tunes where the manager looks; empty fields use the
// conventional pyenv layout.
type Options struct {
	// ShimsDir is the directory holding pyenv's shims. Empty derives it
	// from $PYENV_ROOT (or ~/.pyenv) + "/shims".
	ShimsDir string
	// Dispatcher is the pyenv binary to probe. Empty uses `pyenv` on PATH.
	Dispatcher string
}

// New returns a Manager using the conventional pyenv layout.
func New() *Manager { return NewWithOptions(Options{}) }

// NewWithOptions returns a Manager with explicit locations.
func NewWithOptions(opts Options) *Manager {
	return &Manager{shimsDir: opts.ShimsDir, dispatcher: opts.Dispatcher}
}

// Name implements vmshim.Manager.
func (m *Manager) Name() string { return "pyenv" }

// OwnsShim implements vmshim.Manager: the candidate lives in pyenv's
// shims dir.
func (m *Manager) OwnsShim(candidate, _ string) bool {
	if dir := m.shimsDirOrDefault(); dir != "" && filepath.Dir(filepath.Clean(candidate)) == filepath.Clean(dir) {
		return true
	}
	return strings.Contains(candidate, "/.pyenv/shims/")
}

// Which implements vmshim.Manager via `pyenv which <name>`.
func (m *Manager) Which(ctx context.Context, _ string, name, dir string, env []string) (string, error) {
	return vmshim.RunWhich(ctx, m.Name(), m.dispatcherPath(), []string{"which", name}, name, dir, env)
}

func (m *Manager) shimsDirOrDefault() string {
	if m.shimsDir != "" {
		return m.shimsDir
	}
	if root := os.Getenv("PYENV_ROOT"); root != "" {
		return filepath.Join(root, "shims")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".pyenv", "shims")
}

func (m *Manager) dispatcherPath() string {
	if m.dispatcher != "" {
		return m.dispatcher
	}
	if p, err := exec.LookPath("pyenv"); err == nil {
		return p
	}
	return ""
}
