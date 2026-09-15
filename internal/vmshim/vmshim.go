// Package vmshim recognizes version-manager shim dispatchers (mise, asdf,
// pyenv) sitting on PATH and asks them which real binary their shim would
// exec, so veto never hands control to a shim that would bounce straight
// back into veto.
//
// Why this exists: veto's Layer-2 shim resolves the real package manager
// by walking PATH and taking the first entry that is not veto itself. On
// a version-manager host that entry is usually the manager's own shim
// (`~/.local/share/mise/shims/go`), which is the documented, intended
// hand-off — the manager picks the project-pinned toolchain and execs
// it. The hand-off is only sound while the manager can actually resolve
// the tool. When it cannot (the pinned version is not installed, or its
// install dir exists but lacks the executable — a GOBIN-only ghost dir),
// mise falls back to a PATH search of its own, finds veto's shim again,
// and the two shims exec each other forever: `go version` hangs with no
// output, and a gated verb re-runs the gate on every lap. The probe in
// this package asks the manager up front and lets the resolver skip the
// shim instead of entering that loop.
//
// The parent package holds the contract and the shared probe runner; each
// manager lives in its own subpackage so a consumer of the contract does
// not inherit any one manager's heuristics.
package vmshim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ProbeTimeout bounds one Which call. A healthy manager answers in tens
// of milliseconds; a manager that is itself wedged (network prompt,
// broken plugin) must not turn the resolver into the very hang it exists
// to prevent.
const ProbeTimeout = 10 * time.Second

// ErrUnresolvable is the sentinel wrapped by every UnresolvableError. A
// manager returns it when it owns the shim but cannot name a real binary
// for the requested tool from the given directory — exactly the state in
// which the manager would fall back to its own PATH search.
var ErrUnresolvable = errors.New("version manager cannot resolve a real binary for this shim")

// UnresolvableError carries the manager's own explanation of why it
// cannot resolve the tool. Detail is the manager's stderr (flattened) and
// Hint is a copy-pasteable remediation extracted from it when the manager
// printed one (mise prints `mise install --force go@1.25.1`).
type UnresolvableError struct {
	Manager string
	Name    string
	Detail  string
	Hint    string
}

// Error implements error.
func (e *UnresolvableError) Error() string {
	msg := fmt.Sprintf("%s cannot resolve %s", e.Manager, e.Name)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// Unwrap lets errors.Is(err, ErrUnresolvable) match.
func (e *UnresolvableError) Unwrap() error { return ErrUnresolvable }

// Manager is one version manager's shim protocol.
//
// Implementations are stateless and safe for concurrent use.
type Manager interface {
	// Name returns the manager's short name as users know it ("mise").
	Name() string

	// OwnsShim reports whether candidate — a PATH entry the resolver is
	// about to exec — is one of this manager's shims. resolved is
	// candidate with symlinks evaluated (equal to candidate when
	// evaluation failed). Pure; consults nothing but the two strings and
	// the manager's configured directories.
	OwnsShim(candidate, resolved string) bool

	// Which asks the manager, evaluated from dir (empty = the current
	// directory), which real binary its shim for name would exec.
	// Blocking, bounded by ctx and ProbeTimeout. env is the exact
	// environment the probe runs under; callers pass a veto-sanitized
	// environment so the probe itself can never be rewritten back into
	// veto. Returns the resolved path on success, an *UnresolvableError
	// (matching ErrUnresolvable) when the manager cannot name a binary,
	// and any other error when the probe could not be run at all
	// (dispatcher missing, deadline expired).
	Which(ctx context.Context, candidate, name, dir string, env []string) (string, error)
}

// Registry is the ordered set of managers the resolver consults. Order
// matters only when two managers claim the same path, which no supported
// layout produces.
type Registry []Manager

// Owner returns the first manager whose OwnsShim accepts the candidate,
// or nil when no manager claims it.
func (r Registry) Owner(candidate, resolved string) Manager {
	for _, m := range r {
		if m.OwnsShim(candidate, resolved) {
			return m
		}
	}
	return nil
}

// RunWhich is the shared probe runner every manager subpackage uses: it
// runs `dispatcher args...` in dir under env with ProbeTimeout applied on
// top of ctx, and interprets the outcome uniformly.
//
//   - exit 0 with a non-empty first stdout line → that line, cleaned, is
//     the resolved path.
//   - any non-zero exit → *UnresolvableError carrying the manager's
//     stderr; a line beginning with `<manager> install` is lifted into
//     Hint.
//   - the dispatcher failing to start, or the deadline expiring → a plain
//     error. Callers decide the fail-safe direction; see the resolver.
func RunWhich(ctx context.Context, manager, dispatcher string, args []string, name, dir string, env []string) (string, error) {
	if dispatcher == "" {
		return "", fmt.Errorf("%s: no dispatcher binary to probe", manager)
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, dispatcher, args...)
	cmd.Dir = dir
	cmd.Env = env
	// A manager that spawns its own children (plugin scripts) can leave
	// them holding our stdout/stderr pipes after the deadline kills the
	// dispatcher; without a WaitDelay, Run would block until those
	// grandchildren exit on their own.
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s which %s: probe timed out after %s", manager, name, ProbeTimeout)
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		line := firstLine(stdout.String())
		if line == "" {
			return "", &UnresolvableError{Manager: manager, Name: name, Detail: "which printed no path"}
		}
		return filepath.Clean(line), nil
	case errors.As(err, &exitErr):
		detail := strings.TrimSpace(stderr.String())
		return "", &UnresolvableError{
			Manager: manager,
			Name:    name,
			Detail:  compactDetail(detail),
			Hint:    extractHint(manager, detail),
		}
	default:
		return "", fmt.Errorf("%s which %s: %w", manager, name, err)
	}
}

// firstLine returns the first non-empty, whitespace-trimmed line of s.
func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// compactDetail flattens multi-line manager stderr into one line so it
// fits a single warning or doctor row. The `mise ERROR ` prefix and the
// trailing version/verbose boilerplate mise appends are dropped.
func compactDetail(detail string) string {
	var parts []string
	for line := range strings.SplitSeq(detail, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "mise ERROR ")
		if line == "" || strings.HasPrefix(line, "Version:") || strings.HasPrefix(line, "Run with --verbose") {
			continue
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, " ")
}

// extractHint returns the first stderr line that reads as a remediation
// command for the manager (`mise install --force go@1.25.1`), or "".
func extractHint(manager, detail string) string {
	for line := range strings.SplitSeq(detail, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, manager+" install") {
			return line
		}
	}
	return ""
}
