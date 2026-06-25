// Package pmlist is the single source of truth for "what binary names
// does veto recognise as a package manager." It exists to prevent the
// drift hazard documented in M1: prior to this package the same set
// was hand-maintained in five separate spots (isShimName in main.go,
// shimmedManagers in shims.go, wrappedManagers in install_wrappers.go,
// PM_NAMES in the C interposer, and shimmedPMs in the claudecode hook)
// — so a B2-style addition (python/python3) or B5-style addition (rush)
// had to be applied in five places, and any one omission would open a
// silent bypass.
//
// Layout of the canonical sets:
//
//   - Shimmed     — every PM we install Layer-2 PATH shims for and that
//     main()'s shim-dispatch must recognise. Includes
//     python/python3 because `python -m pip install …` is
//     the canonical install form inside virtualenvs and
//     Dockerfiles; main() fast-paths every non-`-m {pm}`
//     python call so the shim doesn't slow down REPLs,
//     `-V`, `-c`, scripts, `-m http.server`, etc.
//
//   - Wrapped     — every PM we install Layer-4 real-binary wrappers
//     for. Mostly identical to Shimmed, with python/python3
//     also wrapped: closing the uv-venv bypass requires
//     wrapping the canonical uv-managed cpython binaries
//     too, so the wrapper-on-disk approach has to cover
//     every python flavor we shim. main()'s `-m {pm}`
//     fast-path keeps non-install python invocations
//     cheap — the per-invocation cost is real but
//     bounded.
//
//   - Interposer  — every PM the Layer-3 native interposer (and the
//     Layer-1 claudecode hook) must recognise as "could
//     be a risky invocation; classify further." A
//     superset of Shimmed that also includes rush /
//     rushx — rush isn't a PM we install a shim/wrapper
//     for (rush projects are rare and use their own
//     bootstrapping), but if a process spawns one
//     directly we still want is_risky() / Analyze() to
//     route the install verbs through veto.
//
// Versioned python aliases:
//
// Pythons commonly appear on disk as `python3.{8,9,10,11,12}` aliases
// (uv-managed cpython, pyenv installs, distro packages). MatchesShim /
// MatchesWrapped / MatchesInterposer recognise these via a strict
// `python3\.\d+(\.\d+)?` regex in addition to static-list membership,
// so a `python3.12 -m pip install …` invocation routes through veto
// regardless of which python the venv resolved to. The static slices
// stay the canonical install-output / codegen seed; the regex applies
// only at lookup time.
//
// All three sets are exported as both slices (stable order for install
// output and code generation) and presence maps (fast set membership
// for hot paths). The slices are the source of truth; the maps are
// derived in init().
//
// CGo / C-header generation: the interposer's PM_NAMES array is
// regenerated from InterposerPMs by `go generate
// ./internal/interposer/...` (see internal/interposer/generate.go). The
// Makefile runs `go generate` before compiling the dylib/so, so the
// canonical Go list is authoritative for the C side too — there is no
// hand-edited C list to drift. The versioned-python regex is handled
// separately by C's is_risky() so PM_NAMES doesn't need to be
// regenerated every time a user installs a new uv python.
package pmlist

import "regexp"

// Shimmed lists every package-manager binary that:
//   - main()'s isShimName() must recognise so shim-dispatch works.
//   - `veto install-shims` creates a symlink for.
//
// Order is the stable install-output order; do not sort.
var Shimmed = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
	"python", "python3",
}

// Wrapped lists every package-manager binary that `veto
// install-wrappers` will atomically replace on disk.
//
// python and python3 are wrapped (in addition to being shimmed) so the
// uv-venv bypass is closed. Background: uv's venvs symlink (or copy)
// the canonical uv-managed cpython binary in
// ~/.local/share/uv/python/cpython-*/bin/python3.X, so an
// `uv run python -c "..."` invocation reaches the venv python by an
// absolute path that bypasses PATH (Layer 2) entirely. Wrapping the
// canonical cpython binary closes that hole.
//
// The cost is real: every python invocation now resolves through veto's
// binary load + main() dispatch before fast-pathing to the real
// interpreter via pythonDashMTarget(). The user has accepted that cost
// in exchange for closing the bypass — main()'s `-m {pm}` fast-path
// (see cmd/veto/main.go) keeps every non-install invocation cheap (no
// intel store touch, no config parse beyond loadConfig).
//
// pmsurvey.PathsFor("python3.X") walks the uv canonical store in
// addition to PATH so install-wrappers covers the canonical pythons
// without depending on `python` / `python3` being in PATH at all.
var Wrapped = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
	"python", "python3",
}

// InterposerPMs lists every package-manager binary the Layer-3
// interposer (C) and Layer-1 claudecode hook (Go) must classify
// further. Superset of Shimmed: also includes rush/rushx, which veto
// does not install shims/wrappers for but DOES still want to gate
// when a process spawns them directly.
//
// This slice is the source the `go generate` step uses to emit the
// C header consumed by veto_interpose.c — see
// internal/interposer/generate.go and the resulting pm_names.h.
var InterposerPMs = []string{
	"npm", "npx", "yarn", "pnpm", "pnpx",
	"rush", "rushx", "bun", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
	"go", "cargo",
	"python", "python3",
}

// pythonVersionedRe matches the conventional versioned python aliases:
// "python3.10", "python3.11.2", etc. Deliberately strict:
//
//   - "python3" (no minor) is excluded so the static list stays the
//     canonical match for the base name (avoids two truths for the
//     same string).
//   - "python3.X-foo", "python3.Xa", "python4", "python3-config" all
//     fail the regex.
//   - At most one trailing "(.N)" segment, so "python3.10.2.4" fails.
//
// Used by MatchesShim / MatchesWrapped / MatchesInterposer; the regex
// is compiled once at package init for the hot path.
var pythonVersionedRe = regexp.MustCompile(`^python3\.\d+(\.\d+)?$`)

// shimmedSet, wrappedSet, interposerSet are the hot-path membership
// lookups. Built once at init from the slices above so the slices stay
// the source of truth.
var (
	shimmedSet    map[string]struct{}
	wrappedSet    map[string]struct{}
	interposerSet map[string]struct{}
)

func init() {
	shimmedSet = sliceToSet(Shimmed)
	wrappedSet = sliceToSet(Wrapped)
	interposerSet = sliceToSet(InterposerPMs)
}

func sliceToSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// IsShimmed reports whether name is one of the binaries `veto
// install-shims` wires up. Static-list only — does NOT match the
// versioned `python3.X` pattern. Callers in the hot path that need to
// recognise versioned pythons (main()'s shim-dispatch, the claudecode
// hook's risk classifier) must use MatchesShim instead. This helper
// stays in place for code that genuinely needs the canonical install
// set (e.g. iterating the install output's row order).
func IsShimmed(name string) bool {
	_, ok := shimmedSet[name]
	return ok
}

// IsWrapped reports whether name is one of the binaries `veto
// install-wrappers` will replace on disk. Static-list only — does
// NOT match `python3.X`. See MatchesWrapped for the pattern-aware
// variant.
func IsWrapped(name string) bool {
	_, ok := wrappedSet[name]
	return ok
}

// IsInterposerPM reports whether name is one of the binaries the
// Layer-3 interposer / Layer-1 hook recognise as "potentially risky;
// classify further." Static-list only. See MatchesInterposer for the
// pattern-aware variant.
func IsInterposerPM(name string) bool {
	_, ok := interposerSet[name]
	return ok
}

// MatchesShim reports whether name should be treated as a shim-eligible
// PM by main()'s dispatch. Returns true for any static-list member OR
// any name matching the versioned python pattern (`python3.10`,
// `python3.11.2`, …).
//
// Hot-path callers (main()'s isShimName, the claudecode hook's
// classifier) consume this so a `python3.12` shim — installed by
// `veto install-shims` enumerating uv-managed cpython versions —
// routes through veto's shim dispatch instead of being dropped.
func MatchesShim(name string) bool {
	if _, ok := shimmedSet[name]; ok {
		return true
	}
	return pythonVersionedRe.MatchString(name)
}

// MatchesWrapped reports whether name should be treated as a
// wrapper-eligible PM. Returns true for static-list members OR
// versioned python aliases. install-wrappers consumes this when
// validating that a discovered candidate basename is one we'd actually
// wrap.
func MatchesWrapped(name string) bool {
	if _, ok := wrappedSet[name]; ok {
		return true
	}
	return pythonVersionedRe.MatchString(name)
}

// MatchesInterposer reports whether name should be classified further
// by the Layer-3 interposer / Layer-1 hook. Returns true for
// static-list members OR versioned python aliases.
//
// The C interposer implements an equivalent regex check in is_risky()
// (see internal/interposer/csrc/veto_interpose.c) rather than baking
// every on-disk python3.X into PM_NAMES — that approach would make the
// generated header churn whenever a user installs a new uv python.
func MatchesInterposer(name string) bool {
	if _, ok := interposerSet[name]; ok {
		return true
	}
	return pythonVersionedRe.MatchString(name)
}

// IsVersionedPython reports whether name matches the strict
// `python3.X` (or `python3.X.Y`) pattern. Exposed so callers that need
// to distinguish "versioned alias" from "canonical python/python3"
// (e.g. install-shims enumeration, install-wrappers candidate
// classification) can branch without duplicating the regex.
func IsVersionedPython(name string) bool {
	return pythonVersionedRe.MatchString(name)
}
