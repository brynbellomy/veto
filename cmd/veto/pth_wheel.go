package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/pthscan"
	"github.com/brynbellomy/veto/internal/pthscan/wheel"
)

// pthWheelScanTimeout bounds the whole wheel-download-and-inspect pass.
// Each `pip download` is a network fetch; the cap keeps a slow registry
// from stalling the install indefinitely.
const pthWheelScanTimeout = 120 * time.Second

// pthWheelScanDisabled is the sentinel returned by pthWheelScanMode when the
// scan has been explicitly disabled via VETO_PTH_WHEEL_SCAN=off. The caller
// should log and surface this in the install summary so operators can see
// when the prescan is silently inactive.
const pthWheelScanDisabled = "off"

// pthWheelScanMode reads VETO_PTH_WHEEL_SCAN.
//
//   - "off"                   → disabled (the ONLY accepted disable value)
//   - "full" / "all" / "transitive" → fetch every resolved install too
//   - anything else (default) → argv-direct only
//
// Note: legacy boolean-ish values ("0", "false", "no") are no longer treated
// as disable. An unrecognised value is logged and treated as the default
// (argv-direct only) so a typo doesn't silently turn the scan off.
func pthWheelScanMode() (enabled bool, full bool, rawEnv string) {
	v := os.Getenv("VETO_PTH_WHEEL_SCAN")
	switch v {
	case pthWheelScanDisabled:
		return false, false, v
	case "full", "all", "transitive":
		return true, true, v
	default:
		return true, false, v
	}
}

// pthWheelPreflight downloads and inspects wheels for the Hades / Shai-Hulud
// .pth startup-hook worm BEFORE the real install extracts them and the next
// `python` startup loads them. Mirrors the gyp_tarball preflight.
//
// Fail-OPEN on its own errors (network failure, pip error, timeout): this is
// an additive heuristic layer, and a registry hiccup must not block every
// install. Critical findings always refuse.
func pthWheelPreflight(
	logger zerolog.Logger,
	w io.Writer,
	cfg config,
	directInstalls []packagemanager.Install,
	resolvedInstalls []packagemanager.Install,
) bool {
	enabled, full, rawEnv := pthWheelScanMode()
	if !enabled {
		// Log at WARN — disabled prescan is an observable operational event,
		// not a silent state. An attacker that already has env-write can set
		// VETO_PTH_WHEEL_SCAN=off to bypass this layer; make that visible.
		logger.Warn().
			Str("VETO_PTH_WHEEL_SCAN", rawEnv).
			Msg(".pth wheel prescan DISABLED via VETO_PTH_WHEEL_SCAN=off — wheel contents will NOT be inspected before install")
		fmt.Fprintln(w, "veto: WARNING — .pth wheel prescan is DISABLED (VETO_PTH_WHEEL_SCAN=off). Wheels will not be inspected before install.")
		return false
	}
	// Log unrecognised values so a mis-typed env var is caught at the
	// operator level rather than silently falling back to default behaviour.
	if rawEnv != "" && rawEnv != "full" && rawEnv != "all" && rawEnv != "transitive" {
		logger.Warn().
			Str("VETO_PTH_WHEEL_SCAN", rawEnv).
			Msg(".pth wheel prescan: unrecognised VETO_PTH_WHEEL_SCAN value; using default (argv-direct only). Use 'off' to disable, 'full' for transitive scan.")
	}

	targets := selectWheelTargets(directInstalls, resolvedInstalls, full)
	if len(targets) == 0 {
		return false
	}

	realPip, err := findRealBinary("pip", wrapperRegisteredFunc(cfg))
	if err != nil {
		logger.Warn().Err(err).Msg(".pth wheel preflight: cannot locate real pip; skipping")
		return false
	}

	workdir, err := os.MkdirTemp("", "veto-pth-download-*")
	if err != nil {
		logger.Warn().Err(err).Msg(".pth wheel preflight: mkdtemp failed; skipping")
		return false
	}
	defer os.RemoveAll(workdir)

	ctx, cancel := context.WithTimeout(context.Background(), pthWheelScanTimeout)
	defer cancel()

	var flagged []wheelFinding
	var sdistRefused []string
	for _, tgt := range targets {
		if err := ctx.Err(); err != nil {
			logger.Warn().Err(err).Msg(".pth wheel preflight: timed out; allowing (fail-open)")
			break
		}
		verdict, err := downloadAndInspectWheel(ctx, realPip, workdir, tgt)
		if err != nil {
			var sdistErr *errSdistOnly
			if isErrSdistOnly(err, &sdistErr) {
				// Fail-CLOSED: the package has no binary wheel. veto cannot
				// inspect an sdist before install (build-time code runs).
				// Refuse rather than allow. An attacker shipping sdist-only
				// worms would otherwise bypass the prescan entirely.
				logger.Error().
					Err(err).
					Str("spec", tgt.spec()).
					Msg(".pth wheel preflight: sdist-only package; refusing install (cannot inspect before build)")
				sdistRefused = append(sdistRefused, tgt.spec())
				continue
			}
			// Transient error (network, pip crash, timeout on one package) →
			// fail-open so a registry hiccup doesn't block all installs.
			logger.Warn().Err(err).Str("spec", tgt.spec()).Msg(".pth wheel preflight: fetch/inspect failed; skipping this package")
			continue
		}
		if verdict.Severity == pthscan.SeverityCritical {
			flagged = append(flagged, wheelFinding{spec: tgt.spec(), verdict: verdict})
		}
	}

	if len(sdistRefused) > 0 {
		printSdistRefusal(w, sdistRefused)
		return true
	}

	if len(flagged) == 0 {
		return false
	}
	printWheelRefusal(w, flagged)
	return true
}

type wheelTarget struct {
	name    string
	version string
}

func (t wheelTarget) spec() string {
	if t.version == "" {
		return t.name
	}
	return t.name + "==" + t.version
}

type wheelFinding struct {
	spec    string
	verdict pthscan.Verdict
}

func selectWheelTargets(direct, resolved []packagemanager.Install, full bool) []wheelTarget {
	resolvedVer := map[string]string{}
	for _, ins := range resolved {
		if ins.Ref.Ecosystem == intel.EcosystemPyPI && ins.Ref.Name != "" && ins.Ref.Version != "" {
			resolvedVer[ins.Ref.Name] = ins.Ref.Version
		}
	}

	seen := map[string]struct{}{}
	var out []wheelTarget
	add := func(name, version string) {
		if name == "" {
			return
		}
		if v, ok := resolvedVer[name]; ok && version == "" {
			version = v
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, wheelTarget{name: name, version: version})
	}

	for _, ins := range direct {
		if ins.Ref.Ecosystem != intel.EcosystemPyPI || ins.LocalPath || ins.OpaqueRemote {
			continue
		}
		add(ins.Ref.Name, ins.Ref.Version)
	}
	if full {
		for _, ins := range resolved {
			if ins.Ref.Ecosystem != intel.EcosystemPyPI || ins.LocalPath || ins.OpaqueRemote {
				continue
			}
			add(ins.Ref.Name, ins.Ref.Version)
		}
	}
	return out
}

// errSdistOnly is returned by downloadAndInspectWheel when pip successfully
// contacted the index but found no binary wheel — the package is sdist-only.
// This is a sentinel for the caller: unlike a transient fetch error (network
// timeout, registry 5xx, unknown package), sdist-only is a structural
// property of the package that means veto cannot inspect it before install.
// The caller must fail-closed rather than fail-open.
type errSdistOnly struct {
	spec   string
	detail string // pip output excerpt
}

func (e *errSdistOnly) Error() string {
	if e.detail != "" {
		return fmt.Sprintf("pip download %s: no binary wheel available (sdist-only): %s", e.spec, e.detail)
	}
	return fmt.Sprintf("pip download %s: no binary wheel available (package may be sdist-only or require a build backend)", e.spec)
}

// pipOutputIndicatesSdistOnly returns true when pip's combined output contains
// canonical "no binary distribution found" messages. These messages appear
// when --only-binary :all: is specified and no wheel matches the platform.
func pipOutputIndicatesSdistOnly(output string) bool {
	// Canonical pip messages for "no binary wheel exists":
	//   pip 22+: "No matching distribution found for <pkg>"
	//   pip 22+: "Could not find a version that satisfies the requirement <pkg>"
	//   pip 22+: "ERROR: Could not find a version …" (--no-color is not set so may have ANSI)
	//   pip hint: "Note: This would have installed a sdist …" (--only-binary :all: hint)
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no matching distribution") ||
		strings.Contains(lower, "could not find a version that satisfies") ||
		strings.Contains(lower, "no matching distribution found") ||
		strings.Contains(lower, "sdist") // pip hint: "would have installed a sdist"
}

// downloadAndInspectWheel downloads one package's wheel with `pip download
// --no-deps --only-binary :all:` (no sdist building; wheels only) into
// workdir and inspects it in memory. The wheel is never installed.
//
// Returns *errSdistOnly when the package has no binary wheel (sdist-only).
// The caller MUST fail-closed on that sentinel — not skip-and-continue.
func downloadAndInspectWheel(ctx context.Context, realPip, workdir string, tgt wheelTarget) (pthscan.Verdict, error) {
	before, err := whlSet(workdir)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	cmd := exec.CommandContext(ctx, realPip,
		"download", tgt.spec(),
		"--no-deps", "--only-binary", ":all:",
		"--dest", workdir, "--quiet",
		"--disable-pip-version-check",
	)
	cmd.Dir = workdir
	cmd.Env = sanitizedEnv(os.Environ())
	pipOut, pipErr := cmd.CombinedOutput()
	if pipErr != nil {
		// pip exited non-zero. Distinguish "no wheel" from "transient error".
		if pipOutputIndicatesSdistOnly(string(pipOut)) {
			return pthscan.Verdict{}, &errSdistOnly{
				spec:   tgt.spec(),
				detail: truncateForError(string(pipOut), 200),
			}
		}
		return pthscan.Verdict{}, fmt.Errorf("pip download %s: %w (%s)", tgt.spec(), pipErr, truncateForError(string(pipOut), 400))
	}

	whlPath, err := newlyWrittenWhl(workdir, before)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	if whlPath == "" {
		// pip exited 0 but wrote no wheel. This can happen when:
		//   - the package only publishes sdists (pip --only-binary :all: succeeds
		//     but produces nothing on some pip versions)
		//   - a wheel was already present in workdir and pip treated it as cached
		//     (we guard against that with the before-set diff, so this is the former)
		// Treat as sdist-only: fail-closed.
		return pthscan.Verdict{}, &errSdistOnly{
			spec:   tgt.spec(),
			detail: truncateForError(string(pipOut), 200),
		}
	}

	f, err := os.Open(whlPath)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	defer f.Close()
	defer os.Remove(whlPath)
	info, err := f.Stat()
	if err != nil {
		return pthscan.Verdict{}, err
	}
	return wheel.Inspect(f, info.Size())
}

func whlSet(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".whl" {
			set[e.Name()] = struct{}{}
		}
	}
	return set, nil
}

func newlyWrittenWhl(dir string, before map[string]struct{}) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".whl" {
			continue
		}
		if _, existed := before[e.Name()]; !existed {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", nil
}

func printWheelRefusal(w io.Writer, findings []wheelFinding) {
	fmt.Fprintln(w, "veto: install refused — a wheel about to be installed carries a .pth startup-hook worm (Hades / Shai-Hulud):")
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", f.spec)
		for _, sig := range f.verdict.Signals {
			val := sig.Detail
			if sig.Excerpt != "" {
				val = sig.Detail + " — " + sig.Excerpt
			}
			fmt.Fprintf(w, "      [%s] %s\n", sig.Code, val)
		}
	}
	fmt.Fprintln(w, "\nThis wheel ships a `.pth` that Python would exec() at every interpreter startup,")
	fmt.Fprintln(w, "so installing it would detonate the worm on the next `python` call. The wheel was")
	fmt.Fprintln(w, "downloaded for inspection only and never installed. Do NOT install it; the package")
	fmt.Fprintln(w, "name may be a trusted one compromised via account takeover.")
}

// isErrSdistOnly unwraps err and sets *target to the *errSdistOnly if present.
// Uses type-assertion rather than errors.As to avoid importing errors; this
// function and errSdistOnly are in the same package so direct assertion is fine.
func isErrSdistOnly(err error, target **errSdistOnly) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*errSdistOnly)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// printSdistRefusal renders the refusal message for sdist-only packages.
func printSdistRefusal(w io.Writer, specs []string) {
	fmt.Fprintln(w, "veto: install refused — one or more packages publish only source distributions (sdists) and cannot be inspected before install:")
	for _, s := range specs {
		fmt.Fprintf(w, "  - %s\n", s)
	}
	fmt.Fprintln(w, "\nveto's .pth wheel prescan requires a binary wheel to inspect. An sdist is built")
	fmt.Fprintln(w, "at install time, which means arbitrary code in setup.py / build backends runs")
	fmt.Fprintln(w, "before veto can inspect any .pth files it installs. To proceed, either:")
	fmt.Fprintln(w, "  1. Confirm the package is safe via an out-of-band channel and use `pip install`")
	fmt.Fprintln(w, "     directly (bypassing veto — do this only if you understand the risk).")
	fmt.Fprintln(w, "  2. Build the sdist into a wheel locally (`pip wheel <pkg>`) and install the wheel.")
}
