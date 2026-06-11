package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	for _, tgt := range targets {
		if err := ctx.Err(); err != nil {
			logger.Warn().Err(err).Msg(".pth wheel preflight: timed out; allowing (fail-open)")
			break
		}
		verdict, err := downloadAndInspectWheel(ctx, realPip, workdir, tgt)
		if err != nil {
			logger.Warn().Err(err).Str("spec", tgt.spec()).Msg(".pth wheel preflight: fetch/inspect failed; skipping this package")
			continue
		}
		if verdict.Severity == pthscan.SeverityCritical {
			flagged = append(flagged, wheelFinding{spec: tgt.spec(), verdict: verdict})
		}
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

// downloadAndInspectWheel downloads one package's wheel with `pip download
// --no-deps --only-binary :all:` (no sdist building; wheels only) into
// workdir and inspects it in memory. The wheel is never installed.
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return pthscan.Verdict{}, fmt.Errorf("pip download %s: %w (%s)", tgt.spec(), err, truncateForError(string(out), 400))
	}

	whlPath, err := newlyWrittenWhl(workdir, before)
	if err != nil {
		return pthscan.Verdict{}, err
	}
	if whlPath == "" {
		return pthscan.Verdict{}, fmt.Errorf("pip download %s produced no wheel (only-binary forbids sdist; package may not publish wheels)", tgt.spec())
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
