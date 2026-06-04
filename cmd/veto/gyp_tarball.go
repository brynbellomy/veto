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

	"github.com/brynbellomy/veto/internal/gypscan"
	"github.com/brynbellomy/veto/internal/gypscan/tarball"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// gypTarballScanTimeout bounds the whole tarball-fetch-and-inspect pass. Each
// `npm pack` is a network download; the cap keeps a slow registry from
// stalling the install indefinitely. The pass is best-effort and fails open
// on its own errors (see gypTarballPreflight), so a timeout does not refuse.
const gypTarballScanTimeout = 90 * time.Second

// gypTarballScanEnabled reports whether install-time tarball inspection for
// the binding.gyp worm is on. It is ENABLED BY DEFAULT for the argv-direct
// installs (the cheap, high-value case: `npm install <pkg>` fetching a
// freshly-compromised version). Set VETO_GYP_TARBALL_SCAN=0/off/false to
// disable, or =full to also fetch every newly-resolved transitive (slower:
// one `npm pack` per package).
func gypTarballScanMode() (enabled bool, full bool) {
	switch os.Getenv("VETO_GYP_TARBALL_SCAN") {
	case "0", "off", "false", "no":
		return false, false
	case "full", "all", "transitive":
		return true, true
	default:
		return true, false
	}
}

// gypTarballPreflight fetches and inspects npm package tarballs for the
// phantom-gyp / Miasma worm BEFORE the real install extracts them and node-gyp
// runs their binding.gyp. It is the install-time complement to the
// node_modules walker (gypPreflight): the resolver pre-scan is
// --package-lock-only, so a freshly-resolved package's files never hit disk
// for the walker to see — this closes that gap by fetching the tarball with
// `npm pack --ignore-scripts` (download only, runs nothing) and inspecting it
// in memory.
//
// Scope: by default only the argv-direct installs (resolved to concrete
// versions by the pre-scan when available, else the argv version). With
// VETO_GYP_TARBALL_SCAN=full, every resolved install is fetched.
//
// Returns true when the install must be refused. Fail-OPEN on its own errors
// (network failure, npm pack error, timeout): this is an additional heuristic
// layer, and a registry hiccup must not block every install. A confirmed
// critical worm match always refuses.
func gypTarballPreflight(
	logger zerolog.Logger,
	w io.Writer,
	cfg config,
	directInstalls []packagemanager.Install,
	resolvedInstalls []packagemanager.Install,
) bool {
	enabled, full := gypTarballScanMode()
	if !enabled {
		return false
	}

	targets := selectTarballTargets(directInstalls, resolvedInstalls, full)
	if len(targets) == 0 {
		return false
	}

	realNpm, err := findRealBinary("npm", wrapperRegisteredFunc(cfg))
	if err != nil {
		logger.Warn().Err(err).Msg("gyp tarball preflight: cannot locate real npm; skipping")
		return false
	}

	workdir, err := os.MkdirTemp("", "veto-gyp-pack-*")
	if err != nil {
		logger.Warn().Err(err).Msg("gyp tarball preflight: mkdtemp failed; skipping")
		return false
	}
	defer os.RemoveAll(workdir)

	ctx, cancel := context.WithTimeout(context.Background(), gypTarballScanTimeout)
	defer cancel()

	var flagged []tarballFinding
	for _, tgt := range targets {
		if err := ctx.Err(); err != nil {
			logger.Warn().Err(err).Msg("gyp tarball preflight: timed out; allowing (fail-open)")
			break
		}
		verdict, err := fetchAndInspect(ctx, realNpm, workdir, tgt)
		if err != nil {
			logger.Warn().Err(err).Str("spec", tgt.spec()).Msg("gyp tarball preflight: fetch/inspect failed; skipping this package")
			continue
		}
		if verdict.Severity == gypscan.SeverityCritical {
			flagged = append(flagged, tarballFinding{spec: tgt.spec(), verdict: verdict})
		}
	}

	if len(flagged) == 0 {
		return false
	}
	printTarballRefusal(w, flagged)
	return true
}

// tarballTarget is one (name, version) to fetch and inspect.
type tarballTarget struct {
	name    string
	version string
}

func (t tarballTarget) spec() string {
	if t.version == "" {
		return t.name
	}
	return t.name + "@" + t.version
}

type tarballFinding struct {
	spec    string
	verdict gypscan.Verdict
}

// selectTarballTargets builds the set of packages to fetch. Direct installs
// are always included; with full=true, every resolved install is too. A
// direct install's version is upgraded to the resolver-resolved concrete
// version when the pre-scan produced one, so we inspect exactly what will be
// installed rather than a range.
func selectTarballTargets(direct, resolved []packagemanager.Install, full bool) []tarballTarget {
	resolvedVer := map[string]string{}
	for _, ins := range resolved {
		if ins.Ref.Ecosystem == intel.EcosystemNPM && ins.Ref.Name != "" && ins.Ref.Version != "" {
			resolvedVer[ins.Ref.Name] = ins.Ref.Version
		}
	}

	seen := map[string]struct{}{}
	var out []tarballTarget
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
		out = append(out, tarballTarget{name: name, version: version})
	}

	for _, ins := range direct {
		if ins.Ref.Ecosystem != intel.EcosystemNPM || ins.LocalPath || ins.OpaqueRemote {
			continue
		}
		add(ins.Ref.Name, ins.Ref.Version)
	}
	if full {
		for _, ins := range resolved {
			if ins.Ref.Ecosystem != intel.EcosystemNPM || ins.LocalPath || ins.OpaqueRemote {
				continue
			}
			add(ins.Ref.Name, ins.Ref.Version)
		}
	}
	return out
}

// fetchAndInspect downloads one package tarball with `npm pack
// --ignore-scripts` (download only; runs no lifecycle scripts and no
// node-gyp) into workdir, then inspects it in memory. The tarball is never
// extracted to a runnable tree.
func fetchAndInspect(ctx context.Context, realNpm, workdir string, tgt tarballTarget) (gypscan.Verdict, error) {
	before, err := tgzSet(workdir)
	if err != nil {
		return gypscan.Verdict{}, err
	}
	cmd := exec.CommandContext(ctx, realNpm, "pack", tgt.spec(),
		"--ignore-scripts", "--pack-destination", workdir, "--silent")
	cmd.Dir = workdir
	cmd.Env = sanitizedEnv(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		return gypscan.Verdict{}, fmt.Errorf("npm pack %s: %w (%s)", tgt.spec(), err, truncateForError(string(out), 400))
	}

	tgzPath, err := newlyWrittenTgz(workdir, before)
	if err != nil {
		return gypscan.Verdict{}, err
	}
	if tgzPath == "" {
		return gypscan.Verdict{}, fmt.Errorf("npm pack %s produced no tarball", tgt.spec())
	}

	f, err := os.Open(tgzPath)
	if err != nil {
		return gypscan.Verdict{}, err
	}
	defer f.Close()
	defer os.Remove(tgzPath)
	return tarball.Inspect(f)
}

// tgzSet returns the set of .tgz file names currently in dir.
func tgzSet(dir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".tgz" {
			set[e.Name()] = struct{}{}
		}
	}
	return set, nil
}

// newlyWrittenTgz returns the path of the .tgz that appeared in dir since the
// before-set was captured, or "" if none. Isolating by diff handles the case
// where an earlier target left a tarball behind that fetchAndInspect failed to
// remove.
func newlyWrittenTgz(dir string, before map[string]struct{}) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".tgz" {
			continue
		}
		if _, existed := before[e.Name()]; !existed {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", nil
}

// printTarballRefusal renders the install-time tarball worm refusal.
func printTarballRefusal(w io.Writer, findings []tarballFinding) {
	fmt.Fprintln(w, "veto: install refused — a package about to be installed carries a binding.gyp worm (phantom-gyp / Miasma):")
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
	fmt.Fprintln(w, "\nThis package's binding.gyp would execute at install time via node-gyp, even with")
	fmt.Fprintln(w, "--ignore-scripts. The tarball was downloaded for inspection only and never run.")
	fmt.Fprintln(w, "Do NOT install it. The package name may be a trusted one compromised via account")
	fmt.Fprintln(w, "takeover; verify against published IOC lists before trusting any nearby version.")
}
