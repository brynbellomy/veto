package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/bun"
	"github.com/brynbellomy/veto/internal/packagemanager/cargo"
	"github.com/brynbellomy/veto/internal/packagemanager/golang"
	"github.com/brynbellomy/veto/internal/packagemanager/jslock"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
	"github.com/brynbellomy/veto/internal/packagemanager/pipreport"
	"github.com/brynbellomy/veto/internal/packagemanager/pnpm"
	"github.com/brynbellomy/veto/internal/packagemanager/pylock"
	"github.com/brynbellomy/veto/internal/packagemanager/yarn"
)

// TestSanitizedEnv covers the env-scrub helper that execReal applies
// before syscall.Exec. The contract:
//
//   - VETO_PATH must be removed (otherwise the interposer's is_risky()
//     fires again in the child and re-rewrites the call to veto,
//     producing the B6 infinite loop).
//   - VETO_PYTHON_M_ORIGINAL must be removed (belt-and-suspenders for
//     the B2 python-m re-entry concern; execPMOrPythonM already
//     Unsetenv's it, but a future refactor could regress that).
//   - DYLD_INSERT_LIBRARIES and LD_PRELOAD must NOT be touched — we
//     deliberately keep Layer 3 loaded in the child so sibling
//     processes spawned by other parents in the same shell still get
//     the interposer (we only defang the recursion via VETO_PATH).
//   - Unrelated vars (PATH, HOME, FOO=bar, even an empty-valued one)
//     pass through unchanged.
//
// If a future contributor decides to also strip the OS preload vars,
// they should change the "preserved" cases here too — that's an
// intentional tripwire.
func TestSanitizedEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/Users/test",
		"VETO_PATH=/opt/veto/bin/veto",
		"DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto_interpose.dylib",
		"LD_PRELOAD=/opt/veto/lib/libveto_interpose.so",
		"VETO_PYTHON_M_ORIGINAL=python3",
		"VETO_LOG=debug",
		"VETO_CACHE_DIR=/tmp/veto",
		"FOO=bar",
		"EMPTY=",
	}

	out := sanitizedEnv(in)

	got := map[string]bool{}
	for _, kv := range out {
		got[kv] = true
	}

	// Stripped:
	require.False(t, got["VETO_PATH=/opt/veto/bin/veto"],
		"VETO_PATH must be stripped to break the interposer-recursion loop")
	require.False(t, got["VETO_PYTHON_M_ORIGINAL=python3"],
		"VETO_PYTHON_M_ORIGINAL must be stripped to prevent B2 double-rewrite")

	// Preserved (deliberate — keep Layer 3 loaded in siblings):
	require.True(t, got["DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto_interpose.dylib"],
		"DYLD_INSERT_LIBRARIES must be preserved; we rely on it for sibling-process Layer 3 coverage")
	require.True(t, got["LD_PRELOAD=/opt/veto/lib/libveto_interpose.so"],
		"LD_PRELOAD must be preserved; same rationale as DYLD_INSERT_LIBRARIES")

	// Unrelated vars passed through verbatim:
	require.True(t, got["PATH=/usr/bin:/bin"])
	require.True(t, got["HOME=/Users/test"])
	require.True(t, got["VETO_LOG=debug"], "non-control VETO_* vars must pass through")
	require.True(t, got["VETO_CACHE_DIR=/tmp/veto"], "non-control VETO_* vars must pass through")
	require.True(t, got["FOO=bar"])
	require.True(t, got["EMPTY="])
}

// TestSanitizedEnvOnlyExactPrefix guards against an over-eager
// prefix match. A var like VETO_PATHWAY=foo or
// VETO_PYTHON_M_ORIGINALITY=bar (contrived, but plausible if a future
// env var picks a similar name) must NOT be stripped — the helper
// uses "VETO_PATH=" (with the equals) so only the exact name matches.
func TestSanitizedEnvOnlyExactPrefix(t *testing.T) {
	in := []string{
		"VETO_PATHWAY=should-pass",
		"VETO_PATH_EXTRA=should-pass",
		"VETO_PYTHON_M_ORIGINALITY=should-pass",
	}
	out := sanitizedEnv(in)
	require.ElementsMatch(t, in, out,
		"sanitizedEnv must only match VETO_PATH= and VETO_PYTHON_M_ORIGINAL= exactly, not as substrings")
}

// TestSanitizedEnvEmpty is a tiny smoke test that the helper doesn't
// blow up on an empty input env (some test harnesses produce one).
func TestSanitizedEnvEmpty(t *testing.T) {
	require.Empty(t, sanitizedEnv(nil))
	require.Empty(t, sanitizedEnv([]string{}))
}

func TestSanitizedEnvFor_PreservesVETO_PATH_OnGoRun(t *testing.T) {
	env := []string{
		"VETO_PATH=/opt/veto/bin/veto",
		"DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto.dylib",
		"PATH=/usr/bin",
	}
	got := sanitizedEnvFor("go", []string{"run", "./cmd/foo"}, env)
	require.Contains(t, got, "VETO_PATH=/opt/veto/bin/veto",
		"VETO_PATH must survive `go run` so Layer 3 stays armed in descendants")
}

func TestSanitizedEnvFor_StripsVETO_PATH_OnGoInstall(t *testing.T) {
	env := []string{
		"VETO_PATH=/opt/veto/bin/veto",
		"DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto.dylib",
		"PATH=/usr/bin",
	}
	got := sanitizedEnvFor("go", []string{"install", "pkg@latest"}, env)
	require.NotContains(t, got, "VETO_PATH=/opt/veto/bin/veto",
		"VETO_PATH must be stripped for `go install` to prevent recursion")
}

func TestSanitizedEnvFor_StripsForUnknownVerb(t *testing.T) {
	env := []string{"VETO_PATH=/opt/veto/bin/veto"}
	got := sanitizedEnvFor("go", []string{"some-future-verb"}, env)
	require.NotContains(t, got, "VETO_PATH=/opt/veto/bin/veto",
		"unknown verbs must default to strip (default-deny)")
}

func TestSanitizedEnvFor_StripsForPMWithoutPolicy(t *testing.T) {
	env := []string{"VETO_PATH=/opt/veto/bin/veto"}
	got := sanitizedEnvFor("npm", []string{"install", "foo"}, env)
	require.NotContains(t, got, "VETO_PATH=/opt/veto/bin/veto")
}

func TestSeedResolverWorkdir(t *testing.T) {
	projectDir := t.TempDir()
	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	require.NoError(t, os.WriteFile("package.json", []byte(`{"name":"app"}`), 0o644))
	require.NoError(t, os.Mkdir("nested", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join("nested", "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600))
	require.NoError(t, os.Mkdir("ignored-dir", 0o755))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Symlink("package.json", "link.json"))
	}

	err = seedResolverWorkdir(workdir, []string{
		"package.json",
		"missing.json",
		"nested/package-lock.json",
		"ignored-dir",
		"/abs/path",
		"../escape.json",
		"link.json",
		"package.json",
	})
	require.NoError(t, err)

	gotPkg, err := os.ReadFile(filepath.Join(workdir, "package.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"app"}`, string(gotPkg))

	gotLock, err := os.ReadFile(filepath.Join(workdir, "nested", "package-lock.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"lockfileVersion":3}`, string(gotLock))
	info, err := os.Stat(filepath.Join(workdir, "nested", "package-lock.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_, err = os.Stat(filepath.Join(workdir, "ignored-dir"))
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(workdir, "link.json"))
	require.True(t, os.IsNotExist(err))
}

func TestRunResolverPreScanExtractsGeneratedTransitives(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })
	require.NoError(t, os.WriteFile("package.json", []byte(`{"name":"app","version":"1.0.0"}`), 0o644))

	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	fakeNPM := `#!/bin/sh
set -eu
	case " $* " in
  *" --package-lock=true "*) ;;
  *) echo "missing --package-lock=true" >&2; exit 40 ;;
esac
case " $* " in
  *" --package-lock-only "*) ;;
  *) echo "missing --package-lock-only" >&2; exit 41 ;;
esac
case " $* " in
  *" --ignore-scripts "*) ;;
  *) echo "missing --ignore-scripts" >&2; exit 42 ;;
esac
if [ -n "${VETO_PATH:-}" ]; then
  echo "VETO_PATH leaked into resolver" >&2
  exit 43
fi
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/clean-direct": {"version": "1.0.0"},
    "node_modules/clean-direct/node_modules/evil-transitive": {"version": "9.9.9"}
  }
}
JSON
`
	require.NoError(t, os.WriteFile(npmPath, []byte(fakeNPM), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VETO_PATH", "/tmp/veto")

	got, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock=true", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
		SeedFiles: []string{"package.json"},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, jslock.New())
	require.NoError(t, err)
	require.Contains(t, got, packagemanager.Install{
		Ref: intel.PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      "evil-transitive",
			Version:   "9.9.9",
		},
		RawSpec: "evil-transitive@9.9.9",
	})
}

func TestRunResolverPreScanRequiresDirectInstallInOutput(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	fakeNPM := `#!/bin/sh
set -eu
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/stale-existing": {"version": "1.0.0"}
  }
}
JSON
`
	require.NoError(t, os.WriteFile(npmPath, []byte(fakeNPM), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err = runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, jslock.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolver pre-scan output did not include every requested package")
}

func TestRunResolverPreScanRequiresOutputLockfile(t *testing.T) {
	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	require.NoError(t, os.WriteFile(npmPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
	}, jslock.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolver pre-scan did not produce expected output")
}

func TestRunPipResolverPreScanExtractsGeneratedTransitives(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	fakeBin := t.TempDir()
	pipPath := filepath.Join(fakeBin, "pip")
	fakePIP := `#!/bin/sh
set -eu
case " $* " in
  *" --dry-run "*) ;;
  *) echo "missing --dry-run" >&2; exit 40 ;;
esac
case " $* " in
  *" --report veto-pip-report.json "*) ;;
  *) echo "missing --report" >&2; exit 41 ;;
esac
case " $* " in
  *" --only-binary :all: "*) ;;
  *) echo "missing --only-binary" >&2; exit 42 ;;
esac
if [ -n "${VETO_PATH:-}" ]; then
  echo "VETO_PATH leaked into resolver" >&2
  exit 43
fi
cat > veto-pip-report.json <<'JSON'
{
  "install": [
    {"metadata": {"name": "clean-direct", "version": "1.0.0"}},
    {"metadata": {"name": "evil-transitive", "version": "9.9.9"}}
  ]
}
JSON
`
	require.NoError(t, os.WriteFile(pipPath, []byte(fakePIP), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VETO_PATH", "/tmp/veto")

	got, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "pip", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--dry-run", "--ignore-installed", "--report", "veto-pip-report.json", "--only-binary", ":all:"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "veto-pip-report.json", Kind: packagemanager.ManifestKindPipReportJSON},
		},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, pipreport.New())
	require.NoError(t, err)
	require.Contains(t, got, packagemanager.Install{
		Ref: intel.PackageRef{
			Ecosystem: intel.EcosystemPyPI,
			Name:      "evil-transitive",
			Version:   "9.9.9",
		},
		RawSpec: "evil-transitive==9.9.9",
	})
}

func TestRunUvResolverPreScanExtractsGeneratedTransitives(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	fakeBin := t.TempDir()
	uvPath := filepath.Join(fakeBin, "uv")
	fakeUV := `#!/bin/sh
set -eu
if [ "$1" != "pip" ] || [ "$2" != "compile" ]; then
  echo "unexpected uv command: $*" >&2
  exit 40
fi
case " $* " in
  *" veto-uv-requirements.in "*) ;;
  *) echo "missing generated input" >&2; exit 41 ;;
esac
case " $* " in
  *" --output-file pylock.veto.toml "*) ;;
  *) echo "missing output file" >&2; exit 42 ;;
esac
case " $* " in
  *" --format pylock.toml "*) ;;
  *) echo "missing pylock format" >&2; exit 43 ;;
esac
case " $* " in
  *" --only-binary :all: "*) ;;
  *) echo "missing wheel-only flag" >&2; exit 44 ;;
esac
if [ -n "${VETO_PATH:-}" ]; then
  echo "VETO_PATH leaked into resolver" >&2
  exit 45
fi
grep -qx 'clean-direct' veto-uv-requirements.in
cat > pylock.veto.toml <<'TOML'
lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "clean-direct"
version = "1.0.0"

[[packages]]
name = "evil-transitive"
version = "9.9.9"
TOML
`
	require.NoError(t, os.WriteFile(uvPath, []byte(fakeUV), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VETO_PATH", "/tmp/veto")

	got, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "uv", packagemanager.ResolverPreScanPlan{
		Args: []string{"pip", "compile", "veto-uv-requirements.in", "--output-file", "pylock.veto.toml", "--format", "pylock.toml", "--only-binary", ":all:", "--no-progress"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "pylock.veto.toml", Kind: packagemanager.ManifestKindUvLock},
		},
		GeneratedFiles: map[string][]byte{"veto-uv-requirements.in": []byte("clean-direct\n")},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemPyPI, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, pylock.New())
	require.NoError(t, err)
	require.Contains(t, got, packagemanager.Install{
		Ref: intel.PackageRef{
			Ecosystem: intel.EcosystemPyPI,
			Name:      "evil-transitive",
			Version:   "9.9.9",
		},
		RawSpec: "evil-transitive==9.9.9",
	})
}

func TestProjectPreflightExpanderRequiresAuthoritativeManifest(t *testing.T) {
	expander := projectPreflightExpander{delegate: newCompoundExpander()}

	_, err := expander.Expand(packagemanager.ManifestRef{Path: filepath.Join(t.TempDir(), "go.mod"), Kind: packagemanager.ManifestKindGoMod})
	require.Error(t, err)
	require.Contains(t, err.Error(), "required project manifest unavailable")

	_, err = expander.Expand(packagemanager.ManifestRef{Path: filepath.Join(t.TempDir(), "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml})
	require.Error(t, err)
	require.Contains(t, err.Error(), "required project manifest unavailable")
}

func TestProjectPreflightExpanderTreatsEvidenceFilesAsOptional(t *testing.T) {
	expander := projectPreflightExpander{delegate: newCompoundExpander()}

	goSum, err := expander.Expand(packagemanager.ManifestRef{Path: filepath.Join(t.TempDir(), "go.sum"), Kind: packagemanager.ManifestKindGoSum})
	require.NoError(t, err)
	require.Empty(t, goSum)

	cargoLock, err := expander.Expand(packagemanager.ManifestRef{Path: filepath.Join(t.TempDir(), "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock})
	require.NoError(t, err)
	require.Empty(t, cargoLock)
}

func TestProjectPreflightDecisionRefusesGoProjectDependency(t *testing.T) {
	projectDir := t.TempDir()
	goMod := filepath.Join(projectDir, "go.mod")
	require.NoError(t, os.WriteFile(goMod, []byte("module example.com/app\n\nrequire github.com/evil/module v1.2.3\n"), 0o644))

	store := storeWithFakeReports(t, []intel.MalwareReport{
		{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: "github.com/evil/module", Version: "v1.2.3"},
			SourceID:   "test-feed",
			Reason:     "known malicious go module",
		},
	})
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = newCompoundExpander()
	g := gate.New(store, policy, zerolog.Nop())
	decision := g.Evaluate([]packagemanager.Install{}, packagemanager.ManifestRef{Path: goMod, Kind: packagemanager.ManifestKindGoMod})

	require.Equal(t, gate.OutcomeRefuse, decision.Outcome)
	require.Len(t, decision.Flagged(), 1)
	require.Equal(t, "github.com/evil/module", decision.Flagged()[0].Ref.Name)
}

func TestProjectPreflightPlanOnlyForPassThroughCommands(t *testing.T) {
	pm := golang.New()

	plan, ok := projectPreflightPlan(pm, []string{"test", "./..."}, nil, nil)
	require.True(t, ok)
	require.NotEmpty(t, plan.ManifestRefs)

	_, ok = projectPreflightPlan(pm, []string{"get", "github.com/evil/module@v1.2.3"}, []packagemanager.Install{{RawSpec: "github.com/evil/module@v1.2.3"}}, nil)
	require.False(t, ok)
}

func TestProjectPreflightPlanFindsParentGoModule(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "cmd", "app")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.sum"), []byte("github.com/evil/module v1.2.3 h1:abc\n"), 0o644))
	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)

	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(nested))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	plan, ok := projectPreflightPlan(golang.New(), []string{"test", "./..."}, nil, nil)
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join(resolvedRoot, "go.mod"), Kind: packagemanager.ManifestKindGoMod},
		{Path: filepath.Join(resolvedRoot, "go.sum"), Kind: packagemanager.ManifestKindGoSum},
	}, plan.ManifestRefs)
}

func TestProjectPreflightPlanFindsParentCargoManifest(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "src")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.lock"), []byte("[[package]]\nname = \"evil-crate\"\nversion = \"9.9.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"), 0o644))
	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)

	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(nested))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	plan, ok := projectPreflightPlan(cargo.New(), []string{"test"}, nil, nil)
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: filepath.Join(resolvedRoot, "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join(resolvedRoot, "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
	}, plan.ManifestRefs)
}

func TestProjectPreflightPlanFindsWorkspaceCargoLock(t *testing.T) {
	workspace := t.TempDir()
	crate := filepath.Join(workspace, "crates", "app")
	require.NoError(t, os.MkdirAll(crate, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workspace, "Cargo.toml"), []byte("[workspace]\nmembers = [\"crates/app\"]\n\n[workspace.dependencies]\nevil-workspace = \"=8.8.8\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(crate, "Cargo.toml"), []byte("[package]\nname = \"app\"\nversion = \"0.1.0\"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(workspace, "Cargo.lock"), []byte("[[package]]\nname = \"evil-crate\"\nversion = \"9.9.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"), 0o644))
	resolvedWorkspace, err := filepath.EvalSymlinks(workspace)
	require.NoError(t, err)

	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(crate))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	plan, ok := projectPreflightPlan(cargo.New(), []string{"test"}, nil, nil)
	require.True(t, ok)
	require.Equal(t, []packagemanager.ManifestRef{
		{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
		{Path: filepath.Join(resolvedWorkspace, "Cargo.lock"), Kind: packagemanager.ManifestKindCargoLock},
		{Path: filepath.Join(resolvedWorkspace, "Cargo.toml"), Kind: packagemanager.ManifestKindCargoToml},
	}, plan.ManifestRefs)
}

func TestResolverPreScanDecisionRefusesGeneratedTransitive(t *testing.T) {
	g := gateWithFakeStore(t, []intel.MalwareReport{
		{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-transitive", Version: "9.9.9"},
			SourceID:   "test-feed",
			Reason:     "known malicious transitive",
		},
	})

	decision := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct", Version: "1.0.0"}, RawSpec: "clean-direct@1.0.0"},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-transitive", Version: "9.9.9"}, RawSpec: "evil-transitive@9.9.9"},
	})

	require.Equal(t, gate.OutcomeRefuse, decision.Outcome)
	require.Len(t, decision.Flagged(), 1)
	require.Equal(t, "evil-transitive", decision.Flagged()[0].Ref.Name)
}

func gateWithFakeStore(t *testing.T, reports []intel.MalwareReport) *gate.Gate {
	t.Helper()
	return gate.New(storeWithFakeReports(t, reports), gate.DefaultPolicy(), zerolog.Nop())
}

func storeWithFakeReports(t *testing.T, reports []intel.MalwareReport) intel.Store {
	t.Helper()
	store := intel.NewStore(zerolog.Nop(), fakeSource{reports: reports})
	require.NoError(t, store.Refresh(context.Background()))
	return store
}

type fakeSource struct {
	reports []intel.MalwareReport
}

func TestPMErrorSummary(t *testing.T) {
	npmGlobal := strings.Join([]string{
		`npm warn Unknown user config "min-release-age". This will stop working in the next major version of npm.`,
		"npm error code ESHRINKWRAPGLOBAL",
		"npm error cannot generate lockfile for global packages",
		"npm error A complete log of this run can be found in: /Users/x/.npm/_logs/foo-debug-0.log",
	}, "\n")

	summary := pmErrorSummary(npmGlobal)
	require.Contains(t, summary, "ESHRINKWRAPGLOBAL")
	require.Contains(t, summary, "cannot generate lockfile for global packages")
	require.NotContains(t, summary, "complete log of this run")

	require.Equal(t, "", pmErrorSummary(""))
	require.Equal(t, "", pmErrorSummary("everything is fine\nresolved 12 packages"))
}

func TestRunResolverPreScanSurfacesPMError(t *testing.T) {
	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	script := "#!/bin/sh\n" +
		"echo 'npm error code ESHRINKWRAPGLOBAL' 1>&2\n" +
		"echo 'npm error cannot generate lockfile for global packages' 1>&2\n" +
		"exit 1\n"
	require.NoError(t, os.WriteFile(npmPath, []byte(script), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "-g", "clean-direct", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
	}, jslock.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolver pre-scan command failed")
	require.Contains(t, err.Error(), "ESHRINKWRAPGLOBAL")
}

func TestProjectPreflightPlanJSFamilyRunReturnsRefs(t *testing.T) {
	// Verify that run/test verbs for each JS-family PM return a non-empty
	// preflight plan, while install/add verbs do not (those route through
	// ParseInstalls/ManifestRefs instead).
	cases := []struct {
		pm     packagemanager.PackageManager
		name   string
		okArgs [][]string
		noArgs [][]string
	}{
		{
			pm:   npm.New(),
			name: "npm",
			okArgs: [][]string{
				{"run", "dev"},
				{"start"},
				{"test"},
				{"restart"},
				{"stop"},
			},
			noArgs: [][]string{
				{"install"},
				{"install", "lodash"},
				{"ci"},
			},
		},
		{
			pm:   pnpm.New(),
			name: "pnpm",
			okArgs: [][]string{
				{"run", "dev"},
				{"start"},
				{"test"},
				{"restart"},
				{"stop"},
			},
			noArgs: [][]string{
				{"install"},
				{"add", "lodash"},
				{"dlx", "some-tool"},
			},
		},
		{
			pm:   yarn.New(),
			name: "yarn",
			okArgs: [][]string{
				{"run", "dev"},
				{"start"},
				{"test"},
				{"restart"},
				{"stop"},
			},
			noArgs: [][]string{
				{"install"},
				{"add", "lodash"},
			},
		},
		{
			pm:   bun.New(),
			name: "bun",
			okArgs: [][]string{
				{"run", "dev"},
				{"test"},
			},
			noArgs: [][]string{
				{"install"},
				{"add", "lodash"},
				{"x", "some-tool"},
				{"create", "app"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, args := range c.okArgs {
				plan, ok := projectPreflightPlan(c.pm, args, nil, nil)
				require.True(t, ok, "expected preflight ok=true for %s %v", c.name, args)
				require.NotEmpty(t, plan.ManifestRefs, "expected non-empty ManifestRefs for %s %v", c.name, args)
			}
			for _, args := range c.noArgs {
				_, ok := projectPreflightPlan(c.pm, args, nil, nil)
				require.False(t, ok, "expected preflight ok=false for %s %v", c.name, args)
			}
		})
	}
}

func TestProjectPreflightPlanJSFamilySkippedWhenInstallsPresent(t *testing.T) {
	// projectPreflightPlan returns false when installs != nil — the gate
	// routes through the normal install path instead of the preflight path.
	// This ensures run/start/test are not double-gated on install commands.
	npmPM := npm.New()
	_, ok := projectPreflightPlan(npmPM, []string{"run", "dev"}, []packagemanager.Install{{RawSpec: "lodash"}}, nil)
	require.False(t, ok)
}

func TestProjectPreflightPlanJSFamilyFindsPackageJSON(t *testing.T) {
	// Verify that bun run dev returns a preflight plan with a package.json ref
	// and at least one lockfile ref. The expander tolerates missing files, so
	// emitting the full set speculatively is safe.
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app","version":"1.0.0"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "bun.lock"), []byte(""), 0o644))

	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(root))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	plan, ok := projectPreflightPlan(bun.New(), []string{"run", "dev"}, nil, nil)
	require.True(t, ok)
	var kinds []packagemanager.ManifestKind
	for _, r := range plan.ManifestRefs {
		kinds = append(kinds, r.Kind)
	}
	require.Contains(t, kinds, packagemanager.ManifestKindPackageJSON)
	require.Contains(t, kinds, packagemanager.ManifestKindBunLock)
}

func (s fakeSource) ID() string { return "test-feed" }

func (s fakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	out := make([]intel.MalwareReport, 0, len(s.reports))
	for _, r := range s.reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}
