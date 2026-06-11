package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/npm"
)

const wormBindingGyp = `{
  "targets": [{
    "target_name": "Setup",
    "type": "none",
    "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"]
  }]
}`

func writeGypFixture(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestGypPreflightRefusesWormInTree(t *testing.T) {
	cwd := t.TempDir()
	pkg := filepath.Join(cwd, "node_modules", "innocent-util")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), wormBindingGyp)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"innocent-util","version":"1.2.4"}`)
	writeGypFixture(t, filepath.Join(pkg, "index.js"), "// blob")

	var buf bytes.Buffer
	refused := gypPreflight(zerolog.Nop(), &buf, cwd)

	require.True(t, refused)
	require.Contains(t, buf.String(), "binding.gyp worm pattern detected")
	require.Contains(t, buf.String(), "gyp-command-in-sources")
}

func TestGypPreflightAllowsCleanTree(t *testing.T) {
	cwd := t.TempDir()
	pkg := filepath.Join(cwd, "node_modules", "real-addon")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), `{
  "targets": [{
    "target_name": "real_addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`)
	writeGypFixture(t, filepath.Join(pkg, "src", "addon.cc"), "// native")

	var buf bytes.Buffer
	refused := gypPreflight(zerolog.Nop(), &buf, cwd)

	require.False(t, refused)
	require.Empty(t, buf.String())
}

func TestGypPreflightAllowsEmptyTree(t *testing.T) {
	var buf bytes.Buffer
	require.False(t, gypPreflight(zerolog.Nop(), &buf, t.TempDir()))
	require.Empty(t, buf.String())
}

func TestGypPreflightMediumOnlyDoesNotRefuse(t *testing.T) {
	// A pure-JS package with a type:none gyp but no command expansion is
	// medium severity — surfaced by `veto scan` but NOT a hot-path refusal.
	cwd := t.TempDir()
	pkg := filepath.Join(cwd, "node_modules", "left-pad")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), `{ "targets": [ { "target_name": "noop", "type": "none" } ] }`)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"left-pad","main":"index.js"}`)
	writeGypFixture(t, filepath.Join(pkg, "index.js"), "module.exports=function(){}")

	var buf bytes.Buffer
	require.False(t, gypPreflight(zerolog.Nop(), &buf, cwd))
	require.Empty(t, buf.String())
}

func TestRunGypPreflightIfNpmFamilyScansPrefixTarget(t *testing.T) {
	cwd := t.TempDir()
	target := t.TempDir()
	chdirForTest(t, cwd)

	pkg := filepath.Join(target, "node_modules", "innocent-util")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), wormBindingGyp)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"innocent-util","version":"1.2.4"}`)
	writeGypFixture(t, filepath.Join(pkg, "index.js"), "// blob")

	refused := runGypPreflightIfNpmFamily(zerolog.Nop(), config{CacheDir: t.TempDir()}, npm.New(), []string{"install", "--prefix", target, "foo"})

	require.True(t, refused)
}

func TestRunGypPreflightIfNpmFamilyStillScansCwdWithoutPrefix(t *testing.T) {
	cwd := t.TempDir()
	chdirForTest(t, cwd)

	pkg := filepath.Join(cwd, "node_modules", "innocent-util")
	writeGypFixture(t, filepath.Join(pkg, "binding.gyp"), wormBindingGyp)
	writeGypFixture(t, filepath.Join(pkg, "package.json"), `{"name":"innocent-util","version":"1.2.4"}`)
	writeGypFixture(t, filepath.Join(pkg, "index.js"), "// blob")

	refused := runGypPreflightIfNpmFamily(zerolog.Nop(), config{CacheDir: t.TempDir()}, npm.New(), []string{"install", "foo"})

	require.True(t, refused)
}

func TestGypPreflightScopedToNodeModules(t *testing.T) {
	// A worm-shaped binding.gyp OUTSIDE node_modules (old project junk under
	// a Documents-like subdir) must not block: node-gyp never runs there.
	cwd := t.TempDir()
	junk := filepath.Join(cwd, "Documents", "old-project", "vendored")
	writeGypFixture(t, filepath.Join(junk, "binding.gyp"), wormBindingGyp)

	var buf bytes.Buffer
	require.False(t, gypPreflight(zerolog.Nop(), &buf, cwd))
	require.Empty(t, buf.String())

	// The same file under node_modules blocks as before.
	writeGypFixture(t, filepath.Join(cwd, "node_modules", "evil", "binding.gyp"), wormBindingGyp)
	writeGypFixture(t, filepath.Join(cwd, "node_modules", "evil", "package.json"), `{"name":"evil","version":"1.0.0"}`)
	require.True(t, gypPreflight(zerolog.Nop(), &buf, cwd))
}

func TestGypScanRootsForInstallSkipsRootsWithoutNodeModules(t *testing.T) {
	bare := t.TempDir()
	require.Empty(t, gypScanRootsForInstall("npm", []string{"i", "-g", "foo"}, bare))

	withNM := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(withNM, "node_modules"), 0o755))
	require.Equal(t,
		[]string{filepath.Join(withNM, "node_modules")},
		gypScanRootsForInstall("npm", []string{"install", "foo"}, withNM))
}

func TestGypPreflightAllowlistedFindingDoesNotRefuse(t *testing.T) {
	cwd := t.TempDir()
	gypPath := filepath.Join(cwd, "node_modules", "legit-probe", "binding.gyp")
	writeGypFixture(t, gypPath, wormBindingGyp)
	writeGypFixture(t, filepath.Join(cwd, "node_modules", "legit-probe", "package.json"), `{"name":"legit-probe","version":"1.0.0"}`)

	digest, err := sha256File(gypPath)
	require.NoError(t, err)
	allowed := map[string]struct{}{digest: {}}

	var buf bytes.Buffer
	roots := gypScanRootsForInstall("npm", []string{"install", "foo"}, cwd)
	require.False(t, gypPreflightRoots(zerolog.Nop(), &buf, roots, allowed))
	require.Empty(t, buf.String())

	// Tampered content no longer matches the acknowledged hash → blocks.
	writeGypFixture(t, gypPath, wormBindingGyp+"\n// tampered")
	require.True(t, gypPreflightRoots(zerolog.Nop(), &buf, roots, allowed))
}

func TestIsNpmFamily(t *testing.T) {
	require.True(t, isNpmFamily("npm"))
	require.False(t, isNpmFamily("pypi"))
	require.False(t, isNpmFamily("go"))
	require.False(t, isNpmFamily("crates.io"))
}

func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(prev)) })
}
