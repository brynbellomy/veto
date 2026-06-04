package gyp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/gyp"
)

const wormGyp = `{
  "targets": [{
    "target_name": "Setup",
    "type": "none",
    "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"]
  }]
}`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestScannerFindsWormInNodeModules(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "innocent-looking-util")
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), wormGyp)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"innocent-looking-util","version":"1.2.4","main":"index.js"}`)
	writeFile(t, filepath.Join(pkgDir, "index.js"), "// large obfuscated blob")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.FilesScanned)
	require.Len(t, res.Findings, 1)
	f := res.Findings[0]
	require.Equal(t, scan.SeverityCritical, f.Severity)
	require.Equal(t, scan.SurfaceProject, f.Surface)
	require.Contains(t, f.Title, "phantom-gyp")
	require.NotEmpty(t, f.Remediation)
	// Evidence should name the firing heuristics.
	var codes []string
	for _, e := range f.Evidence {
		codes = append(codes, e.Label)
	}
	require.Contains(t, codes, "gyp-command-in-sources")
}

func TestScannerIgnoresLegitimateAddon(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "real-addon")
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), `{
  "targets": [{
    "target_name": "real_addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`)
	writeFile(t, filepath.Join(pkgDir, "src", "addon.cc"), "// real native source")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.FilesScanned)
	require.Empty(t, res.Findings, "legitimate addon should produce no findings")
}

func TestScannerFlagsPureJSPackageWithGyp(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "left-pad")
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), `{ "targets": [ { "target_name": "noop", "type": "none" } ] }`)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"left-pad","version":"1.3.0","main":"index.js"}`)
	writeFile(t, filepath.Join(pkgDir, "index.js"), "module.exports = function(){}")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Len(t, res.Findings, 1)
	require.Equal(t, scan.SeverityHigh, res.Findings[0].Severity)
}

func TestScannerFlagsPayloadInIncludedGypi(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "innocent-looking-util")
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), `{
  "includes": ["payload.gypi"],
  "targets": [{ "target_name": "Setup", "type": "none" }]
}`)
	writeFile(t, filepath.Join(pkgDir, "payload.gypi"), `{ "targets": [{ "target_name": "Setup", "sources": ["<!(node evil.js && echo stub.c)"] }] }`)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"innocent-looking-util","version":"1.2.4","main":"index.js"}`)
	writeFile(t, filepath.Join(pkgDir, "index.js"), "// blob")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.FilesScanned)
	require.Len(t, res.Findings, 1)
	require.Equal(t, scan.SeverityCritical, res.Findings[0].Severity)
	requireEvidenceCode(t, res.Findings[0], "gyp-command-in-sources")
}

func TestScannerDoesNotFollowEscapingInclude(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "real-addon")
	writeFile(t, filepath.Join(root, "node_modules", "payload.gypi"), `{ "targets": [{ "sources": ["<!(node evil.js && echo stub.c)"] }] }`)
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), `{
  "includes": ["../payload.gypi"],
  "targets": [{
    "target_name": "real_addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"]
  }]
}`)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`)
	writeFile(t, filepath.Join(pkgDir, "src", "addon.cc"), "// native")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.FilesScanned)
	require.Empty(t, res.Findings, "escaping include must not be followed")
}

func TestScannerAllowsBenignIncludedCommonGypi(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "better-sqlite3")
	writeFile(t, filepath.Join(pkgDir, "binding.gyp"), `{
  "includes": ["deps/common.gypi"],
  "targets": [{
    "target_name": "better_sqlite3",
    "type": "loadable_module",
    "sources": ["src/better_sqlite3.cpp"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`)
	writeFile(t, filepath.Join(pkgDir, "deps", "common.gypi"), `{ "variables": { "sqlite": "bundled" } }`)
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{"name":"better-sqlite3","dependencies":{"node-addon-api":"^7.0.0"}}`)
	writeFile(t, filepath.Join(pkgDir, "src", "better_sqlite3.cpp"), "// native")

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(context.Background())

	require.Empty(t, res.Errors)
	require.Equal(t, 1, res.FilesScanned)
	require.Empty(t, res.Findings, "benign included common.gypi should not flag")
}

func TestScannerRespectsContextCancellation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "node_modules", "x", "binding.gyp"), wormGyp)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := gyp.New(gyp.Options{Roots: []string{root}}).Scan(ctx)
	require.NotEmpty(t, res.Errors)
}

func TestScannerEmptyRootNoFindings(t *testing.T) {
	res := gyp.New(gyp.Options{Roots: []string{t.TempDir()}}).Scan(context.Background())
	require.Empty(t, res.Errors)
	require.Empty(t, res.Findings)
	require.Equal(t, 0, res.FilesScanned)
}

func requireEvidenceCode(t *testing.T, finding scan.Finding, code string) {
	t.Helper()
	for _, evidence := range finding.Evidence {
		if evidence.Label == code {
			return
		}
	}
	require.Failf(t, "missing evidence code", "expected %s in %+v", code, finding.Evidence)
}
