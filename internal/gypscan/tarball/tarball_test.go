package tarball_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gypscan"
	"github.com/brynbellomy/veto/internal/gypscan/tarball"
)

type tarEntry struct {
	name    string
	content string
}

// buildTarball writes an npm-style .tgz (every path prefixed with `package/`)
// from the given name→content map and returns the gzipped bytes.
func buildTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	entries := make([]tarEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, tarEntry{name: name, content: content})
	}
	return buildTarballOrdered(t, entries)
}

func buildTarballOrdered(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var gzbuf bytes.Buffer
	gz := gzip.NewWriter(&gzbuf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     "package/" + entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.content)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(entry.content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return gzbuf.Bytes()
}

const wormGyp = `{ "targets": [{ "target_name": "Setup", "type": "none", "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"] }] }`

func TestInspectFlagsWormTarball(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"binding.gyp":  wormGyp,
		"package.json": `{"name":"innocent-util","version":"1.2.4","main":"index.js"}`,
		"index.js":     "// large obfuscated blob",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
}

func TestInspectCleanNativeAddonTarball(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"binding.gyp": `{
  "targets": [{
    "target_name": "addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`,
		"package.json": `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`,
		"addon.cc":     "// native source at root",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.False(t, v.Flagged(), "legit addon tarball flagged: %+v", v.Signals)
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectTarballWithoutGypIsClean(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"package.json": `{"name":"pure-js","version":"1.0.0"}`,
		"index.js":     "module.exports = 1",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.False(t, v.Flagged())
	require.Empty(t, v.Signals)
}

func TestInspectOversizedRootBindingGypIsCritical(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"binding.gyp":  strings.Repeat(" ", 1<<20+1) + wormGyp,
		"package.json": `{"name":"innocent-util","version":"1.2.4","main":"index.js"}`,
		"index.js":     "// blob",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-file-too-large"), "got %v", codes(v))
}

func TestInspectOversizedIncludedGypiIsCritical(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"binding.gyp": `{
  "includes": ["build/payload.gypi"],
  "targets": [{ "target_name": "addon", "type": "loadable_module", "sources": ["addon.cc"] }]
}`,
		"build/payload.gypi": strings.Repeat(" ", 1<<20+1) + wormGyp,
		"package.json":       `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`,
		"addon.cc":           "// native source at root",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-file-too-large"), "got %v", codes(v))
}

func TestInspectPureJSPackageWithRootGypFlags(t *testing.T) {
	tgz := buildTarball(t, map[string]string{
		"binding.gyp":  `{ "targets": [ { "target_name": "noop", "type": "none" } ] }`,
		"package.json": `{"name":"left-pad","version":"1.3.0","main":"index.js"}`,
		"index.js":     "module.exports = function(){}",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityMedium, v.Severity)
}

func TestInspectMalformedStreamErrors(t *testing.T) {
	_, err := tarball.Inspect(bytes.NewReader([]byte("not a gzip stream")))
	require.Error(t, err)
}

func TestInspectIgnoresNestedBindingGyp(t *testing.T) {
	// A binding.gyp buried in a vendored subdir is not what npm hands node-gyp
	// for this package; only the root binding.gyp is run at install time.
	tgz := buildTarball(t, map[string]string{
		"vendor/dep/binding.gyp": wormGyp,
		"package.json":           `{"name":"x","version":"1.0.0"}`,
		"index.js":               "1",
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.False(t, v.Flagged(), "nested binding.gyp should not flag")
}

func TestInspectFollowsIncludedGypiRegardlessTarEntryOrder(t *testing.T) {
	root := `{ "includes": ["build/payload.gypi"], "targets": [{ "target_name": "Setup", "type": "none" }] }`
	payload := `{ "targets": [{ "target_name": "Setup", "sources": ["<!(node evil.js && echo stub.c)"] }] }`

	cases := []struct {
		name    string
		entries []tarEntry
	}{
		{
			name: "include before root binding gyp",
			entries: []tarEntry{
				{name: "build/payload.gypi", content: payload},
				{name: "binding.gyp", content: root},
				{name: "package.json", content: `{"name":"innocent-util","version":"1.2.4"}`},
				{name: "index.js", content: "// blob"},
			},
		},
		{
			name: "include after root binding gyp",
			entries: []tarEntry{
				{name: "binding.gyp", content: root},
				{name: "package.json", content: `{"name":"innocent-util","version":"1.2.4"}`},
				{name: "index.js", content: "// blob"},
				{name: "build/payload.gypi", content: payload},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tarball.Inspect(bytes.NewReader(buildTarballOrdered(t, tc.entries)))
			require.NoError(t, err)
			require.True(t, v.Flagged())
			require.Equal(t, gypscan.SeverityCritical, v.Severity)
			require.True(t, hasSignal(v, "gyp-command-in-sources"), "got %v", codes(v))
		})
	}
}

func TestInspectCleanNestedIncludesAreClean(t *testing.T) {
	tgz := buildTarballOrdered(t, []tarEntry{
		{name: "binding.gyp", content: `{
  "includes": ["build/common.gypi"],
  "targets": [{
    "target_name": "addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`},
		{name: "build/common.gypi", content: `{ "includes": ["nested/vars.gypi"], "variables": { "sqlite": "bundled" } }`},
		{name: "build/nested/vars.gypi", content: `{ "variables": { "openssl_fips": "" } }`},
		{name: "package.json", content: `{"name":"real-addon","dependencies":{"node-addon-api":"^7.0.0"}}`},
		{name: "src/addon.cc", content: "// native source"},
	})

	v, err := tarball.Inspect(bytes.NewReader(tgz))
	require.NoError(t, err)
	require.False(t, v.Flagged(), "clean nested includes should not flag: %+v", v.Signals)
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func hasSignal(v gypscan.Verdict, code string) bool {
	for _, s := range v.Signals {
		if s.Code == code {
			return true
		}
	}
	return false
}

func codes(v gypscan.Verdict) []string {
	out := make([]string, 0, len(v.Signals))
	for _, s := range v.Signals {
		out = append(out, s.Code)
	}
	return out
}
