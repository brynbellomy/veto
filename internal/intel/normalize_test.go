package intel_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// TestNormalizeNamePyPI exercises PEP 503: lower-case, then collapse every
// run of `[-_.]` into a single `-`. Reference cases are drawn from PEP 503
// directly plus the typosquat shapes that motivated this fix.
func TestNormalizeNamePyPI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// PEP 503 canonical examples.
		{"Evil_Pkg", "evil-pkg"},
		{"Foo.Bar", "foo-bar"},
		{"requests___OAUTH-lib", "requests-oauth-lib"},
		// Idempotent on already-normalized input.
		{"evil-pkg", "evil-pkg"},
		{"requests", "requests"},
		// Mixed runs of -._ collapse to a single dash.
		{"a_._-_b", "a-b"},
		{"EVIL.pkg", "evil-pkg"},
		// Empty stays empty.
		{"", ""},
		// Leading/trailing separators are not stripped by PEP 503;
		// they collapse to a single dash.
		{"-foo", "-foo"},
		{"foo-", "foo-"},
		{"__foo__", "-foo-"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeName(intel.EcosystemPyPI, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeNameNPM verifies the defensive lower-case applied to npm
// names. Scoped names keep their `@scope/` prefix; only case changes.
func TestNormalizeNameNPM(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"React", "react"},
		{"react", "react"},
		{"@scope/Foo", "@scope/foo"},
		{"@SCOPE/foo", "@scope/foo"},
		{"left-pad", "left-pad"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeName(intel.EcosystemNPM, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeNameUnknownEcosystem: an ecosystem the helper doesn't know
// about passes through untouched. New ecosystems must opt in explicitly.
func TestNormalizeNameUnknownEcosystem(t *testing.T) {
	got := intel.NormalizeName(intel.Ecosystem("unknown"), "Mixed_Case.Name")
	require.Equal(t, "Mixed_Case.Name", got)
}

func TestNormalizeVersionGo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"v0.0.0-20260524000000-abcdefabcdef", "0.0.0-20260524000000-abcdefabcdef"},
		{"", ""},
		{"v", "v"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeVersion(intel.EcosystemGo, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeVersionUnknownEcosystem(t *testing.T) {
	got := intel.NormalizeVersion(intel.Ecosystem("unknown"), "v1.2.3")
	require.Equal(t, "v1.2.3", got)
}

// TestNormalizeVersionPyPI exercises PEP 440 canonical form for PyPI versions.
// The goal is that alternate spellings of the same version collapse to the
// same key, so an advisory for "0.8.6.post1" also catches an install of
// "0.8.6-post1" or "0.8.6_post1", and vice-versa.
//
// Design choice for local labels (+local): stripped. PyPI rejects
// "+local" versions at publish time, so they cannot appear in advisory
// feeds. Stripping lets a locally-built variant of a flagged version
// still be caught by exact-version lookup.
func TestNormalizeVersionPyPI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Plain release — unchanged.
		{"0.8.6", "0.8.6"},
		{"1.0.0", "1.0.0"},
		{"3.11.2", "3.11.2"},
		// Post-release variants (all three separator styles).
		{"0.8.6.post1", "0.8.6.post1"},
		{"0.8.6-post1", "0.8.6.post1"},
		{"0.8.6_post1", "0.8.6.post1"},
		{"0.8.6post1", "0.8.6.post1"},
		// Post-0 (implicit post release).
		{"0.8.6.post0", "0.8.6.post0"},
		// Pre-release: rc / alpha / beta.
		{"0.8.6rc1", "0.8.6rc1"},
		{"0.8.6.rc1", "0.8.6rc1"},
		{"0.8.6-RC1", "0.8.6rc1"},
		{"0.8.6a1", "0.8.6a1"},
		{"0.8.6alpha1", "0.8.6a1"},
		{"0.8.6b2", "0.8.6b2"},
		{"0.8.6beta2", "0.8.6b2"},
		// Dev release.
		{"0.8.6.dev1", "0.8.6.dev1"},
		{"0.8.6-dev1", "0.8.6.dev1"},
		{"0.8.6dev1", "0.8.6.dev1"},
		// Local label stripped (cannot be published to PyPI).
		{"0.8.6+local", "0.8.6"},
		{"0.8.6+local.1.2", "0.8.6"},
		// Epoch.
		{"1!0.8.6", "1!0.8.6"},
		{"1!0.8.6.post1", "1!0.8.6.post1"},
		// v-prefix stripped.
		{"v0.8.6", "0.8.6"},
		// Underscore/dash separator in release segment normalised to dot
		// via PEP 440 parser; unusual but valid.
		// Idempotent on already-canonical input.
		{"0.8.6.post1", "0.8.6.post1"},
		// Non-parseable input returned unchanged.
		{"not-a-version", "not-a-version"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := intel.NormalizeVersion(intel.EcosystemPyPI, tc.in)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNormalizeVersionPyPI_HadesVariants specifically tests the Hades intel
// use case: an advisory entry for a plain version must match common PEP 440
// variant spellings of that version after normalization.
func TestNormalizeVersionPyPI_HadesVariants(t *testing.T) {
	// post-release of 0.8.6 — realistic attack variant
	require.Equal(t, "0.8.6.post1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6.post1"))
	require.Equal(t, "0.8.6.post1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6-post1"))
	// pre-release
	require.Equal(t, "0.8.6rc1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6rc1"))
	require.Equal(t, "0.8.6rc1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6.rc1"))
	// dev release
	require.Equal(t, "0.8.6.dev1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6.dev1"))
	require.Equal(t, "0.8.6.dev1", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6-dev1"))
	// local segment stripped — cannot be published to PyPI
	require.Equal(t, "0.8.6", intel.NormalizeVersion(intel.EcosystemPyPI, "0.8.6+local"))
}
