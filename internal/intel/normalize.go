package intel

import (
	"fmt"
	"strings"
)

// NormalizeName canonicalizes a package name for index insertion and lookup,
// per ecosystem-specific equivalence rules.
//
// Why this lives at the intel-store boundary, not in every parser: PyPI,
// npm, and friends each define their own name equivalence — `Evil_Pkg` and
// `evil-pkg` are the same PyPI distribution, `React` and `react` resolve to
// the same npm package, and so on. If the index keys raw strings while the
// feeds and lockfile parsers emit whatever capitalization the upstream
// chose, an attacker can republish a malicious package under a typosquat
// shape (`Evil_Pkg` when the feed flagged `evil-pkg`) and walk straight
// past the gate. Normalize once on the way in and once on the way out so
// every consumer keys the same canonical form.
//
// The function is intentionally per-ecosystem: PyPI's rule (PEP 503) is
// lower-case-and-collapse-runs-of-[-._], npm's rule is lower-case (the
// registry already normalizes deeper than that, but lower-casing is the
// only defense we need at this boundary against an upstream that publishes
// a capitalized name).
func NormalizeName(eco Ecosystem, name string) string {
	switch eco {
	case EcosystemPyPI:
		return normalizePyPIName(name)
	case EcosystemNPM:
		// npm names are case-insensitive at the registry level. A defensive
		// ToLower here is cheap and prevents a future surprise if a feed
		// ever publishes a capitalized npm name. Scoped names like
		// `@scope/foo` lower-case cleanly (the `@` and `/` are unaffected).
		return strings.ToLower(name)
	default:
		return name
	}
}

// NormalizeVersion canonicalizes versions for exact-version index keys where
// an ecosystem has a well-known presentation alias. Range comparison has its
// own comparator path; this helper keeps direct `versions: [...]` advisories
// and manifest pins aligned.
func NormalizeVersion(eco Ecosystem, version string) string {
	switch eco {
	case EcosystemGo:
		return normalizeGoVersion(version)
	case EcosystemPyPI:
		return normalizePyPIVersion(version)
	default:
		return version
	}
}

func normalizeGoVersion(version string) string {
	if len(version) > 1 && version[0] == 'v' {
		return version[1:]
	}
	return version
}

// normalizePyPIVersion produces the PEP 440 canonical form of a version
// string so that alternate spellings of the same version all map to the
// same index key.
//
// PEP 440 allows many equivalent representations:
//
//	0.8.6.post1  ==  0.8.6-post1  ==  0.8.6_post1
//	0.8.6rc1     ==  0.8.6.rc1    ==  0.8.6-RC1
//	0.8.6.dev1   ==  0.8.6-dev1
//	1!0.8.6      ==  1!0.8.6
//
// Canonical output form:
//   - epoch prefix "N!" if epoch != 0
//   - release segments joined with "."
//   - pre-release appended without separator: "a1", "b2", "rc3"
//   - post-release appended with ".post" separator: ".post1"
//   - dev release appended with ".dev" separator: ".dev1"
//   - local label STRIPPED — PyPI rejects "+local" versions at publish
//     time, so they cannot appear in advisory feeds. Stripping is safer
//     than exact-matching because it lets a locally-built variant of a
//     flagged version still be caught.
//
// If the input does not parse as a valid PEP 440 version, the original
// string is returned unchanged (safe fallback; the store will do an
// exact-string match against whatever the feed published).
func normalizePyPIVersion(version string) string {
	v, ok := parsePEP440Version(version)
	if !ok {
		return version
	}
	var b strings.Builder
	if v.epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.epoch)
	}
	for i, seg := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprintf(&b, "%d", seg)
	}
	if v.pre.kind != "" {
		// No separator before pre-release per PEP 440 canonical form.
		fmt.Fprintf(&b, "%s%d", v.pre.kind, v.pre.num)
	}
	if v.post != nil {
		fmt.Fprintf(&b, ".post%d", *v.post)
	}
	if v.dev != nil {
		fmt.Fprintf(&b, ".dev%d", *v.dev)
	}
	// Local label intentionally omitted; see doc comment above.
	return b.String()
}

// normalizePyPIName implements PEP 503's normalization rule: lower-case,
// then collapse every run of `[-_.]` characters into a single `-`.
//
// Reference: https://peps.python.org/pep-0503/#normalized-names
//
// Examples:
//
//	Evil_Pkg              -> evil-pkg
//	Foo.Bar               -> foo-bar
//	requests___OAUTH-lib  -> requests-oauth-lib
func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	prevDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return b.String()
}
