package gemnasium

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
)

// affectedRangeResult is the outcome of translating one gemnasium
// `affected_range` string. Ranges holds bounded intervals (Version empty);
// ExactVersions holds the versions an `=`/bare-version comparator pinned.
// Skipped is true when at least one OR-alternative could not be translated
// cleanly and was deliberately dropped rather than guessed — the caller
// logs the original expression so the gap is auditable.
type affectedRangeResult struct {
	Ranges        []intel.VersionRange
	ExactVersions []string
	Skipped       bool
}

// translateAffectedRange parses a gemnasium `affected_range` expression for
// ecosystem eco into intel range/version constraints.
//
// Grammar (per the GitLab Advisory Database schema):
//
//   - `||` separates OR-alternatives; each alternative becomes one
//     intel.VersionRange (or one exact-version pin).
//   - within an alternative, `,` separates AND-ed comparators, e.g.
//     `>=2.2a1,<2.2.25`.
//   - each comparator is `<op><version>` with op in
//     {`<`, `<=`, `>`, `>=`, `=`, `==`}; a bare version (npm/cargo semver)
//     is treated as an exact pin.
//
// Translation is conservative and honest about intel's interval model,
// which expresses an inclusive lower bound (Introduced), an exclusive upper
// bound (Fixed), and an inclusive upper bound (LastAffected) — but NO
// exclusive lower bound. An alternative that needs `>X` (strict greater-than)
// cannot be represented without silently shifting the boundary, so the whole
// alternative is dropped and Skipped is set. A wrong range that under- or
// over-blocks adjacent versions is worse than an explicit, logged gap.
//
// An empty / `*` / `>=0` alternative collapses to the unbounded range (all
// versions affected). Returns Skipped=true with no ranges when nothing could
// be translated.
func translateAffectedRange(eco intel.Ecosystem, expr string) affectedRangeResult {
	var res affectedRangeResult
	expr = strings.TrimSpace(expr)
	if expr == "" {
		// No constraint string at all — treat as "all versions affected".
		res.Ranges = append(res.Ranges, intel.VersionRange{Introduced: "0"})
		return res
	}

	for _, alt := range strings.Split(expr, "||") {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		rng, exact, ok := translateAlternative(eco, alt)
		if !ok {
			res.Skipped = true
			continue
		}
		if exact != "" {
			res.ExactVersions = append(res.ExactVersions, exact)
			continue
		}
		res.Ranges = append(res.Ranges, rng)
	}
	return res
}

// translateAlternative converts a single comma-separated comparator set into
// one intel.VersionRange or a single exact version. The third return value is
// false when the alternative contains a comparator intel cannot represent
// (notably strict `>`), or is internally contradictory (two lower or two
// upper bounds), in which case the caller drops it.
func translateAlternative(eco intel.Ecosystem, alt string) (intel.VersionRange, string, bool) {
	parts := strings.Split(alt, ",")

	var (
		rng          intel.VersionRange
		haveLower    bool
		haveUpper    bool
		exactVersion string
		haveExact    bool
		haveAnyBound bool
	)

	for _, raw := range parts {
		op, ver, ok := splitComparator(raw)
		if !ok {
			return intel.VersionRange{}, "", false
		}
		ver = normalizeBoundVersion(eco, ver)

		switch op {
		case opGE:
			if haveLower {
				return intel.VersionRange{}, "", false
			}
			rng.Introduced = ver
			haveLower = true
			haveAnyBound = true
		case opLT:
			if haveUpper {
				return intel.VersionRange{}, "", false
			}
			rng.Fixed = ver
			haveUpper = true
			haveAnyBound = true
		case opLE:
			if haveUpper {
				return intel.VersionRange{}, "", false
			}
			rng.LastAffected = ver
			haveUpper = true
			haveAnyBound = true
		case opEQ:
			if haveExact {
				return intel.VersionRange{}, "", false
			}
			exactVersion = ver
			haveExact = true
		case opGT:
			// intel.VersionRange has no exclusive lower bound. Refuse to
			// approximate it (using ver as an inclusive Introduced would
			// wrongly flag ver itself). Drop the alternative honestly.
			return intel.VersionRange{}, "", false
		default:
			return intel.VersionRange{}, "", false
		}
	}

	// An exact pin must stand alone; mixing `=1.2.3` with bounds is ambiguous.
	if haveExact {
		if haveAnyBound {
			return intel.VersionRange{}, "", false
		}
		return intel.VersionRange{}, exactVersion, true
	}

	// A bound-only alternative with neither a lower nor an upper limit means
	// the comparator set was effectively empty — over-block as unbounded.
	if !haveLower && !haveUpper {
		return intel.VersionRange{Introduced: "0"}, "", true
	}

	return rng, "", true
}

type comparatorOp int

const (
	opNone comparatorOp = iota
	opLT
	opLE
	opGT
	opGE
	opEQ
)

// splitComparator separates a comparator like ">=1.2.3" into its operator and
// version. A bare version with no operator (npm/cargo semver pins) is treated
// as `=`. Returns false for malformed input (empty version, unknown operator
// such as `~` or `^` range sugar that gemnasium does not emit in
// affected_range but which we refuse rather than misinterpret).
func splitComparator(raw string) (comparatorOp, string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return opNone, "", false
	}

	switch {
	case strings.HasPrefix(s, ">="):
		return opGE, strings.TrimSpace(s[2:]), s[2:] != ""
	case strings.HasPrefix(s, "<="):
		return opLE, strings.TrimSpace(s[2:]), s[2:] != ""
	case strings.HasPrefix(s, "=="):
		return opEQ, strings.TrimSpace(s[2:]), s[2:] != ""
	case strings.HasPrefix(s, ">"):
		return opGT, strings.TrimSpace(s[1:]), s[1:] != ""
	case strings.HasPrefix(s, "<"):
		return opLT, strings.TrimSpace(s[1:]), s[1:] != ""
	case strings.HasPrefix(s, "="):
		return opEQ, strings.TrimSpace(s[1:]), s[1:] != ""
	case strings.HasPrefix(s, "~"), strings.HasPrefix(s, "^"):
		// Tilde/caret range sugar would need expansion into bounds; gemnasium
		// `affected_range` does not use it, and guessing the expansion risks
		// mis-bounding. Refuse.
		return opNone, "", false
	default:
		// Bare version — exact pin.
		return opEQ, s, true
	}
}

// normalizeBoundVersion strips an ecosystem-specific presentation alias from a
// bound version so it round-trips through intel's comparator. Go advisories
// write `v`-prefixed versions (`<v1.7.0`); intel's Go path normalizes the
// query side too, so we align the bound here. Other ecosystems pass through.
func normalizeBoundVersion(eco intel.Ecosystem, ver string) string {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return ver
	}
	return intel.NormalizeVersion(eco, ver)
}
