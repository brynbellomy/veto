// Package intel defines the contract for malicious-package intelligence
// sources and the deduplicated lookup store they feed into.
//
// A Source is one upstream feed (Aikido, OpenSSF malicious-packages, OSV, ...).
// A Store aggregates reports from many Sources and answers membership queries
// keyed by (ecosystem, name, version). Consumers depend on the parent package
// only — concrete sources live in subpackages so their dependencies (HTTP
// clients, format-specific parsers) never bleed into the contract.
package intel

import (
	"context"
	"time"

	"github.com/brynbellomy/go-utils/errors"
)

// Ecosystem identifies a package ecosystem (npm, PyPI, Go, crates.io, ...).
// Sources translate their internal taxonomies into this set so the Store can be
// ecosystem-agnostic.
type Ecosystem string

const (
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemGo     Ecosystem = "go"
	EcosystemCrates Ecosystem = "crates.io"
)

// AllEcosystems lists every ecosystem the project understands today. New
// ecosystems get appended here and the corresponding Source method dispatches
// to them.
var AllEcosystems = []Ecosystem{EcosystemNPM, EcosystemPyPI, EcosystemGo, EcosystemCrates}

// PackageRef identifies a specific package version within an ecosystem. An
// empty Version means "match any version of this package."
type PackageRef struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// MalwareReport is one finding from one Source about one package version.
// Multiple reports for the same PackageRef from different sources are kept
// distinct in the Store so downstream UI can show all sources that flagged a
// package.
type MalwareReport struct {
	PackageRef

	// SourceID is the stable identifier of the upstream source (e.g. "aikido").
	SourceID string

	// Reason is a free-form description from the source. Sources differ in how
	// much detail they provide; this is for display only, never for matching.
	Reason string

	// AdvisoryID is the source-specific identifier (e.g. "MAL-2024-1234").
	// Empty if the source has no per-finding ID.
	AdvisoryID string

	// PublishedAt is when the source first flagged this finding. Zero value
	// means the source did not record this.
	PublishedAt time.Time

	// Range, when non-nil, constrains this report to versions matching the
	// interval under the ecosystem's comparator. Used by sources that emit
	// bounded advisories (e.g. OSV `{introduced: "0", fixed: "2.0.3"}`):
	// the report's PackageRef.Version is left empty and the interval lives
	// here so Lookup can test membership. nil means "no range constraint" —
	// PackageRef.Version is then the sole version selector (or "all
	// versions" when both Range and Version are empty).
	Range *VersionRange
}

// Source fetches malicious-package intelligence for one upstream feed.
//
// Implementations should be safe to call concurrently. Fetch is expected to
// return quickly when the source has a cached snapshot still valid by etag or
// equivalent; the parent project handles scheduling refreshes.
type Source interface {
	// ID returns a short stable identifier (e.g. "aikido"). Two sources
	// must not share an ID.
	ID() string

	// Fetch retrieves the current malware list for the given ecosystem.
	// Returns ErrUnsupportedEcosystem when the source does not cover the
	// ecosystem (and the Store skips it without treating it as an error).
	Fetch(ctx context.Context, eco Ecosystem) ([]MalwareReport, error)
}

// ErrUnsupportedEcosystem is returned by Source.Fetch when the source has no
// data for an ecosystem. The Store treats it as a benign skip rather than a
// fetch failure.
var ErrUnsupportedEcosystem = errors.New("source does not cover this ecosystem")

// ErrDamagedCache is returned by Source.Fetch when the source's on-disk
// cache payload is present but fails integrity verification — its bytes
// no longer match the content hash recorded when it was written (truncated,
// emptied, or replaced), and no intact copy could be recovered (upstream
// unreachable, or the re-fetch also failed verification).
//
// The Store routes this error to its damaged-source report rather than the
// ordinary fetch-error path: a damaged cache is a distinct condition from a
// network failure, because the operator's remediation differs (inspect the
// cache dir vs. check connectivity) and because serving *anything* from the
// damaged bucket would silently reduce that source's coverage.
var ErrDamagedCache = errors.New("cached payload failed content-hash verification")

// Verdict is the result of a Store lookup. Empty Reports means "no source
// flagged this package version."
type Verdict struct {
	Ref     PackageRef
	Reports []MalwareReport
}

// Flagged reports whether at least one source produced a report.
func (v Verdict) Flagged() bool { return len(v.Reports) > 0 }

// Sources returns the unique SourceIDs that contributed to the verdict, in
// stable order.
func (v Verdict) Sources() []string {
	seen := make(map[string]struct{}, len(v.Reports))
	out := make([]string, 0, len(v.Reports))
	for _, r := range v.Reports {
		if _, ok := seen[r.SourceID]; ok {
			continue
		}
		seen[r.SourceID] = struct{}{}
		out = append(out, r.SourceID)
	}
	return out
}
