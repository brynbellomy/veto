// Package ioc defines the contract for host-level indicator-of-compromise
// (IOC) feeds and the keyed lookup store they feed into.
//
// A Source is one upstream IOC feed (abuse.ch, a MISP instance, ...). Unlike
// intel.Source, an IOC Source is NOT ecosystem-scoped: Fetch returns every
// indicator the feed knows about in a single call, because IOCs (file hashes,
// domains, IPs, URLs) are not partitioned by package ecosystem. A Store
// aggregates indicators from many Sources and answers O(1) membership queries
// keyed by (type, value).
//
// Consumers depend on the parent package only — concrete sources live in
// subpackages under sources/ so their dependencies (HTTP clients,
// format-specific parsers) never bleed into the contract.
//
// YARA byte-pattern matching is a deliberately separate contract: it runs
// rules against file CONTENTS rather than answering a keyed lookup. See
// rules.go (RuleScanner) for that seam.
package ioc

import (
	"context"
	"time"
)

// IndicatorType identifies the kind of atom an Indicator carries. The type is
// part of the Store's lookup key: a SHA256 value and an identical-looking
// domain string never collide because their types differ.
type IndicatorType string

const (
	// IndicatorSHA256 is a hex-encoded SHA-256 file hash (64 lowercase hex
	// chars when normalized).
	IndicatorSHA256 IndicatorType = "sha256"
	// IndicatorSHA1 is a hex-encoded SHA-1 file hash (40 lowercase hex chars).
	IndicatorSHA1 IndicatorType = "sha1"
	// IndicatorMD5 is a hex-encoded MD5 file hash (32 lowercase hex chars).
	IndicatorMD5 IndicatorType = "md5"
	// IndicatorDomain is a DNS hostname (lowercase, no scheme, no path).
	IndicatorDomain IndicatorType = "domain"
	// IndicatorIPv4 is a dotted-quad IPv4 address.
	IndicatorIPv4 IndicatorType = "ipv4"
	// IndicatorURL is a full URL (lowercase scheme+host).
	IndicatorURL IndicatorType = "url"
)

// Indicator is one indicator-of-compromise reported by one Source. It is the
// IOC analogue of intel.MalwareReport: the Store keeps indicators from
// different sources distinct so downstream UI can show every feed that flagged
// a given atom.
type Indicator struct {
	// Type is the indicator kind and the first half of the Store's lookup key.
	Type IndicatorType

	// Value is the NORMALIZED indicator payload: lowercase hex for hashes,
	// lowercase host for domains and URLs, canonical dotted-quad for IPv4. It
	// is the second half of the Store's lookup key. Sources MUST normalize
	// before emitting so the Store can key raw bytes without re-parsing; the
	// Store also normalizes the query side so an attacker can't bypass a hit
	// with mixed-case hex.
	Value string

	// SourceID is the stable identifier of the upstream feed (e.g. "abusech").
	SourceID string

	// ThreatLabel is a free-form description from the source (malware family,
	// campaign name, ...). Display only — never used for matching.
	ThreatLabel string

	// Reference is a source-specific URL or identifier for the indicator.
	// Empty when the source has none.
	Reference string

	// PublishedAt is when the source first observed the indicator. Zero value
	// means the source did not record this.
	PublishedAt time.Time
}

// Source fetches indicators of compromise from one upstream feed.
//
// Unlike intel.Source, a Source is not ecosystem-scoped: Fetch returns every
// indicator the feed knows about. Implementations MUST be safe to call
// concurrently and MUST emit Indicator.Value already normalized (lowercase hex
// for hashes, lowercase host for domains/URLs); the Store keys on the raw
// value and does not re-normalize Source output.
type Source interface {
	// ID returns a short stable identifier (e.g. "abusech"). Two sources must
	// not share an ID.
	ID() string

	// Fetch retrieves the feed's current indicator set. Implementations should
	// return quickly when a cached snapshot is still valid (etag or
	// equivalent); the parent project schedules refreshes.
	Fetch(ctx context.Context) ([]Indicator, error)
}

// Verdict is the result of a Store lookup. It echoes the queried indicator and
// carries every Indicator that matched it. Empty Matches means "no source
// flagged this (type, value)."
type Verdict struct {
	// Type and Value echo the (normalized) query so the verdict is
	// self-describing for downstream display and logging.
	Type  IndicatorType
	Value string

	// Matches holds every Indicator that matched the query, across all
	// sources. One feed reporting the same atom twice collapses to one entry;
	// two feeds reporting it stay distinct.
	Matches []Indicator
}

// Matched reports whether at least one source flagged the queried indicator.
func (v Verdict) Matched() bool { return len(v.Matches) > 0 }

// Sources returns the unique SourceIDs that contributed to the verdict, in
// stable order.
func (v Verdict) Sources() []string {
	seen := make(map[string]struct{}, len(v.Matches))
	out := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		if _, ok := seen[m.SourceID]; ok {
			continue
		}
		seen[m.SourceID] = struct{}{}
		out = append(out, m.SourceID)
	}
	return out
}
