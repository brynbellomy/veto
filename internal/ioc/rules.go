package ioc

import "context"

// RuleScanner runs byte-pattern rules (YARA and equivalents) against file
// contents and reports which rules matched. It is a DELIBERATELY SEPARATE
// contract from Store: a Store answers an O(1) keyed lookup of a precomputed
// atom (a hash, a domain), whereas a RuleScanner streams raw bytes through a
// rule engine that decides matches by content. The two never share an index
// and must not be conflated.
//
// The engine is DEFERRED. A real YARA engine means CGO (libyara) or a pure-Go
// reimplementation; CGO is in tension with veto's distroless/static build
// target, and no vetted pure-Go YARA engine is in the dependency budget today.
// This interface is the target a future engine (or feed-driven rule loader)
// implements; until one lands, NopRuleScanner is wired everywhere and the
// subsystem costs nothing. Do NOT add libyara or a yara-go module to satisfy
// this contract — implement it in a subpackage that owns that dependency, the
// same way concrete Sources own their HTTP clients.
type RuleScanner interface {
	// ScanBytes runs every loaded rule against data and returns one RuleMatch
	// per matching rule. Implementations must respect ctx cancellation and be
	// safe for concurrent use. An empty slice with a nil error means "no rule
	// matched."
	ScanBytes(ctx context.Context, data []byte) ([]RuleMatch, error)
}

// RuleMatch records one rule firing against scanned bytes.
type RuleMatch struct {
	// RuleName is the matched rule's identifier (e.g. a YARA rule name).
	RuleName string

	// SourceID is the stable identifier of the feed that supplied the rule.
	SourceID string

	// Tags are the rule's free-form tags (malware family, severity, ...).
	// Display only — never used for matching.
	Tags []string
}

// NopRuleScanner is a RuleScanner that loads no rules and matches nothing. It
// is the zero-cost default while the YARA engine is deferred; wire it in at
// construction so call sites stay unconditional.
type NopRuleScanner struct{}

var _ RuleScanner = (*NopRuleScanner)(nil)

// ScanBytes implements RuleScanner. Always returns no matches and a nil error.
func (NopRuleScanner) ScanBytes(ctx context.Context, data []byte) ([]RuleMatch, error) {
	return nil, nil
}
