package ioc

import "context"

// NopSource is a Source that returns no indicators. It is the zero-cost
// default for disabled or unconfigured feeds; wire it in at construction so
// callers can avoid nil-checks.
type NopSource struct{}

var _ Source = (*NopSource)(nil)

// ID implements Source.
func (NopSource) ID() string { return "nop" }

// Fetch implements Source. Always returns an empty slice and a nil error.
func (NopSource) Fetch(ctx context.Context) ([]Indicator, error) {
	return nil, nil
}

// NopStore is a Store that matches nothing and indexes nothing. It is the
// zero-cost default for an IOC subsystem with no feeds configured (the
// shipping default — every feed is opt-in). Because its
// IndicatorCountByType is always zero, callers that gate work on indicator
// presence (the cache hash-scan) do no work at all.
type NopStore struct{}

var _ Store = (*NopStore)(nil)

// Lookup implements Store. Always returns an unmatched Verdict echoing the
// (normalized) query.
func (NopStore) Lookup(typ IndicatorType, value string) Verdict {
	return Verdict{Type: typ, Value: normalizeValue(value)}
}

// Refresh implements Store. No-op; always succeeds.
func (NopStore) Refresh(ctx context.Context) error { return nil }

// SourceIDs implements Store. Always empty.
func (NopStore) SourceIDs() []string { return nil }

// IndicatorCount implements Store. Always zero.
func (NopStore) IndicatorCount() int { return 0 }

// IndicatorCountByType implements Store. Always zero.
func (NopStore) IndicatorCountByType(typ IndicatorType) int { return 0 }
