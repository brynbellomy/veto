package ioc

import (
	"context"
	stderrors "errors"
	"maps"
	"strings"
	"sync"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// Store is the in-memory, deduplicated lookup index built from one or more
// Sources. Implementations must be safe for concurrent Lookup calls while a
// Refresh is in flight; Lookup is the hot path and may run on every cached
// file during a scan.
type Store interface {
	// Lookup returns a Verdict for the given indicator type and value. The
	// query value is normalized internally (lowercased) before keying, so
	// callers may pass raw upstream-cased values. An empty Verdict.Matches
	// means no source flagged the atom.
	Lookup(typ IndicatorType, value string) Verdict

	// Refresh re-fetches all configured sources concurrently and atomically
	// replaces the in-memory index on success. Per-source errors are logged
	// but do not abort the whole refresh; previous data is retained per source
	// when a fetch fails or returns implausibly few indicators. Returns an
	// error only when no source produced usable data and there was nothing to
	// retain.
	Refresh(ctx context.Context) error

	// SourceIDs returns the IDs of all sources registered with this Store, in
	// registration order.
	SourceIDs() []string

	// IndicatorCount returns the total number of indexed (source, type, value)
	// tuples. Callers use this to fail closed when the index is implausibly
	// small.
	IndicatorCount() int

	// IndicatorCountByType returns the number of indexed indicators of the
	// given type. The cache scanner reads it to gate expensive work — when
	// IndicatorCountByType(IndicatorSHA256) is zero, no cached file is opened
	// or hashed, so an unconfigured IOC store imposes no scan cost.
	IndicatorCountByType(typ IndicatorType) int
}

// NewStore builds a Store backed by the given sources. The Store is empty
// until Refresh is called. With no sources, it serves an always-unmatched
// index over a single NopSource.
func NewStore(logger zerolog.Logger, sources ...Source) Store {
	if len(sources) == 0 {
		sources = []Source{NopSource{}}
	}
	return &memStore{
		logger:   logger.With().Str("component", "ioc.store").Logger(),
		sources:  sources,
		byKey:    make(map[indicatorKey][]Indicator),
		bySource: make(map[string][]Indicator),
		typeSet:  make(map[IndicatorType]int),
	}
}

// partialDropThreshold is the minimum fraction of a source's previous
// indicator count that a new fetch must clear to be swapped in. A fetch
// returning fewer is treated as a partial failure for that source — the new
// data is rejected and the previous slice retained — so a single MITM'd or
// wedged upstream can't silently shrink the index. IOC feeds grow over time,
// so a meaningful drop is suspicious. Mirrors intel.partialDropThreshold.
//
// Edge case: int(float64(1) * 0.5) = 0, so a previous count of 1 makes the
// guard unreachable. Intentional — you can't claim "shrunk" from a baseline
// of a single indicator.
const partialDropThreshold = 0.5

// indicatorKey is the (type, value) tuple the Store serves Lookups from. The
// value is always stored normalized.
type indicatorKey struct {
	Type  IndicatorType
	Value string
}

// dedupKey identifies a single Indicator in the deduplication pass. A struct
// (rather than a concatenated string) avoids separator-collision and makes the
// dedup intent obvious. Distinct sources reporting the same atom stay
// distinct; one source reporting it twice collapses to one entry.
type dedupKey struct {
	SourceID string
	Type     IndicatorType
	Value    string
}

type memStore struct {
	logger  zerolog.Logger
	sources []Source

	mu    sync.RWMutex
	byKey map[indicatorKey][]Indicator
	// bySource retains the most recent successful fetch of each source so the
	// next Refresh can decide, per source, whether the new data is plausible
	// (use it) or implausibly small (retain the previous slice). Read+written
	// under the same mu as byKey.
	bySource map[string][]Indicator
	// typeSet counts indexed indicators per type. IndicatorCountByType reads it
	// to answer "are there any SHA256 indicators?" in O(1) so callers can gate
	// expensive work (file hashing) on the cheap signal. Maintained under mu.
	typeSet map[IndicatorType]int
}

var _ Store = (*memStore)(nil)

// normalizeValue canonicalizes an indicator value for keying. Hashes and
// hostnames are case-insensitive; lowercasing both the index and the query
// side closes the mixed-case bypass. Surrounding whitespace is trimmed.
func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// Lookup implements Store. O(1) keyed by (type, normalized value).
func (s *memStore) Lookup(typ IndicatorType, value string) Verdict {
	norm := normalizeValue(value)
	verdict := Verdict{Type: typ, Value: norm}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if matches, ok := s.byKey[indicatorKey{Type: typ, Value: norm}]; ok {
		verdict.Matches = append(verdict.Matches, matches...)
	}
	return verdict
}

// fetchResult bundles one source's fetch outcome.
type fetchResult struct {
	sourceID   string
	indicators []Indicator
	err        error
}

// Refresh implements Store.
//
// Three-stage pipeline mirroring intel.Store:
//
//  1. fetchAll: concurrent per-source fetch.
//  2. applyRetention: per-source decision to USE the new slice or RETAIN the
//     previous one (on fetch error or a steep count drop). Closes the
//     partial-refresh hole where a single MITM'd feed wipes a source's
//     coverage.
//  3. reindex+swap: rebuild byKey from the resolved per-source slices and swap
//     under the write lock.
//
// Fail-closed: returns an error (leaving the index unchanged) only when the
// resolved set is empty — every source errored with no previous data to
// retain.
func (s *memStore) Refresh(ctx context.Context) error {
	results := s.fetchAll(ctx)

	// Snapshot previous bySource under the read lock so retention can fall back
	// to it without holding the write lock during decisions. Slice contents
	// are never mutated post-publication.
	s.mu.RLock()
	prevBySource := make(map[string][]Indicator, len(s.bySource))
	maps.Copy(prevBySource, s.bySource)
	s.mu.RUnlock()

	resolved, stats, fetchErrs := s.applyRetention(results, prevBySource)

	if len(resolved) == 0 {
		if len(fetchErrs) > 0 {
			return errors.WithNew("all ioc sources failed to refresh").
				Set("failures", len(fetchErrs)).
				Cause(stderrors.Join(fetchErrs...))
		}
		// No errors and nothing resolved means every source returned an empty
		// set with no prior data. That is a valid "no indicators configured"
		// state for an all-Nop store, not a failure.
		s.mu.Lock()
		s.byKey = make(map[indicatorKey][]Indicator)
		s.bySource = make(map[string][]Indicator)
		s.typeSet = make(map[IndicatorType]int)
		s.mu.Unlock()
		return nil
	}

	nextByKey, nextTypeSet, total := buildIndex(resolved)

	s.mu.Lock()
	s.byKey = nextByKey
	s.bySource = resolved
	s.typeSet = nextTypeSet
	s.mu.Unlock()

	s.logger.Info().
		Int("indicators", total).
		Int("sources_fresh", stats.fresh).
		Int("sources_retained", stats.retained).
		Int("sources_failed", len(fetchErrs)).
		Msg("ioc store refreshed")

	return nil
}

// fetchAll runs every source fetch concurrently and collects every result.
func (s *memStore) fetchAll(ctx context.Context) []fetchResult {
	out := make(chan fetchResult, len(s.sources))
	var wg sync.WaitGroup
	for _, src := range s.sources {
		wg.Add(1)
		go func(src Source) {
			defer wg.Done()
			// Pre-check ctx so an already-cancelled refresh short-circuits
			// without paying the spawn-then-fail cost across sources.
			select {
			case <-ctx.Done():
				out <- fetchResult{sourceID: src.ID(), err: ctx.Err()}
				return
			default:
			}
			indicators, err := src.Fetch(ctx)
			out <- fetchResult{sourceID: src.ID(), indicators: indicators, err: err}
		}(src)
	}
	go func() { wg.Wait(); close(out) }()

	results := make([]fetchResult, 0, len(s.sources))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// retentionStats reports how many sources used new data vs. retained previous
// data this refresh. Logged for observability.
type retentionStats struct {
	fresh    int
	retained int
}

// applyRetention turns raw fetch results into the resolved per-source slices
// that populate the next index. Retention triggers per-source — a fetch error
// or a steep count drop keeps the previous data instead of letting it vanish.
//
// Returned fetchErrs include only sources that errored AND had no previous
// data to retain.
func (s *memStore) applyRetention(
	results []fetchResult,
	prev map[string][]Indicator,
) (map[string][]Indicator, retentionStats, []error) {
	resolved := make(map[string][]Indicator)
	var stats retentionStats
	var fetchErrs []error

	for _, r := range results {
		if r.err != nil {
			if prevIndicators, ok := prev[r.sourceID]; ok && len(prevIndicators) > 0 {
				resolved[r.sourceID] = prevIndicators
				stats.retained++
				s.logger.Warn().
					Err(r.err).
					Str("source", r.sourceID).
					Int("retained_indicators", len(prevIndicators)).
					Msg("ioc source fetch failed; retaining previous data")
				continue
			}
			s.logger.Warn().
				Err(r.err).
				Str("source", r.sourceID).
				Msg("ioc source fetch failed; no previous data to retain")
			fetchErrs = append(fetchErrs,
				errors.With(r.err, "fetch failed").Set("source", r.sourceID))
			continue
		}

		// Fetch succeeded. An empty result with no prior baseline is a valid
		// "this feed has nothing" state; skip it without inflating the index
		// or the retention counters.
		newCount := len(r.indicators)
		prevIndicators, hadPrev := prev[r.sourceID]
		prevCount := len(prevIndicators)
		if hadPrev && prevCount > 0 {
			minAllowed := int(float64(prevCount) * partialDropThreshold)
			if newCount < minAllowed {
				resolved[r.sourceID] = prevIndicators
				stats.retained++
				s.logger.Warn().
					Str("source", r.sourceID).
					Int("new_count", newCount).
					Int("prev_count", prevCount).
					Float64("threshold", partialDropThreshold).
					Msg("ioc source returned implausibly few indicators; retaining previous data")
				continue
			}
		}
		if newCount == 0 {
			continue
		}
		resolved[r.sourceID] = r.indicators
		stats.fresh++
	}

	return resolved, stats, fetchErrs
}

// buildIndex flattens per-source slices into the lookup map the Store serves
// Lookups from, plus a per-type count. Dedup is keyed by dedupKey: distinct
// sources reporting the same atom stay distinct, a single source reporting it
// twice collapses to one entry.
func buildIndex(resolved map[string][]Indicator) (
	map[indicatorKey][]Indicator,
	map[IndicatorType]int,
	int,
) {
	byKey := make(map[indicatorKey][]Indicator)
	typeSet := make(map[IndicatorType]int)
	seen := make(map[dedupKey]struct{})
	total := 0
	for _, indicators := range resolved {
		for _, ind := range indicators {
			norm := normalizeValue(ind.Value)
			dk := dedupKey{SourceID: ind.SourceID, Type: ind.Type, Value: norm}
			if _, ok := seen[dk]; ok {
				continue
			}
			seen[dk] = struct{}{}
			// Index the normalized value; preserve the source's reported
			// casing on the Indicator itself for display.
			k := indicatorKey{Type: ind.Type, Value: norm}
			byKey[k] = append(byKey[k], ind)
			typeSet[ind.Type]++
			total++
		}
	}
	return byKey, typeSet, total
}

// SourceIDs implements Store.
func (s *memStore) SourceIDs() []string {
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.ID())
	}
	return out
}

// IndicatorCount implements Store. Sums every value slice in the index.
func (s *memStore) IndicatorCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, indicators := range s.byKey {
		total += len(indicators)
	}
	return total
}

// IndicatorCountByType implements Store. O(1) read of the per-type counter.
func (s *memStore) IndicatorCountByType(typ IndicatorType) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.typeSet[typ]
}
