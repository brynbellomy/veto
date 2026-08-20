package intel

import (
	"context"
	stderrors "errors"
	"maps"
	"sync"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// Store is the deduplicated, in-memory lookup index built from one or more
// Sources. Implementations must be safe for concurrent Lookup calls while a
// Refresh is in flight; Lookup is the hot path and runs on every install.
type Store interface {
	// Lookup returns a Verdict for the given package reference. Matching is
	// (ecosystem, name, version): an exact-version match returns reports that
	// specifically named that version; if the lookup ref has an empty Version,
	// reports for any version of the package are returned.
	Lookup(ref PackageRef) Verdict

	// Refresh re-fetches all configured sources concurrently and atomically
	// replaces the in-memory index on success. Per-source errors are logged
	// but do not abort the whole refresh; ErrUnsupportedEcosystem is silently
	// skipped. Returns the aggregate error only when every source failed.
	Refresh(ctx context.Context) error

	// SourceIDs returns the IDs of all sources registered with this Store, in
	// registration order.
	SourceIDs() []string

	// ReportCount returns the total number of indexed (source, package, version)
	// tuples. Callers can use this to fail closed when the index is implausibly
	// small (e.g. an upstream feed returning an empty payload).
	ReportCount() int

	// Damaged returns the (source, ecosystem) buckets that failed
	// integrity verification on the most recent Refresh and could not be
	// repaired or retained. The base Store implementation returns nil;
	// BaselineStore (NewStoreWithBaseline) reports real damage. Callers
	// enforcing fail-closed behavior consult this after Refresh.
	Damaged() []SourceDamage
}

// NewStore builds a Store backed by the given sources. The Store is empty
// until Refresh is called.
func NewStore(logger zerolog.Logger, sources ...Source) Store {
	if len(sources) == 0 {
		sources = []Source{NopSource{}}
	}
	return &memStore{
		logger:      logger.With().Str("component", "intel.store").Logger(),
		sources:     sources,
		byVersion:   make(map[versionKey][]MalwareReport),
		byName:      make(map[nameKey][]MalwareReport),
		bySourceEco: make(map[sourceEcoKey][]MalwareReport),
	}
}

// partialDropThreshold is the minimum fraction of the previous Refresh's
// per-(source, ecosystem) report count that the new fetch must clear to
// have its data swapped in. A new fetch returning < threshold * previous
// is treated as a partial failure for that (source, ecosystem) pair —
// the new data is rejected and the previous slice retained, so a single
// MITM'd or wedged upstream can't silently shrink the index. Set
// conservatively: malware feeds grow over time, so any meaningful drop
// is suspicious.
//
// Edge case: int(float64(1) * 0.5) = 0, so a previous count of 1 makes
// the retention guard unreachable — any newCount (including 0) clears
// the bar. Intentional: you can't meaningfully claim "shrunk" from a
// baseline of a single report, and an empty fetch following a single
// stale one is the case where the new data is probably correct.
const partialDropThreshold = 0.5

// SourceDamage describes one (source, ecosystem) bucket that failed
// integrity verification or implausibly collapsed against its baseline,
// and could not be repaired or retained. Reported via Store.Damaged so
// the caller (the gate, sync, doctor) can decide fail-closed behavior
// and the operator can see exactly which source's coverage went missing.
type SourceDamage struct {
	SourceID  string
	Ecosystem Ecosystem
	// Reason is a human-readable classification of the failure mode.
	Reason string
	// Got is the report count the fetch produced (0 when the fetch
	// errored before producing reports).
	Got int
	// Baseline is the recorded known-good count (0 when no baseline
	// existed for the bucket).
	Baseline int
}

// versionKey targets exact (ecosystem, name, version) lookups.
type versionKey struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// nameKey targets "any version of (ecosystem, name)" lookups. Used both for
// reports that flag every version of a package, and for unversioned install
// requests where the user is implicitly accepting whatever version resolves.
type nameKey struct {
	Ecosystem Ecosystem
	Name      string
}

// sourceEcoKey identifies the unit of work the store retains per Refresh:
// one (source, ecosystem) fetch. Retention happens at this granularity so a
// failure in (aikido, pypi) doesn't drag down (aikido, npm) — and so a
// network MITM that drops a single feed can't quietly remove every aikido
// finding from the lookup index.
type sourceEcoKey struct {
	SourceID  string
	Ecosystem Ecosystem
}

// dedupKey identifies a single MalwareReport in the deduplication pass.
// A struct (rather than a concatenated string) avoids the theoretical
// collision where any field contains the separator character, and the
// extra type-safety makes the dedup intent obvious at the call site.
//
// Range bounds are included so a single advisory with multiple
// distinct intervals (e.g. OSV ranges that decompose into two
// `[introduced, fixed]` pairs) doesn't collapse to one report — each
// interval expresses a different version constraint and needs to
// survive into the index.
type dedupKey struct {
	SourceID     string
	Ecosystem    Ecosystem
	Name         string
	Version      string
	Introduced   string
	Fixed        string
	LastAffected string
}

type memStore struct {
	logger  zerolog.Logger
	sources []Source

	mu        sync.RWMutex
	byVersion map[versionKey][]MalwareReport
	byName    map[nameKey][]MalwareReport
	// bySourceEco retains the most recent successful fetch of each
	// (source, ecosystem) pair so the next Refresh can decide, per pair,
	// whether the new data is plausible (use it) or implausibly small
	// (retain the previous slice and log a warning). Read+written under
	// the same mu as byVersion/byName.
	bySourceEco map[sourceEcoKey][]MalwareReport
}

var _ Store = (*memStore)(nil)

// Lookup implements Store. Version-aware semantics:
//
//   - ref.Version == "":   unpinned install. The caller didn't pin, so any
//     flagged version against this name is a hit. Returns every byName entry.
//   - ref.Version != "":   pinned install. Refuses when ANY of:
//   - an exact (name, version) match exists in byVersion, OR
//   - a byName entry carries a Range that contains ref.Version
//     (under the per-ecosystem comparator in range.go), OR
//   - a byName entry has both Range==nil and Version=="" — the legacy
//     "all versions, no interval" shape. Post-osvschema-rewrite OSV
//     feeds emit unbounded ranges instead, but non-OSV sources (e.g.
//     Aikido, which doesn't model ranges) still produce this shape
//     and the gate must keep refusing those.
//
// A byName entry with a concrete-but-different Version is scoped to
// that specific version and does NOT apply to the current query. This
// is the version-aware semantics introduced in commit 183f807 that
// fixed the react@1.0.0/35.0.0 false positive.
//
// What changed in the range-aware layer: bounded ranges
// (`introduced: 1.0.0, fixed: 2.0.0`) used to be emitted by
// osvschema.Reports as a single empty-Version, empty-Range report,
// which refused every version of the name — including post-fix ones.
// Now osvschema emits one report per interval with the interval
// attached as Range, and Lookup tests interval membership at query
// time. This closes the MAL-2022-466 / foo@3.0.0 false positive where
// a `{introduced:"0", fixed:"2.0.3"}` advisory was refusing every
// install of `foo` even though 3.0.0 is outside the affected range.
func (s *memStore) Lookup(ref PackageRef) Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Preserve the caller's view of the ref in the returned Verdict so
	// downstream UI can display the name the user typed. Normalize a
	// separate lookupName for indexing so an attacker can't bypass the
	// gate by typo-equivalent capitalization (PEP 503 PyPI, lowercased
	// npm). See internal/intel/normalize.go.
	verdict := Verdict{Ref: ref}
	lookupName := NormalizeName(ref.Ecosystem, ref.Name)
	lookupVersion := NormalizeVersion(ref.Ecosystem, ref.Version)

	if ref.Version == "" {
		if reports, ok := s.byName[nameKey{ref.Ecosystem, lookupName}]; ok {
			verdict.Reports = append(verdict.Reports, reports...)
		}
		return verdict
	}

	// Exact (name, version) match — every entry here applies.
	if reports, ok := s.byVersion[versionKey{ref.Ecosystem, lookupName, lookupVersion}]; ok {
		verdict.Reports = append(verdict.Reports, reports...)
	}
	// Range-bearing and legacy "all versions" findings. byName holds
	// every report (pinned, ranged, and the rare empty-Version-empty-Range
	// case from non-OSV sources). We pick out the entries that apply to
	// lookupVersion here:
	//   - r.Range != nil: defer to the per-ecosystem comparator. An
	//     unbounded range short-circuits to true; a bounded range
	//     calls into the semver parser.
	//   - r.Range == nil && r.Version == "": legacy any-version shape.
	//   - r.Range == nil && r.Version != "": concrete-but-different
	//     version — already handled by the byVersion lookup above and
	//     skipped here so it doesn't double-count or false-positive.
	if reports, ok := s.byName[nameKey{ref.Ecosystem, lookupName}]; ok {
		for _, r := range reports {
			switch {
			case r.Range != nil:
				if InRange(ref.Ecosystem, lookupVersion, *r.Range) {
					verdict.Reports = append(verdict.Reports, r)
				}
			case r.Version == "":
				verdict.Reports = append(verdict.Reports, r)
			}
		}
	}

	return verdict
}

// fetchResult bundles one (source, ecosystem) fetch outcome.
type fetchResult struct {
	key     sourceEcoKey
	reports []MalwareReport
	err     error
}

// Refresh implements Store.
//
// Three-stage pipeline:
//
//  1. fetchAll: concurrent per-(source, ecosystem) fetch.
//  2. applyRetention: per-(source, ecosystem) decision to USE the new
//     slice or RETAIN the previous one. Retention triggers when:
//     - the fetch returned an error (and we have previous data), OR
//     - the new count drops below partialDropThreshold * previous count
//     This closes the partial-refresh hole where a single MITM'd feed
//     could silently wipe an entire source's coverage.
//  3. reindex+swap: build byVersion / byName from the resolved
//     per-source-ecosystem slices, then swap under the write lock.
//
// Fail-closed conditions (Refresh returns an error and the in-memory
// index is left unchanged):
//
//   - every (source, ecosystem) fetch returned a real error.
//   - every (source, ecosystem) fetch returned ErrUnsupportedEcosystem
//     (the prior code accepted this case as "success" and would have
//     swapped in an empty index — M4 in the audit).
//   - the resolved set is non-empty but every retained slice is empty
//     AND we have no previous data to retain.
func (s *memStore) Refresh(ctx context.Context) error {
	results := s.fetchAll(ctx)

	// Snapshot previous bySourceEco under the read lock so retention can
	// fall back to it without holding the write lock during retention
	// decisions. Slice contents are never mutated post-publication.
	s.mu.RLock()
	prevBySourceEco := make(map[sourceEcoKey][]MalwareReport, len(s.bySourceEco))
	maps.Copy(prevBySourceEco, s.bySourceEco)
	s.mu.RUnlock()

	resolved, retentionInfo, fetchErrs := s.applyRetention(results, prevBySourceEco)

	if len(resolved) == 0 {
		if len(fetchErrs) > 0 {
			return errors.WithNew("all intel sources failed to refresh").
				Set("failures", len(fetchErrs)).
				Cause(stderrors.Join(fetchErrs...))
		}
		// Every (source, ecosystem) returned ErrUnsupportedEcosystem AND
		// there was no prior data to retain. Without successful fetches
		// we cannot safely swap in a (presumably empty) index.
		return errors.WithNew("no intel source produced data").
			Set("hint", "check VETO_SOURCES configuration and feed ecosystem support")
	}

	nextByVersion, nextByName, totalReports := buildIndices(resolved)

	s.mu.Lock()
	s.byVersion = nextByVersion
	s.byName = nextByName
	s.bySourceEco = resolved
	s.mu.Unlock()

	s.logger.Info().
		Int("reports", totalReports).
		Int("source_ecos_fresh", retentionInfo.fresh).
		Int("source_ecos_retained", retentionInfo.retained).
		Int("source_ecos_failed", len(fetchErrs)).
		Msg("intel store refreshed")

	return nil
}

// fetchAll runs every (source, ecosystem) fetch concurrently and collects
// every result. Caller decides what to do with errors / empty slices.
func (s *memStore) fetchAll(ctx context.Context) []fetchResult {
	out := make(chan fetchResult, len(s.sources)*len(AllEcosystems))
	var wg sync.WaitGroup
	for _, src := range s.sources {
		for _, eco := range AllEcosystems {
			wg.Add(1)
			go func(src Source, eco Ecosystem) {
				defer wg.Done()
				// Pre-check ctx so an already-cancelled refresh
				// short-circuits without paying the spawn-then-fail cost
				// across len(sources)*len(AllEcosystems) goroutines.
				select {
				case <-ctx.Done():
					out <- fetchResult{
						key: sourceEcoKey{SourceID: src.ID(), Ecosystem: eco},
						err: ctx.Err(),
					}
					return
				default:
				}
				reports, err := src.Fetch(ctx, eco)
				out <- fetchResult{
					key:     sourceEcoKey{SourceID: src.ID(), Ecosystem: eco},
					reports: reports,
					err:     err,
				}
			}(src, eco)
		}
	}
	go func() { wg.Wait(); close(out) }()

	results := make([]fetchResult, 0, len(s.sources)*len(AllEcosystems))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// retentionStats reports how many (source, ecosystem) buckets used new
// data vs. retained previous data this refresh. Logged for observability.
type retentionStats struct {
	fresh    int
	retained int
}

// applyRetention turns raw fetch results into the resolved
// per-(source, ecosystem) report slices that will populate the next
// index. Retention triggers per-bucket — a fetch error or a steep drop
// in count keeps the previous data instead of letting it vanish.
//
// Returned fetchErrs include only buckets that errored AND had no
// previous data to retain — those are the buckets that genuinely
// failed and could not be recovered.
func (s *memStore) applyRetention(
	results []fetchResult,
	prev map[sourceEcoKey][]MalwareReport,
) (map[sourceEcoKey][]MalwareReport, retentionStats, []error) {
	resolved := make(map[sourceEcoKey][]MalwareReport)
	var stats retentionStats
	var fetchErrs []error

	for _, r := range results {
		// ErrUnsupportedEcosystem is not a failure — the source simply
		// doesn't cover this ecosystem. Skip without contributing to
		// either fresh or retained.
		if r.err != nil && stderrors.Is(r.err, ErrUnsupportedEcosystem) {
			continue
		}

		if r.err != nil {
			// Real error. Retain prior data if any; otherwise record
			// the failure so the caller can decide whether the refresh
			// as a whole is salvageable.
			if prevReports, ok := prev[r.key]; ok && len(prevReports) > 0 {
				resolved[r.key] = prevReports
				stats.retained++
				s.logger.Warn().
					Err(r.err).
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("retained_reports", len(prevReports)).
					Msg("source fetch failed; retaining previous data")
				continue
			}
			s.logger.Warn().
				Err(r.err).
				Str("source", r.key.SourceID).
				Str("ecosystem", string(r.key.Ecosystem)).
				Msg("source fetch failed; no previous data to retain")
			fetchErrs = append(fetchErrs,
				errors.With(r.err, "fetch failed").
					Set("source", r.key.SourceID).
					Set("ecosystem", string(r.key.Ecosystem)))
			continue
		}

		// Fetch succeeded. Decide between new and previous based on
		// the partial-drop threshold. Only triggers when we have a
		// previous baseline to compare against — first-ever fetches
		// always use the new data.
		newCount := len(r.reports)
		prevReports, hadPrev := prev[r.key]
		prevCount := len(prevReports)
		if hadPrev && prevCount > 0 {
			minAllowed := int(float64(prevCount) * partialDropThreshold)
			if newCount < minAllowed {
				resolved[r.key] = prevReports
				stats.retained++
				s.logger.Warn().
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("new_count", newCount).
					Int("prev_count", prevCount).
					Float64("threshold", partialDropThreshold).
					Msg("source returned implausibly few reports; retaining previous data")
				continue
			}
		}
		resolved[r.key] = r.reports
		stats.fresh++
	}

	return resolved, stats, fetchErrs
}

// buildIndices flattens per-(source, ecosystem) slices into the two
// lookup maps the Store serves Lookups from. Dedup is keyed by
// dedupKey so that distinct sources reporting the same package stay
// distinct, but a single source reporting the same finding twice
// (unusual but legal in OSV-style feeds) collapses to one entry.
func buildIndices(resolved map[sourceEcoKey][]MalwareReport) (
	map[versionKey][]MalwareReport,
	map[nameKey][]MalwareReport,
	int,
) {
	byVersion := make(map[versionKey][]MalwareReport)
	byName := make(map[nameKey][]MalwareReport)
	seen := make(map[dedupKey]struct{})
	total := 0
	for _, reports := range resolved {
		for _, report := range reports {
			// Normalize the indexed name to its ecosystem-canonical form
			// so an attacker can't republish under a typo-equivalent
			// capitalization (PEP 503 PyPI, lowercased npm) and slip past
			// Lookup. The report's own Name field stays as the feed
			// reported it so the verdict surface still shows the upstream
			// spelling. See internal/intel/normalize.go.
			indexName := NormalizeName(report.Ecosystem, report.Name)
			indexVersion := NormalizeVersion(report.Ecosystem, report.Version)
			k := dedupKey{
				SourceID:  report.SourceID,
				Ecosystem: report.Ecosystem,
				Name:      indexName,
				Version:   indexVersion,
			}
			if report.Range != nil {
				k.Introduced = report.Range.Introduced
				k.Fixed = report.Range.Fixed
				k.LastAffected = report.Range.LastAffected
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			if report.Version != "" {
				vk := versionKey{report.Ecosystem, indexName, indexVersion}
				byVersion[vk] = append(byVersion[vk], report)
			}
			nk := nameKey{report.Ecosystem, indexName}
			byName[nk] = append(byName[nk], report)
			total++
		}
	}
	return byVersion, byName, total
}

// SourceIDs implements Store.
func (s *memStore) SourceIDs() []string {
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.ID())
	}
	return out
}

// ReportCount implements Store. Sums the size of every value slice in the
// version-keyed index plus name-only reports (those with empty Version, kept
// only in byName). The number is a coarse signal of intel-store health — a
// healthy store has hundreds of thousands of reports.
func (s *memStore) ReportCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, reports := range s.byVersion {
		total += len(reports)
	}
	// Add reports that are name-only (no entry in byVersion). These are
	// the "any version of this package is bad" findings.
	for _, reports := range s.byName {
		for _, r := range reports {
			if r.Version == "" {
				total++
			}
		}
	}
	return total
}

// Damaged implements Store. The base store has no persistent baseline and
// no damaged-cache classification, so it always reports no damage. Use
// NewStoreWithBaseline for the integrity-enforcing variant.
func (s *memStore) Damaged() []SourceDamage {
	return nil
}
