package intel

import (
	"context"
	stderrors "errors"
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
const partialDropThreshold = 0.5

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
type dedupKey struct {
	SourceID  string
	Ecosystem Ecosystem
	Name      string
	Version   string
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

// Lookup implements Store. Semantics:
//
//   - ref.Version == "":   unpinned install. Returns every report against any
//     version of the package.
//   - ref.Version != "":   pinned install. Returns reports for that exact
//     version, AND any other report for the same name — every source we
//     ingest is malware-only, so a name match at any version is a hit.
//
// Why name-match wins regardless of recorded version: aikido / openssf /
// osv / pypa entries assert "this package name is malicious." The
// Version field on the report is the version the source happened to
// sample, not "only this version is bad." Treating a different-version
// query as a miss would let an attacker republish the same name under a
// new version and bypass the gate; a lockfile pinning a version the
// source didn't sample would also slip through. We refuse on name.
//
// If a future source introduces version-specific non-malware advisories,
// this policy must be revisited — but every source today is malware-only
// (filtered to MAL-* IDs / aikido's malware feed), so name = refuse is
// the right default.
func (s *memStore) Lookup(ref PackageRef) Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verdict := Verdict{Ref: ref}

	if ref.Version == "" {
		if reports, ok := s.byName[nameKey{ref.Ecosystem, ref.Name}]; ok {
			verdict.Reports = append(verdict.Reports, reports...)
		}
		return verdict
	}

	// Exact-version hits go first so their position in the verdict
	// reflects "this is the version the upstream feed flagged."
	exactVersionHits := map[*MalwareReport]struct{}{}
	if reports, ok := s.byVersion[versionKey{ref.Ecosystem, ref.Name, ref.Version}]; ok {
		for i := range reports {
			verdict.Reports = append(verdict.Reports, reports[i])
			exactVersionHits[&reports[i]] = struct{}{}
		}
	}
	// Name-match: include every other report for this name. Dedups
	// against the exact-version hits above by report identity so a
	// single entry doesn't appear twice in the refusal output.
	if reports, ok := s.byName[nameKey{ref.Ecosystem, ref.Name}]; ok {
		for i := range reports {
			r := reports[i]
			if r.Version == ref.Version {
				// This is an exact-version hit; already counted above.
				continue
			}
			verdict.Reports = append(verdict.Reports, r)
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
	for k, v := range s.bySourceEco {
		prevBySourceEco[k] = v
	}
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
			k := dedupKey{
				SourceID:  report.SourceID,
				Ecosystem: report.Ecosystem,
				Name:      report.Name,
				Version:   report.Version,
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			if report.Version != "" {
				vk := versionKey{report.Ecosystem, report.Name, report.Version}
				byVersion[vk] = append(byVersion[vk], report)
			}
			nk := nameKey{report.Ecosystem, report.Name}
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
	for k, reports := range s.byName {
		for _, r := range reports {
			if r.Version == "" {
				_ = k
				total++
			}
		}
	}
	return total
}
