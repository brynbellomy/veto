package intel

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// baselineFileName is the per-installation record of what each
// (source, ecosystem) bucket produced on its last known-good fetch.
// It closes the cold-start hole in the store's in-process retention
// guard: the previous-refresh map lives in process memory, which every
// CLI invocation starts without, so a damaged cache silently passed the
// relative check on every fresh run. The baseline file is the durable
// equivalent, written after a refresh resolves and consulted at the
// start of the next one.
const baselineFileName = "intel-baseline.json"

// baselineThreshold is the minimum fraction of a bucket's recorded
// baseline count that a new fetch must clear to be accepted when there is
// no in-process previous slice to retain. Same value as the in-process
// partialDropThreshold, deliberately: one policy, two storage layers.
//
// Ratio-only, no absolute per-source floor: the nine network sources span
// four orders of magnitude (aikido ~120k npm reports vs hades's 6 static
// entries), so any absolute floor is either useless for the small feeds
// or trips constantly for the large ones. A feed that legitimately sheds
// half its entries in one update is not a shape any of these feeds has
// exhibited — they are append-only malware/vuln catalogs — and the
// operator-facing message names the numbers so a legitimate curation can
// be resolved by deleting the baseline file.
const baselineThreshold = partialDropThreshold

// BaselineStore wraps the in-memory store with a persistent per-bucket
// count baseline. Construct via NewStoreWithBaseline; NewStore returns a
// store without one (tests and embedders that don't care about
// cross-invocation integrity).
//
// The baseline adds two decisions on top of the plain store's retention
// policy, both on the cold-start path where the in-process previous map
// is empty:
//
//   - a fetch error carrying ErrDamagedCache (a source refused to serve
//     its damaged cache and could not re-fetch) is reported as damage
//     instead of a plain fetch failure, because the operator's
//     remediation differs (inspect the cache dir vs. check connectivity);
//   - a successful fetch whose count collapses below
//     baselineThreshold * the recorded baseline — with nothing in-process
//     to retain — is rejected (the bucket contributes nothing) and
//     reported as damage. Serving it would silently reduce that source's
//     coverage, which is the vulnerability this type exists to close.
type BaselineStore struct {
	*memStore

	baselinePath string
	logger       zerolog.Logger

	// mu guards damaged between the Refresh goroutine fan-in and Damaged
	// readers. memStore's own mu guards the index; this one is separate so
	// a Damaged() call never contends with Lookups.
	mu      sync.Mutex
	damaged []SourceDamage
}

var _ Store = (*BaselineStore)(nil)

// NewStoreWithBaseline builds a Store backed by the given sources plus a
// persistent per-(source, ecosystem) count baseline stored at
// baselinePath (typically <cacheDir>/intel-baseline.json). The file is
// created lazily on the first successful refresh; its absence is not an
// error — the first refresh simply records the baseline instead of
// comparing against one.
func NewStoreWithBaseline(logger zerolog.Logger, baselinePath string, sources ...Source) *BaselineStore {
	if len(sources) == 0 {
		sources = []Source{NopSource{}}
	}
	inner := &memStore{
		logger:      logger.With().Str("component", "intel.store").Logger(),
		sources:     sources,
		byVersion:   make(map[versionKey][]MalwareReport),
		byName:      make(map[nameKey][]MalwareReport),
		bySourceEco: make(map[sourceEcoKey][]MalwareReport),
	}
	return &BaselineStore{
		memStore:     inner,
		baselinePath: baselinePath,
		logger:       logger.With().Str("component", "intel.store.baseline").Logger(),
	}
}

// Refresh implements Store. Runs the underlying refresh, then applies the
// persistent-baseline checks on top: damaged-cache errors and
// below-baseline collapses that the in-process retention layer cannot
// see (because this process has no previous slice to compare against).
func (b *BaselineStore) Refresh(ctx context.Context) error {
	// Load the durable baseline before fetching; on any read error we
	// proceed with an empty baseline (fail-open on a missing/corrupt
	// baseline file — the file is an integrity signal, not a credential,
	// and the in-process checks plus the content-hash binding in the
	// sources remain in force).
	baseline := b.loadBaseline()

	results := b.fetchAll(ctx)

	// Snapshot the in-process previous state, same as memStore.Refresh.
	b.mu.Lock()
	b.damaged = nil
	b.mu.Unlock()

	b.memStore.mu.RLock()
	prevBySourceEco := make(map[sourceEcoKey][]MalwareReport, len(b.memStore.bySourceEco))
	for k, v := range b.memStore.bySourceEco {
		prevBySourceEco[k] = v
	}
	b.memStore.mu.RUnlock()

	resolved, retentionInfo, fetchErrs, damaged := b.applyRetentionWithBaseline(results, prevBySourceEco, baseline)

	if len(resolved) == 0 {
		if len(fetchErrs) > 0 {
			b.setDamaged(damaged)
			return errors.WithNew("all intel sources failed to refresh").
				Set("failures", len(fetchErrs)).
				Set("damaged", len(damaged)).
				Cause(joinErrors(fetchErrs))
		}
		b.setDamaged(damaged)
		return errors.WithNew("no intel source produced data").
			Set("hint", "check VETO_SOURCES configuration and feed ecosystem support")
	}

	nextByVersion, nextByName, totalReports := buildIndices(resolved)

	b.memStore.mu.Lock()
	b.memStore.byVersion = nextByVersion
	b.memStore.byName = nextByName
	b.memStore.bySourceEco = resolved
	b.memStore.mu.Unlock()

	// Persist the new baseline. Carries OLD entries forward for buckets
	// that are absent from `resolved` — rejected (collapsed) buckets,
	// damaged-cache buckets, and temporarily-unconfigured sources. This
	// is load-bearing: writing the baseline from `resolved` alone would
	// drop the rejected bucket's entry, and the very next invocation
	// would accept the collapsed count as fresh with no baseline to
	// compare against — the vulnerability, one run later. Retained
	// buckets keep their previous count implicitly (the retained slice IS
	// the known-good data); fresh-accepted buckets record their new count
	// (feeds grow).
	nextBaseline := mergeBaseline(baseline, resolved)
	if err := b.saveBaseline(nextBaseline); err != nil {
		// The baseline is an integrity signal, not a gate input; failing
		// to persist it degrades to the pre-baseline behavior (in-process
		// checks only), which never refuses a healthy refresh.
		b.logger.Warn().Err(err).Msg("persist baseline failed; cold-start integrity checks disabled until next successful write")
	}

	b.setDamaged(damaged)

	b.logger.Info().
		Int("reports", totalReports).
		Int("source_ecos_fresh", retentionInfo.fresh).
		Int("source_ecos_retained", retentionInfo.retained).
		Int("source_ecos_failed", len(fetchErrs)).
		Int("source_ecos_damaged", len(damaged)).
		Msg("intel store refreshed")

	return nil
}

// Damaged returns the (source, ecosystem) buckets that failed integrity
// verification this refresh and could not be repaired or retained. The
// slice is a copy; callers may retain it.
func (b *BaselineStore) Damaged() []SourceDamage {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]SourceDamage, len(b.damaged))
	copy(out, b.damaged)
	return out
}

func (b *BaselineStore) setDamaged(d []SourceDamage) {
	b.mu.Lock()
	b.damaged = d
	b.mu.Unlock()
}

// applyRetentionWithBaseline is memStore.applyRetention extended with the
// cold-start baseline comparison and ErrDamagedCache routing. See the
// BaselineStore doc comment for the two added decisions.
func (b *BaselineStore) applyRetentionWithBaseline(
	results []fetchResult,
	prev map[sourceEcoKey][]MalwareReport,
	baseline map[sourceEcoKey]int,
) (map[sourceEcoKey][]MalwareReport, retentionStats, []error, []SourceDamage) {
	resolved := make(map[sourceEcoKey][]MalwareReport)
	var stats retentionStats
	var fetchErrs []error
	var damaged []SourceDamage

	for _, r := range results {
		if r.err != nil && stderrorsIs(r.err, ErrUnsupportedEcosystem) {
			continue
		}

		if r.err != nil {
			// Damaged-cache errors get their own classification: the
			// source itself verified the on-disk payload was damaged and
			// could not re-fetch. The operator's remediation is to
			// inspect the cache dir (or get network back), not to check
			// VETO_SOURCES.
			if stderrorsIs(r.err, ErrDamagedCache) {
				if prevReports, ok := prev[r.key]; ok && len(prevReports) > 0 {
					// In-process retention keeps coverage; report as damage
					// anyway so the operator sees the disk is rotting.
					resolved[r.key] = prevReports
					stats.retained++
					damaged = append(damaged, SourceDamage{
						SourceID:  r.key.SourceID,
						Ecosystem: r.key.Ecosystem,
						Reason:    "cache payload failed content-hash verification; retained previous in-process data",
						Got:       0,
						Baseline:  len(prevReports),
					})
					b.logger.Warn().
						Err(r.err).
						Str("source", r.key.SourceID).
						Str("ecosystem", string(r.key.Ecosystem)).
						Int("retained_reports", len(prevReports)).
						Msg("damaged cache; retaining previous in-process data")
					continue
				}
				if baseCount, ok := baseline[r.key]; ok {
					damaged = append(damaged, SourceDamage{
						SourceID:  r.key.SourceID,
						Ecosystem: r.key.Ecosystem,
						Reason:    "cache payload failed content-hash verification and could not be re-fetched",
						Got:       0,
						Baseline:  baseCount,
					})
				}
				b.logger.Warn().
					Err(r.err).
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Msg("damaged cache; no previous data to retain")
				fetchErrs = append(fetchErrs,
					errors.With(r.err, "fetch failed (damaged cache)").
						Set("source", r.key.SourceID).
						Set("ecosystem", string(r.key.Ecosystem)))
				continue
			}

			// Ordinary fetch error. Retain prior data if any; otherwise
			// record the failure so the caller can decide whether the
			// refresh as a whole is salvageable.
			if prevReports, ok := prev[r.key]; ok && len(prevReports) > 0 {
				resolved[r.key] = prevReports
				stats.retained++
				b.logger.Warn().
					Err(r.err).
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("retained_reports", len(prevReports)).
					Msg("source fetch failed; retaining previous data")
				continue
			}
			b.logger.Warn().
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

		// Fetch succeeded. Two retention layers, most specific first:
		//
		// 1. In-process previous slice (the existing policy, unchanged).
		// 2. Persistent baseline — the cold-start comparison this type
		//    adds. Only consulted when there is no in-process previous
		//    slice, i.e. on the first refresh of a process.
		newCount := len(r.reports)
		prevReports, hadPrev := prev[r.key]
		prevCount := len(prevReports)
		if hadPrev && prevCount > 0 {
			minAllowed := int(float64(prevCount) * partialDropThreshold)
			if newCount < minAllowed {
				resolved[r.key] = prevReports
				stats.retained++
				b.logger.Warn().
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("new_count", newCount).
					Int("prev_count", prevCount).
					Float64("threshold", partialDropThreshold).
					Msg("source returned implausibly few reports; retaining previous data")
				continue
			}
		} else if baseCount, hasBase := baseline[r.key]; hasBase && baseCount > 0 {
			// Cold start with a recorded baseline. newCount below
			// baselineThreshold * baseCount means the feed we just read
			// bears no resemblance to the feed this installation
			// previously accepted. Reject the bucket — serving it would
			// silently reduce coverage — and report it as damage so the
			// gate can fail closed.
			minAllowed := int(float64(baseCount) * baselineThreshold)
			if newCount < minAllowed {
				damaged = append(damaged, SourceDamage{
					SourceID:  r.key.SourceID,
					Ecosystem: r.key.Ecosystem,
					Reason:    "report count collapsed below recorded baseline",
					Got:       newCount,
					Baseline:  baseCount,
				})
				b.logger.Warn().
					Str("source", r.key.SourceID).
					Str("ecosystem", string(r.key.Ecosystem)).
					Int("new_count", newCount).
					Int("baseline_count", baseCount).
					Float64("threshold", baselineThreshold).
					Msg("source returned implausibly few reports vs persistent baseline; rejecting bucket")
				continue
			}
		}
		resolved[r.key] = r.reports
		stats.fresh++
	}

	return resolved, stats, fetchErrs, damaged
}

// loadBaseline reads the durable baseline file. Missing or unreadable
// files yield an empty map (grandfather: the first refresh after
// upgrade records a baseline rather than comparing against one). A
// corrupt file also yields an empty map with a warning — the file is an
// integrity signal, and a corrupt signal must not brick the gate.
func (b *BaselineStore) loadBaseline() map[sourceEcoKey]int {
	out := make(map[sourceEcoKey]int)
	data, err := os.ReadFile(b.baselinePath)
	if err != nil {
		return out
	}
	var wire map[string]int
	if err := json.Unmarshal(data, &wire); err != nil {
		b.logger.Warn().Err(err).Str("path", b.baselinePath).Msg("baseline file corrupt; treating as absent")
		return out
	}
	for k, v := range wire {
		srcID, eco, ok := parseBaselineKey(k)
		if !ok {
			continue
		}
		out[sourceEcoKey{SourceID: srcID, Ecosystem: eco}] = v
	}
	return out
}

// saveBaseline atomically persists the per-bucket counts of the accepted
// (resolved) slices.
func (b *BaselineStore) saveBaseline(counts map[sourceEcoKey]int) error {
	wire := make(map[string]int, len(counts))
	for k, v := range counts {
		wire[baselineKey(k)] = v
	}
	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return errors.With(err, "marshal baseline")
	}
	if err := os.MkdirAll(filepath.Dir(b.baselinePath), 0o700); err != nil {
		return errors.With(err, "create baseline parent dir").Set("path", b.baselinePath)
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.baselinePath), baselineFileName+".tmp-")
	if err != nil {
		return errors.With(err, "create baseline temp file")
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return errors.With(err, "write baseline temp file")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "close baseline temp file")
	}
	if err := os.Rename(tmpPath, b.baselinePath); err != nil {
		os.Remove(tmpPath)
		return errors.With(err, "rename baseline file")
	}
	return nil
}

// mergeBaseline builds the next durable baseline: old entries are carried
// forward for every bucket absent from resolved (rejected, damaged, or
// unconfigured), and resolved buckets record their accepted count. See
// the call site for why carrying forward is load-bearing.
func mergeBaseline(old map[sourceEcoKey]int, resolved map[sourceEcoKey][]MalwareReport) map[sourceEcoKey]int {
	out := make(map[sourceEcoKey]int, len(old)+len(resolved))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range resolved {
		out[k] = len(v)
	}
	return out
}

// baselineKey renders a sourceEcoKey as a stable, human-readable JSON
// object key. "\x1f" (unit separator) cannot appear in source IDs or
// ecosystem names, so the round-trip is injective.
func baselineKey(k sourceEcoKey) string {
	return k.SourceID + "\x1f" + string(k.Ecosystem)
}

// parseBaselineKey is the inverse of baselineKey.
func parseBaselineKey(s string) (string, Ecosystem, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1f {
			return s[:i], Ecosystem(s[i+1:]), true
		}
	}
	return "", "", false
}

// stderrorsIs is stderrors.Is, aliased so this file reads consistently
// with store.go's stderrors import.
func stderrorsIs(err, target error) bool {
	return stderrors.Is(err, target)
}

// joinErrors is stderrors.Join, aliased for symmetry with stderrorsIs.
func joinErrors(errs []error) error {
	return stderrors.Join(errs...)
}
