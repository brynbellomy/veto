// Package cacheonlytest is a shared harness for the cache-only integrity
// contract: under intel.WithCacheOnly, a source must NEVER serve a
// damaged on-disk cache layer, and must never adopt the hash of bytes it
// did not just download or have upstream-validated.
//
// This exists because the guard is duplicated per source (nine copies and
// counting) and each copy can be reverted independently — exactly what
// the verdict-only-mode rebase did, silently, in eight of the nine. A
// guard that nothing tests is a guard on a timer. Every network source
// MUST plug into this harness; cmd/veto's source-registry test fails
// loudly when a new source is added without one.
//
// The harness is test-only scaffolding in every sense: it lives under
// sources/internal/ (internal-only import path), its name ends in
// "test", and it is imported exclusively from _test.go files. Nothing in
// production links against it.
package cacheonlytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// Case describes one source's plug-in point for the shared scenario. The
// harness runs the same contract against every source; only the fixture
// construction and cache-file naming differ, and those are exactly what
// a Case supplies.
type Case struct {
	// Name is the source ID, used in failure messages and by
	// cmd/veto's registry test to detect un-plugged-in sources.
	Name string

	// Ecosystem is the ecosystem the warm-up fetch exercises.
	Ecosystem intel.Ecosystem

	// Serve builds the upstream handler: it must serve the INTACT
	// payload for every request (the harness wraps it for hit
	// counting). It should write the body and any etag header it wants;
	// it must NOT close its own server — the harness owns lifecycle.
	Serve func(t *testing.T) http.HandlerFunc

	// NewSource builds a Source pointed at srvURL with the given cache
	// dir. Called twice per scenario (warm instance, then a COLD instance
	// so in-memory state cannot short-circuit the disk path — the CLI's
	// cold-start shape).
	NewSource func(t *testing.T, srvURL, cacheDir string) intel.Source

	// WarmReports is the exact report count the intact payload yields.
	WarmReports int

	// GuttedName is a package name present ONLY in the gutted payload.
	// Any report carrying this name after the damage step is proof the
	// gutted bytes were served.
	GuttedName string

	// Damage replaces the source's on-disk cache payload with a
	// parseable-but-gutted variant (the vulnerability's damage shape).
	// It must leave every other cache file (etags, hash sidecars, gobs)
	// exactly as the warm-up left them, so the only changed thing is the
	// payload's bytes.
	Damage func(t *testing.T, cacheDir string)

	// StripHashSidecars simulates a pre-integrity-fix cache by deleting
	// every *.sha256 sidecar in cacheDir. Used by the
	// unrecorded-must-not-adopt scenario.
	StripHashSidecars func(t *testing.T, cacheDir string)

	// HeadValidated marks the gob/tarball family (ghsa, openssf,
	// rustsec): they validate via a HEAD etag probe rather than
	// If-None-Match, so the 304-unrecorded scenario's "conditional"
	// request is the HEAD, and the "refetch" is any GET.
	HeadValidated bool
}

// RunGuttedUnderCacheOnly is the core scenario: warm the cache with a
// network fetch, gut the on-disk payload, then fetch under the
// cache-only directive with a COLD source instance. The gutted bytes
// must NOT be served: the fetch either heals via network (reports come
// from the intact payload, upstream is hit) or fails closed with the
// ErrDamagedCache sentinel. The auto-merge defect this pins is the
// directive's early return skipping the content-hash verdict entirely.
func RunGuttedUnderCacheOnly(t *testing.T, c Case) {
	t.Helper()

	var hits int
	inner := c.Serve(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		inner(w, r)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()

	// Warm the cache with a network fetch (records hash sidecars).
	warm := c.NewSource(t, srv.URL, cacheDir)
	warmReports, err := warm.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err, "warm-up fetch must succeed")
	require.Len(t, warmReports, c.WarmReports,
		"fixture sanity: intact payload must yield exactly %d reports", c.WarmReports)
	require.NotZero(t, hits, "fixture sanity: warm-up must contact upstream")

	// Gut the on-disk payload.
	c.Damage(t, cacheDir)

	// Cold source + cache-only directive: in-memory state cannot
	// short-circuit, so the on-disk path — the one the directive serves
	// from — is what runs.
	cold := c.NewSource(t, srv.URL, cacheDir)
	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, c.Ecosystem)

	if err != nil {
		// Fail-closed is acceptable: the source may prefer it over
		// healing, but it must carry the damaged-cache sentinel so
		// the store classifies it as damage, not absence.
		require.ErrorIs(t, err, intel.ErrDamagedCache,
			"failing closed is allowed but must be the ErrDamagedCache sentinel, got: %v", err)
		return
	}

	// Healed via network: every report must come from the intact payload.
	require.NotEmpty(t, reports, "a cache-only fetch over a gutted cache must heal or fail closed, not return empty")
	for _, r := range reports {
		require.NotEqual(t, c.GuttedName, r.Name,
			"source %s served the GUTTED payload under the cache-only directive — the auto-merge defect", c.Name)
	}
	require.Equal(t, c.WarmReports, len(reports),
		"healed fetch must return the intact payload's report set")
	require.Greater(t, hits, 1,
		"the mismatch must trigger a real re-fetch, not a disk serve")
}

// RunUnrecordedMustNotAdopt pins rule 3: a pre-integrity-fix cache
// (sidecars stripped) serves under the cache-only directive — refusing
// would brick every upgraded installation inside the freshness window —
// but its hash must NOT be adopted. Adoption without upstream validation
// blesses whatever bytes happen to be on disk, laundering existing
// damage into "verified" and permanently blinding the gate.
func RunUnrecordedMustNotAdopt(t *testing.T, c Case) {
	t.Helper()

	inner := c.Serve(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner(w, r)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()

	// Warm with a network fetch, then strip every sidecar: the cache now
	// looks exactly like one written before the integrity fix.
	warm := c.NewSource(t, srv.URL, cacheDir)
	_, err := warm.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err, "warm-up fetch must succeed")
	c.StripHashSidecars(t, cacheDir)

	// Cold source + cache-only: unrecorded payloads serve, and nothing
	// upstream validates them, so no sidecar may appear.
	cold := c.NewSource(t, srv.URL, cacheDir)
	ctx := intel.WithCacheOnly(context.Background())
	reports, err := cold.Fetch(ctx, c.Ecosystem)
	require.NoError(t, err, "an unrecorded cache must still serve under cache-only")
	require.Len(t, reports, c.WarmReports)

	leftover := findSidecars(t, cacheDir)
	require.Empty(t, leftover,
		"source %s adopted (recorded) a hash under the cache-only directive with no upstream validation — laundering unvalidated bytes into \"verified\"", c.Name)
}

// RegisteredSources is the list of source IDs plugged into the harness.
// cmd/veto's TestCacheOnlyHarnessCoversEverySource asserts this list
// matches buildSource's registry so a new source FAILS LOUDLY until it
// is wired in. Update both when adding a source.
var RegisteredSources = []string{
	"aikido",
	"datadog",
	"gemnasium",
	"ghsa",
	"govulndb",
	"openssf",
	"osv",
	"pypa",
	"rustsec",
}

// findSidecars lists every *.sha256 sidecar under dir, RECURSIVELY. The
// gob family nests nothing today, but a source that ever grows a
// per-ecosystem subdirectory must not silently escape the unrecorded
// scenario's strip (FIX 6: the non-recursive version missed nested
// sidecars and the test would pass against a cache it never fully
// un-recorded).
func findSidecars(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(d.Name()) == ".sha256" {
			out = append(out, path)
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

// StripSidecarsInRoot removes every *.sha256 sidecar under dir,
// RECURSIVELY (FIX 6: the flat-only version silently missed nested
// sidecars, letting a partially-stripped cache pass the unrecorded
// scenario). All nine current sources use flat layouts; recursion costs
// nothing and survives a future nested layout.
func StripSidecarsInRoot(t *testing.T, dir string) {
	t.Helper()
	for _, path := range findSidecars(t, dir) {
		require.NoError(t, os.Remove(path))
	}
}

// removeGobLayers deletes every parsed-*.gob file so the 304-loop
// scenario cannot be satisfied by serving an unrecorded gob out
// of the upstream-unreachable availability arm. The gob family
// only fails closed when no local layer is servable.
func removeGobLayers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "parsed-") && strings.HasSuffix(e.Name(), ".gob") {
			require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
		}
	}
}

// Run304UnrecordedGuttedMustRebindFromWire pins FIX 1: a payload whose
// sidecar is MISSING (crash between WriteAtomic and RecordPayloadHash, a
// deleted sidecar, or any pre-sidecar cache) and whose bytes have been
// gutted, served a live 304 against the still-intact etag, must NOT
// adopt the gutted bytes' hash. The 304 validates the etag — the upstream
// representation — not the bytes on disk; adopting on read-side evidence
// alone blesses whatever happens to be on disk and the bucket reads
// HashMatch on gutted bytes forever after. The fetch must instead treat
// 304+Unrecorded exactly like Mismatch: drop the etag, GET the body off
// the wire, and record the hash of THOSE bytes.
func Run304UnrecordedGuttedMustRebindFromWire(t *testing.T, c Case) {
	t.Helper()

	// Upstream answers 304 against whatever etag the warm fetch recorded
	// (echoed back verbatim); a request with NO If-None-Match is the
	// forced refetch and must get the intact body. The HeadValidated
	// family (gob/tarball sources) validates via a HEAD etag probe
	// instead: the HEAD is the "conditional" and any GET is the refetch.
	inner := c.Serve(t)
	var sawConditional, sawUnconditional bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.HeadValidated {
			if r.Method == http.MethodHead {
				sawConditional = true
				inner(w, r) // inner sets ETag; no body on HEAD
				return
			}
			sawUnconditional = true
			inner(w, r)
			return
		}
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			sawConditional = true
			w.Header().Set("ETag", inm)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		sawUnconditional = true
		inner(w, r)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()

	// Warm with a network fetch — the server sets etag "warm".
	warm := c.NewSource(t, srv.URL, cacheDir)
	warmReports, err := warm.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err)
	require.Len(t, warmReports, c.WarmReports,
		"fixture sanity: intact warm fetch must yield %d reports", c.WarmReports)
	c.StripHashSidecars(t, cacheDir)
	c.Damage(t, cacheDir)

	// The fetch under test: etag intact, payload gutted, sidecar gone.
	// Pre-request verdict is Unrecorded, so the conditional GET goes out;
	// upstream 304s; the 304 arm must NOT adopt the gutted bytes.
	cold := c.NewSource(t, srv.URL, cacheDir)
	reports, err := cold.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err, "the fetch must heal via the wire")
	require.True(t, sawConditional, "fixture sanity: the intact etag must draw a conditional/HEAD request")
	require.True(t, sawUnconditional, "the validated-etag arm must force an unconditional refetch")

	for _, r := range reports {
		require.NotEqual(t, c.GuttedName, r.Name,
			"source %s adopted/served GUTTED bytes off a 304+Unrecorded — the FIX 1 defect", c.Name)
	}
	require.Equal(t, c.WarmReports, len(reports),
		"the healed fetch must return the intact payload's report set")

}

// Run304LoopMustFailClosed pins the retry budget (grok's round-5
// finding): an upstream that answers 304 to an UNCONDITIONAL GET — a
// broken or hostile CDN — must not drive unbounded recursion. The FIX 1
// arms drop the etag and refetch without If-None-Match; a well-behaved
// upstream answers that with a body, but nothing enforces it, so each
// source carries a one-shot budget and fails closed with
// ErrDamagedCache when the budget is spent. govulndb shipped without
// the budget: the loop ran until the context died, and then the
// network-failure arm served the unbound (possibly gutted) zip — the
// original critical through a side door.
//
// Fixture shape: the server answers the FIRST request (the warm fetch)
// with the intact body + etag, then flips into broken mode and answers
// every subsequent request — conditional or not — with 304. A 304
// fixture that serves a body when If-None-Match is absent would never
// exercise the budget, which is exactly why the suite stayed green
// across nine sources while govulndb looped.
func Run304LoopMustFailClosed(t *testing.T, c Case) {
	t.Helper()

	var servedBody bool
	inner := c.Serve(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Flip to broken mode only after the first request that actually
		// CARRIES a body answer. The HeadValidated family (gob/tarball
		// sources) opens every fetch with a HEAD probe — flipping on the
		// first request would break the warm fetch itself. HEADs and
		// conditional GETs before the body is served pass through inner.
		if !servedBody && r.Method == http.MethodGet && r.Header.Get("If-None-Match") == "" {
			servedBody = true
			inner(w, r)
			return
		}
		if servedBody {
			// Broken/hostile mode: 304 to everything, including bare GETs.
			if inm := r.Header.Get("If-None-Match"); inm != "" {
				w.Header().Set("ETag", inm)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	warm := c.NewSource(t, srv.URL, cacheDir)
	warmReports, err := warm.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err)
	require.Len(t, warmReports, c.WarmReports, "fixture sanity: warm fetch must serve the intact body")
	require.True(t, servedBody, "fixture sanity: the server must have served the intact body once")

	// Gut + strip + orphan: sidecars gone, payload damaged, etag
	// intact, and every parsed-*.gob layer REMOVED. Two independent
	// threats share this fixture. For the payload family the loop is
	// the hazard: the conditional GET draws a 304, the FIX 1 arm drops
	// the etag and refetches unconditionally, the broken server 304s
	// THAT too, and the budget must fire. For the HeadValidated family
	// the HEAD probe itself draws the 304; the family correctly fails
	// closed on damaged-cache-plus-dead-upstream — but only if the
	// availability arm cannot serve an unrecorded gob as a fallback.
	// Deleting the gob forces every local layer through its gate so
	// both families terminate in ErrDamagedCache, never a hang, and
	// never the gutted bytes.
	c.StripHashSidecars(t, cacheDir)
	c.Damage(t, cacheDir)
	removeGobLayers(t, cacheDir)

	cold := c.NewSource(t, srv.URL, cacheDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type result struct {
		reports []intel.MalwareReport
		err     error
	}
	done := make(chan result, 1)
	go func() {
		reports, err := cold.Fetch(ctx, c.Ecosystem)
		done <- result{reports: reports, err: err}
	}()

	select {
	case res := <-done:
		require.Error(t, res.err,
			"source %s must fail closed on a 304-looping upstream, not serve", c.Name)
		require.ErrorIs(t, res.err, intel.ErrDamagedCache,
			"the 304-loop failure must carry ErrDamagedCache (budget exhausted), got: %v", res.err)
		for _, r := range res.reports {
			require.NotEqual(t, c.GuttedName, r.Name,
				"source %s served the GUTTED payload out of a 304 loop — the original critical through the side door", c.Name)
		}
	case <-time.After(45 * time.Second):
		t.Fatalf("source %s appears to be looping on a 304-to-everything upstream (no result within 45s) — the retry budget is missing", c.Name)
	}
}

// RunHead304WithUnrecordedLayerFailsClosed pins the availability-arm half
// of the broken-304 classification for the HeadValidated family. After
// a warm fetch every hash sidecar is deleted (both local layers become
// Unrecorded), and the source is pointed at a server that answers 304
// to every request — the HEAD probe draws the 304. A 304 to an
// unconditional HEAD is protocol garbage from a broken upstream, NOT
// a dead one: the upstream-unreachable fallback arms must not serve
// the unrecorded local layers. Before the fix the plain
// "unexpected head status" error dropped into those arms and served
// the gob — a broken upstream laundered into a clean cache hit.
func RunHead304WithUnrecordedLayerFailsClosed(t *testing.T, c Case) {
	t.Helper()
	if !c.HeadValidated {
		t.Skipf("source %s is not in the HeadValidated family", c.Name)
	}

	inner := c.Serve(t)
	warm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner(w, r)
	}))
	t.Cleanup(warm.Close)

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			w.Header().Set("ETag", inm)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(broken.Close)

	cacheDir := t.TempDir()
	warmSrc := c.NewSource(t, warm.URL, cacheDir)
	warmReports, err := warmSrc.Fetch(context.Background(), c.Ecosystem)
	require.NoError(t, err)
	require.Len(t, warmReports, c.WarmReports, "fixture sanity: warm fetch must serve the intact body")

	// Strip every sidecar: both local layers become Unrecorded.
	c.StripHashSidecars(t, cacheDir)

	cold := c.NewSource(t, broken.URL, cacheDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type result struct {
		reports []intel.MalwareReport
		err     error
	}
	done := make(chan result, 1)
	go func() {
		reports, err := cold.Fetch(ctx, c.Ecosystem)
		done <- result{reports: reports, err: err}
	}()

	select {
	case res := <-done:
		require.Error(t, res.err,
			"source %s: HEAD-304 with unrecorded local layers must fail closed, not serve them", c.Name)
		require.ErrorIs(t, res.err, intel.ErrDamagedCache,
			"the HEAD-304 failure must carry ErrDamagedCache (broken upstream), got: %v", res.err)
		require.Empty(t, res.reports, "no reports may be served out of a broken-upstream fallback")
	case <-time.After(45 * time.Second):
		t.Fatalf("source %s appears to be looping on HEAD-304 — no result within 45s", c.Name)
	}
}
