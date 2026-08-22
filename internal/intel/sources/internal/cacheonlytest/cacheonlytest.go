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
	"testing"

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
