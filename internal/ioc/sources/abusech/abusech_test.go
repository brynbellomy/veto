package abusech_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/ioc"
	"github.com/brynbellomy/veto/internal/ioc/sources/abusech"
)

const testAuthKey = "test-auth-key"

// loadFixture reads a trimmed sub-feed sample from testdata/.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// feedServer routes each sub-feed path to its fixture and asserts the Auth-Key
// header is present on every request. Paths are distinct so one server backs
// the whole fan-out.
func feedServer(t *testing.T) *httptest.Server {
	t.Helper()
	bazaar := loadFixture(t, "malwarebazaar_recent.csv")
	feodo := loadFixture(t, "feodo_ipblocklist.json")
	urlhaus := loadFixture(t, "urlhaus_recent.csv")
	threatfox := loadFixture(t, "threatfox_get_iocs.json")

	mux := http.NewServeMux()
	mux.HandleFunc("/bazaar", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testAuthKey, r.Header.Get("Auth-Key"))
		_, _ = w.Write(bazaar)
	})
	mux.HandleFunc("/feodo", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testAuthKey, r.Header.Get("Auth-Key"))
		_, _ = w.Write(feodo)
	})
	mux.HandleFunc("/urlhaus", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testAuthKey, r.Header.Get("Auth-Key"))
		_, _ = w.Write(urlhaus)
	})
	mux.HandleFunc("/threatfox", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testAuthKey, r.Header.Get("Auth-Key"))
		require.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write(threatfox)
	})
	return httptest.NewServer(mux)
}

// newSource builds a Source pointed at srv with all four sub-feeds wired.
func newSource(t *testing.T, srv *httptest.Server, authKey string) *abusech.Source {
	t.Helper()
	src, err := abusech.New(abusech.Options{
		CacheDir:     t.TempDir(),
		AuthKey:      authKey,
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL + "/bazaar",
		FeodoURL:     srv.URL + "/feodo",
		URLhausURL:   srv.URL + "/urlhaus",
		ThreatFoxURL: srv.URL + "/threatfox",
	})
	require.NoError(t, err)
	return src
}

// byTypeValue indexes indicators by (type,value) for order-independent
// assertions: Fetch fans out across feeds so output order is unstable.
func byTypeValue(indicators []ioc.Indicator) map[string]ioc.Indicator {
	out := map[string]ioc.Indicator{}
	for _, ind := range indicators {
		out[string(ind.Type)+"|"+ind.Value] = ind
	}
	return out
}

func TestID(t *testing.T) {
	src, err := abusech.New(abusech.Options{CacheDir: t.TempDir()})
	require.NoError(t, err)
	require.Equal(t, "abusech", src.ID())
}

func TestNewRequiresCacheDir(t *testing.T) {
	_, err := abusech.New(abusech.Options{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "CacheDir")
}

// TestFetchEmptyAuthKeyNoOp verifies the graceful-degradation contract: with no
// AuthKey, Fetch returns (nil, nil) and never touches the network.
func TestFetchEmptyAuthKeyNoOp(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer srv.Close()

	src, err := abusech.New(abusech.Options{
		CacheDir:     t.TempDir(),
		AuthKey:      "", // no key configured
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL,
		FeodoURL:     srv.URL,
		URLhausURL:   srv.URL,
		ThreatFoxURL: srv.URL,
	})
	require.NoError(t, err)

	indicators, err := src.Fetch(context.Background())
	require.NoError(t, err, "missing auth key must not error")
	require.Nil(t, indicators, "missing auth key must yield no indicators")
	require.False(t, hit, "missing auth key must skip the network entirely")
}

// TestFetchHappyPath exercises the full fan-out and asserts each sub-feed
// contributes its expected indicators, with correct types, normalization,
// labels, references, and timestamps.
func TestFetchHappyPath(t *testing.T) {
	srv := feedServer(t)
	defer srv.Close()
	src := newSource(t, srv, testAuthKey)

	indicators, err := src.Fetch(context.Background())
	require.NoError(t, err)

	idx := byTypeValue(indicators)

	// --- MalwareBazaar: sha256 always; sha1/md5 only when present ---
	// Row 1 has all three hashes (uppercase in the fixture → lowercased).
	mbSHA256 := idx["sha256|aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]
	require.Equal(t, ioc.IndicatorSHA256, mbSHA256.Type)
	require.Equal(t, "abusech", mbSHA256.SourceID)
	require.Equal(t, "Dridex", mbSHA256.ThreatLabel)
	require.Equal(t,
		"https://bazaar.abuse.ch/sample/aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899/",
		mbSHA256.Reference)
	require.Equal(t, time.Date(2026, 6, 7, 10, 15, 0, 0, time.UTC), mbSHA256.PublishedAt)
	require.Contains(t, idx, "md5|0123456789abcdef0123456789abcdef")
	require.Contains(t, idx, "sha1|da39a3ee5e6b4b0d3255bfef95601890afd80709")

	// Row 2 has sha256 only (empty md5/sha1) → no spurious hash indicators.
	require.Contains(t, idx, "sha256|11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
	require.NotContains(t, idx, "md5|")

	// Row 3 has sha256 + md5 but empty sha1 and empty signature.
	require.Contains(t, idx, "sha256|ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
	require.Contains(t, idx, "md5|ffeeddccbbaa99887766554433221100")

	// --- Feodo: ipv4, port-irrelevant; bad IP skipped ---
	feodo := idx["ipv4|203.0.113.10"]
	require.Equal(t, ioc.IndicatorIPv4, feodo.Type)
	require.Equal(t, "Emotet", feodo.ThreatLabel)
	require.Equal(t, time.Date(2026, 6, 1, 8, 30, 0, 0, time.UTC), feodo.PublishedAt)
	require.Contains(t, idx, "ipv4|198.51.100.5")
	// "not-an-ip" must be dropped.
	for k := range idx {
		require.NotContains(t, k, "not-an-ip")
	}

	// --- URLhaus: url; host lowercased + fragment stripped; bad URL skipped ---
	require.Contains(t, idx, "url|http://evil.example.com/Malware/Payload.exe")
	uh := idx["url|http://evil.example.com/Malware/Payload.exe"]
	require.Equal(t, ioc.IndicatorURL, uh.Type)
	require.Equal(t, "malware_download", uh.ThreatLabel)
	require.Equal(t, "https://urlhaus.abuse.ch/url/3210001/", uh.Reference)
	require.Equal(t, time.Date(2026, 6, 7, 11, 0, 0, 0, time.UTC), uh.PublishedAt)
	require.Contains(t, idx, "url|https://bad.test/path?id=42")
	// "not a url at all" has no host → dropped.

	// --- ThreatFox: mixed types; ip:port stripped; unsupported md5_hash dropped ---
	require.Contains(t, idx, "ipv4|192.0.2.55") // port 443 stripped
	tf := idx["ipv4|192.0.2.55"]
	require.Equal(t, "Cobalt Strike", tf.ThreatLabel)
	require.Equal(t, "https://threatfox.abuse.ch/ioc/1500001/", tf.Reference)
	require.Equal(t, time.Date(2026, 6, 7, 9, 15, 0, 0, time.UTC), tf.PublishedAt)
	require.Contains(t, idx, "domain|bad-domain.example.org")      // lowercased
	require.Contains(t, idx, "url|http://phish.example.net/login") // host lowercased, frag stripped
	require.Contains(t, idx,
		"sha256|ddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc") // lowercased
	// The md5_hash ioc_type is not in ThreatFox's supported mapping → dropped.
	require.NotContains(t, idx, "md5|deadbeef")
}

// TestFetchEtagShortCircuit confirms a second Fetch re-uses cached payloads when
// upstream answers 304, and that the etag persists per sub-feed.
func TestFetchEtagShortCircuit(t *testing.T) {
	bazaar := loadFixture(t, "malwarebazaar_recent.csv")
	var bazaarHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testAuthKey, r.Header.Get("Auth-Key"))
		if r.URL.Path == "/bazaar" {
			bazaarHits++
			if r.Header.Get("If-None-Match") == `"mb-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"mb-1"`)
			_, _ = w.Write(bazaar)
			return
		}
		// Other feeds: empty-but-valid payloads so the fan-out doesn't error.
		switch r.URL.Path {
		case "/feodo":
			_, _ = w.Write([]byte("[]"))
		case "/urlhaus":
			_, _ = w.Write([]byte("# header\n"))
		case "/threatfox":
			_, _ = w.Write([]byte(`{"query_status":"ok","data":[]}`))
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	src, err := abusech.New(abusech.Options{
		CacheDir:     cacheDir,
		AuthKey:      testAuthKey,
		Logger:       zerolog.Nop(),
		BazaarURL:    srv.URL + "/bazaar",
		FeodoURL:     srv.URL + "/feodo",
		URLhausURL:   srv.URL + "/urlhaus",
		ThreatFoxURL: srv.URL + "/threatfox",
	})
	require.NoError(t, err)

	first, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, second)

	require.Equal(t, 2, bazaarHits, "expected two upstream bazaar calls")
	etag, err := os.ReadFile(filepath.Join(cacheDir, "malwarebazaar.etag"))
	require.NoError(t, err)
	require.Equal(t, `"mb-1"`, string(etag))
}

// TestFetchSubFeedFailureIsolated proves one sub-feed erroring (5xx) does not
// sink the others: the healthy feeds' indicators still come back.
func TestFetchSubFeedFailureIsolated(t *testing.T) {
	feodo := loadFixture(t, "feodo_ipblocklist.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bazaar":
			w.WriteHeader(http.StatusInternalServerError) // this feed is down
		case "/feodo":
			_, _ = w.Write(feodo)
		case "/urlhaus":
			_, _ = w.Write([]byte("# header\n"))
		case "/threatfox":
			_, _ = w.Write([]byte(`{"query_status":"ok","data":[]}`))
		}
	}))
	defer srv.Close()

	src := newSource(t, srv, testAuthKey)

	indicators, err := src.Fetch(context.Background())
	require.NoError(t, err, "a single sub-feed failure must not fail the whole Fetch")

	idx := byTypeValue(indicators)
	// Feodo (healthy) still contributes.
	require.Contains(t, idx, "ipv4|203.0.113.10")
	// MalwareBazaar (down) contributes nothing.
	require.NotContains(t, idx, "sha256|aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
}
