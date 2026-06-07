package ioc_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/ioc"
)

// fakeSource is a hand-written stub used only inside this test file. The
// surface is tiny and the tests assert on behavior, not call counts; a
// cross-package consumer of ioc.Source would register the interface with
// mockery instead.
type fakeSource struct {
	id         string
	indicators []ioc.Indicator
	fetchErr   error
}

func (f *fakeSource) ID() string { return f.id }

func (f *fakeSource) Fetch(_ context.Context) ([]ioc.Indicator, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.indicators, nil
}

func sha256Indicator(value, sourceID, label string) ioc.Indicator {
	return ioc.Indicator{Type: ioc.IndicatorSHA256, Value: value, SourceID: sourceID, ThreatLabel: label}
}

func TestStoreLookup(t *testing.T) {
	logger := zerolog.Nop()

	a := &fakeSource{
		id: "alpha",
		indicators: []ioc.Indicator{
			sha256Indicator("aaaa1111", "alpha", "trojan"),
			{Type: ioc.IndicatorDomain, Value: "evil.example", SourceID: "alpha", ThreatLabel: "c2"},
		},
	}
	b := &fakeSource{
		id: "beta",
		indicators: []ioc.Indicator{
			sha256Indicator("aaaa1111", "beta", "also-trojan"),
		},
	}

	store := ioc.NewStore(logger, a, b)
	require.NoError(t, store.Refresh(context.Background()))

	t.Run("hash matched by all sources", func(t *testing.T) {
		v := store.Lookup(ioc.IndicatorSHA256, "aaaa1111")
		require.True(t, v.Matched())
		require.Len(t, v.Matches, 2)
		require.ElementsMatch(t, []string{"alpha", "beta"}, v.Sources())
	})

	t.Run("query value is normalized", func(t *testing.T) {
		// Upper-case query must still hit the lower-case-keyed indicator.
		v := store.Lookup(ioc.IndicatorSHA256, "AAAA1111")
		require.True(t, v.Matched())
		require.Equal(t, "aaaa1111", v.Value)
	})

	t.Run("type is part of the key", func(t *testing.T) {
		// The same string under a different type must not match.
		v := store.Lookup(ioc.IndicatorDomain, "aaaa1111")
		require.False(t, v.Matched())
	})

	t.Run("domain match", func(t *testing.T) {
		v := store.Lookup(ioc.IndicatorDomain, "EVIL.example")
		require.True(t, v.Matched())
		require.Equal(t, []string{"alpha"}, v.Sources())
	})

	t.Run("unknown value is unmatched", func(t *testing.T) {
		v := store.Lookup(ioc.IndicatorSHA256, "deadbeef")
		require.False(t, v.Matched())
	})

	t.Run("counts", func(t *testing.T) {
		require.Equal(t, 3, store.IndicatorCount())
		require.Equal(t, 2, store.IndicatorCountByType(ioc.IndicatorSHA256))
		require.Equal(t, 1, store.IndicatorCountByType(ioc.IndicatorDomain))
		require.Equal(t, 0, store.IndicatorCountByType(ioc.IndicatorMD5))
	})
}

func TestStoreDedupSameSourceSameAtom(t *testing.T) {
	store := ioc.NewStore(zerolog.Nop(), &fakeSource{
		id: "alpha",
		indicators: []ioc.Indicator{
			sha256Indicator("cafe", "alpha", "x"),
			sha256Indicator("CAFE", "alpha", "x"), // same atom, different case
		},
	})
	require.NoError(t, store.Refresh(context.Background()))

	v := store.Lookup(ioc.IndicatorSHA256, "cafe")
	require.True(t, v.Matched())
	require.Len(t, v.Matches, 1, "one source reporting the same atom twice collapses to one match")
	require.Equal(t, 1, store.IndicatorCount())
}

func TestStoreRefreshFailClosedAllSourcesError(t *testing.T) {
	boom := stderrors.New("boom")
	store := ioc.NewStore(zerolog.Nop(), &fakeSource{id: "alpha", fetchErr: boom})

	err := store.Refresh(context.Background())
	require.Error(t, err, "a refresh where every source errors and there is no prior data must fail closed")
	require.Equal(t, 0, store.IndicatorCount())
}

func TestStoreRefreshRetainsPreviousOnLaterError(t *testing.T) {
	src := &fakeSource{
		id:         "alpha",
		indicators: []ioc.Indicator{sha256Indicator("aaaa", "alpha", "x"), sha256Indicator("bbbb", "alpha", "y")},
	}
	store := ioc.NewStore(zerolog.Nop(), src)
	require.NoError(t, store.Refresh(context.Background()))
	require.True(t, store.Lookup(ioc.IndicatorSHA256, "aaaa").Matched())

	// Second refresh errors: previous data must survive (fail-closed retention).
	src.fetchErr = stderrors.New("upstream down")
	require.NoError(t, store.Refresh(context.Background()),
		"a source error with retained previous data is not a whole-refresh failure")
	require.True(t, store.Lookup(ioc.IndicatorSHA256, "aaaa").Matched(),
		"previous data must survive a transient source error")
}

func TestStoreRefreshRejectsImplausibleShrink(t *testing.T) {
	src := &fakeSource{id: "alpha"}
	for i := 0; i < 100; i++ {
		src.indicators = append(src.indicators, sha256Indicator(hashHex(i), "alpha", "x"))
	}
	store := ioc.NewStore(zerolog.Nop(), src)
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 100, store.IndicatorCount())

	// Second refresh returns 1 indicator (1% of 100, well under the 50%
	// threshold). The new data is rejected and the previous slice retained.
	src.indicators = []ioc.Indicator{sha256Indicator(hashHex(0), "alpha", "x")}
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 100, store.IndicatorCount(),
		"an implausible shrink must be rejected in favor of the previous index")
}

func TestStoreRefreshAcceptsModestShrink(t *testing.T) {
	src := &fakeSource{id: "alpha"}
	for i := 0; i < 100; i++ {
		src.indicators = append(src.indicators, sha256Indicator(hashHex(i), "alpha", "x"))
	}
	store := ioc.NewStore(zerolog.Nop(), src)
	require.NoError(t, store.Refresh(context.Background()))

	// 80 of 100 = 80%, above the 50% threshold: new data wins.
	src.indicators = src.indicators[:80]
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 80, store.IndicatorCount())
}

func TestStoreRefreshContextCancelled(t *testing.T) {
	store := ioc.NewStore(zerolog.Nop(), &fakeSource{
		id:         "alpha",
		indicators: []ioc.Indicator{sha256Indicator("aaaa", "alpha", "x")},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := store.Refresh(ctx)
	require.Error(t, err, "a cancelled refresh with no prior data fails closed")
}

func TestNopStore(t *testing.T) {
	var store ioc.Store = ioc.NopStore{}
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 0, store.IndicatorCount())
	require.Equal(t, 0, store.IndicatorCountByType(ioc.IndicatorSHA256))
	require.Empty(t, store.SourceIDs())

	v := store.Lookup(ioc.IndicatorSHA256, "ANYTHING")
	require.False(t, v.Matched())
	require.Equal(t, "anything", v.Value, "Nop still normalizes the echoed query value")
}

func TestNopSource(t *testing.T) {
	var src ioc.Source = ioc.NopSource{}
	require.Equal(t, "nop", src.ID())
	indicators, err := src.Fetch(context.Background())
	require.NoError(t, err)
	require.Empty(t, indicators)
}

func TestNewStoreNoSourcesIsEmptyNotPanicking(t *testing.T) {
	store := ioc.NewStore(zerolog.Nop())
	require.NoError(t, store.Refresh(context.Background()))
	require.Equal(t, 0, store.IndicatorCount())
	require.False(t, store.Lookup(ioc.IndicatorSHA256, "aaaa").Matched())
}

func TestNopRuleScanner(t *testing.T) {
	var rs ioc.RuleScanner = ioc.NopRuleScanner{}
	matches, err := rs.ScanBytes(context.Background(), []byte("anything"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

// hashHex builds a distinct lowercase-hex-looking value per index.
func hashHex(i int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for j := range out {
		out[j] = digits[(i+j)%16]
	}
	// Make each fully distinct by appending the index.
	return string(out) + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
