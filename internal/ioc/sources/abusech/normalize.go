package abusech

import (
	"net"
	"net/url"
	"strings"
	"time"
)

// abuseTimeLayouts are the timestamp formats abuse.ch emits across its feeds.
// CSV dumps use "2006-01-02 15:04:05" (UTC, space-separated); the JSON APIs use
// the same shape, occasionally with a trailing " UTC" suffix. We try each in
// order and fall back to a zero time when none match, since PublishedAt is
// display-only metadata and a missing timestamp must not drop an indicator.
var abuseTimeLayouts = []string{
	"2006-01-02 15:04:05 UTC",
	"2006-01-02 15:04:05",
	time.RFC3339,
}

// parseAbuseTime parses an abuse.ch timestamp, returning the zero time.Time when
// the value is empty or unrecognized. abuse.ch timestamps are UTC.
func parseAbuseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range abuseTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// normalizeHash lowercases a hex hash and reports whether it is non-empty after
// trimming. abuse.ch hashes are already hex; lowercasing is the only
// normalization the store's keying requires.
func normalizeHash(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	return s, true
}

// normalizeIPv4 parses an IPv4 address (optionally trailing a ":port", as
// ThreatFox emits for ip:port IOCs) and returns its canonical dotted-quad form.
// It reports false for empty input, non-IPv4 addresses, or unparseable values.
func normalizeIPv4(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// Strip a trailing port if present (ThreatFox ip:port). Use SplitHostPort
	// first; fall back to the raw value when there's no port so bare IPs still
	// parse.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		// IPv6 (or an IPv4-mapped-IPv6 that didn't fit a /32) — out of scope
		// for the IndicatorIPv4 type.
		return "", false
	}
	return v4.String(), true
}

// normalizeDomain lowercases a hostname and strips any scheme, path, port, or
// surrounding whitespace, returning the bare host. It reports false when the
// result is empty.
func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	// A ThreatFox "domain" IOC is a bare host, but tolerate a stray scheme or
	// path by routing through the URL host extractor when one is present.
	if strings.Contains(s, "/") || strings.Contains(s, "://") {
		if host, ok := hostOfURL(s); ok {
			s = host
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", false
	}
	return s, true
}

// normalizeURL canonicalizes a URL for keying: it lowercases the scheme and
// host, strips the fragment, and otherwise preserves the path and query (which
// are case-sensitive and part of the malicious identity). It reports false when
// the value is empty or unparseable.
func normalizeURL(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	// Fragments never reach a server, so they're not part of the malicious
	// identity — strip them consistently so two URLs differing only by #frag
	// collapse to one indicator.
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), true
}

// hostOfURL extracts the lowercase host from a URL-ish string, reporting false
// when no host can be parsed.
func hostOfURL(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	if host == "" {
		return "", false
	}
	return strings.ToLower(host), true
}
