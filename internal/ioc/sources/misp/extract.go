package misp

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/ioc"
)

// extractEvent parses one per-event JSON document and returns the normalized
// indicators its attributes (including those nested in MISP Objects) map to.
// Attributes whose type isn't an IOC kind veto matches on are silently skipped;
// a malformed document is a hard error so the caller can drop just that event.
func extractEvent(body []byte, srcID string) ([]ioc.Indicator, error) {
	var doc eventDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.With(err, "unmarshal event")
	}

	ev := doc.Event
	reference := ev.UUID

	var out []ioc.Indicator
	add := func(attrs []attribute) {
		for _, a := range attrs {
			ind, ok := indicatorFromAttribute(a, ev, srcID, reference)
			if !ok {
				continue
			}
			out = append(out, ind)
		}
	}

	add(ev.Attribute)
	for _, obj := range ev.Object {
		add(obj.Attribute)
	}
	return out, nil
}

// indicatorFromAttribute maps one MISP attribute to a normalized ioc.Indicator.
// The bool is false when the attribute type isn't an IOC kind veto matches on,
// or when its value fails normalization (non-IPv4 address, empty hash, ...).
func indicatorFromAttribute(a attribute, ev event, srcID, reference string) (ioc.Indicator, bool) {
	typ, value, ok := mapAttribute(a.Type, a.Value)
	if !ok {
		return ioc.Indicator{}, false
	}

	published := a.Timestamp.Time()
	if published.IsZero() {
		published = ev.Timestamp.Time()
	}

	return ioc.Indicator{
		Type:        typ,
		Value:       value,
		SourceID:    srcID,
		ThreatLabel: threatLabel(a, ev),
		Reference:   reference,
		PublishedAt: published,
	}, true
}

// mapAttribute maps a MISP attribute (type, value) to a veto IndicatorType and
// a normalized value. The bool is false for types veto doesn't match on or
// values that fail normalization. Composite hash types ("filename|md5", ...)
// contribute only their hash half; the filename half is dropped.
func mapAttribute(typ, value string) (ioc.IndicatorType, string, bool) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}

	// Composite hash types encode "<filename>|<hash>"; keep the hash half. The
	// composite's left side is the filename, which veto doesn't key on.
	if hashType, ok := compositeHashType(typ); ok {
		if i := strings.LastIndex(value, "|"); i >= 0 {
			value = value[i+1:]
		}
		norm, ok := normalizeHash(value)
		return hashType, norm, ok
	}

	switch typ {
	case "md5":
		norm, ok := normalizeHash(value)
		return ioc.IndicatorMD5, norm, ok
	case "sha1":
		norm, ok := normalizeHash(value)
		return ioc.IndicatorSHA1, norm, ok
	case "sha256":
		norm, ok := normalizeHash(value)
		return ioc.IndicatorSHA256, norm, ok
	case "domain", "hostname":
		norm, ok := normalizeHost(value)
		return ioc.IndicatorDomain, norm, ok
	case "ip-src", "ip-dst":
		norm, ok := normalizeIPv4(value)
		return ioc.IndicatorIPv4, norm, ok
	case "url":
		norm, ok := normalizeURL(value)
		return ioc.IndicatorURL, norm, ok
	default:
		return "", "", false
	}
}

// compositeHashType maps a MISP composite attribute type such as
// "filename|sha256" to the hash IndicatorType it carries. The bool is false for
// non-composite or non-hash types.
func compositeHashType(typ string) (ioc.IndicatorType, bool) {
	i := strings.Index(typ, "|")
	if i < 0 {
		return "", false
	}
	switch typ[i+1:] {
	case "md5":
		return ioc.IndicatorMD5, true
	case "sha1":
		return ioc.IndicatorSHA1, true
	case "sha256":
		return ioc.IndicatorSHA256, true
	default:
		return "", false
	}
}

// normalizeHash lowercases a hex hash and rejects anything that isn't pure hex.
// The bool is false for empty or non-hex input so callers drop it.
func normalizeHash(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", false
		}
	}
	return v, true
}

// normalizeHost lowercases a hostname and strips a trailing dot. The bool is
// false for empty input.
func normalizeHost(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return "", false
	}
	return v, true
}

// normalizeIPv4 accepts only a single dotted-quad IPv4 address. IPv6 and CIDR
// notation are out of scope for the host-IOC store today and return false so
// the caller skips them.
func normalizeIPv4(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "/") {
		// CIDR ranges aren't single-value lookups; skip until the store grows
		// range support.
		return "", false
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		// IPv6 (or an IPv4-mapped form we won't normalize); skip.
		return "", false
	}
	return v4.String(), true
}

// normalizeURL lowercases the scheme and host of a URL while leaving the path,
// query, and fragment untouched (those are case-sensitive). A value with no
// scheme is treated as a bare host+path and lowercased wholesale. The bool is
// false for empty input.
func normalizeURL(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		// Not a parseable absolute URL; lowercase the whole thing so a
		// host-only value still normalizes consistently.
		return strings.ToLower(v), true
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), true
}

// threatLabel picks a display-only label for an attribute, preferring its
// MISP category, then its comment, then the event title. Never used for
// matching.
func threatLabel(a attribute, ev event) string {
	if s := strings.TrimSpace(a.Category); s != "" {
		return s
	}
	if s := strings.TrimSpace(a.Comment); s != "" {
		return s
	}
	return strings.TrimSpace(ev.Info)
}
