package misp

import (
	"strconv"
	"strings"
	"time"
)

// manifest is the parsed shape of a MISP feed's manifest.json: a map from event
// UUID to the event's summary metadata.
type manifest map[string]eventMeta

// eventMeta is the per-event metadata carried in manifest.json. Only the fields
// veto reads are modeled; MISP includes more (Orgc, Tag, analysis, ...) that we
// ignore. Timestamp is the change-detection key.
type eventMeta struct {
	// Info is the event's human-readable title. Used as a ThreatLabel fallback
	// when an attribute carries no category or comment.
	Info string `json:"info"`

	// Timestamp is the event's last-modified Unix epoch seconds. MISP encodes
	// it as a JSON string; mispTime tolerates both string and number.
	Timestamp mispTime `json:"timestamp"`
}

// eventDoc is the parsed shape of a per-event <uuid>.json document. MISP wraps
// the event in a single top-level "Event" object.
type eventDoc struct {
	Event event `json:"Event"`
}

// event is a MISP Event. Indicator attributes live both directly on the event
// (Attribute) and nested inside MISP Objects (Object[].Attribute); we harvest
// both so object-modeled file/network indicators aren't missed.
type event struct {
	UUID      string      `json:"uuid"`
	Info      string      `json:"info"`
	Timestamp mispTime    `json:"timestamp"`
	Attribute []attribute `json:"Attribute"`
	Object    []mispObj   `json:"Object"`
}

// mispObj is a MISP Object: a typed bundle of attributes (e.g. a "file" object
// grouping its md5/sha1/sha256). We flatten its attributes into the event.
type mispObj struct {
	Attribute []attribute `json:"Attribute"`
}

// attribute is a single MISP attribute. Type drives the IndicatorType mapping;
// Value is the raw indicator; Category/Comment feed the display-only label.
type attribute struct {
	Type      string   `json:"type"`
	Category  string   `json:"category"`
	Value     string   `json:"value"`
	Comment   string   `json:"comment"`
	Timestamp mispTime `json:"timestamp"`
}

// mispTime decodes a MISP timestamp that may be a JSON string ("1456329107")
// or a JSON number (1456329107), both Unix epoch seconds. A zero or unparseable
// value decodes to the zero time.Time.
type mispTime struct {
	t time.Time
}

// UnmarshalJSON implements json.Unmarshaler, tolerating both the string and
// number encodings MISP uses for epoch-second timestamps.
func (m *mispTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" || s == "0" {
		return nil
	}
	secs, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// A non-numeric timestamp is treated as "unknown" rather than fatal;
		// the event still parses and its attributes are still extracted.
		return nil
	}
	m.t = time.Unix(secs, 0).UTC()
	return nil
}

// Time returns the decoded timestamp (zero time.Time when absent/unparseable).
func (m mispTime) Time() time.Time { return m.t }

// Unix returns the epoch seconds, or 0 when absent. Used as the cache key for
// change detection.
func (m mispTime) Unix() int64 {
	if m.t.IsZero() {
		return 0
	}
	return m.t.Unix()
}
