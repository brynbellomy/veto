package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/ioc"
)

// threatFoxRequest is the JSON body for ThreatFox's get_iocs query. days is
// clamped to the API maximum (7) so a single call captures the widest recent
// window the free endpoint serves.
type threatFoxRequest struct {
	Query string `json:"query"`
	Days  int    `json:"days"`
}

// threatFoxResponse is the envelope ThreatFox returns. query_status is "ok" on
// success; anything else (including "no_result") means data is absent or
// unusable.
type threatFoxResponse struct {
	QueryStatus string         `json:"query_status"`
	Data        []threatFoxIOC `json:"data"`
}

// threatFoxIOC mirrors one entry of a ThreatFox get_iocs response. Only the
// fields veto consumes are decoded.
type threatFoxIOC struct {
	ID        json.RawMessage `json:"id"`
	IOC       string          `json:"ioc"`
	IOCType   string          `json:"ioc_type"`
	Malware   string          `json:"malware_printable"`
	FirstSeen string          `json:"first_seen"`
	Reference string          `json:"reference"`
}

// fetchThreatFox queries ThreatFox's get_iocs API for the recent window and
// emits one indicator per entry, mapping ioc_type to the corresponding
// IndicatorType: ip:port->ipv4 (port stripped), domain->domain, url->url,
// sha256_hash->sha256. Entries of other ioc_types are skipped.
func (s *Source) fetchThreatFox(ctx context.Context, url string) ([]ioc.Indicator, error) {
	reqBody, err := json.Marshal(threatFoxRequest{Query: "get_iocs", Days: 7})
	if err != nil {
		return nil, errors.With(err, "marshal threatfox request")
	}

	payload, commit, err := s.fetchPayload(ctx, "threatfox", url, http.MethodPost, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return nil, errors.With(err, "threatfox fetch")
	}

	indicators, err := parseThreatFoxJSON(payload)
	if err != nil {
		s.dropEtag("threatfox")
		return nil, err
	}
	commit()
	return indicators, nil
}

// parseThreatFoxJSON decodes a ThreatFox get_iocs response into normalized
// indicators. A query_status other than "ok" with empty data yields no
// indicators and no error; malformed JSON is an error.
func parseThreatFoxJSON(payload []byte) ([]ioc.Indicator, error) {
	var resp threatFoxResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, errors.With(err, "parse threatfox json")
	}

	out := make([]ioc.Indicator, 0, len(resp.Data))
	for _, e := range resp.Data {
		ind, ok := threatFoxIndicator(e)
		if !ok {
			continue
		}
		out = append(out, ind)
	}
	return out, nil
}

// threatFoxIndicator maps one ThreatFox entry to a normalized Indicator,
// reporting false when the ioc_type is unsupported or the value fails to
// normalize.
func threatFoxIndicator(e threatFoxIOC) (ioc.Indicator, bool) {
	base := ioc.Indicator{
		SourceID:    sourceID,
		ThreatLabel: e.Malware,
		Reference:   e.Reference,
		PublishedAt: parseAbuseTime(e.FirstSeen),
	}
	switch e.IOCType {
	case "ip:port":
		v, ok := normalizeIPv4(e.IOC)
		if !ok {
			return ioc.Indicator{}, false
		}
		base.Type, base.Value = ioc.IndicatorIPv4, v
	case "domain":
		v, ok := normalizeDomain(e.IOC)
		if !ok {
			return ioc.Indicator{}, false
		}
		base.Type, base.Value = ioc.IndicatorDomain, v
	case "url":
		v, ok := normalizeURL(e.IOC)
		if !ok {
			return ioc.Indicator{}, false
		}
		base.Type, base.Value = ioc.IndicatorURL, v
	case "sha256_hash":
		v, ok := normalizeHash(e.IOC)
		if !ok {
			return ioc.Indicator{}, false
		}
		base.Type, base.Value = ioc.IndicatorSHA256, v
	default:
		return ioc.Indicator{}, false
	}
	return base, true
}
