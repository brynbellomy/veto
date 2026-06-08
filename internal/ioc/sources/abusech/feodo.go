package abusech

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/ioc"
)

// feodoEntry mirrors one element of Feodo Tracker's ipblocklist.json: a botnet
// C2 server keyed by IPv4 address. Only the fields veto consumes are decoded;
// the dump carries more (as_number, country, hostname, last_online) that are
// irrelevant to an ipv4 indicator.
type feodoEntry struct {
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	FirstSeen string `json:"first_seen_utc"`
	Malware   string `json:"malware"`
}

// fetchFeodo pulls Feodo Tracker's botnet-C2 IP blocklist and emits one ipv4
// indicator per entry. The malware family rides along as the threat label.
func (s *Source) fetchFeodo(ctx context.Context, url string) ([]ioc.Indicator, error) {
	payload, commit, err := s.fetchPayload(ctx, "feodo", url, http.MethodGet, nil, "")
	if err != nil {
		return nil, errors.With(err, "feodo fetch")
	}

	indicators, err := parseFeodoJSON(payload)
	if err != nil {
		s.dropEtag("feodo")
		return nil, err
	}
	commit()
	return indicators, nil
}

// parseFeodoJSON decodes Feodo Tracker's ipblocklist.json into normalized ipv4
// indicators. Entries whose ip_address fails to parse as IPv4 are skipped.
func parseFeodoJSON(payload []byte) ([]ioc.Indicator, error) {
	var raw []feodoEntry
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.With(err, "parse feodo json")
	}

	out := make([]ioc.Indicator, 0, len(raw))
	for _, e := range raw {
		v, ok := normalizeIPv4(e.IPAddress)
		if !ok {
			continue
		}
		out = append(out, ioc.Indicator{
			Type:        ioc.IndicatorIPv4,
			Value:       v,
			SourceID:    sourceID,
			ThreatLabel: e.Malware,
			Reference:   "https://feodotracker.abuse.ch/browse/host/" + v + "/",
			PublishedAt: parseAbuseTime(e.FirstSeen),
		})
	}
	return out, nil
}
