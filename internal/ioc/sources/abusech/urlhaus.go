package abusech

import (
	"context"
	"io"
	"net/http"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/ioc"
)

// URLhaus csv_recent column layout (the documented, stable 9-column order). The
// dump is comma-separated, every value double-quoted, and prefixed with
// "#"-comment lines we skip.
const (
	uhColID        = 0 // id
	uhColDateAdded = 1 // dateadded (UTC)
	uhColURL       = 2 // url
	uhColStatus    = 3 // url_status
	uhColLastSeen  = 4 // last_online
	uhColThreat    = 5 // threat
	uhColTags      = 6 // tags
	uhColLink      = 7 // urlhaus_link
	uhColReporter  = 8 // reporter

	uhMinColumns = uhColReporter + 1
)

// fetchURLhaus pulls URLhaus's csv_recent dump and emits one url indicator per
// row. The threat classification rides along as the threat label and the
// URLhaus entry link as the reference.
func (s *Source) fetchURLhaus(ctx context.Context, url string) ([]ioc.Indicator, error) {
	payload, commit, err := s.fetchPayload(ctx, "urlhaus", url, http.MethodGet, nil, "")
	if err != nil {
		return nil, errors.With(err, "urlhaus fetch")
	}

	indicators, err := parseURLhausCSV(payload)
	if err != nil {
		s.dropEtag("urlhaus")
		return nil, err
	}
	commit()
	return indicators, nil
}

// parseURLhausCSV decodes a URLhaus csv_recent/csv_online dump into normalized
// url indicators. Comment lines and short rows are skipped; a row whose url
// can't be canonicalized contributes nothing.
func parseURLhausCSV(payload []byte) ([]ioc.Indicator, error) {
	r := newAbuseCSVReader(payload, uhMinColumns)

	var out []ioc.Indicator
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.With(err, "parse urlhaus csv")
		}
		if row == nil {
			continue
		}

		v, ok := normalizeURL(field(row, uhColURL))
		if !ok {
			continue
		}
		out = append(out, ioc.Indicator{
			Type:        ioc.IndicatorURL,
			Value:       v,
			SourceID:    sourceID,
			ThreatLabel: field(row, uhColThreat),
			Reference:   field(row, uhColLink),
			PublishedAt: parseAbuseTime(field(row, uhColDateAdded)),
		})
	}
	return out, nil
}
