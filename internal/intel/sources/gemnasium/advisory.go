package gemnasium

import (
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/brynbellomy/veto/internal/intel"
)

// advisory is the subset of the gemnasium YAML schema veto consumes. The
// GitLab Advisory Database stores one advisory per file under
// `<ecosystem>/<package>/<identifier>.yml`, with these fields. Unmodeled
// fields (urls, cvss, cwe_ids, solution, ...) are ignored.
type advisory struct {
	Identifier    string   `yaml:"identifier"`
	Identifiers   []string `yaml:"identifiers"`
	PackageSlug   string   `yaml:"package_slug"`
	Title         string   `yaml:"title"`
	Description   string   `yaml:"description"`
	AffectedRange string   `yaml:"affected_range"`
	Date          string   `yaml:"date"`
	PubDate       string   `yaml:"pubdate"`
}

// parseAdvisory decodes one gemnasium YAML document. Returns an error only for
// structurally invalid YAML; semantic gaps (missing package_slug, untranslatable
// range) are handled by the caller during report emission.
func parseAdvisory(payload []byte) (advisory, error) {
	var adv advisory
	if err := yaml.Unmarshal(payload, &adv); err != nil {
		return advisory{}, errors.With(err, "decode gemnasium advisory")
	}
	return adv, nil
}

// advisoryID picks the most useful identifier for display/dedup: the explicit
// `identifier` field if present, else the first entry of `identifiers`.
func (a advisory) advisoryID() string {
	if a.Identifier != "" {
		return a.Identifier
	}
	if len(a.Identifiers) > 0 {
		return a.Identifiers[0]
	}
	return ""
}

// publishedAt parses `pubdate` (the original publication date) into a time,
// falling back to `date` (last-modified). Returns the zero time when neither
// parses; the report then records no publication date, matching the contract
// on intel.MalwareReport.PublishedAt.
func (a advisory) publishedAt() time.Time {
	for _, raw := range []string{a.PubDate, a.Date} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if t, err := time.Parse("2006-01-02", raw); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// splitPackageSlug splits a gemnasium `package_slug` ("<eco>/<name>") into its
// ecosystem prefix and package name. The name may itself contain slashes (Go
// import paths like `go/github.com/gin-gonic/gin`), so only the FIRST slash is
// the separator. Returns ok=false when there is no slash.
func splitPackageSlug(slug string) (ecoPrefix, name string, ok bool) {
	slug = strings.TrimSpace(slug)
	idx := strings.IndexByte(slug, '/')
	if idx <= 0 || idx == len(slug)-1 {
		return "", "", false
	}
	return slug[:idx], slug[idx+1:], true
}

// normalizeEcosystem maps a gemnasium ecosystem directory/slug prefix to the
// intel taxonomy. Ecosystems veto does not gate (gem, maven, packagist, nuget,
// conan, swift, pub) return ok=false so the caller skips them cleanly.
func normalizeEcosystem(prefix string) (intel.Ecosystem, bool) {
	switch strings.ToLower(strings.TrimSpace(prefix)) {
	case "npm":
		return intel.EcosystemNPM, true
	case "pypi":
		return intel.EcosystemPyPI, true
	case "go":
		return intel.EcosystemGo, true
	case "cargo":
		return intel.EcosystemCrates, true
	default:
		return "", false
	}
}

// reportsFromAdvisory converts one parsed advisory into MalwareReports under
// the given source ID, for the requested ecosystem only. An advisory whose
// package_slug names a different ecosystem yields no reports (the caller groups
// the whole feed by ecosystem on ingest).
//
// Each translated OR-alternative of `affected_range` becomes one report:
// bounded intervals carry Range (Version empty); exact pins carry Version.
// When an alternative cannot be translated cleanly, it is dropped and a
// structured warning is logged with the offending expression — the report set
// stays correct at the cost of explicit, auditable coverage gaps.
func reportsFromAdvisory(adv advisory, want intel.Ecosystem, sourceID string, logger zerolog.Logger) []intel.MalwareReport {
	ecoPrefix, name, ok := splitPackageSlug(adv.PackageSlug)
	if !ok || name == "" {
		return nil
	}
	eco, ok := normalizeEcosystem(ecoPrefix)
	if !ok || eco != want {
		return nil
	}

	id := adv.advisoryID()
	reason := adv.Title
	if reason == "" {
		reason = adv.Description
	}
	if reason == "" {
		reason = "VULNERABILITY"
	}
	published := adv.publishedAt()

	res := translateAffectedRange(eco, adv.AffectedRange)
	if res.Skipped {
		logger.Warn().
			Str("advisory", id).
			Str("package_slug", adv.PackageSlug).
			Str("ecosystem", string(eco)).
			Str("affected_range", adv.AffectedRange).
			Msg("gemnasium: dropping untranslatable affected_range alternative(s); no guessed range emitted")
	}

	var out []intel.MalwareReport
	base := intel.PackageRef{Ecosystem: eco, Name: name}

	for _, v := range res.ExactVersions {
		ref := base
		ref.Version = v
		out = append(out, intel.MalwareReport{
			PackageRef:  ref,
			SourceID:    sourceID,
			Reason:      reason,
			AdvisoryID:  id,
			PublishedAt: published,
		})
	}
	for i := range res.Ranges {
		rng := res.Ranges[i]
		out = append(out, intel.MalwareReport{
			PackageRef:  base,
			SourceID:    sourceID,
			Reason:      reason,
			AdvisoryID:  id,
			PublishedAt: published,
			Range:       &rng,
		})
	}
	return out
}
