// Package hades is a curated static intel source for the June 2026 Hades /
// Shai-Hulud PyPI worm wave. It is an explicit STOPGAP: the durable defense
// is the pthscan content heuristic, which catches the worm by .pth shape
// even when the (name, version) is brand-new and absent from every other
// feed. This source exists only to shorten the window for the
// already-known names while the worm's tail of compromised versions is
// catalogued elsewhere.
package hades

import (
	"context"

	"github.com/brynbellomy/veto/internal/intel"
)

const sourceID = "hades"

// Source implements intel.Source with a fixed list. Construct via New.
type Source struct{}

var _ intel.Source = (*Source)(nil)

// New builds a Hades stopgap source. No options.
func New() *Source { return &Source{} }

// ID implements intel.Source.
func (s *Source) ID() string { return sourceID }

// Fetch returns the curated Hades report list. Only the PyPI ecosystem is
// covered; other ecosystems get ErrUnsupportedEcosystem.
func (s *Source) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	if eco != intel.EcosystemPyPI {
		return nil, intel.ErrUnsupportedEcosystem
	}
	out := make([]intel.MalwareReport, 0, len(hadesEntries))
	for _, e := range hadesEntries {
		out = append(out, intel.MalwareReport{
			PackageRef: intel.PackageRef{
				Ecosystem: intel.EcosystemPyPI,
				Name:      e.name,
				Version:   e.version,
			},
			SourceID: sourceID,
			Reason:   "Hades / Shai-Hulud (June 2026) PyPI worm wave (.pth startup-hook). See https://socket.dev/blog and the OSV advisories.",
		})
	}
	return out, nil
}

// hadesEntries is the curated list of known Hades package@versions. Curated by
// hand from the published advisories — versions are exact, not ranges. New
// versions discovered after this commit must be added here AND the underlying
// content heuristic (pthscan) catches them automatically.
var hadesEntries = []struct {
	name    string
	version string
}{
	{"ensmallen", "0.8.6"},
	{"embiggen", "0.11.20"},
	{"pyphetools", "0.13.6"},
	{"gpsea", "0.10.3"},
	{"phenopacket-store-toolkit", "0.1.5"},
	{"ppkt2synergy", "0.0.2"},
}
