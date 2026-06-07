// Package sources is the home for concrete ioc.Source implementations.
//
// It is intentionally empty today: this foundation ships the ioc.Source and
// ioc.Store contracts but no feeds. Wave 4 adds one subpackage per feed,
// mirroring internal/intel/sources/:
//
//   - sources/abusech/ — abuse.ch URLhaus / MalwareBazaar (hash + URL + domain
//     indicators)
//   - sources/misp/    — a MISP instance's published event attributes
//
// Each subpackage owns its own HTTP client and format parser so those
// dependencies never reach the slim ioc parent package, and registers itself
// through buildIOCSource in cmd/veto/main.go (a single case + import +
// default-slice entry).
package sources
