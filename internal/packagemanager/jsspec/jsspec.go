// Package jsspec parses npm-registry-style package specifiers shared across
// npm, pnpm, yarn, and bun: scoped/unscoped names with optional versions,
// plus local-path and git-url forms.
//
// This helper lives next to its consumers — siblings under
// internal/packagemanager/ — rather than in the parent, so the parent
// interface package stays ecosystem-agnostic.
package jsspec

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
)

// Parse turns a single command-line spec into an Install for the npm
// ecosystem. Recognizes:
//
//   - "lodash"                         → name only
//   - "lodash@4.17.21"                 → name + version
//   - "lodash@^4.17"                   → name + range (kept verbatim as version)
//   - "@scope/pkg"                     → scoped, no version
//   - "@scope/pkg@1.2.3"               → scoped + version
//   - "./local", "../sibling", "/abs"  → LocalPath=true
//   - "file:./local"                   → LocalPath=true
//   - "git+https://...", "github:org/repo", "user/repo",
//     "https://x.com/pkg.tgz"          → OpaqueRemote=true
//
// LocalPath specs are unverifiable (no name in the intel store); the gate
// passes them through by default. OpaqueRemote specs fetch code outside
// the registry and are refused by default — set VETO_ALLOW_OPAQUE=1 to
// opt in. See gate.Policy.
func Parse(spec string) packagemanager.Install {
	if IsLocalPathSpec(spec) {
		return packagemanager.Install{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: spec},
			RawSpec:   spec,
			LocalPath: true,
		}
	}
	// npm aliases ("alias@npm:realname[@version]") MUST unwrap before the
	// opaque-remote shorthand heuristic, because the realname may itself be
	// scoped (e.g. "compat@npm:@scope/real@1.0") and contain a "/" that the
	// "user/repo" shorthand check would otherwise misclassify as a github
	// reference. Aliases are also routed through the gate as the REAL
	// package — that's the entire point of fixing this class of bug.
	if name, version, ok := tryParseAlias(spec); ok {
		return packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version},
			RawSpec: spec,
		}
	}
	if IsOpaqueRemoteSpec(spec) {
		return packagemanager.Install{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: spec},
			RawSpec:      spec,
			OpaqueRemote: true,
		}
	}

	name, version := splitNameVersion(spec)
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version},
		RawSpec: spec,
	}
}

// tryParseAlias returns (realName, version, true) when spec is an npm alias
// of the form "alias@npm:realname[@version]". The alias name itself can be
// scoped or unscoped; the realname can be scoped or unscoped too. Returns
// (_, _, false) for anything that isn't an alias.
func tryParseAlias(spec string) (string, string, bool) {
	name, version := rawSplitNameVersion(spec)
	if name == "" {
		return "", "", false
	}
	return UnwrapNpmAlias(version)
}

// IsLocalPathSpec recognises filesystem-path specs that the gate cannot
// look up but that don't fetch remote code on their own. `file:` URIs are
// included even though they have a scheme — they reference a path on
// this machine.
//
// Exported so manifest readers (jsmanifest) can classify package.json values
// — which use the same shorthand grammar as command-line specs — without
// re-deriving the predicate.
func IsLocalPathSpec(spec string) bool {
	if spec == "" {
		return false
	}
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
		return true
	}
	if strings.HasPrefix(spec, "file:") {
		return true
	}
	// Phase 1.6: yarn berry and pnpm workspace pins. None of these
	// fetch from the registry; they reference paths or workspace
	// members the user already controls. Without this, the previous
	// classifier sent `link:./pkg` through IsOpaqueRemoteSpec (which
	// matched on the embedded `/`) and gates would refuse legitimate
	// monorepo installs.
	for _, prefix := range []string{"link:", "portal:", "workspace:", "catalog:", "patch:"} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	return false
}

// IsOpaqueRemoteSpec recognises specs that pull code from outside the
// registry: git refs (in any of npm's accepted forms), tarball URLs, and
// the "user/repo" GitHub shorthand. These are refused by default because
// upstream malware feeds can name them by URL / commit / tag and we'd
// silently bypass the lookup if we treated them like local paths.
//
// Exported so manifest readers (jsmanifest) can classify package.json values
// — which use the same shorthand grammar as command-line specs — without
// re-deriving the predicate.
func IsOpaqueRemoteSpec(spec string) bool {
	if spec == "" {
		return false
	}
	for _, prefix := range []string{
		"git+", "git://", "github:", "gist:", "bitbucket:", "gitlab:", "http://", "https://",
	} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	// "user/repo" shorthand: a slash without a leading @scope is a github
	// shorthand in npm. We treat anything containing "/" and not starting
	// with "@" as remote-fetching.
	if !strings.HasPrefix(spec, "@") && strings.Contains(spec, "/") {
		return true
	}
	return false
}

// splitNameVersion handles both scoped (@scope/pkg@ver) and unscoped (pkg@ver)
// forms. Returns (name, version); version may be empty.
//
// npm package aliases ("alias@npm:realname@version") are unwrapped to the
// real package: e.g. "lodash@npm:evil-pkg@1.0" returns ("evil-pkg", "1.0"),
// so the gate looks up the actually-installed package rather than the alias
// the user typed. Without this, an attacker can ship a malicious package and
// hide it behind a clean-looking local name.
func splitNameVersion(spec string) (string, string) {
	name, version := rawSplitNameVersion(spec)
	if alias, aliasVer, ok := UnwrapNpmAlias(version); ok {
		return alias, aliasVer
	}
	return name, version
}

// rawSplitNameVersion is the pre-alias-unwrap splitter — it just finds the
// "name@version" boundary.
func rawSplitNameVersion(spec string) (string, string) {
	if strings.HasPrefix(spec, "@") {
		// Scoped: find the SECOND '@' to split name from version.
		// "@scope/pkg@1.2.3" → name "@scope/pkg", version "1.2.3"
		if idx := strings.Index(spec[1:], "@"); idx >= 0 {
			return spec[:1+idx], spec[1+idx+1:]
		}
		return spec, ""
	}
	if name, version, ok := strings.Cut(spec, "@"); ok {
		return name, version
	}
	return spec, ""
}

// UnwrapNpmAlias detects npm's `npm:realname@version` alias syntax in the
// version slot. Returns (realname, version, true) when the version is of the
// form "npm:<name>[@<version>]". The realname may itself be scoped
// ("@scope/pkg").
//
// Exported so lockfile/manifest readers (jslock, jsmanifest) can unwrap the
// same alias shape they see in pnpm/yarn-berry headers and package.json
// values — without each format re-deriving the logic.
//
// Examples:
//
//	"npm:evil-pkg@1.0"        → ("evil-pkg",   "1.0", true)
//	"npm:bar"                 → ("bar",        "",    true)
//	"npm:@scope/pkg@1.0"      → ("@scope/pkg", "1.0", true)
//	"1.0.0"                   → ("", "", false)
func UnwrapNpmAlias(version string) (string, string, bool) {
	rest, ok := strings.CutPrefix(version, "npm:")
	if !ok {
		return "", "", false
	}
	name, ver := rawSplitNameVersion(rest)
	if name == "" {
		return "", "", false
	}
	return name, ver, true
}

// ParseInstallArgs is the shared parser for npm-family CLIs (npm/pnpm/yarn/bun).
// It identifies the install verb (first non-flag matching installVerbs) and
// returns Install records for every non-flag token after it. Returns nil when
// args do not start an install command; an empty slice when args ARE an install
// verb but no explicit specs were named (e.g. `npm install`, `npm ci`).
//
// Respects the POSIX `--` separator: every token after `--` is treated as a
// positional package spec even if it starts with `-` (so leading-dash
// typosquat names like `-chalk` are gated rather than silently bypassed).
//
// flagsTakingValues is the PM's table of flags whose next argv token is a
// value, not a positional (e.g. npm's "--prefix /tmp"). A nil/empty map is
// accepted; the parser then degrades to flag-name-only skipping, which can
// misread a flag's value as the verb. Pass the PM-specific table.
func ParseInstallArgs(args []string, installVerbs map[string]struct{}, flagsTakingValues argv.FlagsWithValues) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsTakingValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsTakingValues)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, Parse(spec))
	}
	return installs
}

// ProjectPreflightRefs returns ManifestRefs for the full set of files needed
// to gate a JS-family command that executes project code (run/start/test/etc.)
// without installing packages. The set is package.json + every JS lockfile
// format. The expander tolerates missing files, so emitting all speculatively
// provides full transitive coverage regardless of which PM or lockfile format
// the project uses.
func ProjectPreflightRefs() []packagemanager.ManifestRef {
	return []packagemanager.ManifestRef{
		{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON},
		{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		{Path: "npm-shrinkwrap.json", Kind: packagemanager.ManifestKindNpmShrinkwrap},
		{Path: "pnpm-lock.yaml", Kind: packagemanager.ManifestKindPnpmLockYAML},
		{Path: "yarn.lock", Kind: packagemanager.ManifestKindYarnLock},
		{Path: "bun.lock", Kind: packagemanager.ManifestKindBunLock},
	}
}

// PackageJSONManifestRefs returns ManifestRefs for both the package.json
// manifest AND each lockfile we know about (package-lock.json,
// npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock). The expander tolerates
// missing files, so emitting all of them speculatively gives transitive
// coverage without the parser having to know which PM is running.
//
// Refs are emitted in two cases:
//
//  1. The verb is in alwaysReadsManifest (npm's `ci` and similar
//     deterministic-from-lockfile verbs).
//  2. The verb is an install verb with no explicit specs — the PM is
//     going to derive its work from the local manifest + lockfile.
//
// When the user named explicit specs (`npm install foo`), the gate's
// argv-driven lookup already covers them; we still emit lockfile refs so
// the existing transitive tree on disk gets re-gated on every install
// (strictly safer — a known-flagged transitive dep can't sit in the
// lockfile unnoticed just because the user is installing something
// unrelated). For pure performance, install-with-explicit-specs could
// suppress lockfile expansion; we prefer the safety side here.
func PackageJSONManifestRefs(
	args []string,
	installVerbs map[string]struct{},
	alwaysReadsManifest map[string]struct{},
	flagsTakingValues argv.FlagsWithValues,
) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsTakingValues)
	if !ok {
		return nil
	}
	if _, isInstall := installVerbs[verb]; !isInstall {
		return nil
	}
	// Derive lockfile refs from ProjectPreflightRefs, skipping package.json
	// (which is added conditionally below). This keeps the lockfile list in
	// one place.
	allPreflightRefs := ProjectPreflightRefs()
	lockRefs := make([]packagemanager.ManifestRef, 0, len(allPreflightRefs)-1)
	for _, r := range allPreflightRefs {
		if r.Kind != packagemanager.ManifestKindPackageJSON {
			lockRefs = append(lockRefs, r)
		}
	}
	pkgRef := packagemanager.ManifestRef{Path: "package.json", Kind: packagemanager.ManifestKindPackageJSON}
	if _, always := alwaysReadsManifest[verb]; always {
		return append([]packagemanager.ManifestRef{pkgRef}, lockRefs...)
	}
	if specs := argv.CollectPositionalsWithTable(rest, flagsTakingValues); len(specs) > 0 {
		// User named explicit specs; gate them via argv. Still re-gate
		// the on-disk lockfile so a known-flagged transitive doesn't
		// hide there.
		return lockRefs
	}
	return append([]packagemanager.ManifestRef{pkgRef}, lockRefs...)
}
