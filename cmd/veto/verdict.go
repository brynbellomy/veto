package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// verdictFormat selects the output encoding for `veto test`.
type verdictFormat string

const (
	verdictFormatJSON verdictFormat = "json"
	verdictFormatText verdictFormat = "text"
)

// commandVerdict is the structured result of asking veto "what do you think
// of this command line?" without executing anything. It is the Gate-side
// counterpart to runGate's enforcement path: same parse, same intel store,
// same gate.Gate.Evaluate call — but no exec, no resolver pre-scan, no
// tarball/wheel fetches, no opaque-git clones.
//
// Decision vocabulary reuses gate.Outcome verbatim ("allow", "refuse",
// "passthrough", "abort") so consumers share one contract with the
// enforcement layer. "warn" does not exist in veto's gate and is not
// invented here.
type commandVerdict struct {
	// Decision is the gate outcome: "allow", "refuse", "passthrough", or
	// "abort". "refuse" means the intel+policy gate would block the
	// command. "allow" is NOT a safety statement: it excludes the
	// enforcement-only layers (resolver pre-scan transitives, gyp
	// tarball/tree scan, pth wheel/tree scan) — see evaluateCommandLine.
	Decision string `json:"decision"`

	// PM is the package-manager binary the command was parsed as (e.g.
	// "npm"). Empty when args[0] did not name a known package manager.
	PM string `json:"pm,omitempty"`

	// Args echoes the PM arguments that were evaluated.
	Args []string `json:"args"`

	// Reason summarizes why the decision fired. For refusals it names the
	// first flagged package and driving source; for passthrough it explains
	// that the command is not an install verb.
	Reason string `json:"reason,omitempty"`

	// Installs is the per-package verdict detail the gate evaluated.
	// Empty for passthrough decisions.
	Installs []installVerdict `json:"installs,omitempty"`

	// Errors carries the internal failures behind an "abort" decision.
	Errors []string `json:"errors,omitempty"`

	// Damage lists the (source, ecosystem) intel buckets that failed
	// integrity verification and could not be restored, for ecosystems
	// THIS command touches. Non-empty always accompanies decision
	// "abort": the gate cannot see its full coverage, so the verdict is
	// neither allow (nothing was flagged — we simply cannot see) nor
	// refuse (no package was flagged). A machine consumer must treat
	// damage as "indeterminate, fail closed" — the same stance the
	// enforcement path takes with exit 70.
	Damage []damageEntry `json:"damage,omitempty"`
}

// damageEntry is one damaged (source, ecosystem) intel bucket in a
// commandVerdict. The fields mirror intel.SourceDamage so a consumer can
// correlate with `veto doctor` / `veto status` output.
type damageEntry struct {
	Source   string `json:"source"`
	Eco      string `json:"ecosystem"`
	Reason   string `json:"reason"`
	Got      int    `json:"got"`
	Baseline int    `json:"baseline"`
}

// installVerdict is one package's gate outcome inside a commandVerdict.
type installVerdict struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	RawSpec   string   `json:"raw_spec,omitempty"`
	Flagged   bool     `json:"flagged"`
	Sources   []string `json:"sources,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
}

// runVerdict implements `veto test [--format json|text] <pm> <pm-args...>`:
// a verdict-only mode that never executes the package manager. Exit codes
// mirror the enforcement path so integrators can branch on $? alone:
// allow/passthrough → 0, refuse → 1, usage error → 64, abort/internal → 70.
func runVerdict(logger zerolog.Logger, cfg config, args []string) int {
	format := verdictFormatJSON
	var pmArgs []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "veto test: --format requires a value (json|text)")
				return exitUsage
			}
			format = verdictFormat(args[i+1])
			i++
		case strings.HasPrefix(a, "--format="):
			format = verdictFormat(strings.TrimPrefix(a, "--format="))
		default:
			pmArgs = append(pmArgs, a)
		}
	}

	switch format {
	case verdictFormatJSON, verdictFormatText:
	default:
		fmt.Fprintf(os.Stderr, "veto test: unknown --format %q (want json|text)\n", format)
		return exitUsage
	}

	if len(pmArgs) == 0 {
		fmt.Fprintln(os.Stderr, "veto test: missing command line — usage: veto test [--format json|text] <pm> <pm-args...>")
		return exitUsage
	}

	verdict, code := evaluateCommandLine(logger, cfg, pmArgs)
	if format == verdictFormatJSON {
		if err := json.NewEncoder(os.Stdout).Encode(verdict); err != nil {
			logger.Error().Err(err).Msg("write verdict json")
			return exitInternal
		}
	} else {
		writeVerdictText(os.Stdout, verdict)
	}
	return code
}

// evaluateCommandLine runs the decide-phase of the gate against a command
// line and returns the structured verdict plus the exit code an integrator
// should see. It performs no execution: the only side effects are the intel
// store's own cache reads (and an etag-gated refresh when the cache is
// stale), identical to what the enforcement path does before deciding.
//
// The decision pipeline is deliberately the same one runGate uses, extracted
// into gateInputsFor so the verdict path and the enforcement path cannot
// drift: parseInstalls → manifestRefs → projectPreflightPlan → store
// refresh → sanity floor → preflight evaluate → gate.Evaluate.
//
// SCOPE — read this before trusting an "allow". The verdict is the
// intel+policy gate's answer over the argv and the on-disk manifests it
// names. It does NOT include four enforcement layers that run after
// gate.Evaluate in runGate, because they execute commands or fetch beyond
// the intel cache and would break this mode's "executes nothing" contract:
//
//   - runResolverPreScanIfAvailable (main.go) — generates a fresh lockfile
//     via e.g. `npm install --package-lock-only` and re-gates the RESOLVED
//     TRANSITIVE tree. A transitive dep flagged in intel is invisible to
//     the verdict when argv names only a clean direct dep.
//   - gypTarballPreflight — downloads the named packages' tarballs
//     (npm pack --ignore-scripts) and inspects each binding.gyp for the
//     phantom-gyp / Miasma worm class. Default-on.
//   - runGypPreflightIfNpmFamily — scans the existing node_modules tree's
//     binding.gyp files, since an install re-runs node-gyp for the whole
//     tree.
//   - pthWheelPreflight / runPthPreflightIfPythonFamily — the analogous
//     .pth startup-hook worm layers for the Python ecosystem (wheel
//     prescan + site-packages tree scan).
//
// Practical consequence, stated plainly: an "allow" verdict is NOT a
// statement that the install is safe. It means intel+policy found nothing
// on the argv and manifests. A package whose TRANSITIVE dependency is
// flagged, or that carries a worm binding.gyp / .pth file, returns
// "allow" here while `veto npm install` refuses. Integrators (sirene's
// Gate) must treat this as a fast intel lookup, not a replacement for
// the executing gate — veto keeps executing package-manager commands
// precisely because of these four layers.
//
// DAMAGED INTEL — a state a consumer must handle distinctly. When an
// intel (source, ecosystem) bucket in an ecosystem this command touches
// failed integrity verification and could not be restored, the verdict
// is "abort" (exit 70) with the damaged buckets enumerated in the
// "damage" array (source, ecosystem, reason, got, baseline) and
// summarized in "errors". This is neither "allow" (nothing was flagged
// — the gate simply cannot see part of its coverage) nor "refuse" (no
// package was flagged): it is INDETERMINATE, and the consumer must fail
// closed exactly as it would for any other abort. The damage decision is
// computed in gateInputsFor, the single site both this path and runGate
// flow through, so the two surfaces cannot disagree on whether damage
// blocks. Damage confined to ecosystems this command does not touch is
// non-blocking and never appears here (runGate prints those as WARNs).
//
// The asymmetry that DOES hold: for `cargo add --git`, enforcement may
// clone-and-resolve the spec into an allow while the verdict refuses it
// without fetching. Within the layers the verdict evaluates, it never
// allows what the same layers would refuse. Damage composes with this:
// both surfaces abort identically on it.
func evaluateCommandLine(logger zerolog.Logger, cfg config, args []string) (commandVerdict, int) {
	pmName, pmArgs := args[0], args[1:]
	v := commandVerdict{PM: pmName, Args: pmArgs}

	pms := buildPackageManagers()
	pm, ok := pms[pmName]
	if !ok {
		// Unknown PM: the enforcement path passes through to exec untouched,
		// so the verdict is "passthrough" with the reason recorded.
		v.PM = ""
		v.Decision = string(gate.OutcomePassThrough)
		v.Reason = "unknown package manager; command is not gated"
		return v, exitOK
	}

	in, decided := gateInputsFor(logger, cfg, pm, pmArgs)
	if !decided {
		v.Decision = string(gate.OutcomePassThrough)
		v.Reason = "not an install command; veto would pass it through"
		return v, exitOK
	}
	if in.store == nil {
		// gateInputsFor already logged the internal failure (store build,
		// refresh, or sanity floor); storeErr carries the case-specific line.
		v.Decision = string(gate.OutcomeAbort)
		v.Reason = in.storeErr
		return v, exitInternal
	}

	// Damaged intel bucket in an ecosystem this command touches: the gate
	// cannot see its full coverage, so there is no honest verdict to give.
	// "abort" (exit 70) matches the enforcement path's fail-closed stance;
	// the reason names the damaged source and ecosystem so a machine
	// consumer can surface remediation without parsing prose. This check
	// lives in gateInputsFor (in.damageRefusals) — not here — so the two
	// surfaces cannot drift on whether damage blocks.
	if len(in.damageRefusals) > 0 {
		v.Decision = string(gate.OutcomeAbort)
		v.Reason = verdictDamageReason(in.damageRefusals)
		for _, d := range in.damageRefusals {
			v.Damage = append(v.Damage, damageEntry{
				Source:   d.SourceID,
				Eco:      string(d.Ecosystem),
				Reason:   d.Reason,
				Got:      d.Got,
				Baseline: d.Baseline,
			})
			v.Errors = append(v.Errors, fmt.Sprintf(
				"intel source %s (ecosystem %s) damaged: %s (got %d reports, baseline %d)",
				d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline))
		}
		return v, exitInternal
	}

	var decision gate.Decision
	if in.hasPreflight {
		preflightPolicy := in.policy
		preflightPolicy.ManifestExpander = projectPreflightExpander{delegate: in.expander}
		decision = gate.New(in.store, preflightPolicy, logger).Evaluate([]packagemanager.Install{}, in.preflight.ManifestRefs...)
	} else {
		decision = gate.New(in.store, in.policy, logger).Evaluate(in.installs, in.manifestRefs...)
	}

	v = verdictFromDecision(pmName, pmArgs, &decision)
	return v, codeForOutcome(decision.Outcome)
}

// verdictDamageReason renders the abort reason for a damaged-bucket
// verdict: one line naming the first damaged source and ecosystem, with
// the full list in v.Damage / v.Errors.
func verdictDamageReason(refusals []intel.SourceDamage) string {
	if len(refusals) == 0 {
		return ""
	}
	d := refusals[0]
	more := ""
	if len(refusals) > 1 {
		more = fmt.Sprintf(" (+%d more)", len(refusals)-1)
	}
	return fmt.Sprintf(
		"intel for this install is damaged and could not be verified: source %s (ecosystem %s): %s (got %d reports, baseline %d)%s",
		d.SourceID, d.Ecosystem, d.Reason, d.Got, d.Baseline, more)
}

// verdictFromDecision maps a gate.Decision to its structured commandVerdict
// form. Kept separate from store construction so tests can drive a real
// gate.Gate with fixture intel and assert on the exact JSON shape an
// integrator consumes.
// normalizeOutcome enforces the verdict JSON's decision vocabulary:
// allow, refuse, passthrough, abort. gate.Outcome is a string type and
// the gate could in principle mint a new value; codeForOutcome already
// maps unknowns to exit 70, but the JSON used to emit the raw string —
// a consumer branching on "decision" would see an unknown token and
// fall through its switch to whatever its default is (often allow).
// Unknown outcomes normalize to abort so the JSON and the exit code can
// never disagree (FIX 6).
func normalizeOutcome(o gate.Outcome) string {
	switch o {
	case gate.OutcomeAllow, gate.OutcomeRefuse, gate.OutcomePassThrough, gate.OutcomeAbort:
		return string(o)
	default:
		return string(gate.OutcomeAbort)
	}
}

func verdictFromDecision(pmName string, pmArgs []string, d *gate.Decision) commandVerdict {
	v := commandVerdict{PM: pmName, Args: pmArgs, Decision: normalizeOutcome(d.Outcome)}
	for _, gv := range d.Verdicts {
		v.Installs = append(v.Installs, toInstallVerdict(gv))
	}
	for _, err := range d.Errors {
		v.Errors = append(v.Errors, err.Error())
	}
	v.Reason = verdictReason(d)
	return v
}

// gateInputs is the shared parse→refresh decide-phase setup used by both the
// enforcement path (runGate) and the verdict-only path (evaluateCommandLine).
// Extracting it is what guarantees the two paths parse the command, build
// and refresh the intel store, enforce the health floor, and configure the
// gate policy identically — the only difference between them is what happens
// *after* the gate's Decision comes back (exec vs. JSON).
//
// decided=false means the command is not an install verb at all; the caller
// passes through without consulting intel. A nil store with decided=true
// means the intel store itself is unusable; storeErr then carries the
// case-specific stderr line (build vs. refresh vs. sanity floor) so the
// caller's error message keeps the specificity an operator needs to tell
// the three apart. The failure is also logged here because both callers
// fail-closed on it identically.
type gateInputs struct {
	store        intel.Store
	storeErr     string
	policy       gate.Policy
	expander     *compoundExpander
	installs     []packagemanager.Install
	manifestRefs []packagemanager.ManifestRef
	preflight    packagemanager.ProjectPreflightPlan
	hasPreflight bool

	// damageRefusals lists the (source, ecosystem) damage buckets in
	// ecosystems this command touches. Non-empty means the intel store is
	// missing part of its coverage for THIS install: the gate cannot see
	// everything it claims to, so both the enforcement path and the
	// verdict path must fail closed. Computed in gateInputsFor — the one
	// place both paths flow through — so the two surfaces cannot diverge
	// on whether damage blocks (the verdict path previously skipped this
	// check entirely and answered "allow" over a damaged bucket).
	damageRefusals []intel.SourceDamage
}

func gateInputsFor(
	logger zerolog.Logger,
	cfg config,
	pm packagemanager.PackageManager,
	pmArgs []string,
) (gateInputs, bool) {
	installs := pm.ParseInstalls(pmArgs)
	manifestRefs := pm.ManifestRefs(pmArgs)
	preflight, hasPreflight := projectPreflightPlan(pm, pmArgs, installs, manifestRefs)
	if installs == nil && len(manifestRefs) == 0 && !hasPreflight {
		return gateInputs{}, false
	}

	store, err := buildStoreFn(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return gateInputs{storeErr: fmt.Sprintf("veto: INTERNAL ERROR — could not build intel store (%v); install aborted fail-closed.", err)}, true
	}

	// Refresh synchronously before gating; the cache layer keeps this fast
	// on the common path, and the freshness window makes repeated
	// invocations in quick succession skip the network entirely.
	if err := refreshStoreWithFreshnessWindow(logger, cfg, store); err != nil {
		// Don't fail open: if we have zero intel, we can't gate.
		logger.Error().Err(err).Msg("intel refresh failed — refusing to gate without data")
		return gateInputs{storeErr: "veto: INTERNAL ERROR — intel refresh failed; install aborted fail-closed."}, true
	}

	// Sanity floor on store health. An empty store means every lookup would
	// return "clean," which is worse than useless — it's silently allowing
	// packages through under the appearance of being gated.
	if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
		logger.Error().
			Int("reports", reportCount).
			Int("floor", minHealthyReportCount).
			Msg("intel store below sanity floor — refusing to gate")
		return gateInputs{storeErr: fmt.Sprintf(
			"veto: INTERNAL ERROR — intel store has only %d reports (expected at least %d); install aborted fail-closed.",
			reportCount, minHealthyReportCount)}, true
	}

	// Per-source damage check, computed HERE so the enforcement path and
	// the verdict path cannot disagree on it: a (source, ecosystem) bucket
	// that failed integrity verification — and could not be re-fetched or
	// retained — means the store is missing part of its coverage. For
	// damage in an ecosystem this command touches, the caller must fail
	// closed; damage confined to untouched ecosystems stays non-blocking
	// (an npm install must not wedge because the crates feed is rotting).
	// Callers own presentation: runGate prints the operator block on
	// stderr, evaluateCommandLine encodes it into the verdict JSON.
	damageRefusals := damagedRefusals(store.Damaged(), pm.Ecosystem(), installs)
	if len(damageRefusals) > 0 {
		for _, d := range damageRefusals {
			logger.Error().
				Str("source", d.SourceID).
				Str("ecosystem", string(d.Ecosystem)).
				Str("reason", d.Reason).
				Int("got", d.Got).
				Int("baseline", d.Baseline).
				Msg("intel source damaged — refusing to gate")
		}
	}

	expander := newCompoundExpander()
	policy := gate.DefaultPolicy()
	policy.ManifestExpander = expander

	return gateInputs{
		store:          store,
		policy:         policy,
		expander:       expander,
		installs:       installs,
		manifestRefs:   manifestRefs,
		preflight:      preflight,
		hasPreflight:   hasPreflight,
		damageRefusals: damageRefusals,
	}, true
}

// codeForOutcome maps a gate outcome to the CLI exit-code contract shared
// by the enforcement and verdict paths.
func codeForOutcome(outcome gate.Outcome) int {
	switch outcome {
	case gate.OutcomeAllow, gate.OutcomePassThrough:
		return exitOK
	case gate.OutcomeRefuse:
		return exitRefused
	default:
		return exitInternal
	}
}

// verdictReason renders a one-line human summary of a gate decision.
func verdictReason(d *gate.Decision) string {
	switch d.Outcome {
	case gate.OutcomeAllow:
		return "no package matched malware intel"
	case gate.OutcomePassThrough:
		return "command is not an install; passed through"
	case gate.OutcomeRefuse:
		flagged := d.Flagged()
		if len(flagged) == 0 {
			return "refused"
		}
		f := flagged[0]
		src := ""
		if len(f.Reports) > 0 {
			src = f.Reports[0].SourceID
		}
		return fmt.Sprintf("package intelligence flagged %s (%s)", f.Ref.Name, src)
	case gate.OutcomeAbort:
		return "gate could not reach a confident verdict; aborted fail-closed"
	default:
		return ""
	}
}

// toInstallVerdict converts a gate-layer intel.Verdict into its JSON shape.
func toInstallVerdict(v intel.Verdict) installVerdict {
	iv := installVerdict{
		Ecosystem: string(v.Ref.Ecosystem),
		Name:      v.Ref.Name,
		Version:   v.Ref.Version,
		Flagged:   v.Flagged(),
		Sources:   v.Sources(),
	}
	for _, r := range v.Reports {
		reason := r.Reason
		if reason == "" {
			reason = "flagged"
		}
		if r.AdvisoryID != "" {
			reason = r.AdvisoryID + ": " + reason
		}
		iv.Reasons = append(iv.Reasons, reason)
	}
	return iv
}

// writeVerdictText renders a commandVerdict in the same human shape the
// enforcement path's printers use, for interactive use.
func writeVerdictText(w io.Writer, v commandVerdict) {
	fmt.Fprintf(w, "veto: %s — %s %s\n", v.Decision, v.PM, strings.Join(v.Args, " "))
	if v.Reason != "" {
		fmt.Fprintf(w, "  reason: %s\n", v.Reason)
	}
	for _, ins := range v.Installs {
		if !ins.Flagged {
			continue
		}
		version := ins.Version
		if version == "" {
			version = "<any>"
		}
		fmt.Fprintf(w, "  - %s@%s (ecosystem: %s)\n", ins.Name, version, ins.Ecosystem)
		for i, src := range ins.Sources {
			reason := "flagged"
			if i < len(ins.Reasons) {
				reason = ins.Reasons[i]
			}
			fmt.Fprintf(w, "      [%s] %s\n", src, reason)
		}
	}
	for _, e := range v.Errors {
		fmt.Fprintf(w, "  error: %s\n", e)
	}
}
