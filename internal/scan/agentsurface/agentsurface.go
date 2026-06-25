// Package agentsurface audits agent hooks, MCP configs, and launchd surfaces.
package agentsurface

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/scan"
)

// Options configures an agent-surface Scanner.
type Options struct {
	Home         string
	ProjectRoots []string
}

// Scanner audits agent configuration and persistence surfaces.
type Scanner struct {
	home         string
	projectRoots []string
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds an agent-surface scanner.
func New(opts Options) *Scanner {
	return &Scanner{home: opts.Home, projectRoots: append([]string{}, opts.ProjectRoots...)}
}

// Scan implements scan.Scanner.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	for _, target := range s.targets() {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		info, err := os.Stat(target.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.Errors = append(result.Errors, errors.With(err, "stat agent surface path").Set("path", target.path))
			continue
		}
		if info.IsDir() {
			if err := filepath.WalkDir(target.path, func(path string, entry fs.DirEntry, walkErr error) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if walkErr != nil {
					result.Errors = append(result.Errors, errors.With(walkErr, "walk agent surface path").Set("path", path))
					if entry != nil && entry.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if entry.IsDir() {
					if shouldPruneDir(entry.Name()) {
						return fs.SkipDir
					}
					return nil
				}
				if !target.accept(path) {
					return nil
				}
				findings, err := scanFile(path, target.owner)
				result.FilesScanned++
				result.Findings = append(result.Findings, findings...)
				if err != nil {
					result.Errors = append(result.Errors, err)
				}
				return nil
			}); err != nil {
				result.Errors = append(result.Errors, errors.With(err, "walk agent surface root").Set("path", target.path))
			}
			continue
		}
		findings, err := scanFile(target.path, target.owner)
		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
	}
	result.Findings = append(result.Findings, s.scanLaunchdDisabled(ctx)...)
	result.Findings = append(result.Findings, s.scanHadesHostArtifacts()...)
	result.Findings = append(result.Findings, s.scanHadesTmpLocks()...)
	result.Findings = append(result.Findings, s.scanHadesPersistence(ctx)...)
	result.Findings = append(result.Findings, s.scanCustomizePresence(ctx)...)
	return result
}

type target struct {
	owner  string
	path   string
	accept func(string) bool
}

func (s *Scanner) targets() []target {
	acceptConfig := func(path string) bool {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json", ".toml", ".yaml", ".yml", ".js", ".ts", ".sh", ".mdc", ".txt", ".plist":
			return true
		default:
			return filepath.Base(path) == "command.txt"
		}
	}
	var out []target
	if s.home != "" {
		out = append(out,
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "settings.json"), accept: acceptConfig},
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "settings.local.json"), accept: acceptConfig},
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "hooks"), accept: acceptConfig},
			target{owner: "codex", path: filepath.Join(s.home, ".codex", "config.toml"), accept: acceptConfig},
			target{owner: "cursor", path: filepath.Join(s.home, ".cursor", "mcp.json"), accept: acceptConfig},
			target{owner: "sirene", path: filepath.Join(s.home, ".sirene"), accept: acceptConfig},
			target{owner: "launchd", path: filepath.Join(s.home, "Library", "LaunchAgents"), accept: acceptConfig},
		)
		if runtime.GOOS == "darwin" && s.home == currentUserHome() {
			out = append(out, target{owner: "launchd", path: "/Library/LaunchAgents", accept: acceptConfig})
		}
	}
	for _, root := range s.projectRoots {
		if root == "" {
			continue
		}
		out = append(out,
			target{owner: "claude", path: filepath.Join(root, ".claude"), accept: acceptConfig},
			target{owner: "cursor", path: filepath.Join(root, ".cursor"), accept: acceptConfig},
			target{owner: "sirene", path: filepath.Join(root, ".sirene"), accept: acceptConfig},
		)
	}
	return out
}

var (
	// hadesAttackerNamingRe matches the Hades / Shai-Hulud worm's
	// attacker-controlled GitHub repo / directory naming.
	hadesAttackerNamingRe = regexp.MustCompile(`(?i)\b(?:Shai-Hulud|stygian-cerberus[-_][A-Za-z0-9._-]+|tartarean-charon[-_][A-Za-z0-9._-]+)\b`)

	// hadesWorkflowExfilRe matches a GitHub Actions workflow that posts to
	// a webhook with environment / secret material in its body — the worm's
	// exfiltration shape. Heuristic, not a parser.
	//
	// The (?s) flag makes . match newlines, which is required for the first
	// alternative: real exfil workflows frequently split curl, -X POST, the
	// target URL, and ${{ secrets.X }} across multiple lines inside a YAML
	// run: | block, so [^\n]* would silently miss them. We use .*? (non-greedy)
	// to avoid catastrophic backtracking on large YAML files while still
	// spanning arbitrary line breaks within a single run block.
	hadesWorkflowExfilRe = regexp.MustCompile(`(?is)curl\s+.*?-X\s*POST.*?\$\{\{\s*secrets\.|toJson\(\s*secrets\s*\)|webhook\.site|webhooks?\.[A-Za-z0-9.-]+/`)
)

// scanHadesPersistence emits findings for local GitHub persistence under each
// project root: workflow yml files matching the worm's exfil shape, and
// directories whose name / remote URL matches attacker naming.
func (s *Scanner) scanHadesPersistence(ctx context.Context) []scan.Finding {
	var out []scan.Finding
	for _, root := range s.projectRoots {
		if err := ctx.Err(); err != nil {
			return out
		}
		if root == "" {
			continue
		}
		// Directory name match — cheap; check first.
		base := filepath.Base(root)
		if hadesAttackerNamingRe.MatchString(base) {
			out = append(out, finding("hades", root, "attacker-naming", scan.SeverityHigh,
				"Project directory name matches Hades / Shai-Hulud attacker naming",
				"Confirm this clone is intentional. Attacker repos with this naming have been observed staging the Hades PyPI worm.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "dir", Value: base},
			))
		}
		// .git/config remote URL match.
		gitCfg, err := os.ReadFile(filepath.Join(root, ".git", "config"))
		if err == nil && hadesAttackerNamingRe.MatchString(string(gitCfg)) {
			out = append(out, finding("hades", filepath.Join(root, ".git", "config"), "attacker-remote", scan.SeverityHigh,
				"Git remote URL matches Hades / Shai-Hulud attacker naming",
				"Inspect the configured remote; if it is not yours, treat any pushed branches as exfiltrated and remove the remote.",
				scan.Evidence{Label: "owner", Value: "hades"},
			))
		}
		// .github/workflows/*.yml exfil-shape match.
		wfDir := filepath.Join(root, ".github", "workflows")
		entries, err := os.ReadDir(wfDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			path := filepath.Join(wfDir, name)
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if !hadesWorkflowExfilRe.Match(content) {
				continue
			}
			out = append(out, finding("hades", path, "workflow-exfil", scan.SeverityHigh,
				"GitHub Actions workflow posts secrets to an external webhook (Hades exfil shape)",
				"Inspect the workflow; if it is not yours, delete it, rotate every secret it can read, and audit recent workflow runs.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "snippet", Value: snippet(content, hadesWorkflowExfilRe, 200)},
			))
		}
	}
	return out
}

// snippet returns a single-line, length-capped excerpt centered on the first
// match of re inside content, for display in the finding's evidence.
func snippet(content []byte, re *regexp.Regexp, limit int) string {
	loc := re.FindIndex(content)
	if loc == nil {
		return ""
	}
	start := max(loc[0]-limit/4, 0)
	end := min(start+limit, len(content))
	frag := strings.Join(strings.Fields(string(content[start:end])), " ")
	if len(frag) > limit {
		frag = frag[:limit] + "…"
	}
	return frag
}

// scanCustomizePresence walks each project root for `sitecustomize.py` or
// `usercustomize.py` files inside a `site-packages` directory and emits a
// medium presence finding. We never read or evaluate the body — these files
// legitimately do real work in some toolchains; their presence-in-site-packages
// is itself the structural signal.
func (s *Scanner) scanCustomizePresence(ctx context.Context) []scan.Finding {
	var out []scan.Finding
	for _, root := range s.projectRoots {
		if err := ctx.Err(); err != nil {
			return out
		}
		_ = filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				// Descend into venvs — that is where site-packages
				// lives — but skip purely-noisy trees.
				if shouldPruneDirForCustomize(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			name := entry.Name()
			if name != "sitecustomize.py" && name != "usercustomize.py" {
				return nil
			}
			// Only flag when the file sits in a site-packages directory.
			parent := filepath.Base(filepath.Dir(p))
			if parent != "site-packages" && parent != "dist-packages" {
				return nil
			}
			out = append(out, finding("hades", p, "customize-presence", scan.SeverityMedium,
				"Python "+name+" present inside site-packages",
				"Confirm this customize hook is yours. site-packages-resident "+name+" runs at every interpreter startup; verify its body is not an exfil payload.",
				scan.Evidence{Label: "owner", Value: "hades"},
				scan.Evidence{Label: "kind", Value: name},
			))
			return nil
		})
	}
	return out
}

// hadesHostTargets returns probe paths for the on-host artifacts the Hades /
// Shai-Hulud PyPI worm drops. Presence of any of these is the signal; we
// stat-check rather than scan, so a missing file is the common case and
// returns silently.
func (s *Scanner) hadesHostTargets() []hadesProbe {
	var probes []hadesProbe
	probes = append(probes,
		hadesProbe{path: "/tmp/.bun_ran", reason: "Hades worm runtime marker"},
		hadesProbe{path: "/tmp/_index.js", reason: "Hades second-stage payload"},
		hadesProbe{path: "/tmp/bun", reason: "Bun runtime dropped in /tmp by Hades worm"},
	)
	if home := s.home; home != "" {
		probes = append(probes,
			hadesProbe{path: filepath.Join(home, ".cache", "bun"), reason: "Bun runtime dropped under ~/.cache by Hades worm"},
		)
	}
	return probes
}

type hadesProbe struct {
	path   string
	reason string
}

// scanHadesHostArtifacts emits a finding per Hades probe path present on the
// host. Stat-only; no file contents are read.
func (s *Scanner) scanHadesHostArtifacts() []scan.Finding {
	var out []scan.Finding
	for _, probe := range s.hadesHostTargets() {
		info, err := os.Stat(probe.path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Directory probes (e.g. ~/.cache/bun) only fire when present
			// AND non-empty — an empty dir is unlikely to be the worm.
			entries, _ := os.ReadDir(probe.path)
			if len(entries) == 0 {
				continue
			}
		}
		out = append(out, scan.Finding{
			ID:       fmt.Sprintf("agent-surface:hades-host:%s", probe.path),
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityHigh,
			Path:     probe.path,
			Title:    "Hades / Shai-Hulud .pth worm host artifact present",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "hades"},
				{Label: "reason", Value: probe.reason},
			},
			Remediation: "Verify the artifact is not from the Hades worm; if any Python interpreter recently ran in a poisoned venv, treat reachable credentials as compromised, remove the artifact, and run `veto scan` over all venvs.",
		})
	}
	return out
}

// scanHadesTmpLocks scans /tmp for tmp.*.lock files — the Hades single-
// instance lock shape. Stat-only; we list /tmp once and filter by name.
// /tmp on Linux+macOS is world-readable; on systems where it isn't, the
// listing error is non-fatal.
func (s *Scanner) scanHadesTmpLocks() []scan.Finding {
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return nil
	}
	var out []scan.Finding
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "tmp.") || !strings.HasSuffix(name, ".lock") {
			continue
		}
		path := filepath.Join("/tmp", name)
		out = append(out, scan.Finding{
			ID:       "agent-surface:hades-tmp-lock:" + path,
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityMedium,
			Path:     path,
			Title:    "/tmp/tmp.*.lock matches Hades worm single-instance lock shape",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "hades"},
				{Label: "lock", Value: name},
			},
			Remediation: "If no recent legitimate process explains this lock, investigate the owning process and treat as a possible Hades infection.",
		})
	}
	return out
}

func scanFile(path, owner string) ([]scan.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.With(err, "read agent surface file").Set("path", path)
	}
	text := string(data)
	redacted := redact(text)
	var findings []scan.Finding
	if strings.Contains(text, "SessionStart") {
		sev := scan.SeverityInfo
		title := "agent SessionStart hook configured"
		remediation := "Confirm this startup hook is expected."
		if suspiciousCommand(text) {
			sev = scan.SeverityMedium
			title = "agent SessionStart hook invokes suspicious command surface"
			remediation = "Remove the hook or rewrite it to use pinned, locally verified tooling."
		}
		findings = append(findings, finding(owner, path, "session-start", sev, title, remediation, evidenceSnippets(redacted)...))
	}
	if looksLikeMCPConfig(path, text) && fetchAndRunCommand(text) {
		findings = append(findings, finding(owner, path, "mcp-fetch-run", scan.SeverityMedium,
			"MCP server config uses fetch-and-run package command",
			"Pin and preinstall MCP server packages, or route the command through veto-controlled wrappers.",
			evidenceSnippets(redacted)...))
	}
	if owner == "launchd" && launchdSuspicious(text) {
		sev := scan.SeverityMedium
		if strings.Contains(text, "com.user.kitty-monitor") {
			sev = scan.SeverityLow
		}
		findings = append(findings, finding(owner, path, "launchd", sev,
			"launchd entry references suspicious command surface",
			"Inspect and unload the launch agent if it is not expected.",
			evidenceSnippets(redacted)...))
	}
	if owner == "sirene" && filepath.Base(path) == "command.txt" && suspiciousCommand(text) {
		findings = append(findings, finding(owner, path, "sirene-command", scan.SeverityLow,
			"Sirene CLI log contains package-manager command",
			"Review whether this command went through veto and whether it installed untrusted tooling.",
			evidenceSnippets(redacted)...))
	}
	return findings, nil
}

func (s *Scanner) scanLaunchdDisabled(ctx context.Context) []scan.Finding {
	if s.home == "" || runtime.GOOS != "darwin" {
		return nil
	}
	if s.home != currentUserHome() {
		return nil
	}
	uid := os.Getuid()
	cmd := exec.CommandContext(ctx, "launchctl", "print-disabled", "gui/"+strconv.Itoa(uid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []scan.Finding{{
			ID:       "agent-surface:launchd-disabled:unavailable",
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityInfo,
			Title:    "launchd disabled-label audit unavailable",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "launchd"},
				{Label: "error", Value: redact(strings.TrimSpace(string(out)) + " " + err.Error())},
			},
			Remediation: "Run `launchctl print-disabled gui/$UID` manually if launchd persistence is in scope.",
		}}
	}
	text := string(out)
	if !strings.Contains(text, "com.user.kitty-monitor") {
		return nil
	}
	return []scan.Finding{{
		ID:          "agent-surface:launchd-disabled:com.user.kitty-monitor",
		Surface:     scan.SurfaceAgentSurface,
		Severity:    scan.SeverityLow,
		Title:       "launchd disabled-label residue references com.user.kitty-monitor",
		Evidence:    []scan.Evidence{{Label: "owner", Value: "launchd"}, {Label: "label", Value: "com.user.kitty-monitor"}},
		Remediation: "Treat this as residual evidence unless a matching active plist or process is present.",
	}}
}

func finding(owner, path, kind string, severity scan.Severity, title, remediation string, evidence ...scan.Evidence) scan.Finding {
	return scan.Finding{
		ID:          fmt.Sprintf("agent-surface:%s:%s:%s", owner, kind, path),
		Surface:     scan.SurfaceAgentSurface,
		Severity:    severity,
		Path:        path,
		Title:       title,
		Evidence:    append([]scan.Evidence{{Label: "owner", Value: owner}}, evidence...),
		Remediation: remediation,
	}
}

func evidenceSnippets(text string) []scan.Evidence {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if suspiciousCommand(trimmed) || strings.Contains(trimmed, "SessionStart") || strings.Contains(trimmed, "com.user.kitty-monitor") {
			if len(trimmed) > 240 {
				trimmed = trimmed[:240] + "..."
			}
			return []scan.Evidence{{Label: "snippet", Value: trimmed}}
		}
	}
	return nil
}

func looksLikeMCPConfig(path, text string) bool {
	lowerPath := strings.ToLower(path)
	lowerText := strings.ToLower(text)
	return strings.Contains(lowerPath, "mcp") || strings.Contains(lowerText, "mcp") || strings.Contains(lowerText, "modelcontextprotocol")
}

func fetchAndRunCommand(text string) bool {
	lower := strings.ToLower(text)
	patterns := []string{"npx", "pnpx", "pnpm dlx", "bunx", "uvx", "pipx"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func suspiciousCommand(text string) bool {
	lower := strings.ToLower(text)
	patterns := []string{"npx", "pnx", "pnpm dlx", "bunx", "uvx", "pipx", " npm ", " pnpm ", " yarn ", " bun ", " pip ", "curl", "wget", "bash -c", "sh -c", "http://", "https://"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return packageCommandRE.MatchString(text)
}

func launchdSuspicious(text string) bool {
	if strings.Contains(text, "com.user.kitty-monitor") {
		return true
	}
	return suspiciousCommand(text) || strings.Contains(strings.ToLower(text), "/.cache/") || strings.Contains(strings.ToLower(text), "/_npx/")
}

var (
	packageCommandRE = regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(npm|pnpm|yarn|bun|pip|pip3|uv)(\s|["',\]])`)
	secretLine       = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key)(["'\s:=]+)([^"'\s,}]+)`)
)

func redact(text string) string {
	return secretLine.ReplaceAllString(text, "$1$2<redacted>")
}

func currentUserHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func shouldPruneDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "venv", "env":
		return true
	default:
		return false
	}
}

// shouldPruneDirForCustomize is the customize/site-packages walker's prune
// list. It deliberately does NOT skip `.venv` / `venv` / `env` (those are the
// trees where `sitecustomize.py` would live), only the noisy roots and caches.
func shouldPruneDirForCustomize(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache":
		return true
	default:
		return false
	}
}
