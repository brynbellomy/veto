package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallTargetDir(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "project")
	absoluteTarget := filepath.Join(t.TempDir(), "target")

	cases := []struct {
		name string
		pm   string
		args []string
		want string
	}{
		{
			name: "npm prefix space form",
			pm:   "npm",
			args: []string{"install", "--prefix", absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "npm prefix equals form",
			pm:   "npm",
			args: []string{"install", "--prefix=" + absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "pnpm short C space form",
			pm:   "pnpm",
			args: []string{"install", "-C", absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "pnpm short C equals form",
			pm:   "pnpm",
			args: []string{"install", "-C=" + absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "pnpm dir equals form",
			pm:   "pnpm",
			args: []string{"install", "--dir=" + absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "pnpm prefix relative form",
			pm:   "pnpm",
			args: []string{"install", "--prefix", "workspace/pkg", "lodash"},
			want: filepath.Join(cwd, "workspace", "pkg"),
		},
		{
			name: "yarn cwd space form",
			pm:   "yarn",
			args: []string{"add", "--cwd", absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "yarn cwd equals form",
			pm:   "yarn",
			args: []string{"add", "--cwd=" + absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "bun cwd space form",
			pm:   "bun",
			args: []string{"add", "--cwd", absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "bun cwd equals form",
			pm:   "bun",
			args: []string{"add", "--cwd=" + absoluteTarget, "lodash"},
			want: absoluteTarget,
		},
		{
			name: "absent target flag returns cwd",
			pm:   "npm",
			args: []string{"install", "lodash"},
			want: cwd,
		},
		{
			name: "unknown pm returns cwd",
			pm:   "npx",
			args: []string{"--prefix", absoluteTarget, "lodash"},
			want: cwd,
		},
		{
			name: "missing value returns cwd",
			pm:   "npm",
			args: []string{"install", "--prefix"},
			want: cwd,
		},
		{
			name: "parser stops at option terminator",
			pm:   "npm",
			args: []string{"install", "--", "--prefix", absoluteTarget},
			want: cwd,
		},
		{
			name: "last matching flag wins",
			pm:   "npm",
			args: []string{"install", "--prefix", filepath.Join(t.TempDir(), "first"), "--prefix", absoluteTarget},
			want: absoluteTarget,
		},

		// ── Python-family: pip ────────────────────────────────────────────
		{
			name: "pip --target space form",
			pm:   "pip",
			args: []string{"install", "--target", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip --target equals form",
			pm:   "pip",
			args: []string{"install", "--target=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip -t short form",
			pm:   "pip",
			args: []string{"install", "-t", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip -t equals form",
			pm:   "pip",
			args: []string{"install", "-t=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip --target relative form",
			pm:   "pip",
			args: []string{"install", "--target", "vendor", "requests"},
			want: filepath.Join(cwd, "vendor"),
		},
		{
			name: "pip --prefix space form",
			pm:   "pip",
			args: []string{"install", "--prefix", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip --prefix equals form",
			pm:   "pip",
			args: []string{"install", "--prefix=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip --root space form",
			pm:   "pip",
			args: []string{"install", "--root", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip --root equals form",
			pm:   "pip",
			args: []string{"install", "--root=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip no target flag returns cwd",
			pm:   "pip",
			args: []string{"install", "requests"},
			want: cwd,
		},
		{
			name: "pip3 --target space form",
			pm:   "pip3",
			args: []string{"install", "--target", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip3 -t equals form",
			pm:   "pip3",
			args: []string{"install", "-t=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "pip3 no target flag returns cwd",
			pm:   "pip3",
			args: []string{"install", "requests"},
			want: cwd,
		},

		// ── Python-family: uv pip install ────────────────────────────────
		{
			name: "uv --target space form",
			pm:   "uv",
			args: []string{"pip", "install", "--target", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "uv --target equals form",
			pm:   "uv",
			args: []string{"pip", "install", "--target=" + absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "uv -t short form",
			pm:   "uv",
			args: []string{"pip", "install", "-t", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "uv --prefix space form",
			pm:   "uv",
			args: []string{"pip", "install", "--prefix", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "uv --root space form",
			pm:   "uv",
			args: []string{"pip", "install", "--root", absoluteTarget, "requests"},
			want: absoluteTarget,
		},
		{
			name: "uv no target flag returns cwd",
			pm:   "uv",
			args: []string{"pip", "install", "requests"},
			want: cwd,
		},
		{
			name: "uv last matching flag wins",
			pm:   "uv",
			args: []string{"pip", "install", "--target", filepath.Join(t.TempDir(), "first"), "--target", absoluteTarget, "requests"},
			want: absoluteTarget,
		},

		// ── Python-family: poetry / pdm — no supported target-dir flags ──
		// These PMs manage installs into their own venvs; --directory/
		// --project select the project root, not the install destination.
		// installTargetDir correctly returns cwd for them.
		{
			name: "poetry falls through to cwd",
			pm:   "poetry",
			args: []string{"add", "--directory", absoluteTarget, "requests"},
			want: cwd,
		},
		{
			name: "pdm falls through to cwd",
			pm:   "pdm",
			args: []string{"add", "--project", absoluteTarget, "requests"},
			want: cwd,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, installTargetDir(tc.pm, tc.args, cwd))
		})
	}
}
