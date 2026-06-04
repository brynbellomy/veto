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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, installTargetDir(tc.pm, tc.args, cwd))
		})
	}
}
