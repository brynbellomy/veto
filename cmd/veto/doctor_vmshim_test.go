package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/vmshim"
	"github.com/brynbellomy/veto/internal/vmshim/mise"
)

// TestCheckVersionManagerShims pins the doctor row for the 2026-09-15
// exec-loop incident: from a directory whose mise config pins a go the
// installed tree cannot serve, the first non-veto PATH entry is mise's
// shim, and doctor must WARN with mise's own remediation and name the
// binary veto runs instead. When mise resolves cleanly the row is a
// PASS naming the resolved toolchain; when no version-manager shim is
// met there is no row at all.
func TestCheckVersionManagerShims(t *testing.T) {
	tests := []struct {
		name       string
		miseScript string // "" = no mise shim on PATH at all
		fallbackGo bool   // plant a real `go` after the mise shim
		wantStatus status
		wantRows   int
		wantDetail string
		wantFix    []string
	}{
		{
			name: "mise cannot resolve: WARN with hint and fallback",
			miseScript: "echo 'mise ERROR No executable found for configured tool: go' >&2\n" +
				"echo 'Reinstall it with:' >&2\necho 'mise install --force go@1.25.1' >&2\nexit 1\n",
			fallbackGo: true,
			wantStatus: statusWarn,
			wantRows:   1,
			wantDetail: "mise shim ",
			wantFix:    []string{"mise install --force go@1.25.1", "veto now runs "},
		},
		{
			name: "mise cannot resolve and nothing else on PATH: WARN says the command fails",
			miseScript: "echo 'mise ERROR No executable found for configured tool: go' >&2\n" +
				"echo 'Reinstall it with:' >&2\necho 'mise install --force go@1.25.1' >&2\nexit 1\n",
			wantStatus: statusWarn,
			wantRows:   1,
			wantDetail: "mise shim ",
			wantFix:    []string{"mise install --force go@1.25.1", "cannot find real go"},
		},
		{
			name:       "mise resolves: PASS naming the toolchain",
			miseScript: "echo /toolchains/go-1.25.1/bin/go\n",
			wantStatus: statusPass,
			wantRows:   1,
			wantDetail: "resolves go to /toolchains/go-1.25.1/bin/go",
		},
		{
			name:       "no version-manager shim met: no row",
			fallbackGo: true,
			wantRows:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			shimDir := filepath.Join(home, ".local", "bin")
			require.NoError(t, os.MkdirAll(shimDir, 0o755))

			// veto's own shim: go -> the test binary (stands in for veto).
			self, err := os.Executable()
			require.NoError(t, err)
			require.NoError(t, os.Symlink(self, filepath.Join(shimDir, "go")))

			pathParts := []string{shimDir}
			vmShims := filepath.Join(home, "mise", "shims")
			if tt.miseScript != "" {
				miseBin := filepath.Join(home, "mise", "mise")
				require.NoError(t, os.MkdirAll(vmShims, 0o755))
				require.NoError(t, os.WriteFile(miseBin, []byte("#!/bin/sh\n[ \"$1\" = which ] || exit 9\n"+tt.miseScript), 0o755))
				require.NoError(t, os.Symlink(miseBin, filepath.Join(vmShims, "go")))
				pathParts = append(pathParts, vmShims)
			}
			fallback := filepath.Join(home, "fallback")
			if tt.fallbackGo {
				require.NoError(t, os.MkdirAll(fallback, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(fallback, "go"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
				pathParts = append(pathParts, fallback)
			}
			t.Setenv("PATH", strings.Join(pathParts, string(os.PathListSeparator)))

			reg := vmshim.Registry{mise.NewWithOptions(mise.Options{ShimsDir: vmShims})}
			results := checkVersionManagerShimsWith([]string{"go"}, home, func(string) bool { return false }, reg)
			require.Len(t, results, tt.wantRows, "rows: %+v", results)
			if tt.wantRows == 0 {
				return
			}
			r := results[0]
			require.Equal(t, "vm-shim:go", r.label)
			require.Equal(t, tt.wantStatus, r.status, "%+v", r)
			require.Contains(t, r.detail, tt.wantDetail)
			for _, want := range tt.wantFix {
				require.Contains(t, r.howToFix, want)
			}
			if tt.fallbackGo && tt.wantStatus == statusWarn {
				require.Contains(t, r.howToFix, filepath.Join(fallback, "go"))
			}
		})
	}
}
