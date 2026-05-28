package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// version, commit, buildDate are populated at link time via -ldflags
// "-X main.version=... -X main.commit=... -X main.buildDate=...".
// When unset (e.g. `go build` without ldflags), runVersion falls back
// to debug.ReadBuildInfo() so dev builds still report something useful.
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

// runVersion prints one line describing the running veto build.
// Format: "veto <version> (commit <short-sha>, built <RFC3339>, <go-version> <goos>/<goarch>)".
// Always returns exitOK.
func runVersion(w io.Writer) int {
	v, c, d := resolveVersionInfo()
	fmt.Fprintf(w, "veto %s (commit %s, built %s, %s %s/%s)\n",
		v, c, d, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return exitOK
}

// resolveVersionInfo returns (version, commit, buildDate) using ldflags
// when set; otherwise falls back to debug.ReadBuildInfo for dev builds.
// Pulled out for testability — version_test.go can swap the package vars
// and verify both the ldflag and the fallback paths.
func resolveVersionInfo() (string, string, string) {
	v, c, d := version, commit, buildDate
	if v == "" {
		v = "dev"
	}
	if c == "" || d == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" && len(s.Value) >= 7 {
						c = s.Value[:7]
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
			if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
		}
	}
	if c == "" {
		c = "untagged"
	}
	if d == "" {
		d = "unknown"
	}
	return v, c, d
}
