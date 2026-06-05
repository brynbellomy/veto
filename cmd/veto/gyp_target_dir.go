package main

import (
	"path/filepath"
	"strings"
)

var installTargetDirFlags = map[string]map[string]struct{}{
	"npm": {
		"--prefix": {},
	},
	"pnpm": {
		"-C":       {},
		"--dir":    {},
		"--prefix": {},
	},
	"yarn": {
		"--cwd": {},
	},
	"bun": {
		"--cwd": {},
	},
}

// installTargetDir returns the directory an npm-family install will populate.
func installTargetDir(pmName string, pmArgs []string, cwd string) string {
	flags := installTargetDirFlags[pmName]
	if len(flags) == 0 {
		return cwd
	}

	target := cwd
	for i := 0; i < len(pmArgs); i++ {
		arg := pmArgs[i]
		if arg == "--" {
			break
		}
		if flag, value, ok := splitFlagValue(arg); ok {
			if _, matched := flags[flag]; matched {
				target = resolveInstallTargetDir(value, cwd)
			}
			continue
		}
		if _, matched := flags[arg]; !matched {
			continue
		}
		if i+1 >= len(pmArgs) {
			continue
		}
		target = resolveInstallTargetDir(pmArgs[i+1], cwd)
		i++
	}
	return target
}

func splitFlagValue(arg string) (string, string, bool) {
	idx := strings.IndexByte(arg, '=')
	if idx <= 0 {
		return "", "", false
	}
	return arg[:idx], arg[idx+1:], true
}

func resolveInstallTargetDir(dir, cwd string) string {
	if dir == "" {
		return cwd
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return filepath.Clean(filepath.Join(cwd, dir))
}
