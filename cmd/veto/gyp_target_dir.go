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
	// Python family.
	//
	// pip/pip3: `--target`/`-t` installs packages flat into the given dir
	// (no lib/pythonX.Y/site-packages subtree), making it the most direct
	// analogue of npm's --prefix.  `--prefix` and `--root` redirect the
	// install through a Unix-style prefix tree (e.g.
	// <prefix>/lib/python3.x/site-packages/) or rebase all paths under a
	// sysroot — their actual landing dirs depend on the running Python
	// version and the platform's sysconfig layout, which we cannot
	// determine statically here.  We register all three so they are
	// recognised and not silently ignored; the value passed to the flag is
	// used as the scan root.  For --target that is exact; for --prefix /
	// --root it is an approximation (the scan root is the flag value, which
	// is a parent of the real site-packages dir — pth.Scan descends
	// recursively so it still finds worms in subdirectories).
	"pip": {
		"--target": {},
		"-t":       {},
		"--prefix": {},
		"--root":   {},
	},
	"pip3": {
		"--target": {},
		"-t":       {},
		"--prefix": {},
		"--root":   {},
	},
	// `uv pip install` shares pip's flag vocabulary.
	"uv": {
		"--target": {},
		"-t":       {},
		"--prefix": {},
		"--root":   {},
	},
	// poetry uses `--directory`/`-C` to change the project root before
	// running, not to redirect where packages land (poetry always installs
	// into the venv it manages).  There is no poetry flag that redirects
	// the install destination outside of its managed venv, so no entry is
	// added here.  The cwd-based scan still covers the common case where
	// poetry's venv lives under the project root.
	//
	// pdm uses `--project`/`-p` similarly — it selects which project to
	// operate on, not where packages land.  Omitted for the same reason.
	//
	// uvx/pipx run ephemeral installs into isolated envs that are not
	// meaningful to scan from the current working directory; they are not
	// in the Python-family detection path for the .pth preflight and are
	// intentionally omitted.
}

// installTargetDir returns the directory an install will populate.
// For npm-family package managers it resolves the workspace/prefix flags.
// For Python-family PMs it resolves --target / -t (exact install root),
// and --prefix / --root (approximate root — the scan descends into
// subdirectories so deeper site-packages are still reached).
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
