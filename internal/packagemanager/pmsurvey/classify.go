package pmsurvey

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	utilerrors "github.com/brynbellomy/go-utils/errors"
)

// Classification is the verdict on one wrap-candidate path.
type Classification int

const (
	// ClassReal: path is a regular file (or hard link). Not a symlink at
	// all. The caller's job is "wrap this" (if writable) or "leave it"
	// (if not).
	ClassReal Classification = iota

	// ClassOursByPath: path is a symlink whose target's absolute path
	// equals the veto binary's path. Cheapest positive identification;
	// no hashing required.
	ClassOursByPath

	// ClassOursByHash: path is a symlink whose target's SHA-256 matches
	// the veto binary's. The path is different from veto's resolved
	// path (e.g. veto moved, or the symlink chains through aliases)
	// but the content is provably ours.
	ClassOursByHash

	// ClassForeignWrapper: path is a symlink to a file that exists, is
	// executable, and whose SHA-256 does NOT match the veto binary AND
	// whose target does NOT live in a known package-manager install
	// dir. Almost always means a previous version of veto or a
	// different tool (the "bouncer" case) wrapped this path and was
	// later uninstalled or replaced. Reserved for genuinely
	// user-installed custom wrappers; --force still gates overwriting
	// them.
	ClassForeignWrapper

	// ClassBrokenSymlink: path is a symlink whose target does not
	// exist. The user can't run it, and install-wrappers can't honestly
	// claim to wrap an already-wrapped binary because there is no
	// wrapped binary.
	ClassBrokenSymlink

	// ClassPMLayoutSymlink: path is a symlink whose target's hash is
	// not veto's BUT whose target lives in a known package-manager
	// install dir (Homebrew Cellar / opt, mise/asdf/pyenv/nvm install
	// tree, rustup toolchains, npm node_modules, uv canonical store,
	// ~/.bun/bin, ~/.cargo/bin).
	//
	// This is the canonical layout for Homebrew, npm-cli.js, rustup,
	// mise, etc. — bin/<tool> is a symlink into the package's install
	// tree. install-wrappers MUST wrap these by default (they are the
	// 95% case on macOS dev machines); doctor MUST NOT treat them as
	// foreign wrappers (a SECURITY-grade FAIL row for a routine
	// canonical install is alarming and wrong). The wrap path is
	// identical to ClassReal — applyWrapper's rename + symlink works
	// uniformly on a symlink whose target is a regular file.
	ClassPMLayoutSymlink
)

// String returns a stable short name for use in logs and test diags.
func (c Classification) String() string {
	switch c {
	case ClassReal:
		return "real"
	case ClassOursByPath:
		return "ours-by-path"
	case ClassOursByHash:
		return "ours-by-hash"
	case ClassForeignWrapper:
		return "foreign-wrapper"
	case ClassBrokenSymlink:
		return "broken-symlink"
	case ClassPMLayoutSymlink:
		return "pm-layout-symlink"
	}
	return "unknown"
}

// VetoIdentity describes the running veto binary well enough to
// classify wrap candidates. Use VetoIdentityFor to build one once at
// start of a command, then pass to ClassifySymlink for every path.
type VetoIdentity struct {
	// Path is the absolute, fully-resolved path to the veto binary on
	// this host (filepath.EvalSymlinks applied).
	Path string

	hashOnce sync.Once
	hash     [32]byte
	hashErr  error
}

// Hash returns the SHA-256 of the veto binary's contents, computing it
// lazily on first call. Errors propagate; subsequent calls return the
// cached error so the first call's failure is the only one surfaced.
func (v *VetoIdentity) Hash() ([32]byte, error) {
	v.hashOnce.Do(func() {
		v.hash, v.hashErr = hashFile(v.Path)
	})
	return v.hash, v.hashErr
}

// VetoIdentityFor builds a VetoIdentity for the binary at vetoPath.
// vetoPath should be the result of resolveVetoBinary (or equivalent
// caller-side logic); this function calls EvalSymlinks once so the
// stored Path is the physical file every later comparison uses.
func VetoIdentityFor(vetoPath string) (*VetoIdentity, error) {
	if vetoPath == "" {
		return nil, errors.New("pmsurvey: empty vetoPath")
	}
	resolved, err := filepath.EvalSymlinks(vetoPath)
	if err != nil {
		return nil, utilerrors.With(err, "pmsurvey: resolve veto binary").Set("path", vetoPath)
	}
	return &VetoIdentity{Path: resolved}, nil
}

// ClassifySymlink classifies the file at path against the given veto
// identity. The returned target is the resolved symlink target when
// path is a symlink (or "" for ClassReal), so callers can include it
// in diagnostic output.
//
// On any non-classification I/O error (Lstat failure on path that
// supposedly exists, hash read failure on a target that EvalSymlinks
// resolved), the error is returned and Classification is undefined.
// "Target doesn't exist" is NOT an error — it's ClassBrokenSymlink.
func ClassifySymlink(path string, veto *VetoIdentity) (Classification, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, "", utilerrors.With(err, "pmsurvey: lstat candidate").Set("path", path)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return ClassReal, "", nil
	}
	target, readErr := os.Readlink(path)
	if readErr != nil {
		return 0, "", utilerrors.With(readErr, "pmsurvey: readlink").Set("path", path)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	target = filepath.Clean(target)

	// Try to resolve through any intermediate symlinks. EvalSymlinks
	// returns an error for a broken chain — that's the broken case.
	resolved, evalErr := filepath.EvalSymlinks(path)
	if evalErr != nil {
		if errors.Is(evalErr, os.ErrNotExist) {
			return ClassBrokenSymlink, target, nil
		}
		// Lstat-style "not exist" can come back as a *PathError whose
		// Unwrap returns syscall.ENOENT; the IsNotExist helper covers
		// that without the caller having to think about it.
		if os.IsNotExist(evalErr) {
			return ClassBrokenSymlink, target, nil
		}
		return 0, target, utilerrors.With(evalErr, "pmsurvey: evalsymlinks").Set("path", path)
	}

	// Fast path: the resolved target IS the veto binary by path. No
	// need to hash anything.
	if resolved == veto.Path {
		return ClassOursByPath, resolved, nil
	}

	// Slow path: hash the target and compare. A match proves the
	// symlink leads to a binary byte-identical to veto's, even if a
	// path identity check would say otherwise (veto moved, hard link,
	// different physical path).
	resolvedHash, err := hashFile(resolved)
	if err != nil {
		return 0, resolved, utilerrors.With(err, "pmsurvey: hash candidate target").Set("path", resolved)
	}
	vetoHash, err := veto.Hash()
	if err != nil {
		return 0, resolved, utilerrors.With(err, "pmsurvey: hash veto binary")
	}
	if resolvedHash == vetoHash {
		return ClassOursByHash, resolved, nil
	}

	// The target is not veto. Decide whether it's a canonical
	// package-manager install (wrappable by default) or a genuinely
	// foreign wrapper (--force gated). The check looks at the resolved
	// physical path so symlink chains that route through Homebrew /
	// opt / mise / etc. resolve to their canonical Cellar / install-tree
	// home are recognised. This is the load-bearing safety boundary:
	// only paths inside a known package-manager install dir get the
	// permissive verdict; everything else stays ClassForeignWrapper so
	// the --force gate remains in place for actual user-planted
	// wrappers.
	if isPMLayoutInstall(resolved) {
		return ClassPMLayoutSymlink, resolved, nil
	}
	return ClassForeignWrapper, resolved, nil
}

// isPMLayoutInstall reports whether resolved (an absolute, EvalSymlinks
// path) sits inside a known package-manager install tree. The list is
// curated; expanding it is the correct way to broaden the "wrappable by
// default" set, and the security boundary is exactly this list — any
// path NOT covered here keeps the ClassForeignWrapper verdict and the
// --force gate.
//
// Layouts covered:
//   - Homebrew Apple Silicon: /opt/homebrew/Cellar/*, /opt/homebrew/opt/*,
//     /opt/homebrew/lib/node_modules/* (npm-cli.js etc.)
//   - Homebrew Intel: /usr/local/Cellar/*, /usr/local/opt/*,
//     /usr/local/lib/node_modules/*
//   - mise: ~/.local/share/mise/installs/*
//   - asdf: ~/.asdf/installs/*
//   - pyenv: ~/.pyenv/versions/*
//   - nvm: ~/.nvm/versions/node/*
//   - uv: ~/.local/share/uv/python/*
//   - rustup: ~/.rustup/toolchains/*
//   - bun store: ~/.bun/bin (binary lives in the dir, but the bun
//     installer can also place symlinks here)
//   - cargo: ~/.cargo/bin
//
// Substring-based to cover macOS and Linux uniformly (Linux Homebrew
// lives under /home/linuxbrew/.linuxbrew, which contains
// "/Cellar/" and "/opt/" subpaths matched here).
func isPMLayoutInstall(resolved string) bool {
	clean := filepath.Clean(resolved)
	// Apple Silicon Homebrew + Linux Homebrew share these subpath markers.
	if strings.Contains(clean, "/homebrew/Cellar/") ||
		strings.Contains(clean, "/homebrew/opt/") ||
		strings.Contains(clean, "/homebrew/lib/node_modules/") ||
		strings.Contains(clean, "/.linuxbrew/Cellar/") ||
		strings.Contains(clean, "/.linuxbrew/opt/") ||
		strings.Contains(clean, "/.linuxbrew/lib/node_modules/") {
		return true
	}
	// Homebrew Intel.
	if strings.HasPrefix(clean, "/usr/local/Cellar/") ||
		strings.HasPrefix(clean, "/usr/local/opt/") ||
		strings.HasPrefix(clean, "/usr/local/lib/node_modules/") {
		return true
	}
	// Version managers, store paths.
	switch {
	case strings.Contains(clean, "/.local/share/mise/installs/"),
		strings.Contains(clean, "/.asdf/installs/"),
		strings.Contains(clean, "/.pyenv/versions/"),
		strings.Contains(clean, "/.nvm/versions/node/"),
		strings.Contains(clean, "/.local/share/uv/python/"),
		strings.Contains(clean, "/.rustup/toolchains/"):
		return true
	}
	// User-local PM bin dirs that double as install trees (bun keeps
	// the actual binary here; cargo's `cargo install` lands binaries
	// here too).
	if home, err := os.UserHomeDir(); err == nil {
		if strings.HasPrefix(clean, filepath.Join(home, ".bun", "bin")+string(filepath.Separator)) ||
			clean == filepath.Join(home, ".bun", "bin") {
			return true
		}
		if strings.HasPrefix(clean, filepath.Join(home, ".cargo", "bin")+string(filepath.Separator)) ||
			clean == filepath.Join(home, ".cargo", "bin") {
			return true
		}
	}
	return false
}

// hashFile returns the SHA-256 of the file's contents. Used both for
// the veto binary and for symlink targets.
func hashFile(path string) ([32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
