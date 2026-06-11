package pmsurvey

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
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
	// executable, and whose SHA-256 does NOT match the veto binary.
	// Almost always means a previous version of veto or a different
	// tool (the "bouncer" case) wrapped this path and was later
	// uninstalled or replaced.
	ClassForeignWrapper

	// ClassBrokenSymlink: path is a symlink whose target does not
	// exist. The user can't run it, and install-wrappers can't honestly
	// claim to wrap an already-wrapped binary because there is no
	// wrapped binary.
	ClassBrokenSymlink
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
	return ClassForeignWrapper, resolved, nil
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
