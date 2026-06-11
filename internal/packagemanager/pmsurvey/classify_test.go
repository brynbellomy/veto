package pmsurvey_test

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/pmsurvey"
)

func writeFileWithContent(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, content, mode))
}

func mustBuildVetoIdentity(t *testing.T, path string) *pmsurvey.VetoIdentity {
	t.Helper()
	id, err := pmsurvey.VetoIdentityFor(path)
	require.NoError(t, err)
	return id
}

func TestClassifySymlinkReal(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	npm := filepath.Join(dir, "npm")
	writeFileWithContent(t, npm, []byte("real npm"), 0o755)

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassReal, c, "got %s", c)
	require.Empty(t, target)
}

func TestClassifySymlinkOursByPath(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(veto, npm))

	// On macOS t.TempDir() lives under /var which is a symlink to /private/var;
	// EvalSymlinks in the classifier resolves both sides, so compare against
	// the resolved expected path.
	resolvedVeto, err := filepath.EvalSymlinks(veto)
	require.NoError(t, err)

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassOursByPath, c)
	require.Equal(t, resolvedVeto, target)
}

func TestClassifySymlinkOursByHash(t *testing.T) {
	dir := t.TempDir()
	content := []byte("veto bin v1")
	vetoA := filepath.Join(dir, "veto-a")
	vetoB := filepath.Join(dir, "veto-b")
	writeFileWithContent(t, vetoA, content, 0o755)
	writeFileWithContent(t, vetoB, content, 0o755) // same bytes, different path
	id := mustBuildVetoIdentity(t, vetoA)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(vetoB, npm))

	resolvedB, err := filepath.EvalSymlinks(vetoB)
	require.NoError(t, err)

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassOursByHash, c, "got %s; both vetos have identical bytes", c)
	require.Equal(t, resolvedB, target)
}

func TestClassifySymlinkForeignWrapper(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto bin v1"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	// A foreign wrapper binary with different bytes.
	bouncer := filepath.Join(dir, "bouncer")
	writeFileWithContent(t, bouncer, []byte("bouncer bin v2"), 0o755)

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(bouncer, npm))

	resolvedBouncer, err := filepath.EvalSymlinks(bouncer)
	require.NoError(t, err)

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassForeignWrapper, c)
	require.Equal(t, resolvedBouncer, target)
}

func TestClassifySymlinkBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	missing := filepath.Join(dir, "vanished")
	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(missing, npm)) // target doesn't exist

	c, target, err := pmsurvey.ClassifySymlink(npm, id)
	require.NoError(t, err)
	require.Equal(t, pmsurvey.ClassBrokenSymlink, c)
	require.Equal(t, missing, target,
		"broken-symlink classification must surface the intended target for diagnostics")
}

func TestClassifySymlinkLstatErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	writeFileWithContent(t, veto, []byte("veto"), 0o755)
	id := mustBuildVetoIdentity(t, veto)

	_, _, err := pmsurvey.ClassifySymlink(filepath.Join(dir, "does-not-exist"), id)
	require.Error(t, err, "missing path must surface as an error, not a classification")
}

func TestVetoIdentityHashCachesAfterFirstCall(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto")
	content := []byte("veto bin v1")
	writeFileWithContent(t, veto, content, 0o755)
	id := mustBuildVetoIdentity(t, veto)

	h1, err := id.Hash()
	require.NoError(t, err)

	// Mutate the file under it.
	writeFileWithContent(t, veto, []byte("changed"), 0o755)

	h2, err := id.Hash()
	require.NoError(t, err)
	require.Equal(t, h1, h2, "Hash() must cache the first computation; got fresh hash after file mutation")

	// And the cached hash must match what sha256 of the original content
	// would produce.
	expected := sha256.Sum256(content)
	require.Equal(t, expected, h1)
}
