package fsutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel/sources/internal/fsutil"
)

func TestPayloadHashRoundTrip(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "feed.json")

	// No payload, no sidecar → mismatch (nothing to serve).
	require.Equal(t, fsutil.HashMismatch, fsutil.PayloadHashVerdict(payload))

	// Payload written without a sidecar → Unrecorded (grandfather clause
	// for pre-integrity caches).
	require.NoError(t, os.WriteFile(payload, []byte(`{"a":1}`), 0o600))
	require.Equal(t, fsutil.HashUnrecorded, fsutil.PayloadHashVerdict(payload))

	// Record → match.
	require.NoError(t, fsutil.RecordPayloadHash(payload, []byte(`{"a":1}`)))
	require.Equal(t, fsutil.HashMatch, fsutil.PayloadHashVerdict(payload))

	// Payload swapped (the gutted-manifest shape) → mismatch.
	require.NoError(t, os.WriteFile(payload, []byte(`{"b":2}`), 0o600))
	require.Equal(t, fsutil.HashMismatch, fsutil.PayloadHashVerdict(payload))

	// Truncated → mismatch.
	require.NoError(t, os.WriteFile(payload, []byte(`{"a":`), 0o600))
	require.Equal(t, fsutil.HashMismatch, fsutil.PayloadHashVerdict(payload))

	// Emptied → mismatch.
	require.NoError(t, os.WriteFile(payload, nil, 0o600))
	require.Equal(t, fsutil.HashMismatch, fsutil.PayloadHashVerdict(payload))

	// Restored → match again (the hash is over content, not mtime).
	require.NoError(t, os.WriteFile(payload, []byte(`{"a":1}`), 0o600))
	require.Equal(t, fsutil.HashMatch, fsutil.PayloadHashVerdict(payload))

	// Corrupt-but-readable sidecar → Mismatch (fail closed): the sidecar
	// does not authenticate the payload, so the payload must not be
	// treated as validated. A truly unreadable sidecar (I/O error) is the
	// Unrecorded case in PayloadHashVerdict.
	require.NoError(t, os.WriteFile(payload+".sha256", []byte("not-hex"), 0o600))
	require.Equal(t, fsutil.HashMismatch, fsutil.PayloadHashVerdict(payload))
}

func TestRemovePayloadHash(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "feed.json")
	require.NoError(t, os.WriteFile(payload, []byte("x"), 0o600))
	require.NoError(t, fsutil.RecordPayloadHash(payload, []byte("x")))
	require.FileExists(t, payload+".sha256")

	fsutil.RemovePayloadHash(payload)
	_, err := os.Stat(payload + ".sha256")
	require.True(t, os.IsNotExist(err))

	// Removing an absent sidecar is a no-op.
	fsutil.RemovePayloadHash(payload)
}
