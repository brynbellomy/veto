package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/brynbellomy/go-utils/errors"
)

// payloadHashSuffix is appended to a cached payload's filename to locate
// its content-hash sidecar: <payload>.sha256. The sidecar records the
// SHA-256 of the payload bytes as they were written, binding the etag
// (which upstream controls) to the exact bytes on disk (which anything
// with write access to the cache dir can damage). Without this binding a
// 304 revalidation validates only the *identity of the upstream
// representation* — it says nothing about whether the local copy of that
// representation still matches what we stored.
const payloadHashSuffix = ".sha256"

// HashVerdict is the result of comparing a cached payload against its
// recorded content hash. The Unrecorded case exists so caches written by
// older veto versions (before content binding) keep working: the first
// fresh fetch re-records the hash and every later load is protected.
type HashVerdict int

const (
	// HashMatch: the payload's bytes hash to the recorded value. The
	// payload is exactly what we stored — meaning what the last WRITER
	// stored, which is veto itself under the corruption-only model. It
	// is not proof of upstream authenticity; see the package comment.
	HashMatch HashVerdict = iota
	// HashMismatch: the payload's bytes differ from the recorded hash.
	// The file has been truncated, emptied, or replaced since it was
	// written. The payload MUST NOT be served as validated.
	HashMismatch
	// HashUnrecorded: no sidecar exists for this payload. Either it
	// was written by a veto older than content binding, or the
	// sidecar was lost. Post-FIX-1 the grandfather clause is
	// direction-bound: a network path (upstream reachable, HEAD or
	// conditional GET answered) REFUSES to adopt the unbound bytes
	// and rebinds from the wire — only bytes read off the wire in
	// this request ever get recorded. Serving without adopting is
	// reserved for the paths with no wire to fall back to: the
	// cache-only directive and a genuinely unreachable upstream.
	// Refusing everywhere instead would break every pre-existing
	// installation on upgrade, which is why the clause survives at
	// all.
	HashUnrecorded
)

// String makes HashVerdict log-friendly.
func (v HashVerdict) String() string {
	switch v {
	case HashMatch:
		return "match"
	case HashMismatch:
		return "mismatch"
	case HashUnrecorded:
		return "unrecorded"
	default:
		return "unknown"
	}
}

// RecordPayloadHash writes the SHA-256 of payload to <path>.sha256
// atomically. Call immediately after the payload itself is durably
// written, so the window where a payload exists without its hash is
// bounded by one write. A crash inside that window leaves a payload with
// no sidecar, which reads as HashUnrecorded and self-heals on the next
// fresh fetch — costing one extra download, never a false refusal.
func RecordPayloadHash(path string, payload []byte) error {
	sum := sha256.Sum256(payload)
	sidecar := path + payloadHashSuffix
	if err := WriteAtomic(sidecar, []byte(hex.EncodeToString(sum[:]))); err != nil {
		return errors.With(err, "write payload hash sidecar").Set("path", sidecar)
	}
	return nil
}

// PayloadHashVerdict reads the payload at path and compares its SHA-256
// against the recorded sidecar. A missing payload is a mismatch (nothing
// to serve); a missing sidecar is Unrecorded (grandfather clause); a hash
// that differs — including a readable-but-garbage sidecar — is a mismatch
// (fail closed: a sidecar that doesn't authenticate the payload must not
// validate it). Only a sidecar that cannot be read at all (I/O error) is
// Unrecorded, so a transient read failure can't brick an otherwise
// healthy cache; the next fresh fetch rewrites it.
func PayloadHashVerdict(path string) HashVerdict {
	if _, err := os.Stat(path); err != nil {
		return HashMismatch
	}
	recorded, err := os.ReadFile(path + payloadHashSuffix)
	if err != nil {
		return HashUnrecorded
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return HashMismatch
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) == string(recorded) {
		return HashMatch
	}
	return HashMismatch
}

// PayloadHashPath returns the sidecar path for a payload. Exposed for
// sources that need to drop the sidecar when they deliberately remove a
// payload (e.g. the parse-failure path), so a stale hash can never point
// at bytes that no longer exist.
func PayloadHashPath(path string) string {
	return path + payloadHashSuffix
}

// RemovePayloadHash removes the sidecar for path, ignoring absence. Pair
// with payload removal or deliberate invalidation so a dangling sidecar
// can't mark a future, different payload as damaged.
func RemovePayloadHash(path string) {
	_ = os.Remove(path + payloadHashSuffix)
}
