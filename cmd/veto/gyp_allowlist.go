// gyp-allowlist: operator-acknowledged binding.gyp content hashes.
//
// The gyp preflight's critical tier intentionally pattern-matches payload
// shapes (command chaining, pipes into interpreters) that a handful of
// long-established native packages also use legitimately — sharp's
// pkg-config/readelf ABI probe and bufferutil's `cc -v | perl` version
// probe are the canonical examples. Without an acknowledgment mechanism,
// one such file anywhere in the scanned tree blocks EVERY npm-family
// install from that tree, and deleting it is whack-a-mole: the next
// install of the same package restores the same bytes.
//
// The allowlist pins CONTENT, not paths and not package names: an entry is
// the sha256 of the exact binding.gyp bytes the operator inspected. The
// same legitimate file is acknowledged once and covers every copy in every
// cache and node_modules tree, while a worm-tampered variant of the same
// package hashes differently and still refuses. A path or name allowlist
// would let a compromised release of an acknowledged package sail through;
// a hash allowlist cannot.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/scan"
)

// gypAllowlistFileName lives in the cache dir alongside the intel store and
// wrappers.json so a single VETO_CACHE_DIR override moves all of veto's
// mutable state together. Losing the file (cache wipe) fails closed: the
// findings simply block again until re-acknowledged.
const gypAllowlistFileName = "gyp-allowlist"

func gypAllowlistPath(cacheDir string) string {
	return filepath.Join(cacheDir, gypAllowlistFileName)
}

// loadGypAllowlist parses the allowlist into a set of lowercase hex digests.
// A missing file is an empty allowlist. Malformed lines are skipped with a
// warning rather than erroring: a corrupt allowlist degrades to "block
// again" (fail-closed), never to "allow more".
func loadGypAllowlist(logger zerolog.Logger, cacheDir string) map[string]struct{} {
	allowed := map[string]struct{}{}
	if cacheDir == "" {
		return allowed
	}
	f, err := os.Open(gypAllowlistPath(cacheDir))
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn().Err(err).Msg("gyp allowlist unreadable; treating as empty")
		}
		return allowed
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		digest := strings.ToLower(strings.Fields(line)[0])
		if !isSHA256Hex(digest) {
			logger.Warn().Str("line", line).Msg("gyp allowlist: skipping malformed entry")
			continue
		}
		allowed[digest] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		logger.Warn().Err(err).Msg("gyp allowlist: read error; using entries parsed so far")
	}
	return allowed
}

func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// filterAllowedGypFindings drops findings whose binding.gyp content hash the
// operator has acknowledged. The file is re-read and re-hashed at decision
// time: content that changed between scan and decision no longer matches and
// keeps blocking. Unreadable files also keep blocking — an allow decision
// must be provable against the bytes on disk, never assumed.
func filterAllowedGypFindings(logger zerolog.Logger, findings []scan.Finding, allowed map[string]struct{}) []scan.Finding {
	if len(allowed) == 0 || len(findings) == 0 {
		return findings
	}
	out := make([]scan.Finding, 0, len(findings))
	for _, f := range findings {
		digest, err := sha256File(f.Path)
		if err != nil {
			logger.Warn().Err(err).Str("path", f.Path).Msg("gyp allowlist: cannot hash finding; keeping it blocking")
			out = append(out, f)
			continue
		}
		if _, ok := allowed[digest]; ok {
			logger.Debug().Str("path", f.Path).Str("sha256", digest).Msg("gyp finding acknowledged by allowlist")
			continue
		}
		out = append(out, f)
	}
	return out
}

// runGypAllow implements `veto gyp-allow <binding.gyp>... | --list`.
// Each named file is hashed and appended to the allowlist with a provenance
// comment. The operator is expected to have INSPECTED the file first — the
// command exists to make an explicit, auditable acknowledgment, not a
// convenient bypass; it refuses anything not named binding.gyp.
func runGypAllow(logger zerolog.Logger, cfg config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: veto gyp-allow <path/to/binding.gyp>... | --list")
		return exitUsage
	}
	if args[0] == "--list" {
		data, err := os.ReadFile(gypAllowlistPath(cfg.CacheDir))
		if os.IsNotExist(err) {
			fmt.Println("veto gyp-allow: allowlist is empty.")
			return exitOK
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto gyp-allow: read allowlist: %v\n", err)
			return exitInternal
		}
		fmt.Print(string(data))
		return exitOK
	}

	allowed := loadGypAllowlist(logger, cfg.CacheDir)
	var added []string
	for _, arg := range args {
		abs, err := filepath.Abs(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto gyp-allow: resolve %q: %v\n", arg, err)
			return exitUsage
		}
		if filepath.Base(abs) != "binding.gyp" {
			fmt.Fprintf(os.Stderr, "veto gyp-allow: %q is not a binding.gyp — only binding.gyp findings are gated by this allowlist\n", arg)
			return exitUsage
		}
		digest, err := sha256File(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "veto gyp-allow: hash %q: %v\n", arg, err)
			return exitUsage
		}
		if _, ok := allowed[digest]; ok {
			fmt.Printf("  already acknowledged: %s (%s)\n", arg, digest[:12])
			continue
		}
		allowed[digest] = struct{}{}
		added = append(added, fmt.Sprintf("%s  # %s (added %s)", digest, abs, time.Now().UTC().Format("2006-01-02")))
		fmt.Printf("  acknowledged: %s (%s)\n", arg, digest[:12])
	}
	if len(added) == 0 {
		fmt.Println("veto gyp-allow: nothing to add.")
		return exitOK
	}
	sort.Strings(added)
	if err := appendGypAllowlistEntries(cfg.CacheDir, added); err != nil {
		fmt.Fprintf(os.Stderr, "veto gyp-allow: write allowlist: %v\n", err)
		return exitInternal
	}
	fmt.Printf("veto gyp-allow: %d entr%s added to %s\n", len(added), pluralYIes(len(added)), gypAllowlistPath(cfg.CacheDir))
	return exitOK
}

func pluralYIes(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// appendGypAllowlistEntries rewrites the allowlist atomically (read existing,
// append, tmp+rename) so a crash mid-write can't truncate prior entries.
func appendGypAllowlistEntries(cacheDir string, entries []string) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	path := gypAllowlistPath(cacheDir)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var b strings.Builder
	b.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		b.WriteByte('\n')
	}
	for _, e := range entries {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
