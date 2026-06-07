// Package cache scans package-manager caches for existing exposure.
package cache

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/pelletier/go-toml/v2"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/ioc"
	"github.com/brynbellomy/veto/internal/scan"
)

// maxHashFileSize caps the bytes read when hashing a cache artifact for IOC
// lookup. Distributable archives are tens of MiB at most; a file larger than
// this ceiling is not a normal package tarball and is skipped rather than
// streamed in full, bounding the scan's worst-case I/O.
const maxHashFileSize = 256 << 20 // 256 MiB

type rootKind string

const (
	rootKindGeneric       rootKind = "generic"
	rootKindGo            rootKind = "go"
	rootKindCargoRegistry rootKind = "cargo-registry"
	rootKindCargoGit      rootKind = "cargo-git"
)

// Root is one package-manager cache root and the scanner semantics to use for
// metadata discovered beneath it.
type Root struct {
	Path string
	kind rootKind
}

// GenericRoot returns a cache root that uses package.json and Python metadata
// heuristics.
func GenericRoot(path string) Root { return Root{Path: path, kind: rootKindGeneric} }

// GoRoot returns a Go module cache root.
func GoRoot(path string) Root { return Root{Path: path, kind: rootKindGo} }

// CargoRegistryRoot returns a Cargo registry cache root.
func CargoRegistryRoot(path string) Root { return Root{Path: path, kind: rootKindCargoRegistry} }

// CargoGitRoot returns a Cargo git checkout cache root.
func CargoGitRoot(path string) Root { return Root{Path: path, kind: rootKindCargoGit} }

// Options configures a cache Scanner.
type Options struct {
	Roots       []string
	RootEntries []Root
	Store       intel.Store
	// IOCStore answers known-malicious file-hash lookups for cache artifacts.
	// Optional: when nil it defaults to ioc.NopStore{}, which reports zero
	// SHA256 indicators and so suppresses all file hashing.
	IOCStore ioc.Store
}

// Scanner scans package-manager cache roots for package metadata.
type Scanner struct {
	roots    []Root
	store    intel.Store
	iocStore ioc.Store
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a cache scanner. A nil IOCStore defaults to ioc.NopStore{} so
// call sites never nil-check it; a Nop (or empty) IOC store reports zero
// SHA256 indicators and the scanner opens no files for hashing.
func New(opts Options) *Scanner {
	roots := append([]Root{}, opts.RootEntries...)
	for _, root := range opts.Roots {
		roots = append(roots, GenericRoot(root))
	}
	iocStore := opts.IOCStore
	if iocStore == nil {
		iocStore = ioc.NopStore{}
	}
	return &Scanner{roots: roots, store: opts.Store, iocStore: iocStore}
}

// DefaultRoots returns known package-manager cache roots for the current user.
func DefaultRoots(home string) []string {
	entries := DefaultRootEntries(home)
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Path)
	}
	return out
}

// DefaultRootEntries returns known package-manager cache roots and their cache
// semantics for the current user.
func DefaultRootEntries(home string) []Root {
	if home == "" {
		return nil
	}
	out := []Root{}
	add := func(kind rootKind, paths ...string) {
		for _, path := range paths {
			if path == "" {
				continue
			}
			out = append(out, Root{Path: path, kind: kind})
		}
	}

	add(rootKindGeneric,
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".cache", "npm"),
		filepath.Join(home, "Library", "pnpm", "store"),
		filepath.Join(home, ".pnpm-store"),
		filepath.Join(home, ".local", "share", "pnpm", "store"),
		filepath.Join(home, ".bun", "install", "cache"),
		filepath.Join(home, "Library", "Caches", "pip"),
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, ".cache", "uv"),
		filepath.Join(home, "Library", "Caches", "pypoetry"),
		filepath.Join(home, ".cache", "pypoetry"),
	)
	add(rootKindGo, goModuleCacheRoots(home)...)
	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		cargoHome = filepath.Join(home, ".cargo")
	}
	add(rootKindCargoRegistry, filepath.Join(cargoHome, "registry"))
	add(rootKindCargoGit, filepath.Join(cargoHome, "git"))
	return out
}

// Scan implements scan.Scanner.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	if s.store == nil {
		result.Errors = append(result.Errors, errors.New("cache scanner requires store"))
		return result
	}
	// Decide ONCE whether to hash distributable archives. The IOC hash-scan is
	// cost-free when no SHA256 indicators are configured (the shipping
	// default): if the store reports zero, hashEnabled stays false and no
	// cache file is ever opened or hashed during the walk. Reading the count
	// once here keeps the hot path from re-querying the store per file.
	hashEnabled := s.iocStore.IndicatorCountByType(ioc.IndicatorSHA256) > 0
	seen := map[string]struct{}{}
	for _, rootEntry := range s.roots {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		if rootEntry.Path == "" {
			continue
		}
		cleanRoot := filepath.Clean(rootEntry.Path)
		if _, dup := seen[cleanRoot]; dup {
			continue
		}
		seen[cleanRoot] = struct{}{}
		info, err := os.Stat(cleanRoot)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.Errors = append(result.Errors, errors.With(err, "stat cache root").Set("root", cleanRoot))
			continue
		}
		if !info.IsDir() {
			continue
		}
		if err := filepath.WalkDir(cleanRoot, func(path string, dirEntry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk cache path").Set("path", path))
				if dirEntry != nil && dirEntry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if dirEntry.IsDir() {
				if shouldPruneDir(dirEntry.Name()) {
					return fs.SkipDir
				}
				findings, checked, scanned, skip, err := s.scanCacheDir(cleanRoot, rootEntry.kind, path)
				if scanned {
					result.FilesScanned++
				}
				result.PackagesChecked += checked
				result.Findings = append(result.Findings, findings...)
				if err != nil {
					result.Errors = append(result.Errors, err)
				}
				if skip {
					return fs.SkipDir
				}
				return nil
			}
			findings, checked, scanned, err := s.scanCacheFile(cleanRoot, rootEntry.kind, path)
			if scanned {
				result.FilesScanned++
			}
			result.PackagesChecked += checked
			result.Findings = append(result.Findings, findings...)
			if err != nil {
				result.Errors = append(result.Errors, err)
			}
			// IOC hash-scan: only for package distributable archives, and only
			// when SHA256 indicators are configured. hashEnabled is false in
			// the default (Nop / empty IOC store), so this branch opens no
			// files at all.
			if hashEnabled && isArchivePath(cleanRoot, rootEntry.kind, path) {
				hashFindings, hashed, hashErr := s.scanArchiveHash(cleanRoot, path)
				if hashed {
					result.FilesScanned++
				}
				result.Findings = append(result.Findings, hashFindings...)
				if hashErr != nil {
					result.Errors = append(result.Errors, hashErr)
				}
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk cache root").Set("root", cleanRoot))
		}
	}
	return result
}

func goModuleCacheRoots(home string) []string {
	out := []string{}
	if gomodcache := os.Getenv("GOMODCACHE"); gomodcache != "" {
		out = append(out, gomodcache)
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, dir := range filepath.SplitList(gopath) {
			if dir != "" {
				out = append(out, filepath.Join(dir, "pkg", "mod"))
			}
		}
	}
	out = append(out, filepath.Join(home, "go", "pkg", "mod"))
	return out
}

func (s *Scanner) scanCacheDir(root string, kind rootKind, path string) ([]scan.Finding, int, bool, bool, error) {
	switch kind {
	case rootKindGo:
		meta, ok := readGoModuleDir(root, path)
		if !ok {
			return nil, 0, false, false, nil
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, true, nil
	case rootKindCargoRegistry:
		meta, ok := readCargoRegistryDir(root, path)
		if !ok {
			return nil, 0, false, false, nil
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, true, nil
	default:
		return nil, 0, false, false, nil
	}
}

func (s *Scanner) scanCacheFile(root string, kind rootKind, path string) ([]scan.Finding, int, bool, error) {
	base := filepath.Base(path)
	switch {
	case base == "package.json":
		meta, err := readPackageJSON(path)
		if err != nil {
			return nil, 0, true, err
		}
		return s.findingsForMeta(root, path, meta, isNpxPath(path)), 1, true, nil
	case base == "METADATA" && strings.Contains(path, ".dist-info"+string(filepath.Separator)):
		meta, err := readPythonMetadata(path)
		if err != nil {
			return nil, 0, true, err
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, nil
	case kind == rootKindGo:
		meta, ok := readGoDownloadFile(root, path)
		if !ok {
			return nil, 0, false, nil
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, nil
	case kind == rootKindCargoRegistry:
		meta, ok := readCargoRegistryArchive(root, path)
		if !ok {
			return nil, 0, false, nil
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, nil
	case kind == rootKindCargoGit && base == "Cargo.toml":
		meta, err := readCargoManifest(path)
		if err != nil {
			return nil, 0, true, err
		}
		if meta.Name == "" {
			return nil, 0, true, nil
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, nil
	default:
		return nil, 0, false, nil
	}
}

type packageMeta struct {
	Ecosystem intel.Ecosystem
	Name      string
	Version   string
	PurgePath string
}

func readPackageJSON(path string) (packageMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return packageMeta{}, errors.With(err, "read cached package.json").Set("path", path)
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return packageMeta{}, errors.With(err, "parse cached package.json").Set("path", path)
	}
	return packageMeta{Ecosystem: intel.EcosystemNPM, Name: pkg.Name, Version: pkg.Version}, nil
}

func readPythonMetadata(path string) (packageMeta, error) {
	file, err := os.Open(path)
	if err != nil {
		return packageMeta{}, errors.With(err, "read cached Python metadata").Set("path", path)
	}
	defer file.Close()
	meta := packageMeta{Ecosystem: intel.EcosystemPyPI}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			meta.Name = strings.TrimSpace(value)
		case "version":
			meta.Version = strings.TrimSpace(value)
		}
		if meta.Name != "" && meta.Version != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return packageMeta{}, errors.With(err, "scan cached Python metadata").Set("path", path)
	}
	return meta, nil
}

func readGoModuleDir(root, path string) (packageMeta, bool) {
	if path == root {
		return packageMeta{}, false
	}
	base := filepath.Base(path)
	idx := strings.LastIndex(base, "@v")
	if idx <= 0 {
		return packageMeta{}, false
	}
	version := base[idx+1:]
	if !looksLikeVersion(version) {
		return packageMeta{}, false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageMeta{}, false
	}
	nameRel := filepath.Join(filepath.Dir(rel), base[:idx])
	name := filepath.ToSlash(nameRel)
	if name == "." || name == "" {
		return packageMeta{}, false
	}
	return packageMeta{Ecosystem: intel.EcosystemGo, Name: decodeGoEscapedPath(name), Version: version, PurgePath: path}, true
}

func readGoDownloadFile(root, path string) (packageMeta, bool) {
	ext := filepath.Ext(path)
	if ext != ".zip" && ext != ".mod" && ext != ".info" {
		return packageMeta{}, false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return packageMeta{}, false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 5 || parts[0] != "cache" || parts[1] != "download" {
		return packageMeta{}, false
	}
	versionFile := parts[len(parts)-1]
	version := strings.TrimSuffix(versionFile, ext)
	if parts[len(parts)-2] != "@v" || !looksLikeVersion(version) {
		return packageMeta{}, false
	}
	name := strings.Join(parts[2:len(parts)-2], "/")
	if name == "" {
		return packageMeta{}, false
	}
	return packageMeta{Ecosystem: intel.EcosystemGo, Name: decodeGoEscapedPath(name), Version: version, PurgePath: path}, true
}

func decodeGoEscapedPath(path string) string {
	var b strings.Builder
	b.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '!' && i+1 < len(path) {
			next := path[i+1]
			if next >= 'a' && next <= 'z' {
				b.WriteByte(next - 'a' + 'A')
				i++
				continue
			}
		}
		b.WriteByte(path[i])
	}
	return b.String()
}

func readCargoRegistryDir(root, path string) (packageMeta, bool) {
	parts, ok := relParts(root, path)
	if !ok || len(parts) < 3 || parts[0] != "src" {
		return packageMeta{}, false
	}
	name, version, ok := splitCargoCacheName(filepath.Base(path))
	if !ok {
		return packageMeta{}, false
	}
	return packageMeta{Ecosystem: intel.EcosystemCrates, Name: name, Version: version, PurgePath: path}, true
}

func readCargoRegistryArchive(root, path string) (packageMeta, bool) {
	if filepath.Ext(path) != ".crate" {
		return packageMeta{}, false
	}
	parts, ok := relParts(root, path)
	if !ok || len(parts) < 3 || parts[0] != "cache" {
		return packageMeta{}, false
	}
	name, version, ok := splitCargoCacheName(strings.TrimSuffix(filepath.Base(path), ".crate"))
	if !ok {
		return packageMeta{}, false
	}
	return packageMeta{Ecosystem: intel.EcosystemCrates, Name: name, Version: version, PurgePath: path}, true
}

func relParts(root, path string) ([]string, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, false
	}
	return strings.Split(filepath.ToSlash(rel), "/"), true
}

func readCargoManifest(path string) (packageMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return packageMeta{}, errors.With(err, "read cached Cargo.toml").Set("path", path)
	}
	var manifest struct {
		Package struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return packageMeta{}, errors.With(err, "parse cached Cargo.toml").Set("path", path)
	}
	return packageMeta{
		Ecosystem: intel.EcosystemCrates,
		Name:      manifest.Package.Name,
		Version:   manifest.Package.Version,
		PurgePath: filepath.Dir(path),
	}, nil
}

func splitCargoCacheName(base string) (string, string, bool) {
	idx := strings.LastIndex(base, "-")
	if idx <= 0 || idx == len(base)-1 {
		return "", "", false
	}
	name := base[:idx]
	version := base[idx+1:]
	if name == "" || !looksLikeVersion(version) {
		return "", "", false
	}
	return name, version, true
}

func looksLikeVersion(version string) bool {
	version = strings.TrimPrefix(version, "v")
	return version != "" && version[0] >= '0' && version[0] <= '9'
}

func (s *Scanner) findingsForMeta(root, path string, meta packageMeta, npxResidue bool) []scan.Finding {
	if meta.Name == "" {
		return nil
	}
	ref := intel.PackageRef{Ecosystem: meta.Ecosystem, Name: meta.Name, Version: meta.Version}
	verdict := s.store.Lookup(ref)
	if verdict.Flagged() {
		v := verdict
		confidence := "confirmed"
		purgePath := meta.PurgePath
		if purgePath == "" {
			purgePath = purgeCandidate(path)
		}
		if meta.Version == "" && !allVersionsVerdict(verdict) {
			confidence = "name-only"
			purgePath = ""
		}
		return []scan.Finding{{
			ID:          findingID("malware", path, ref.Name),
			Surface:     scan.SurfaceCache,
			Severity:    scan.SeverityHigh,
			Path:        path,
			Title:       "package-manager cache contains flagged package artifact",
			PackageRef:  &ref,
			Verdict:     &v,
			Evidence:    []scan.Evidence{{Label: "cache_root", Value: root}, {Label: "confidence", Value: confidence}},
			Remediation: "Run `veto quarantine-cache --dry-run` to review removal candidates, then purge if appropriate.",
			PurgePath:   purgePath,
		}}
	}
	if npxResidue && looksLikeMCPTool(meta.Name) {
		return []scan.Finding{{
			ID:         findingID("npx-mcp", path, ref.Name),
			Surface:    scan.SurfaceCache,
			Severity:   scan.SeverityLow,
			Path:       path,
			Title:      "npm _npx cache contains MCP-like fetch-and-run package",
			PackageRef: &ref,
			Evidence: []scan.Evidence{
				{Label: "cache_root", Value: root},
				{Label: "signal", Value: "_npx cache residue"},
			},
			Remediation: "Inspect the MCP config that spawned this package; purge cache residue if it is no longer needed.",
			PurgePath:   purgeCandidate(path),
		}}
	}
	return nil
}

func allVersionsVerdict(verdict intel.Verdict) bool {
	for _, report := range verdict.Reports {
		if report.Version == "" && report.Range == nil {
			return true
		}
		if report.Range != nil && report.Range.IsUnbounded() {
			return true
		}
	}
	return false
}

func isNpxPath(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"_npx"+sep)
}

func looksLikeMCPTool(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "mcp") || strings.Contains(lower, "modelcontextprotocol")
}

func purgeCandidate(packageJSONPath string) string {
	dir := filepath.Dir(packageJSONPath)
	if filepath.Base(dir) == "node_modules" {
		return packageJSONPath
	}
	return dir
}

func shouldPruneDir(name string) bool {
	switch name {
	case ".git", ".cache", "__pycache__":
		return true
	default:
		return false
	}
}

func findingID(kind, path, name string) string {
	return fmt.Sprintf("cache:%s:%s:%s", kind, path, name)
}

// isArchivePath reports whether path is a package distributable archive whose
// raw bytes are worth hashing for an IOC file-hash lookup. The set is the
// shippable artifacts a package manager downloads and caches verbatim:
//
//   - .tgz / .tar.gz : npm/pnpm/yarn/bun package tarballs
//   - .whl           : Python wheels
//   - .crate         : Cargo registry crates
//   - Go module .zip under cache/download : the Go module cache's downloaded
//     archives (a bare .zip elsewhere is not a module distributable, so it is
//     not hashed)
//
// Loose source files, manifests, and metadata are excluded — their identity is
// already covered by the name+version intel lookup; only the byte-identical
// distributable is meaningful against a file-hash IOC feed.
func isArchivePath(root string, kind rootKind, path string) bool {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".tgz"),
		strings.HasSuffix(lower, ".tar.gz"),
		strings.HasSuffix(lower, ".whl"),
		strings.HasSuffix(lower, ".crate"):
		return true
	case kind == rootKindGo && strings.HasSuffix(lower, ".zip"):
		// Restrict to the Go module download cache layout
		// (cache/download/<module>/@v/<version>.zip) so we don't hash
		// arbitrary zips a Go project happens to vendor.
		parts, ok := relParts(root, path)
		return ok && len(parts) >= 2 && parts[0] == "cache" && parts[1] == "download"
	default:
		return false
	}
}

// scanArchiveHash streams an archive's bytes through SHA-256 and looks the
// digest up in the IOC store. Returns any match as a high-severity finding,
// whether the file was hashed (for FilesScanned accounting), and a non-fatal
// error. Files larger than maxHashFileSize are skipped without hashing so a
// pathological artifact can't blow the scan's I/O budget.
func (s *Scanner) scanArchiveHash(root, path string) ([]scan.Finding, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, errors.With(err, "stat cache archive for hash").Set("path", path)
	}
	if info.Size() > maxHashFileSize {
		return nil, false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, false, errors.With(err, "open cache archive for hash").Set("path", path)
	}
	defer file.Close()

	hasher := sha256.New()
	// Bound the copy to the ceiling even if the file grew between stat and
	// read, so a racing writer can't make us stream unbounded bytes.
	if _, err := io.Copy(hasher, io.LimitReader(file, maxHashFileSize)); err != nil {
		return nil, false, errors.With(err, "hash cache archive").Set("path", path)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))

	verdict := s.iocStore.Lookup(ioc.IndicatorSHA256, digest)
	if !verdict.Matched() {
		return nil, true, nil
	}

	finding := scan.Finding{
		ID:       findingID("ioc-hash", path, digest),
		Surface:  scan.SurfaceCache,
		Severity: scan.SeverityHigh,
		Path:     path,
		Title:    "cache artifact matches known-malicious file hash",
		Evidence: []scan.Evidence{
			{Label: "cache_root", Value: root},
			{Label: "ioc_sources", Value: strings.Join(verdict.Sources(), ",")},
			{Label: "threat_label", Value: firstThreatLabel(verdict)},
			{Label: "sha256_prefix", Value: digest[:12]},
		},
		Remediation: "Treat this cached artifact as compromised: do not install it, and purge the cache entry. Investigate how it entered the cache.",
		PurgePath:   path,
	}
	return []scan.Finding{finding}, true, nil
}

// firstThreatLabel returns the first non-empty ThreatLabel among a verdict's
// matches, for display in finding evidence. Threat labels are free-form and
// display-only; this picks one representative label without implying it is the
// match key.
func firstThreatLabel(verdict ioc.Verdict) string {
	for _, m := range verdict.Matches {
		if m.ThreatLabel != "" {
			return m.ThreatLabel
		}
	}
	return ""
}

// PlanPurge turns confirmed cache findings into purge actions. Only findings
// backed by a flagged intel verdict are eligible; IOC-only residue is reported
// but not deleted by this first implementation.
func PlanPurge(findings []scan.Finding, roots []string, purge bool) []scan.PurgeAction {
	resolvedRoots := resolveExistingRoots(roots)
	actions := []scan.PurgeAction{}
	for _, f := range findings {
		if f.Surface != scan.SurfaceCache || f.PurgePath == "" || f.Verdict == nil || !f.Verdict.Flagged() {
			continue
		}
		action := scan.PurgeAction{
			Path:      f.PurgePath,
			Reason:    f.Title,
			FindingID: f.ID,
			Status:    "planned",
		}
		resolved, ok, err := safeCachePath(f.PurgePath, resolvedRoots)
		if err != nil {
			action.Status = "failed"
			action.Error = err.Error()
			actions = append(actions, action)
			continue
		}
		if !ok {
			action.Status = "skipped"
			action.Error = "path is outside known cache roots or no longer exists"
			actions = append(actions, action)
			continue
		}
		action.Path = resolved
		if purge {
			if err := os.RemoveAll(resolved); err != nil {
				action.Status = "failed"
				action.Error = err.Error()
			} else {
				action.Status = "deleted"
			}
		}
		actions = append(actions, action)
	}
	return actions
}

func resolveExistingRoots(roots []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		resolved = filepath.Clean(resolved)
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

func safeCachePath(path string, roots []string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	resolved = filepath.Clean(resolved)
	for _, root := range roots {
		rel, err := filepath.Rel(root, resolved)
		if err != nil {
			continue
		}
		if rel == "." || rel == "" {
			return "", false, nil
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return resolved, true, nil
	}
	return "", false, nil
}
