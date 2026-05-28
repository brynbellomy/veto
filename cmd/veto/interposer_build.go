// interposer_build.go: build libveto_interpose.{dylib,so} from the
// embedded C source at install time.
//
// Motivation: `veto install-all` originally shelled out to
// `make interposer`, which required the veto source tree to be on disk
// alongside the binary. That forced downstream integrators to keep an
// /opt/veto-src/ checkout forever just to re-run install-all. We now
// embed veto_interpose.c + pm_names.h directly into the veto binary
// (see internal/interposer/embed.go) and compile them in a tempdir with
// the host's $(CC) — no source tree required.
//
// The CC flags below MUST stay in sync with the Makefile's
// INTERPOSER_CFLAGS (lines 18–32). If you change one side, change the
// other; pm_names.h drift between the two paths is the exact failure
// mode the canonical-PM-list refactor exists to prevent.

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/interposer"
)

// buildInterposerTimeout caps the cc invocation. 60s is generous —
// veto_interpose.c is a single ~38KB translation unit — but covers
// cold-start CI runners and slow filesystems.
const buildInterposerTimeout = 60 * time.Second

// buildInterposerFromEmbed extracts the embedded interposer source to a
// tempdir, invokes the host C compiler with the same flags the Makefile
// uses, and returns the path to the produced shared library. The caller
// owns the returned cleanup func and MUST defer it AFTER consuming the
// artifact (the tempdir gets blown away on cleanup, so copy the file out
// of it before letting cleanup run).
//
// On success: returns (artifactPath, cleanup, nil). cleanup is always
// safe to call exactly once.
//
// On failure: returns ("", noopCleanup, wrappedErr). cleanup is still
// safe to call (it's a no-op when no tempdir was created or when one was
// already removed) so the caller pattern `defer cleanup()` is always
// correct.
func buildInterposerFromEmbed(logger zerolog.Logger) (string, func(), error) {
	noop := func() {}

	tempDir, err := os.MkdirTemp("", "veto-interposer-build-*")
	if err != nil {
		return "", noop, errors.With(err, "mkdir tempdir for interposer build")
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }

	// Stream every file out of the embedded FS into the tempdir. The
	// embed roots at internal/interposer/, with the C source living
	// under csrc/. We flatten the layout into the tempdir so the
	// #include "pm_names.h" directive at the top of veto_interpose.c
	// resolves against the same directory as the .c file, matching how
	// the Makefile build (which compiles in-place inside csrc/) works.
	if err := writeEmbeddedSource(tempDir); err != nil {
		cleanup()
		return "", noop, err
	}

	outName, cflags, err := interposerBuildFlags()
	if err != nil {
		cleanup()
		return "", noop, err
	}

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		cleanup()
		return "", noop, errors.WithNew("C compiler not found on PATH").
			Set("cc", cc, "hint", ccInstallHint())
	}

	outPath := filepath.Join(tempDir, outName)
	srcPath := filepath.Join(tempDir, "veto_interpose.c")

	args := append([]string{}, cflags...)
	args = append(args, "-o", outPath, srcPath)

	ctx, cancel := context.WithTimeout(context.Background(), buildInterposerTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cc, args...)
	cmd.Dir = tempDir

	logger.Debug().
		Str("cc", cc).
		Strs("args", args).
		Str("tempdir", tempDir).
		Msg("compiling embedded interposer")

	combined, runErr := cmd.CombinedOutput()
	if runErr != nil {
		cleanup()
		// Use the existing helper from install_preload.go so a long
		// compiler dump doesn't explode the error string.
		return "", noop, errors.With(runErr, "compile interposer").Set(
			"cc", cc,
			"output", truncateForError(string(combined), 500),
		)
	}

	if _, err := os.Stat(outPath); err != nil {
		cleanup()
		return "", noop, errors.With(err, "cc reported success but artifact is missing").
			Set("expected", outPath)
	}

	return outPath, cleanup, nil
}

// writeEmbeddedSource extracts every regular file from interposer.SourceFS
// into dst, flattening any subdirectory structure so #include "pm_names.h"
// resolves correctly against the .c file's directory.
//
// We walk rather than hard-code the file list so adding a new embedded
// header (e.g. a vendored prefix) doesn't require touching this function;
// the flatten-by-basename rule means that helper is still implicit. If a
// future change needs subdir structure preserved (e.g. nested include
// hierarchy), revisit this.
func writeEmbeddedSource(dst string) error {
	return fs.WalkDir(interposer.SourceFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.With(walkErr, "walk embedded FS").Set("path", path)
		}
		if d.IsDir() {
			// Directories in the embed FS (including the "csrc/" subdir
			// the source lives in) are flattened — we put every file at
			// the root of dst so the in-tree #include is satisfied.
			return nil
		}
		data, err := interposer.SourceFS.ReadFile(path)
		if err != nil {
			return errors.With(err, "read embedded file").Set("path", path)
		}
		outPath := filepath.Join(dst, filepath.Base(path))
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return errors.With(err, "write embedded file").Set("path", outPath)
		}
		return nil
	})
}

// interposerBuildFlags returns (outputFileName, cflags) for the current
// GOOS/GOARCH. These MUST mirror the Makefile's INTERPOSER_CFLAGS — see
// the comment at the top of this file.
func interposerBuildFlags() (string, []string, error) {
	switch runtime.GOOS {
	case "darwin":
		cflags := []string{"-O2", "-Wall", "-Wextra", "-fno-common", "-dynamiclib"}
		if runtime.GOARCH == "arm64" {
			// Apple Silicon's /bin/sh and /bin/bash are arm64e (pointer-auth
			// ABI variant). dyld refuses non-arm64e dylibs in
			// DYLD_INSERT_LIBRARIES when the host process is arm64e. A fat
			// dylib loads into both arches, so the same artifact works for
			// every DYLD_INSERT_LIBRARIES target on the machine.
			cflags = append(cflags, "-arch", "arm64", "-arch", "arm64e")
		}
		return "libveto_interpose.dylib", cflags, nil
	case "linux":
		return "libveto_interpose.so",
			[]string{"-O2", "-Wall", "-Wextra", "-fPIC", "-shared"},
			nil
	default:
		return "", nil, errors.WithNew("unsupported GOOS for interposer build").
			Set("goos", runtime.GOOS)
	}
}

// ccInstallHint returns a per-OS suggestion for installing a C compiler,
// surfaced in the error when exec.LookPath("cc") fails. The hint is
// advisory — we don't try to run apt/brew ourselves.
func ccInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "install Xcode Command Line Tools via `xcode-select --install`"
	case "linux":
		return "install build-essential (Debian/Ubuntu) or @development-tools (Fedora)"
	default:
		return fmt.Sprintf("install a C compiler for %s", runtime.GOOS)
	}
}
