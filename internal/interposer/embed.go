// Package interposer exposes the native execve-interposer C source as a
// go:embed FS so the veto binary can build a host-matched shared library
// at install time without requiring the veto source tree on disk.
//
// The Makefile builds libveto_interpose.{dylib,so} from these same files;
// the embedded copy is the install-time fallback used by `veto install-all`
// when no source tree or prebuilt artifact is available.
//
// Directory layout: the C source and generated header live in the csrc/
// subdirectory rather than alongside this file, because the Go toolchain
// refuses .c files in a non-cgo package. Keeping the C in a subdir lets
// this package stay pure-Go while still embedding the sources at compile
// time via go:embed. The Makefile compiles the same files standalone with
// $(CC); see Makefile's INTERPOSER_SRC / INTERPOSER_HEADER.
package interposer

import "embed"

// SourceFS contains the C source and the generated pm_names.h header,
// rooted at the csrc/ subdirectory. Consumers see them at the paths
// "csrc/veto_interpose.c" and "csrc/pm_names.h" inside the FS.
//
// pm_names.h is produced by `go generate ./internal/interposer/gen/...`
// at build time; the Makefile's `build` target depends on it so a fresh
// checkout regenerates the header before veto is compiled, keeping the
// embedded copy in sync with internal/packagemanager/pmlist.InterposerPMs.
//
//go:embed csrc/veto_interpose.c csrc/pm_names.h
var SourceFS embed.FS
