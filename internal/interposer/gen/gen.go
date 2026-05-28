// Package gen hosts the go:generate directive and the consistency
// test for the C interposer's PM-name header.
//
// Directory layout: the C source (veto_interpose.c) and the generated
// header (pm_names.h) live in internal/interposer/csrc/ so the parent
// internal/interposer/ Go package can host an embed.go that go:embeds
// them. A Go package cannot mix .go and .c files without using cgo, and
// we deliberately avoid cgo here (the C library is built standalone by
// the Makefile and loaded via DYLD_INSERT_LIBRARIES / LD_PRELOAD at
// runtime; pulling in cgo would also break the static-binary shape that
// veto's distribution model relies on).
//
// The generator emits ../csrc/pm_names.h, which veto_interpose.c
// #includes. `go generate ./internal/interposer/gen/...` and the
// corresponding Makefile recipe both write to that path.
package gen

//go:generate go run ../cmd/genpmlist -o ../csrc/pm_names.h
