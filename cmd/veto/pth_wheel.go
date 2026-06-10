package main

import (
	"io"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/packagemanager"
)

// pthWheelPreflight: stub introduced in Task 7; real implementation lands in
// Task 8. Returns false (no refusal) so the install hot path stays open until
// the wheel prescan is wired in.
func pthWheelPreflight(
	_ zerolog.Logger,
	_ io.Writer,
	_ config,
	_, _ []packagemanager.Install,
) bool {
	return false
}
