//go:build linux

// Linux-specific bits of the elevation layer that differ from
// the Darwin sibling.
//
// Supported is the only such bit: SPEC §3.2.1 puts Linux in
// 1.1 (and IAMT-246 + IAMT-248 are the work that lands it
// there). Darwin is "not supported yet" at the epic
// level, so its Supported() returns false in elevate_darwin.go.
// Splitting the file keeps the build tag the source of truth
// for "supported or not".

package elevate

// Supported reports whether elevate can run on this platform.
// Linux is in 1.1 (SPEC §12); the answer is true.
func Supported() bool { return true }
