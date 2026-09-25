//go:build (!windows && !linux && !darwin) || nogui

package main

// buildVariant for the build with no window in it (IAMT-439).
//
// WHY THIS BUILD EXISTS. The gateway never opens a window, but until
// 23.09.2026 it carried the code that would: one binary, all four roles,
// and on Linux that window talks to X11 and Wayland through cgo. The
// linker therefore wrote libEGL, libwayland-*, libX11-xcb and four more
// into the binary's NEEDED list, and the dynamic linker demands them
// BEFORE main runs. A clean Ubuntu Server has none of them, so the very
// first command on a fresh gateway -- "iamtunnel version" -- died with
// exit 127 and not one word of ours (live install on AWS, 23.09.2026).
//
// Never-executed graphics libraries on the one machine with a port open
// to the internet are not a vulnerability; they are an explanation owed
// at every audit, eight more packages to keep patched, and the reason a
// minimal image cannot run this program at all.
//
// It is a BUILD VARIANT and not a second binary's worth of source: the
// same files, one tag, no second implementation of anything. That
// distinction is the whole reason this is safe to have -- the half that
// is built less often is the half that rots, and a tag that stops
// compiling is caught by gate 1, which builds both.
const buildVariant = "headless (no window compiled in)"
