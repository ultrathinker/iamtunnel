//go:build darwin

// Darwin-specific bits of the elevation layer that differ from
// the Linux sibling.
//
// Supported is the only such bit: Darwin is "not supported
// yet" at the epic level.
// The platform-layer primitives — file system, user lookup —
// still work on Darwin, so a Darwin development build does not
// break, but production install / run / status on Darwin is
// gated on "not supported" elsewhere, not here.

package elevate

// Supported reports whether elevate can run on this platform.
// Darwin is not in 1.1 (SPEC §12); the answer is false here
// while the production-level Darwin support lands.
func Supported() bool { return false }
