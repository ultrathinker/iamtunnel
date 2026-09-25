// Package record writes session recordings: asciicast v2 (.cast) with
// resize events, the VT-parser transcript (.txt) and .meta.json (SPEC
// §6.5). Typed input is never written; a recording opens before the
// first byte and closes on any break. No player in 1.0, and no knowledge
// of SSH itself — it consumes bytes and window sizes.
package record
