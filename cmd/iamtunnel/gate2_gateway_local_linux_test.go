//go:build linux

package main

// This file no longer defines anything: a "_linux" in the file's NAME is
// itself a build constraint — go/build applies it before any //go:build
// line, so whatever this file carried was invisible outside linux no
// matter what its tag said (MAC, 24.09.2026, round 2: the
// linux || darwin tag here sat on top of a name that already said linux,
// and darwin saw neither it nor backupDeniedByOS). The POSIX
// backupDeniedByOS now lives in gate2_gateway_local_posix_test.go, whose
// name carries no GOOS and whose tag spells the choice out. The file
// stays (the round renames and deletes nothing) and keeps pinning the
// linux side of that story.
