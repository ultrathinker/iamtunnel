//go:build windows

package main

// server_ancestors_windows.go - the Windows stand-in for the Unix
// ancestor check. The F-04 boundary this var carries on Unix has its
// own, older machinery here: the machine data directory's ancestors are
// checked by refuseMachineDataDirAncestorOwners inside lockServerTree,
// and the registration itself is held in place by the enrolment anchor
// (machine_anchor.go). Nothing to add to the harden path — the seam
// simply never refuses.

var serverDirAncestorCheck = func(string) error { return nil }
