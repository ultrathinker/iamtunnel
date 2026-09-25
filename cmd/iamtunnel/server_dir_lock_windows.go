//go:build windows

package main

import "github.com/ultrathinker/iamtunnel/internal/winkeys"

// serverTreeBeforeApply, when a test sets it, runs after a child of the
// machine directory has been classified and before its DACL is set: the
// window R2-CX F-12 is about. Nil in the product. The var lives in this
// windows-tagged file rather than iohelpers.go: its only assigner is
// lockServerTree here and its only swapper the windows-tagged F-12 test —
// on darwin/linux it sat unreferenced, and staticcheck's U1000 said so
// (MAC, 24.09.2026).
var serverTreeBeforeApply func(path string)

// lockServerTree locks the machine data directory and everything in it
// (IAMT-213: SYSTEM and Administrators) through handles, owner
// Administrators (winkeys.LockTree, R2-CX F-12, F-13).
func lockServerTree(dir string, replaceACL bool) error {
	// R2 supplementary round: no folder above may belong to another account, whose
	// owner could move the directory aside.
	if err := refuseMachineDataDirAncestorOwners(dir); err != nil {
		return err
	}
	acl, err := winkeys.MachineTreeACL()
	if err != nil {
		return err
	}
	acl.BeforeApply = serverTreeBeforeApply
	release, err := winkeys.LockTree(dir, acl, replaceACL, nil)
	if err != nil {
		return err
	}
	release()
	return nil
}
