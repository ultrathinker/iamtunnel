//go:build windows

package main

// machine_anchor_windows.go - the anchor's Windows half: where it lives,
// how it is written, how it is read. The why is in machine_anchor.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// machineAnchorPath is where this account's anchor lives: per SID, so two
// registrations on one box - two accounts, two profiles - neither share
// nor see each other's anchor. The subtree is "anchors", not "machine":
// the pre-1.4 machine-wide registration sat under %ProgramData%\iamtunnel\machine,
// and the anchor must not move into, or take over, that legacy tree. The
// path needs an absolute %ProgramData%, and the process must know its own
// account.
func machineAnchorPath(env map[string]string) (string, error) {
	programData, err := config.WindowsProgramData(env)
	if err != nil {
		return "", err
	}
	sid, err := currentUserSIDString()
	if err != nil {
		return "", fmt.Errorf("identify this account for the enrolment anchor: %w", err)
	}
	return filepath.Join(programData, "iamtunnel", "anchors", sid, enrolmentAnchorName), nil
}

// anchorTreeName is the anchor's directory for a refusal that must name
// the place even when the path itself could not be built.
func anchorTreeName(env map[string]string) string {
	path, err := machineAnchorPath(env)
	if err != nil {
		return "%ProgramData%\\iamtunnel\\anchors\\<SID>"
	}
	return filepath.Dir(path)
}

// anchorAncestorCheck is the ancestor check the anchor write runs, as a
// var so a test can set its world aside: a test's %ProgramData% points
// into t.TempDir(), whose ancestors on a real box carry this account's
// own and sandbox groups' ACEs, and the check would refuse the fixture
// rather than the product. Nil in production use; the tests swap it and
// restore it.
var anchorAncestorCheck = refuseAnchorTreeAncestors

// anchorTreeCheck is the read-time check (a seam for tests).
var anchorTreeCheck = refuseAnchorTreeChangers

// anchorReadElevated says whether the process reading the anchor is
// elevated - the only kind the read-time check guards (a seam for tests).
var anchorReadElevated = elevate.IsElevated

// anchorFromRecord is the anchor a record lays down: its routing fields.
func anchorFromRecord(rec gatewayRecord) enrolmentAnchor {
	return enrolmentAnchor{Host: rec.Host, Port: rec.Port, Fingerprint: rec.Fingerprint, MachineID: rec.MachineID}
}

// writeMachineEnrolmentAnchorWindows lays the anchor down from the record
// in memory and locks the tree around it before the file lands, so the
// value an unelevated process could not plant, it also cannot change
// afterwards.
func writeMachineEnrolmentAnchorWindows(env map[string]string, rec gatewayRecord) error {
	path, err := machineAnchorPath(env)
	if err != nil {
		return envErrf("enrol: could not name the enrolment anchor: %v", err)
	}
	tree := filepath.Dir(filepath.Dir(path)) // %ProgramData%\iamtunnel\anchors
	if err := os.MkdirAll(tree, 0o700); err != nil {
		return classifyMachinePathErr(err, tree)
	}
	acl, err := winkeys.MachineTreeACL()
	if err != nil {
		return envErrf("enrol: could not build the anchor tree's ACL: %v", err)
	}
	release, err := winkeys.LockTree(tree, acl, false, nil)
	if err != nil {
		return classifyMachinePathErr(err, tree)
	}
	// Held until the anchor is written (review finding R4 N-02): the pinned root is
	// what keeps "anchors" from being renamed away between the check below
	// and the write, LockTree's own contract for a caller that goes on
	// writing into the tree by name.
	defer release()
	// The folders the anchor sits under are held to the standard the
	// gateway install holds its own to (R2 supplementary round), with the running
	// account trusted the way the machine's own ancestor check trusts it:
	// a foreign owner, or a foreign ACE that could rename the anchor tree
	// away - the move F-04 rides on - is refused. The check is handed the
	// anchor's own folder, so the walk covers "anchors" and
	// %ProgramData%\iamtunnel themselves, not only what is above them
	// (review finding R4 N-02: an ordinary account can create %ProgramData%\iamtunnel
	// first, and whoever owns it can move "anchors" aside). It runs after
	// the tree is locked, so "anchors" is judged as it will stand. The
	// default machine passes; a folder someone else owns does not.
	if err := anchorAncestorCheck(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteMachineJSON(path, anchorFromRecord(rec))
}

// refuseAnchorTreeAncestors is refuseGatewayDataDirAncestorWriters with
// the running account trusted: this command runs elevated, and the anchor
// tree below is Administrators-owned the way the machine data directory
// is. What must still be refused is an ancestor another account owns, or
// one whose rights let another account move the anchor tree aside.
//
// root is the anchor's own folder. The anchor tree's two folders -
// "anchors" and %ProgramData%\iamtunnel - are judged WITHOUT trusting the
// running account (review finding R4 N-02): the attacker F-04 is about is that
// account's own unelevated process, and a %ProgramData%\iamtunnel it made
// before enrol is owned by it. An elevated console creates them owned by
// Administrators, so the default machine passes. The folders above them
// keep the running account trusted, as the machine's own check does.
func refuseAnchorTreeAncestors(root string) error {
	who, err := anchorTreeChangers(root)
	if err != nil {
		return err
	}
	above, err := dataDirAncestorWriters(filepath.Dir(filepath.Dir(root)), true, ancestorChangeRights)
	if err != nil {
		return envErrf("could not check who can change the folders above the enrolment anchor tree %s: %v", root, err)
	}
	who = append(who, above...)
	if len(who) > 0 {
		return deniedErrf("the folders above the enrolment anchor tree %s can be changed by %s — whoever can rename one of them can move the anchor aside and put their own in its place. Create those folders from an elevated console or hand them to Administrators (takeown /f \"<folder>\" /a), and repeat.", root, strings.Join(who, ", "))
	}
	return nil
}

// anchorTreeChangers names who, other than SYSTEM, Administrators and
// TrustedInstaller, can move the anchor tree's own two folders - "anchors"
// and %ProgramData%\iamtunnel - with the running account NOT trusted
// (review finding R4 N-02). root is the anchor's own folder.
func anchorTreeChangers(root string) ([]string, error) {
	anchors := filepath.Dir(root)
	var who []string
	for _, p := range []string{anchors, filepath.Dir(anchors)} {
		sids, err := objectWriters(p, "", ancestorChangeRights)
		if err != nil {
			return nil, envErrf("could not check who can change the enrolment anchor tree %s: %v", p, err)
		}
		for _, sid := range sids {
			who = append(who, accountName(sid)+" (on "+p+")")
		}
	}
	return who, nil
}

// refuseAnchorTreeChangers is the check an elevated start runs on the tree
// before it believes the anchor (review finding R4 N-02): the tree's own two
// folders, strictly. The folders above them were checked when the anchor
// was written, and on a real machine they are %ProgramData% and the drive
// root, which only Administrators change.
func refuseAnchorTreeChangers(root string) error {
	who, err := anchorTreeChangers(root)
	if err != nil {
		return err
	}
	if len(who) > 0 {
		return deniedErrf("the enrolment anchor tree %s can be changed by %s — whoever can rename one of its folders can move the anchor aside and put their own in its place, so this elevated start does not believe it. Hand the folders to Administrators (takeown /f \"<folder>\" /a, then run \"iamtunnel server install\" from an elevated console), and repeat.", filepath.Dir(root), strings.Join(who, ", "))
	}
	return nil
}

// readMachineEnrolmentAnchorWindows reads the anchor back; a missing
// anchor is fs.ErrNotExist. The read goes through state.ReadDataFile like
// every data-file read: a link or a FIFO planted at the name is refused,
// not followed.
func readMachineEnrolmentAnchorWindows(env map[string]string) (enrolmentAnchor, error) {
	var anchor enrolmentAnchor
	path, err := machineAnchorPath(env)
	if err != nil {
		return anchor, envErrf("could not name the enrolment anchor: %v", err)
	}
	data, err := state.ReadDataFile(path)
	if err != nil {
		return anchor, err
	}
	// The elevated start believes the anchor only while no other account
	// can move it (review finding R4 N-02): the same check the write ran, at the
	// moment the anchor is used - a tree that became movable after enrol
	// is refused here, not trusted. After the read, so a missing anchor
	// still answers as missing. Only an elevated process asks: an
	// unelevated start has nothing for a planted anchor to raise it to.
	if elevated, eerr := anchorReadElevated(); eerr == nil && elevated {
		if err := anchorTreeCheck(filepath.Dir(path)); err != nil {
			return anchor, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&anchor); err != nil {
		return anchor, envErrf("%s: does not parse (%v) — run \"iamtunnel server install\" from an elevated console to lay the anchor down again, or enrol again", path, err)
	}
	return anchor, nil
}
