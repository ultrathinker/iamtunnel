package main

// machine_anchor.go - the anchor the elevated server start checks the
// profile enrolment against (R4 F-04). Windows-only in effect; the
// dispatch is a runtime.GOOS branch so the cross-platform tests and the
// Linux build see one shape.
//
// The Windows logon task runs "server start" with the account's highest
// token and no prompt, and that start takes the registration - which
// gateway to dial, which fingerprint to pin, which machine id to answer
// to - from %LOCALAPPDATA%\iamtunnel\server. Locking that directory
// (IAMT-213) does not hold it in place: the account's own unelevated
// processes hold FILE_DELETE_CHILD on %LOCALAPPDATA%\iamtunnel, and that
// right on a parent renames the child whatever the child's own DACL says.
// A planted enrolment.json names the attacker's gateway; the elevated
// start dials it, pins what it says, and its door.open writes the
// attacker's key into %ProgramData%\ssh\administrators_authorized_keys -
// an unelevated process turns into a permanent remote administrator
// login.
//
// The anchor takes the trust out of the profile record. "enrol" writes a
// copy of the record's routing identity (host, port, fingerprint, machine
// id) under %ProgramData%\iamtunnel\anchors\<SID>\, from the values it
// holds in memory - not from anything the profile directory could have
// swapped in meanwhile. The tree is handed to Administrators the way the
// machine data directory is (winkeys.LockTree, MachineTreeACL), and
// %ProgramData% gives ordinary accounts no right to delete or rename a
// child, so an unelevated process can plant nothing on the anchor's path
// and change nothing in it. "server start" refuses unless the profile
// record and the anchor say the same thing: a planted record fails, and
// a real one dialled for is the one enrol wrote. "server install" lays
// the anchor for a registration that predates it - the one moment the
// current profile record is trusted, with the operator present and
// elevated, and the command says so in its output.

import (
	"errors"
	"os"
	"runtime"
	"strings"
)

const enrolmentAnchorName = "enrolment.anchor.json"

// enrolmentAnchor is the copy of the registration's routing identity the
// elevated start checks the profile record against. Deliberately not the
// whole record: the OS-user binding and everything else the record
// carries either cannot reroute the elevated process or are checked
// against the gateway's own state, while these four fields decide WHERE
// the elevated process dials and WHAT it pins.
type enrolmentAnchor struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	MachineID   string `json:"machineId"`
}

// anchorMismatches names the fields an anchor and a record disagree on,
// empty when they say the same thing.
func anchorMismatches(anchor enrolmentAnchor, rec gatewayRecord) []string {
	var out []string
	if anchor.Host != rec.Host {
		out = append(out, "host")
	}
	if anchor.Port != rec.Port {
		out = append(out, "port")
	}
	if anchor.Fingerprint != rec.Fingerprint {
		out = append(out, "fingerprint")
	}
	if anchor.MachineID != rec.MachineID {
		out = append(out, "machineId")
	}
	return out
}

// writeMachineEnrolmentAnchor is enrol's half: lay the anchor down from
// the record IN MEMORY, so nothing that read or replaced the profile
// directory meanwhile can influence what the start later checks against.
// On non-Windows there is no profile directory an unelevated process
// could plant under an elevated reader's feet (the machine commands run
// as root there, and hardenServerDir holds the directory's parent to
// root) - nothing to anchor, nothing to check.
func writeMachineEnrolmentAnchor(env map[string]string, rec gatewayRecord) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return writeMachineEnrolmentAnchorWindows(env, rec)
}

// readMachineEnrolmentAnchor reads the anchor back. A missing anchor is
// os.ErrNotExist, so callers can tell "never anchored" from "anchored to
// something else".
func readMachineEnrolmentAnchor(env map[string]string) (enrolmentAnchor, error) {
	if runtime.GOOS != "windows" {
		// No anchor on this platform: the callers treat this exactly like
		// a missing anchor, which on non-Windows is the truth.
		return enrolmentAnchor{}, os.ErrNotExist
	}
	return readMachineEnrolmentAnchorWindows(env)
}

// isAnchorMissing tells "never anchored" from "anchored, and wrong".
func isAnchorMissing(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// joinAnchorFields is the field list a mismatch refusal names, "host,
// port" style.
func joinAnchorFields(fields []string) string {
	return strings.Join(fields, ", ")
}

// verifiedServerRecord is "server start"'s way to a record it may act on:
// the profile record, checked against the anchor before anything dials.
// The record comes back so the rest of the start reads the very bytes
// that were checked, not a second, later read the profile directory
// could have swapped meanwhile.
func verifiedServerRecord(env map[string]string, dir string) (gatewayRecord, error) {
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return gatewayRecord{}, envErrf(`iamtunnel server start: this machine is not registered — run "iamtunnel enrol <code>" first.`)
		}
		return gatewayRecord{}, err
	}
	if runtime.GOOS != "windows" {
		return rec, nil
	}
	anchor, err := readMachineEnrolmentAnchorWindows(env)
	if err != nil {
		if isAnchorMissing(err) {
			return gatewayRecord{}, deniedErrf("iamtunnel server start: the enrolment record in %s has no anchor under %s — and the anchor is what tells the elevated start that this record is the one enrol wrote, not one the account's unelevated processes moved into place. Run \"iamtunnel server install\" once from an elevated console to lay the anchor down (it was registered before the anchor existed), or enrol again.",
				dir, anchorTreeName(env))
		}
		return gatewayRecord{}, err
	}
	if bad := anchorMismatches(anchor, rec); len(bad) > 0 {
		return gatewayRecord{}, deniedErrf("iamtunnel server start: the enrolment record in %s disagrees with its anchor on %s — the anchor says gateway %s:%d (fingerprint %s, machine %s), the record says %s:%d (fingerprint %s, machine %s). The record lives where this account's unelevated processes can replace it; the anchor is where they cannot. Do not start a server on a record like this: enrol again to re-register deliberately, or investigate what replaced the record.",
			dir, joinAnchorFields(bad),
			anchor.Host, anchor.Port, anchor.Fingerprint, anchor.MachineID,
			rec.Host, rec.Port, rec.Fingerprint, rec.MachineID)
	}
	return rec, nil
}

// ensureMachineEnrolmentAnchor is "server install"'s half: a registration
// that predates the anchor gets one laid down here, where the operator is
// present and elevated; an anchor that already exists is only checked,
// never quietly rewritten - rewriting it would bless whatever replaced
// the profile record since enrol.
func ensureMachineEnrolmentAnchor(env map[string]string, dir string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		return err
	}
	anchor, err := readMachineEnrolmentAnchorWindows(env)
	if err == nil {
		if bad := anchorMismatches(anchor, rec); len(bad) > 0 {
			return deniedErrf("iamtunnel server install: the enrolment record in %s disagrees with its anchor on %s — the anchor is what the elevated start checks the record against, and rewriting it here would bless whatever replaced the record. If this machine's registration is genuinely moving, enrol again; otherwise investigate the record first.",
				dir, joinAnchorFields(bad))
		}
		return nil
	}
	if !isAnchorMissing(err) {
		return err
	}
	if err := writeMachineEnrolmentAnchorWindows(env, rec); err != nil {
		return err
	}
	return nil
}
