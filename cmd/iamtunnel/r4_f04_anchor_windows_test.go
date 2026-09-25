//go:build windows

package main

// R4 F-04 (REVIEW-R4-OPUS): the logon task starts "server start" with the
// account's highest token, and that start reads the enrolment record from
// %LOCALAPPDATA%\iamtunnel\server — a directory the account's own
// unelevated processes can move aside and replace (FILE_DELETE_CHILD on
// the parent wins over the locked child's DACL). Whatever they plant in
// its place names the gateway the elevated process dials and the
// fingerprint it pins, and its door.open writes THEIR key into
// %ProgramData%\ssh\administrators_authorized_keys: an unelevated
// process turns into a permanent remote admin login.
//
// The fix under test: the elevated start does not trust the profile
// record alone. "enrol" (and "server install" for registrations made
// before the anchor existed) writes an ANCHOR — a copy of the record's
// host, port, fingerprint and machine id — under
// %ProgramData%\iamtunnel\machine\<SID>\enrolment.anchor.json, where the
// account's unelevated processes can create nothing and rename nothing
// (the tree is handed to Administrators, and %ProgramData% gives
// ordinary accounts no delete-the-child right). "server start" refuses
// unless the profile record and the anchor say the same thing.
//
// Canary: drop the verifiedServerRecord call from cmdServerStart (or the
// writeMachineEnrolmentAnchor call from enrolMachine) and the tests in
// this file go red — the start runs on past the anchor gate to the sshd
// pre-flight instead of refusing, or an enrol leaves no anchor behind.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// f04AnchorPath is where the anchor for this test's account must live.
func f04AnchorPath(t *testing.T, env map[string]string) string {
	t.Helper()
	p, err := machineAnchorPath(env)
	if err != nil {
		t.Fatalf("machine anchor path: %v", err)
	}
	return p
}

// f04RelaxAncestorCheck sets the anchor write's ancestor check aside for
// one test: the fixture's %ProgramData% is t.TempDir(), and on this box
// the folders above it carry sandbox groups' ACEs the real %ProgramData%
// does not have - the check would refuse the fixture, not the product.
// The check's own refusals are pinned by the r2cx ancestor tests; what
// this seam keeps out of the way is only the environment.
func f04RelaxAncestorCheck(t *testing.T) {
	t.Helper()
	saved, savedTree := anchorAncestorCheck, anchorTreeCheck
	anchorAncestorCheck = func(string) error { return nil }
	// The read-time check of an elevated run (review finding R4 N-02) meets the
	// same fixture folders; its own refusals are pinned by the r4cx_n02
	// tests.
	anchorTreeCheck = func(string) error { return nil }
	t.Cleanup(func() { anchorAncestorCheck, anchorTreeCheck = saved, savedTree })
}

// TestF04_ServerStartRefusesWithoutAnchor drives the load-bearing half:
// an enrolled machine whose registration predates the anchor (or whose
// anchor was destroyed) must make "server start" refuse BEFORE the sshd
// pre-flight — the elevated process must not act on an unanchored
// profile record.
func TestF04_ServerStartRefusesWithoutAnchor(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	env := testsupport.PlatformDataEnvAt(t, dir)

	// The anchor this machine never got: the file must not exist, or the
	// refusal below would be the mismatch refusal instead of the missing
	// one. PlatformDataEnvAt points %ProgramData% at dir, and seedEnrolledMachine
	// writes nothing there but the server directory itself.
	anchor := f04AnchorPath(t, env)
	if _, err := os.Stat(anchor); !os.IsNotExist(err) {
		t.Fatalf("precondition: anchor already exists at %s (err=%v)", anchor, err)
	}

	sshdCalled := false
	var out, errs bytes.Buffer
	s := &streams{
		in:   strings.NewReader(""),
		out:  &out,
		errs: &errs,
		env:  env,
		checkSSHD: func(string) error {
			sshdCalled = true
			return errors.New("sshd not reachable")
		},
		isElevated: func() (bool, error) { return true, nil },
	}
	exit := run([]string{"server", "start", "--data-dir", dir}, s)

	if exit != exitDenied {
		t.Fatalf("server start without an anchor: exit = %d, want %d (out=%q errs=%q)", exit, exitDenied, out.String(), errs.String())
	}
	if !strings.Contains(errs.String(), "anchor") {
		t.Fatalf("server start without an anchor: the refusal must name the anchor, got %q", errs.String())
	}
	if sshdCalled {
		t.Fatalf("server start without an anchor reached the sshd pre-flight — it must refuse before acting on an unanchored record")
	}
}

// TestF04_ServerStartRefusesWhenAnchorMismatches is the attack itself: the
// profile record names a gateway the account's unelevated code planted,
// the anchor still holds what enrol wrote. The start must refuse and say
// which field disagrees.
func TestF04_ServerStartRefusesWhenAnchorMismatches(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	env := testsupport.PlatformDataEnvAt(t, dir)

	rec, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("load the seeded record: %v", err)
	}
	// The planted record: same machine id (it is only a name), but the
	// gateway is the attacker's and so is the fingerprint the elevated
	// process would pin.
	planted := rec
	planted.Host = "attacker.example.test"
	if err := atomicWriteMachineJSON(gatewayRecordPath(dir), planted); err != nil {
		t.Fatalf("plant the profile record: %v", err)
	}
	// The anchor keeps the truth: write it from the REAL record, the way
	// enrol did before the profile record was replaced.
	f04RelaxAncestorCheck(t)
	if err := writeMachineEnrolmentAnchor(env, rec); err != nil {
		t.Fatalf("write the anchor: %v", err)
	}

	sshdCalled := false
	var out, errs bytes.Buffer
	s := &streams{
		in:   strings.NewReader(""),
		out:  &out,
		errs: &errs,
		env:  env,
		checkSSHD: func(string) error {
			sshdCalled = true
			return errors.New("sshd not reachable")
		},
		isElevated: func() (bool, error) { return true, nil },
	}
	exit := run([]string{"server", "start", "--data-dir", dir}, s)

	if exit != exitDenied {
		t.Fatalf("server start on a planted record: exit = %d, want %d (out=%q errs=%q)", exit, exitDenied, out.String(), errs.String())
	}
	if !strings.Contains(errs.String(), "fingerprint") {
		t.Fatalf("server start on a planted record: the refusal must name the field that disagrees, got %q", errs.String())
	}
	if sshdCalled {
		t.Fatalf("server start dialled for a planted record — the anchor gate did not hold")
	}
}

// TestF04_AnchoredMachineStartsPastAnchorCheck is the anti-overblock half:
// a machine whose anchor matches its record must get past the anchor gate
// (reaching the sshd pre-flight), so the gate refuses tampering and not
// the product.
func TestF04_AnchoredMachineStartsPastAnchorCheck(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	env := testsupport.PlatformDataEnvAt(t, dir)

	rec, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("load the seeded record: %v", err)
	}
	f04RelaxAncestorCheck(t)
	if err := writeMachineEnrolmentAnchor(env, rec); err != nil {
		t.Fatalf("write the anchor: %v", err)
	}

	sshdAddr := ""
	var out, errs bytes.Buffer
	s := &streams{
		in:   strings.NewReader(""),
		out:  &out,
		errs: &errs,
		env:  env,
		checkSSHD: func(addr string) error {
			sshdAddr = addr
			return errors.New("sshd not reachable (this test stops here on purpose)")
		},
		isElevated: func() (bool, error) { return true, nil },
	}
	exit := run([]string{"server", "start", "--data-dir", dir}, s)

	if sshdAddr == "" {
		t.Fatalf("an anchored machine was refused before the sshd pre-flight (exit=%d errs=%q) — the gate overblocks", exit, errs.String())
	}
	if exit == exitDenied && strings.Contains(errs.String(), "anchor") {
		t.Fatalf("an anchored machine was refused with an anchor error: %q", errs.String())
	}
}

// TestF04_EnrolWritesMatchingAnchor pins the write half: after a real
// enrol exchange the anchor exists, is readable back, and says what the
// saved record says. Drop writeMachineEnrolmentAnchor from enrolMachine
// and this goes red.
func TestF04_EnrolWritesMatchingAnchor(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("enrol refuses root by design (SPEC §3.2.1)")
	}
	const secret = "s3cret-anchor1"
	const wantMachine = "win01-anchor"
	dir := t.TempDir()
	env := testsupport.PlatformDataEnvAt(t, dir)

	addr, fp := startFakeEnrolGateway(t, secret, wantMachine, "")
	code := "iamtunnel-enrol://" + addr + "#" + fp + ":" + secret

	f04RelaxAncestorCheck(t)
	var out, errs bytes.Buffer
	s := &streams{
		in:         strings.NewReader(""),
		out:        &out,
		errs:       &errs,
		env:        env,
		isElevated: func() (bool, error) { return true, nil },
	}
	if got := run([]string{"enrol", "--data-dir", dir, code}, s); got != exitOK {
		t.Fatalf("enrol: exit=%d out=%q errs=%q", got, out.String(), errs.String())
	}

	rec, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("the enrolment record: %v", err)
	}
	anchor, err := readMachineEnrolmentAnchor(env)
	if err != nil {
		t.Fatalf("the anchor enrol must write: %v", err)
	}
	if anchor.Host != rec.Host || anchor.Port != rec.Port || anchor.Fingerprint != rec.Fingerprint || anchor.MachineID != rec.MachineID {
		t.Fatalf("anchor %+v does not match the saved record %+v", anchor, rec)
	}
	// And the account's own SID is where it lives, so two registrations on
	// one box do not share an anchor; the subtree is "anchors", not the
	// legacy pre-1.4 "machine" directory the account could still carry.
	if !strings.Contains(filepath.Dir(f04AnchorPath(t, env)), "anchors") {
		t.Fatalf("anchor path %q does not sit under the anchors tree", f04AnchorPath(t, env))
	}
}

// TestF04_ServerInstallAnchorsLegacyRegistration pins the upgrade half:
// "server install" on a machine whose registration predates the anchor
// writes the anchor from the profile record — the operator is present and
// elevated there — and refuses when the anchor already disagrees.
func TestF04_ServerInstallAnchorsLegacyRegistration(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	env := testsupport.PlatformDataEnvAt(t, dir)

	// The legacy case: no anchor yet. install lays it down.
	f04RelaxAncestorCheck(t)
	if err := ensureMachineEnrolmentAnchor(env, dir); err != nil {
		t.Fatalf("install on an unanchored registration must write the anchor: %v", err)
	}
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("load the seeded record: %v", err)
	}
	anchor, err := readMachineEnrolmentAnchor(env)
	if err != nil {
		t.Fatalf("read back the anchor: %v", err)
	}
	if anchor != (enrolmentAnchor{Host: rec.Host, Port: rec.Port, Fingerprint: rec.Fingerprint, MachineID: rec.MachineID}) {
		t.Fatalf("anchor %+v does not match the record %+v", anchor, rec)
	}

	// The tampered case: the profile record now names another gateway;
	// install must refuse rather than silently re-anchor the attacker's
	// registration.
	planted := rec
	planted.Port = rec.Port + 1
	if err := atomicWriteMachineJSON(gatewayRecordPath(dir), planted); err != nil {
		t.Fatalf("plant the record: %v", err)
	}
	err = ensureMachineEnrolmentAnchor(env, dir)
	if err == nil {
		t.Fatalf("install on a planted record must refuse — re-anchoring it would bless the tamper")
	}
	if !strings.Contains(err.Error(), "fingerprint") && !strings.Contains(err.Error(), "port") && !strings.Contains(err.Error(), "host") {
		t.Fatalf("the refusal must name what disagrees, got %v", err)
	}
}

// seedEnrolmentAnchor lays the anchor for an already-seeded machine, the
// way the enrol that produced the record would have (R4 F-04): a test
// that drives "server start" past the anchor gate drives a registration
// enrol completed.
func seedEnrolmentAnchor(t *testing.T, env map[string]string, dir string) {
	t.Helper()
	f04RelaxAncestorCheck(t)
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("seed the enrolment anchor: load the record: %v", err)
	}
	if err := writeMachineEnrolmentAnchor(env, rec); err != nil {
		t.Fatalf("seed the enrolment anchor: %v", err)
	}
	// An elevated test run starts "server start" elevated too, and that
	// start checks the anchor tree's own folders strictly (review finding R4 N-02).
	// The fixture's %ProgramData%\iamtunnel sits in this account's temp
	// folder with whatever rights that folder hands down; an elevated
	// install would have made it Administrators-only, and so does this.
	if elevated, eerr := elevate.IsElevated(); eerr == nil && elevated {
		path, perr := machineAnchorPath(env)
		if perr != nil {
			t.Fatalf("seed the enrolment anchor: %v", perr)
		}
		tree := filepath.Dir(filepath.Dir(filepath.Dir(path)))
		acl, aerr := winkeys.MachineTreeACL()
		if aerr != nil {
			t.Fatalf("seed the enrolment anchor: tree ACL: %v", aerr)
		}
		release, lerr := winkeys.LockTree(tree, acl, true, nil)
		if lerr != nil {
			t.Fatalf("seed the enrolment anchor: lock %s: %v", tree, lerr)
		}
		release()
	}
}

// relaxAnchorAncestorCheck is the cross-platform name of the seam
// relaxation; on non-Windows there is no anchor and nothing to relax.
func relaxAnchorAncestorCheck(t *testing.T) { f04RelaxAncestorCheck(t) }
