package main

// iamt249_server_systemd_install_test.go — IAMT-249: the systemd half of
// `server install`/`server uninstall` (SPEC §3.2.1) — the machine's
// auto-start through the iamtunnel-machine.service unit, the same
// systemdSetup seam the gateway half uses (IAMT-177).
//
// The tests check the unit's CONTENTS, the seam's call SEQUENCE, and that
// install/uninstall do NOT touch what they must not touch; no real
// id/useradd/systemctl is ever run from the tests — the production
// linuxSystemd is swapped for a recording fake (the systemdRecorder from
// iamt177_systemd_install_test.go, same-package).

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIAMT249_MachineUnitFileCarriesSpec3221 — the unit contents canary:
// the three directives §3.2.1 names verbatim (User=root,
// Restart=on-failure, KillMode=mixed), a start command with the same
// binary and data directory install used, and the gateway unit's
// hardening block.
//
// Canary: drop "KillMode=mixed" (or "Restart=on-failure", "User=root")
// from machineUnitFile — the test turns red on the corresponding assertion
// naming the missing directive; change ExecStart to "server start
// --key-file" — the ExecStart assertion and the "the unit does not pin
// osUser" assertion turn red.
func TestIAMT249_MachineUnitFileCarriesSpec3221(t *testing.T) {
	const bin = "/usr/local/bin/iamtunnel"
	const dataDir = "/var/lib/iamtunnel-machine"
	unit := machineUnitFile(bin, dataDir)

	for _, directive := range []string{
		// §3.2.1: "User=root, Restart=on-failure, KillMode=mixed —
		// only the server gets SIGTERM and removes its own line; SIGKILL
		// for the whole group only on timeout".
		"User=root\n",
		"Restart=on-failure\n",
		"KillMode=mixed\n",
		// Service type: the server is an ordinary long-lived process (not
		// oneshot and not forking: the door and the tunnel live inside it).
		"Type=simple\n",
		// Explicit stop with the same signal `server stop` governs (on
		// SIGTERM the server removes its own line and closes the tunnel,
		// §3.2) — as in the gateway unit.
		"ExecStop=/bin/kill -SIGTERM $MAINPID\n",
		// Auto-start: enable --now activates precisely this [Install].
		"WantedBy=multi-user.target\n",
		// Network and clocks before the start — as in the gateway unit: the
		// machine dials the gateway, and it must not stamp its journal lines
		// with unset clocks. (After network-online.time-sync, After= carries
		// three more sshd unit names — a separate assertion below checks
		// them, which is why this is Wants here, not a shortened After.)
		"Wants=network-online.target time-sync.target\n",
		// The three sshd unit names the §3.2.1 pre-flight accepts — order
		// only (no Wants/Requires).
		"After=network-online.target time-sync.target ssh.service sshd.service ssh.socket\n",
		// Hardening carried over from the gateway unit.
		"NoNewPrivileges=yes\n",
		"PrivateTmp=yes\n",
		"ProtectSystem=full\n",
		"AmbientCapabilities=\n",
		"LimitNOFILE=65536\n",
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("IAMT-249: the unit does NOT contain the %q directive from SPEC §3.2.1.\nunit:\n%s", directive, unit)
		}
	}

	// ExecStart runs the same binary install installed, with the same data
	// directory; the role is precisely "server start", and manual start
	// stays the same code (no separate "server run").
	if !strings.Contains(unit, "ExecStart="+bin+" server start --data-dir "+dataDir+"\n") {
		t.Errorf("IAMT-249: ExecStart does not assemble the start command with the binary and the data directory.\nunit:\n%s", unit)
	}
	// Parametrization: a different directory means a different unit
	// (otherwise the default directory would end up on disk instead of the
	// operator's choice).
	custom := machineUnitFile(bin, "/srv/iamt-machine")
	if !strings.Contains(custom, "ExecStart="+bin+" server start --data-dir /srv/iamt-machine\n") {
		t.Errorf("IAMT-249: ExecStart does not follow --data-dir (/srv/iamt-machine):\n%s", custom)
	}
	if strings.Contains(custom, dataDir) {
		t.Errorf("IAMT-249: the unit kept the default data directory alongside the given one:\n%s", custom)
	}
	otherBin := machineUnitFile("/opt/iamtunnel", dataDir)
	if !strings.Contains(otherBin, "ExecStart=/opt/iamtunnel server start ") {
		t.Errorf("IAMT-249: ExecStart does not follow the binary path:\n%s", otherBin)
	}

	// §3.2.1 knows no --public-host: only the gateway requires it
	// (IAMT-202). Canary: copy ExecStart from gatewayUnitFile wholesale —
	// turns red right here.
	if strings.Contains(unit, "--public-host") {
		t.Errorf("IAMT-249: the machine unit must not carry --public-host (that is the gateway's flag):\n%s", unit)
	}

	// No pinning of osUser in the unit: the door's path
	// (<home>/.ssh/authorized_keys) is computed from the enrolment record,
	// and osUser changes (`admin machines set-user`, §3.3). If the unit
	// carried the user's home (--key-file <home>/.ssh/authorized_keys),
	// then after a user change the door would silently write to the wrong
	// place — exactly the defect class IAMT-248 dealt with.
	if strings.Contains(unit, "--key-file") {
		t.Errorf("IAMT-249: the unit must not pin the door's path (--key-file): osUser is set by enrolment and changes through machines set-user:\n%s", unit)
	}
}

// TestIAMT249_MachineUnitDeliberatelyDropsProtectHome — the hardening
// decision pinned by a test, not only by a comment: the gateway has
// ProtectHome=yes; the machine must not have it and cannot.
//
// Canary: copy the gateway variant's "ProtectHome=yes" line into
// machineUnitFile — the first assertion turns red, explaining that the
// door lives in <home>/.ssh/authorized_keys and that under
// ProtectHome=yes its path is unreachable; set ProtectSystem=strict —
// the second turns red (the pre-flight calls `systemctl is-active`, which
// needs the D-Bus socket in /run that strict takes away).
func TestIAMT249_MachineUnitDeliberatelyDropsProtectHome(t *testing.T) {
	unit := machineUnitFile("/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine")

	if strings.Contains(unit, "ProtectHome") {
		t.Errorf("IAMT-249: the machine unit cannot carry ProtectHome: the door is an entry in <osUser-home>/.ssh/authorized_keys (SPEC §3.2.1), and ProtectHome=yes makes /home and /root unreachable, so the door would never open.\nunit:\n%s", unit)
	}
	if !strings.Contains(unit, "ProtectSystem=full\n") {
		t.Errorf("IAMT-249: expected ProtectSystem=full (see §3.2.1 and the decision in the report): strict takes away /run, and the pre-flight `server start` calls systemctl is-active.\nunit:\n%s", unit)
	}
	if strings.Contains(unit, "ProtectSystem=strict") {
		t.Errorf("IAMT-249: ProtectSystem=strict in the machine unit would break the pre-flight (systemd's D-Bus socket lives in /run):\n%s", unit)
	}
	// ReadWritePaths is only needed by strict; under full it would be a dead line.
	if strings.Contains(unit, "ReadWritePaths") {
		t.Errorf("IAMT-249: ReadWritePaths without ProtectSystem=strict is a dead directive:\n%s", unit)
	}
}

// TestIAMT249_InstallWritesMachineUnitAndRunsSharedTail — the install
// sequence canary: the systemd directory (the machine's unit, not the
// gateway's), exactly one writeUnit, then daemon-reload → enable → start
// in that order, and NOT A SINGLE call into the seam's user half (the
// unit runs as root, not under a service user as the gateway's does).
//
// Canary: reorder systemdInstallTail or call
// userExists/createUser/chownDir from setupMachineSystemd — the
// assertions about rec.order and the empty user-step logs turn red.
func TestIAMT249_InstallWritesMachineUnitAndRunsSharedTail(t *testing.T) {
	const bin = "/usr/local/bin/iamtunnel"
	const dataDir = "/var/lib/iamtunnel-machine"

	rec := &systemdRecorder{}
	if err := setupMachineSystemd(rec.setup(), bin, dataDir); err != nil {
		t.Fatalf("setupMachineSystemd: %v", err)
	}
	if rec.unitPath != "/etc/systemd/system/iamtunnel-machine.service" {
		t.Fatalf("the unit is not written to /etc/systemd/system under the name from SPEC §3.2.1: %q", rec.unitPath)
	}
	want := machineUnitFile(bin, dataDir)
	if rec.unitContent != want {
		t.Fatalf("the wrong unit went to disk:\nwant:\n%s\ngot:\n%s", want, rec.unitContent)
	}
	wantOrder := []string{
		"writeUnit",
		"systemctl: daemon-reload",
		"systemctl: enable iamtunnel-machine.service",
		"systemctl: start iamtunnel-machine.service",
	}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("install sequence = %v, wanted %v", rec.order, wantOrder)
	}
	// The machine's unit runs as root (SPEC §3.2.1): no service user is
	// created, no directory is re-owned. Canary: call setup.userExists
	// from setupMachineSystemd — turns red here.
	if len(rec.userExistsCalls) != 0 || len(rec.createUserCalls) != 0 || len(rec.chownDirCalls) != 0 {
		t.Fatalf("the machine's install must not touch the seam's user half: userExists=%v createUser=%v chownDir=%v",
			rec.userExistsCalls, rec.createUserCalls, rec.chownDirCalls)
	}
}

// TestIAMT249_InstallFailureStopsAndNamesTheStep — a failure of any step
// stops the sequence and is named to the operator by name.
//
// Canary: return a bare error without the envErrf wrapper from
// setupMachineSystemd, or keep the sequence going after a failure — the
// assertion about the text / log tail turns red.
func TestIAMT249_InstallFailureStopsAndNamesTheStep(t *testing.T) {
	t.Run("write unit fails", func(t *testing.T) {
		rec := &systemdRecorder{writeUnitResult: errors.New("read-only file system")}
		err := setupMachineSystemd(rec.setup(), "/b", "/var/lib/iamtunnel-machine")
		if err == nil || !strings.Contains(err.Error(), "write the systemd unit") {
			t.Fatalf("the error does not name the unit write step: %v", err)
		}
		if len(rec.systemctlCalls) != 0 {
			t.Fatalf("after a unit write failure systemctl must not be called: %v", rec.systemctlCalls)
		}
	})

	t.Run("systemctl fails", func(t *testing.T) {
		rec := &systemdRecorder{systemctlResult: errors.New("System has not been booted with systemd")}
		err := setupMachineSystemd(rec.setup(), "/b", "/var/lib/iamtunnel-machine")
		if err == nil || !strings.Contains(err.Error(), "server install: systemctl daemon-reload") {
			t.Fatalf("the error does not name the systemctl command and step: %v", err)
		}
		if len(rec.systemctlCalls) != 1 {
			t.Fatalf("after the first systemctl failure there is no going on: %v", rec.systemctlCalls)
		}
		// The hint must name the machine's unit, not the gateway's.
		if !strings.Contains(err.Error(), machineUnitName) || strings.Contains(err.Error(), gatewayUnitName) {
			t.Fatalf("the hint names the wrong unit: %v", err)
		}
	})
}

// TestIAMT249_UninstallSequenceRemovesOnlyTheMachineUnit — the uninstall
// canary: no unit — "nothing to do" and exactly one unitExists call;
// present — disable --now → remove the file → daemon-reload, in that
// order and at the machine's path.
//
// Canary: remove the file before disable or drop daemon-reload — the
// rec.order comparison turns red.
func TestIAMT249_UninstallSequenceRemovesOnlyTheMachineUnit(t *testing.T) {
	const unitPath = "/etc/systemd/system/iamtunnel-machine.service"

	t.Run("absent unit is a nothing-to-do", func(t *testing.T) {
		rec := &systemdRecorder{} // unitExistsResult == false
		removed, err := uninstallMachineSystemdUnit(rec.setup())
		if err != nil || removed {
			t.Fatalf("a missing unit = (false, nil), got (%v, %v)", removed, err)
		}
		if !reflect.DeepEqual(rec.order, []string{"unitExists"}) {
			t.Fatalf("nothing but the unit lookup may be called: %v", rec.order)
		}
	})

	t.Run("present unit is disabled removed and reloaded in order", func(t *testing.T) {
		rec := &systemdRecorder{unitExistsResult: true}
		removed, err := uninstallMachineSystemdUnit(rec.setup())
		if err != nil || !removed {
			t.Fatalf("wanted (true, nil), got (%v, %v)", removed, err)
		}
		wantOrder := []string{
			"unitExists",
			"systemctl: disable --now iamtunnel-machine.service",
			"removeUnit",
			"systemctl: daemon-reload",
		}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("uninstall sequence = %v, wanted %v", rec.order, wantOrder)
		}
		if !reflect.DeepEqual(rec.removeUnitCalls, []string{unitPath}) {
			t.Errorf("the unit is removed from a path other than /etc/systemd/system: %v", rec.removeUnitCalls)
		}
	})
}

// TestIAMT249_ServerInstallCLI — the CLI level: on Linux `server install`
// reaches the seam and prints what exactly was installed; on a host
// without a service half — a clean refusal that touches no seam and
// nothing on disk.
//
// Canary: drop the platform check from runServerInstall — on
// windows/darwin the "refusal + zero seam calls" assertion turns red;
// drop the printing of the not-registered note — the linux branch turns
// red (t.TempDir() holds no enrolment record).
func TestIAMT249_ServerInstallCLI(t *testing.T) {
	sd := withFakeSystemd(t)
	svc := withFakeGatewayService(t)
	ld := withFakeLaunchd(t)
	// The data directory does not exist yet: t.TempDir() would have created
	// it itself, and the "the refusal creates nothing" assertion would then
	// prove the test created the directory, not install.
	dir := filepath.Join(t.TempDir(), "machine-data")

	out, errs, code := drive(t, "server", "install", "--data-dir", dir)

	switch runtime.GOOS {
	case "linux":
		if code != exitOK {
			t.Fatalf("server install on Linux must succeed (exitOK), got %d; errs=%q", code, errs)
		}
		if sd.unitPath != "/etc/systemd/system/iamtunnel-machine.service" {
			t.Fatalf("install must write the machine's unit through the seam, got %q", sd.unitPath)
		}
		if !strings.Contains(sd.unitContent, "server start --data-dir "+dir) {
			t.Fatalf("ExecStart must carry the chosen --data-dir (%s):\n%s", dir, sd.unitContent)
		}
		wantTail := []string{"daemon-reload", "enable iamtunnel-machine.service", "start iamtunnel-machine.service"}
		if !reflect.DeepEqual(sd.systemctlCalls, wantTail) {
			t.Fatalf("install tail = %v, wanted %v", sd.systemctlCalls, wantTail)
		}
		if len(sd.userExistsCalls) != 0 || len(sd.createUserCalls) != 0 || len(sd.chownDirCalls) != 0 {
			t.Fatalf("the machine's install creates no service user: %v %v %v",
				sd.userExistsCalls, sd.createUserCalls, sd.chownDirCalls)
		}
		if !strings.Contains(out, "iamtunnel-machine.service") {
			t.Fatalf("install's output must name the installed unit: %q", out)
		}
		// The machine's data directory is created and locked down (SPEC §3.2.1: 0700).
		if !fileExists(dir) {
			t.Fatalf("install must create the machine's data directory %s", dir)
		}
		// t.TempDir() holds no enrolment record: install tolerates that but
		// must say the unit would run into a refusal and what to do next.
		if !strings.Contains(out, "not registered yet") || !strings.Contains(out, "enrol") {
			t.Fatalf("install on an unenrolled machine must warn about enrol; out=%q", out)
		}
		// Foreign service halves are not touched.
		if len(svc.serviceExistsCalls) != 0 || len(ld.bootstrapCalls) != 0 {
			t.Fatalf("the Linux path must not touch foreign seams: serviceExists=%v bootstrap=%v", svc.serviceExistsCalls, ld.bootstrapCalls)
		}
	case "darwin":
		// IAMT-263: on macOS the machine has its own half — the
		// com.iamtunnel.machine.plist LaunchDaemon through the same launchd
		// seam.
		if code != exitOK {
			t.Fatalf("server install on macOS must succeed (exitOK), got %d; errs=%q", code, errs)
		}
		if len(ld.writePlistCalls) != 1 || ld.writePlistCalls[0] != machinePlistPath+":0644:0:0" {
			t.Fatalf("install must write the machine's plist (0644 root:wheel) through the seam: %v", ld.writePlistCalls)
		}
		if !reflect.DeepEqual(ld.bootstrapCalls, []string{machinePlistPath}) {
			t.Fatalf("install must load the job from %s: %v", machinePlistPath, ld.bootstrapCalls)
		}
		// IAMT-289: ProgramArguments is an argv ARRAY, each element its own
		// <string>, in argv order; launchd runs the program directly, with
		// no shell, so "one line with all the arguments" would be a real
		// defect (launchd would look for a program with that name). Both
		// sides are checked: four separate elements in order and no merged
		// form.
		wantArgs := []string{"server", "start", "--data-dir", dir}
		idx := 0
		for _, want := range wantArgs {
			el := "<string>" + want + "</string>"
			j := strings.Index(ld.lastPlist[idx:], el)
			if j < 0 {
				t.Fatalf("ProgramArguments must carry %q as a separate <string> and in argv order (--data-dir %s); document:\n%s", want, dir, ld.lastPlist)
			}
			idx += j + len(el)
		}
		if strings.Contains(ld.lastPlist, "<string>server start --data-dir") {
			t.Fatalf("the arguments are merged into one <string>: launchd would get a single program \"server start --data-dir …\" instead of an argv array:\n%s", ld.lastPlist)
		}
		if strings.Contains(ld.lastPlist, "<key>UserName</key>") {
			t.Fatalf("the machine's plist must not name UserName (the job runs as root):\n%s", ld.lastPlist)
		}
		if len(ld.createUserCalls) != 0 || len(ld.lookupUserCalls) != 0 || len(ld.chownCalls) != 0 {
			t.Fatalf("the machine's install creates no service user: create=%v lookup=%v chown=%v",
				ld.createUserCalls, ld.lookupUserCalls, ld.chownCalls)
		}
		if len(sd.systemctlCalls) != 0 || sd.unitContent != "" {
			t.Fatalf("the macOS path must not touch the systemd seam: systemctl=%v unitWritten=%v", sd.systemctlCalls, sd.unitContent != "")
		}
		if len(svc.serviceExistsCalls) != 0 {
			t.Fatalf("the macOS path must not touch the SCM seam: %v", svc.serviceExistsCalls)
		}
		if !strings.Contains(out, machinePlistPath) || !strings.Contains(out, "LaunchDaemon") {
			t.Fatalf("install's output must name the LaunchDaemon and its path: %q", out)
		}
		if !fileExists(dir) {
			t.Fatalf("install must create the machine's data directory %s", dir)
		}
		// The enrolment hint is in Mac idiom (launchctl, not systemctl).
		if !strings.Contains(out, "not registered yet") || !strings.Contains(out, "launchctl kickstart") {
			t.Fatalf("the note on macOS must name launchctl kickstart; out=%q", out)
		}
		if strings.Contains(out, "systemctl") {
			t.Fatalf("the note on macOS must not send the operator to systemctl; out=%q", out)
		}
	case "windows":
		// IAMT-337 / 1.4: Windows got its own auto-start half — a per-user
		// logon task (server_task.go) — so the "platform not supported"
		// refusal is gone from here. There is a refusal, but for a different
		// and more important reason: the PERSONAL auto-start is named after
		// the enrolment record and bound to the account that record carries,
		// and an unenrolled machine has neither. The impersonal Unix service
		// can be installed before enrol; this one cannot, and the refusal
		// must name the command that comes first.
		if code != exitUser {
			t.Fatalf("server install on an unenrolled Windows machine must refuse (exitUser), got %d; out=%q errs=%q", code, out, errs)
		}
		if !strings.Contains(errs, "not registered yet") || !strings.Contains(errs, "iamtunnel enrol") {
			t.Fatalf("the refusal must explain the machine is not enrolled and name enrol: %q", errs)
		}
		if len(sd.systemctlCalls) != 0 || sd.unitContent != "" || len(svc.serviceExistsCalls) != 0 || len(ld.bootstrapCalls) != 0 {
			t.Fatalf("the refusal must not touch a single seam: systemctl=%v unitWritten=%v serviceExists=%v bootstrap=%v",
				sd.systemctlCalls, sd.unitContent != "", svc.serviceExistsCalls, ld.bootstrapCalls)
		}
		if fileExists(dir) {
			t.Fatalf("the refusal must be clean: the data directory %s must not be created", dir)
		}
	default:
		if code != exitEnv {
			t.Fatalf("server install on %s must refuse (exitEnv), got %d; out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
		if !strings.Contains(errs, "supports Linux") {
			t.Fatalf("the refusal must name the supported OSes: %q", errs)
		}
		if len(sd.systemctlCalls) != 0 || sd.unitContent != "" || len(svc.serviceExistsCalls) != 0 || len(ld.bootstrapCalls) != 0 {
			t.Fatalf("the refusal must not touch a single seam: systemctl=%v unitWritten=%v serviceExists=%v bootstrap=%v",
				sd.systemctlCalls, sd.unitContent != "", svc.serviceExistsCalls, ld.bootstrapCalls)
		}
		if fileExists(dir) {
			t.Fatalf("the refusal must be clean: the data directory %s must not be created (nothing on disk before the service half)", dir)
		}
	}
}

// TestIAMT249_ServerInstallStaysQuietWhenRegistered — the other side of
// the note: on an enrolled machine install does not startle the operator
// with the enrol hint. Checked on Linux and macOS; on other OSes the
// command refuses before printing (already covered above).
func TestIAMT249_ServerInstallStaysQuietWhenRegistered(t *testing.T) {
	// IAMT-263: the machine now has two service halves — systemd on Linux
	// and launchd on macOS; a successful install (and therefore the note)
	// exists on both.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("only a successful install can print the note, and it exists only on Linux and macOS")
	}
	// Both seams are substituted, and that is not a formality: install
	// REACHES the service half (it succeeds — that is the point of the
	// test), so on macOS without withFakeLaunchd it would land in the real
	// darwinLaunchd, whose guardProductionLaunchd panics — the test would
	// take down the whole package and, worse, in a live run on someone's
	// Mac it would touch the real launchd. IAMT-285: the substitution was
	// missing precisely here (the file's neighbouring tests do it;
	// TestIAMT249_ServerInstallCLI substitutes all three seams).
	withFakeSystemd(t)
	withFakeLaunchd(t)
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)

	out, errs, code := drive(t, "server", "install", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("install on an enrolled machine: code=%d errs=%q", code, errs)
	}
	if strings.Contains(out, "not registered yet") {
		t.Fatalf("install on an enrolled machine must not print the enrol note; out=%q", out)
	}
}

// TestIAMT249_ServerUninstallCLIReportsIdempotently — the CLI level of
// uninstall: no unit → exitOK and "nothing to do"; present → exitOK,
// "stopped and removed" and the line about the untouched data directory
// (§3.2.1's promise visible to the operator).
//
// Canary: make a missing unit an error or drop the untouched-directory
// line — the corresponding assertion turns red.
func TestIAMT249_ServerUninstallCLIReportsIdempotently(t *testing.T) {
	// IAMT-263: the machine has two service halves — the systemd unit on
	// Linux and the LaunchDaemon on macOS; both subcommands run here, each
	// on its own seam, and on other OSes uninstall refuses (covered by
	// TestIAMT249_ServerInstallCLI).
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the machine's uninstall has a service half only on Linux and macOS")
	}
	sd := withFakeSystemd(t)
	ld := withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "server", "uninstall", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "not installed; nothing to do") {
		t.Fatalf("no service: code=%d out=%q errs=%q", code, out, errs)
	}
	if len(sd.systemctlCalls) != 0 {
		t.Fatalf("with the unit absent systemctl must not be called: %v", sd.systemctlCalls)
	}
	if len(ld.bootoutCalls) != 0 || len(ld.removePlistCalls) != 0 {
		t.Fatalf("with the plist absent launchctl/bootout must not be called: bootout=%v remove=%v", ld.bootoutCalls, ld.removePlistCalls)
	}

	// "The service is present" has its own shape per half: the unit file on
	// Linux, the plist on macOS.
	sd.unitExistsResult = true
	ld.plistExistsRes = true
	out, errs, code = drive(t, "server", "uninstall", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "stopped and removed") {
		t.Fatalf("service present: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, dir) {
		t.Fatalf("the output must name the untouched data directory %s: out=%q", dir, out)
	}
	if strings.Contains(out, "host key") {
		t.Fatalf("the untouched-directory promise must name the MACHINE's artefacts (machine.key/enrolment), not the gateway's: out=%q", out)
	}
	if runtime.GOOS == "linux" && len(sd.removeUnitCalls) == 0 {
		t.Fatalf("on Linux uninstall must take the unit down through the systemd seam: %v", sd.systemctlCalls)
	}
	if runtime.GOOS == "darwin" && !reflect.DeepEqual(ld.removePlistCalls, []string{machinePlistPath}) {
		t.Fatalf("on macOS uninstall must take the plist down through the launchd seam: %v", ld.removePlistCalls)
	}
}

// TestIAMT249_StopAndStatusDoNotDependOnHowTheServerWasStarted — the
// requirement that "stop/status behave the same whether the server was
// started under the unit or manually": both subcommands work through
// control.json and NEVER ask systemd, so a unit-launched start does not
// change their behaviour. That is pinned literally here: a live
// control-listener is brought up by the same production functions
// `server start` uses (serveControl + control.json), and the unit on disk
// "exists" (rec.unitExistsResult = true) — and still not a single seam
// call.
//
// Canary: make cmdServerStopStatus go to systemd (say, "if the unit is
// present, call systemctl") — the zero-seam-calls assertion turns red;
// break the control.json handling — the assertions about
// "running"/"was stopped".
func TestIAMT249_StopAndStatusDoNotDependOnHowTheServerWasStarted(t *testing.T) {
	sd := withFakeSystemd(t)
	// The unit is "installed": that is exactly the state a machine with
	// auto-start is in, and exactly the state that must change nothing for
	// stop/status.
	sd.unitExistsResult = true

	dir := t.TempDir()
	seedEnrolledMachine(t, dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	token := "iamt249-control-token"
	port := ln.Addr().(*net.TCPAddr).Port
	// atomicWriteJSON, not atomicWriteMachineJSON: the file's contents are
	// the same, but the "machine" writer attaches the {SYSTEM,
	// Administrators} DACL on Windows (IAMT-213) — a test process without
	// administrator rights would lose access to the file it had just
	// created. seedEnrolledMachine seeds its files with the same writer.
	if werr := atomicWriteJSON(controlFilePath(dir), controlFileRecord{PID: os.Getpid(), Port: port, Token: token}); werr != nil {
		t.Fatalf("control.json: %v", werr)
	}
	stopped := make(chan struct{})
	var once sync.Once
	// tail is nil here on purpose: this test is about stop/status, and a
	// nil tailFunc is the honest "this caller has no tunnel to relay
	// through" — handleTailCommand answers it with its own words and no
	// gateway verdict (IAMT-340).
	go serveControl(ln, dir, token, func() { once.Do(func() { close(stopped) }) }, func() (bool, bool) { return true, false }, nil, nil, nil)

	out, errs, code := drive(t, "server", "status", "--data-dir", dir)
	// The PID in the response is the PID of the process holding the
	// control-listener (handleControlConn answers os.Getpid()), i.e. here
	// the test binary's PID: it plays the role of "the server started by
	// the unit".
	if code != exitOK || !strings.Contains(out, "the server is running (pid "+strconv.Itoa(os.Getpid())+")") {
		t.Fatalf("status with a live control-listener: code=%d out=%q errs=%q", code, out, errs)
	}

	out, errs, code = drive(t, "server", "stop", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "was stopped") {
		t.Fatalf("stop with a live control-listener: code=%d out=%q errs=%q", code, out, errs)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop never reached the live server's onStop")
	}
	if fileExists(controlFilePath(dir)) {
		t.Fatal("control.json must be removed by a successful stop (otherwise the next start sees the ghost of the previous run)")
	}
	if len(sd.systemctlCalls) != 0 || sd.unitContent != "" || len(sd.removeUnitCalls) != 0 {
		t.Fatalf("stop/status must not touch systemd (they work through control.json): systemctl=%v unitWritten=%v removeUnit=%v",
			sd.systemctlCalls, sd.unitContent != "", sd.removeUnitCalls)
	}
}
