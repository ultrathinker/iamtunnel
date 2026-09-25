package main

// iamt263_server_launchd_test.go — IAMT-263: the macOS half of
// `server install`/`uninstall` (SPEC §3.2.1) — the LaunchDaemon
// com.iamtunnel.machine.plist for the machine role, the same
// darwinLaunchdSetup seam as the gateway's half (IAMT-259), and the
// same shared install/uninstall tails (launchdBootstrapTail /
// launchdTeardownTail) that appeared when the skeleton was split in
// IAMT-263.
//
// The file is deliberately platform-neutral: the plist render and the
// sequences are pure, so they are checked with the recording fake on
// any host OS. The darwin branch's CLI path runs only on a darwin host
// (that is where it is selected by runtime.GOOS) — a separate subtest
// in TestIAMT249_ServerInstallCLI and the iamt264 tests.

import (
	"encoding/xml"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestIAMT263_MachinePlistIsARootJobWithRestartOnFailure — the canary
// for the machine plist's contents. Three things distinguish it from
// the gateway's plist, and all three are SPEC §3.2.1 prescriptions, not
// matters of taste:
//
//   - no UserName key: the job runs as root (the door is written into
//     someone else's home directory, so it cannot be an unprivileged
//     service);
//   - KeepAlive = SuccessfulExit=false: restart only after an
//     UNSUCCESSFUL exit — the macOS form of Restart=on-failure, so an
//     ordinary `server stop` is not undone by a restart while a crash
//     is;
//   - output to machine.log, not gateway.log.
//
// Canary: put UserName _iamtunnel back into the plist (copying the
// gateway's set of values) — the absence-of-key assertion turns red;
// replace KeepAlive with <true/> — the SuccessfulExit assertion turns
// red.
func TestIAMT263_MachinePlistIsARootJobWithRestartOnFailure(t *testing.T) {
	const bin = "/usr/local/bin/iamtunnel"
	const dataDir = "/var/lib/iamtunnel-machine"
	plist, err := machineLaunchdPlist(bin, dataDir)
	if err != nil {
		t.Fatalf("machineLaunchdPlist: %v", err)
	}
	for _, want := range []string{
		"<string>" + machinePlistLabel + "</string>",
		"<key>RunAtLoad</key>",
		"<key>ProgramArguments</key>",
		"<string>" + bin + "</string>",
		"<string>server</string>",
		"<string>start</string>",
		"<string>--data-dir</string>",
		"<string>" + dataDir + "</string>",
		"<key>StandardOutPath</key>\n  <string>" + machineLogPath + "</string>",
		"<key>StandardErrorPath</key>\n  <string>" + machineLogPath + "</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("IAMT-263: the machine plist does not contain %q:\n%s", want, plist)
		}
	}
	// §3.2.1: the job runs as root — there must be no UserName key at
	// all (launchd runs as root by default).
	if strings.Contains(plist, "<key>UserName</key>") {
		t.Errorf("IAMT-263: the machine plist must not name UserName — the job runs as root (§3.2.1):\n%s", plist)
	}
	if strings.Contains(plist, darwinServiceUser) {
		t.Errorf("IAMT-263: the machine plist must not mention the service user %s:\n%s", darwinServiceUser, plist)
	}
	// Restart=on-failure, the macOS way.
	if !strings.Contains(plist, "<key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>") {
		t.Errorf("IAMT-263: KeepAlive must be SuccessfulExit=false (an ordinary stop must not be undone by a restart):\n%s", plist)
	}
	if strings.Contains(plist, "<key>KeepAlive</key>\n  <true/>") {
		t.Errorf("IAMT-263: KeepAlive=true (the gateway form) does not suit the machine role — it undoes an ordinary stop:\n%s", plist)
	}
	// The data directory is parameterized, not hardwired.
	other, err := machineLaunchdPlist(bin, "/srv/iamt-machine")
	if err != nil {
		t.Fatalf("machineLaunchdPlist(other dir): %v", err)
	}
	if !strings.Contains(other, "<string>/srv/iamt-machine</string>") || strings.Contains(other, dataDir) {
		t.Errorf("IAMT-263: --data-dir does not come through into the plist:\n%s", other)
	}
}

// TestIAMT263_MachinePlistEscapesItsValues — the plist's values are
// escaped as XML (the shared renderLaunchdPlistDoc): a path with "&" or
// a quote must not tear apart the document that launchd would refuse to
// parse.
//
// Canary: drop xml.EscapeText from the render — the comparison with the
// expected escaping turns red.
//
// The expected escaped value is built by xml.EscapeText itself, not by
// a literal in the test: the render must ESCAPE the value, and which
// entity form to pick is encoding/xml's business and must not be pinned
// here. It writes `'` as a numeric reference (`&#39;`), not a named one
// (`&apos;`); both forms are valid XML and both are accepted equally by
// launchd/plutil, so hardcoding one of them makes the test red on
// correct code (exactly what happened in acceptance). What is pinned
// here is form-independent: the raw value did not get into the
// document, and the escaped value is present in it.
//
// Canary: drop xml.EscapeText from renderLaunchdPlistDoc — the
// raw-value assertion turns red (it would end up in the plist as
// is).
func TestIAMT263_MachinePlistEscapesItsValues(t *testing.T) {
	const rawExe = "/opt/a&b/iamtunnel"
	const rawDir = `/srv/it's ok`
	plist, err := machineLaunchdPlist(rawExe, rawDir)
	if err != nil {
		t.Fatalf("machineLaunchdPlist: %v", err)
	}
	for _, raw := range []string{rawExe, rawDir} {
		if strings.Contains(plist, raw) {
			t.Errorf("IAMT-263: the raw value %q got into the plist unescaped:\n%s", raw, plist)
		}
		if want := xmlEscapeForTest(t, raw); !strings.Contains(plist, want) {
			t.Errorf("IAMT-263: expected the escaped value %q for %q:\n%s", want, raw, plist)
		}
	}
}

// xmlEscapeForTest builds the expected form the same way the render
// builds it: if encoding/xml ever changes its entity form, the test
// follows along instead of turning red.
func xmlEscapeForTest(t *testing.T, s string) string {
	t.Helper()
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		t.Fatalf("xml.EscapeText(%q): %v", s, err)
	}
	return b.String()
}

// TestIAMT263_InstallSequenceBootstrapsTheMachineJob — the canary for
// the machine install sequence: root → log directory → writePlist
// (0644, root:wheel) → "loaded?" → (bootout) → bootstrap, and NOT ONE
// call of the user half of the seam: no dscl user is created for the
// machine role, and no directories are re-owned (the job runs as
// root).
//
// Canary: call setup.lookupUser/createUser/chownDir from
// setupMachineLaunchd or change the order in launchdBootstrapTail —
// the corresponding assertions turn red.
func TestIAMT263_InstallSequenceBootstrapsTheMachineJob(t *testing.T) {
	t.Run("fresh install", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true}
		if err := setupMachineLaunchd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine"); err != nil {
			t.Fatalf("setupMachineLaunchd: %v", err)
		}
		wantOrder := []string{"root", "makeLogDir", "writePlist", "loaded", "bootstrap"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("install sequence = %v, expected %v", rec.order, wantOrder)
		}
		if !reflect.DeepEqual(rec.makeLogDirCalls, []string{darwinLogDir}) {
			t.Errorf("log directory = %v, expected %s", rec.makeLogDirCalls, darwinLogDir)
		}
		if !reflect.DeepEqual(rec.writePlistCalls, []string{machinePlistPath + ":0644:0:0"}) {
			t.Errorf("the plist is not written as %s with 0644 root:wheel: %v", machinePlistPath, rec.writePlistCalls)
		}
		want := mustMachinePlist(t, "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine")
		if rec.lastPlist != want {
			t.Fatalf("the wrong plist reached disk:\nwant:\n%s\ngot:\n%s", want, rec.lastPlist)
		}
		if !reflect.DeepEqual(rec.bootstrapCalls, []string{machinePlistPath}) {
			t.Errorf("bootstrap = %v, expected %s", rec.bootstrapCalls, machinePlistPath)
		}
		if len(rec.lookupUserCalls) != 0 || len(rec.createUserCalls) != 0 || len(rec.chownCalls) != 0 {
			t.Fatalf("the machine install must not touch the user half of the seam: lookup=%v create=%v chown=%v",
				rec.lookupUserCalls, rec.createUserCalls, rec.chownCalls)
		}
	})

	t.Run("repeat install boots the old job out first", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, loadedRes: true}
		if err := setupMachineLaunchd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine"); err != nil {
			t.Fatalf("setupMachineLaunchd (repeat): %v", err)
		}
		wantOrder := []string{"root", "makeLogDir", "writePlist", "loaded", "bootout", "bootstrap"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("a repeat install must unload the old job before bootstrap: %v", rec.order)
		}
		if !reflect.DeepEqual(rec.bootoutCalls, []string{machinePlistLabel}) {
			t.Errorf("bootout = %v, expected label %s", rec.bootoutCalls, machinePlistLabel)
		}
	})
}

// TestIAMT263_InstallFailureStopsAndNamesTheStep — a failure of any
// step stops the sequence and is named to the operator, with §3.2.1 in
// the root refusal text (not the gateway's §3.5.1).
//
// Canary: drop the envErrf wrapper or continue the sequence after a
// failure — the text/journal-tail assertion turns red.
func TestIAMT263_InstallFailureStopsAndNamesTheStep(t *testing.T) {
	t.Run("needs root", func(t *testing.T) {
		rec := &launchdRecorder{} // rootResult == false
		err := setupMachineLaunchd(rec.setup(), "/b", "/d")
		if err == nil || !strings.Contains(err.Error(), "needs root") {
			t.Fatalf("the no-root refusal must name sudo: %v", err)
		}
		// The SPEC paragraph reference must be the machine one, not the gateway's.
		if !strings.Contains(err.Error(), "§3.2.1") || strings.Contains(err.Error(), "§3.5.1") {
			t.Fatalf("the machine refusal must reference §3.2.1: %v", err)
		}
		if rec.rootCalls != 1 || len(rec.writePlistCalls) != 0 || len(rec.bootstrapCalls) != 0 {
			t.Fatalf("after a root refusal nothing may run: %v %v %v", rec.rootCalls, rec.writePlistCalls, rec.bootstrapCalls)
		}
	})

	t.Run("log dir fails", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, logDirErr: errors.New("read-only file system")}
		err := setupMachineLaunchd(rec.setup(), "/b", "/d")
		if err == nil || !strings.Contains(err.Error(), "create the log directory") {
			t.Fatalf("the error does not name the log-directory step: %v", err)
		}
		if len(rec.writePlistCalls) != 0 {
			t.Fatalf("after a log-directory failure the plist must not be written: %v", rec.writePlistCalls)
		}
	})

	t.Run("write plist fails", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, writePlistErr: errors.New("permission denied")}
		err := setupMachineLaunchd(rec.setup(), "/b", "/d")
		if err == nil || !strings.Contains(err.Error(), "write the LaunchDaemon plist") {
			t.Fatalf("the error does not name the plist-write step: %v", err)
		}
		if len(rec.bootstrapCalls) != 0 {
			t.Fatalf("after a plist-write failure bootstrap must not be called: %v", rec.bootstrapCalls)
		}
	})

	t.Run("bootstrap fails and the job never comes up", func(t *testing.T) {
		// IAMT-308 round 4: runningNotRunning models a GENUINE bootstrap
		// failure (the job never comes up) — a stale "already
		// bootstrapped" EIO 5 with the job actually running is tolerated
		// instead (see the round-4 tests below).
		rec := &launchdRecorder{rootResult: true, bootstrapErr: errors.New("Bootstrap failed: 5: Input/output error"), runningNotRunning: true}
		err := setupMachineLaunchd(rec.setup(), "/b", "/d")
		if err == nil || !strings.Contains(err.Error(), "launchctl bootstrap system "+machinePlistPath) {
			t.Fatalf("the error does not name the bootstrap step and the plist path: %v", err)
		}
		if !strings.Contains(err.Error(), machinePlistPath) {
			t.Fatalf("the hint must name the machine plist: %v", err)
		}
	})
}

// TestIAMT308_MachineRepeatInstallToleratesStaleAlreadyBootstrappedError
// is the machine-role twin of the gateway's round-4 canary: on a real
// Mac, `sudo server install` on an already-installed, already-running
// machine hit the identical "Bootstrap failed: 5: Input/output error"
// and refused, right after the same failure hit `gateway install`. Both
// roles share launchdBootstrapTail, so the fix (tolerate a stale
// "already bootstrapped" bootstrap error when the running check
// confirms the daemon IS up) applies to both — this pins it for the
// machine role specifically.
//
// Canary: return launchdBootstrapTail to refusing immediately on any
// bootstrap error — the "setupMachineLaunchd must succeed" below turns
// red.
func TestIAMT308_MachineRepeatInstallToleratesStaleAlreadyBootstrappedError(t *testing.T) {
	rec := &launchdRecorder{
		rootResult:   true,
		loadedRes:    true,
		bootstrapErr: errors.New("exit status 5: Bootstrap failed: 5: Input/output error"),
		// runningNotRunning defaults to false: the machine daemon is
		// still running — the goal state is reached despite bootstrap's
		// stale EIO 5.
	}
	err := setupMachineLaunchd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine")
	if err != nil {
		t.Fatalf("setupMachineLaunchd must succeed when the daemon is running despite a stale \"already bootstrapped\" bootstrap error: %v", err)
	}
	if !reflect.DeepEqual(rec.bootoutCalls, []string{machinePlistLabel}) {
		t.Fatalf("the previously loaded job must still be torn down before bootstrap: bootout calls = %v", rec.bootoutCalls)
	}
	if len(rec.runningCalls) != 1 {
		t.Fatalf("the running check must still run exactly once, regardless of the stale bootstrap error: got %d calls", len(rec.runningCalls))
	}
}

// TestIAMT263_UninstallSequence — the uninstall canary: no plist —
// "nothing to do" and only plistExists; present and loaded — bootout,
// then remove the file; present and not loaded — just remove the file
// (the job may have died on its own); a bootout failure stops the
// sequence.
//
// Canary: remove the plist before bootout or make uninstall call
// bootstrap — the rec.order comparison turns red.
func TestIAMT263_UninstallSequence(t *testing.T) {
	const unitPath = machinePlistPath

	t.Run("absent plist is a nothing-to-do", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true} // plistExistsRes == false
		removed, err := uninstallMachineLaunchd(rec.setup())
		if err != nil || removed {
			t.Fatalf("a missing plist = (false, nil), got (%v, %v)", removed, err)
		}
		if !reflect.DeepEqual(rec.order, []string{"root", "plistExists"}) {
			t.Fatalf("nothing but the plist lookup may be called: %v", rec.order)
		}
	})

	t.Run("loaded job is booted out then removed", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: true}
		removed, err := uninstallMachineLaunchd(rec.setup())
		if err != nil || !removed {
			t.Fatalf("expected (true, nil), got (%v, %v)", removed, err)
		}
		wantOrder := []string{"root", "plistExists", "loaded", "bootout", "removePlist"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("uninstall sequence = %v, expected %v", rec.order, wantOrder)
		}
		if !reflect.DeepEqual(rec.removePlistCalls, []string{unitPath}) {
			t.Errorf("the plist is not removed through the machine path: %v", rec.removePlistCalls)
		}
	})

	t.Run("job that is not loaded is just removed", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true}
		removed, err := uninstallMachineLaunchd(rec.setup())
		if err != nil || !removed {
			t.Fatalf("expected (true, nil), got (%v, %v)", removed, err)
		}
		if len(rec.bootoutCalls) != 0 {
			t.Fatalf("an unloaded job has nothing to boot out: %v", rec.bootoutCalls)
		}
		if !reflect.DeepEqual(rec.removePlistCalls, []string{unitPath}) {
			t.Errorf("the plist must have been removed: %v", rec.removePlistCalls)
		}
	})

	t.Run("bootout failure stops before removal", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: true, bootoutErr: errors.New("Operation not permitted")}
		_, err := uninstallMachineLaunchd(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "launchctl bootout system/"+machinePlistLabel) {
			t.Fatalf("the error does not name the bootout step: %v", err)
		}
		if len(rec.removePlistCalls) != 0 {
			t.Fatalf("after a bootout failure the plist must not be removed: %v", rec.removePlistCalls)
		}
	})

	t.Run("remove failure is named", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, removePlistErr: errors.New("permission denied")}
		_, err := uninstallMachineLaunchd(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "remove the plist") {
			t.Fatalf("the error does not name the plist-removal step: %v", err)
		}
	})

	t.Run("needs root", func(t *testing.T) {
		rec := &launchdRecorder{} // rootResult == false
		_, err := uninstallMachineLaunchd(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "needs root") {
			t.Fatalf("uninstall without root must refuse: %v", err)
		}
		if len(rec.plistExistsCalls) != 0 {
			t.Fatalf("the plist must not be touched before the root check: %v", rec.plistExistsCalls)
		}
	})
}

// TestIAMT263_MachineAndGatewayPlistShareOneRenderer — the plist
// skeleton is shared (renderLaunchdPlistDoc), and that is not
// cosmetics: the machine role arrived with its own set of values, not
// with its own copy of the XML. The test pins both sides of one knob —
// the gateway form (UserName, KeepAlive always, gateway.log) and the
// machine form (no UserName, SuccessfulExit, machine.log) — so that a
// divergence in the shared renderer breaks both.
//
// Canary: break renderLaunchdPlistDoc so that it writes UserName
// always (or drops KeepAlive) — one of the two assertions below turns
// red.
func TestIAMT263_MachineAndGatewayPlistShareOneRenderer(t *testing.T) {
	gw, err := renderLaunchdPlist("/usr/local/bin/iamtunnel", []string{"gateway", "run", "--data-dir", "/var/lib/iamtunnel"})
	if err != nil {
		t.Fatalf("renderLaunchdPlist: %v", err)
	}
	if !strings.Contains(gw, "<key>UserName</key>\n  <string>"+darwinServiceUser+"</string>") {
		t.Errorf("IAMT-263: the gateway plist must keep UserName %s:\n%s", darwinServiceUser, gw)
	}
	if !strings.Contains(gw, "<key>KeepAlive</key>\n  <true/>") {
		t.Errorf("IAMT-263: the gateway plist must keep KeepAlive=true:\n%s", gw)
	}
	if !strings.Contains(gw, "<string>"+darwinLogPath+"</string>") {
		t.Errorf("IAMT-263: the gateway plist must write to %s:\n%s", darwinLogPath, gw)
	}
	machine := mustMachinePlist(t, "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel-machine")
	if strings.Contains(machine, "<key>UserName</key>") {
		t.Errorf("IAMT-263: the machine plist must remain without UserName:\n%s", machine)
	}
	// Both documents are one and the same XML skeleton.
	for _, shared := range []string{"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "<plist version=\"1.0\">\n<dict>\n", "<key>RunAtLoad</key>\n  <true/>\n", "</dict>\n</plist>\n"} {
		if !strings.Contains(gw, shared) || !strings.Contains(machine, shared) {
			t.Errorf("IAMT-263: the shared plist skeleton diverged on %q", shared)
		}
	}
}

func mustMachinePlist(t *testing.T, exe, dataDir string) string {
	t.Helper()
	plist, err := machineLaunchdPlist(exe, dataDir)
	if err != nil {
		t.Fatalf("machineLaunchdPlist: %v", err)
	}
	return plist
}
