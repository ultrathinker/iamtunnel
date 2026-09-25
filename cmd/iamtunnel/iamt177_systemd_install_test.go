package main

// iamt177_systemd_install_test.go — IAMT-177 (G6 of the earlier
// summary): the systemd half of `gateway install` (SPEC §3.5) — the
// service user, the hardened unit, daemon-reload → enable → start —
// through the systemdSetup seam. The tests check the unit's CONTENTS
// and the CALL SEQUENCE; no real id/useradd/systemctl is ever run from
// a test: the production linuxSystemd is substituted with the recording
// fake (same-package, without any exported "for tests only" product
// surfaces).

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// systemdRecorder is the seam fake: it records every call and returns
// the assigned results. The result fields are filled in by the test
// BEFORE setupSystemd (or uninstallSystemdUnit) is called; the journal
// fields are read afterwards.
type systemdRecorder struct {
	// call journals
	userExistsCalls []string
	createUserCalls []string
	chownDirCalls   []string
	unitPath        string
	unitContent     string
	systemctlCalls  []string
	// IAMT-258: the journal of the seam's uninstall half.
	unitExistsCalls []string
	removeUnitCalls []string

	// assigned results (nil = success)
	userExistsResult error
	createUserResult error
	chownDirResult   error
	writeUnitResult  error
	systemctlResult  error
	// unitExistsResult — whether a unit exists on disk (by default —
	// no); unitExistsErr/removeUnitResult — assigned failures of the
	// uninstall steps. failDaemonReload — an assigned failure of ONLY
	// the daemon-reload step (systemctlResult also fails the first
	// call — disable — so daemon-reload would never be reached).
	unitExistsResult bool
	unitExistsErr    error
	removeUnitResult error
	failDaemonReload bool
	// isActiveInactive: false (zero value) means the freshly started unit
	// answers "active" — the sensible default for every pre-existing test
	// that never heard of IAMT-308/310's post-start liveness check. Set
	// true to make it answer "inactive" instead; isActiveErr overrides
	// both when set.
	isActiveInactive bool
	isActiveErr      error
	isActiveCalls    []string
	// exeWriters — who, besides root, may replace the binary
	// (IAMT-445b); by default nobody: the fake does not look at the real
	// filesystem, and the test binary sits in an ordinary user's
	// directory.
	exeWriters      []string
	exeWritersCalls []string

	// order — the cross-cutting journal of the ORDER of steps across
	// all of the seam's fields (the per-field journals do not show the
	// relative order).
	order []string
}

func (r *systemdRecorder) setup() systemdSetup {
	return systemdSetup{
		userExists: func(name string) error {
			r.userExistsCalls = append(r.userExistsCalls, name)
			r.order = append(r.order, "userExists")
			return r.userExistsResult
		},
		createUser: func(name, home string) error {
			r.createUserCalls = append(r.createUserCalls, name+" "+home)
			r.order = append(r.order, "createUser")
			return r.createUserResult
		},
		chownDir: func(path, user, group string) error {
			r.chownDirCalls = append(r.chownDirCalls, path+" "+user+":"+group)
			r.order = append(r.order, "chownDir")
			return r.chownDirResult
		},
		writeUnit: func(path, content string) error {
			r.unitPath, r.unitContent = path, content
			r.order = append(r.order, "writeUnit")
			return r.writeUnitResult
		},
		systemctl: func(args ...string) error {
			joined := strings.Join(args, " ")
			r.systemctlCalls = append(r.systemctlCalls, joined)
			r.order = append(r.order, "systemctl: "+joined)
			if r.failDaemonReload && len(args) > 0 && args[0] == "daemon-reload" {
				return errors.New("System has not been booted with systemd")
			}
			return r.systemctlResult
		},
		unitExists: func(path string) (bool, error) {
			r.unitExistsCalls = append(r.unitExistsCalls, path)
			r.order = append(r.order, "unitExists")
			return r.unitExistsResult, r.unitExistsErr
		},
		removeUnit: func(path string) error {
			r.removeUnitCalls = append(r.removeUnitCalls, path)
			r.order = append(r.order, "removeUnit")
			return r.removeUnitResult
		},
		exeWriters: func(bin string) ([]string, error) {
			r.exeWritersCalls = append(r.exeWritersCalls, bin)
			r.order = append(r.order, "exeWriters")
			return r.exeWriters, nil
		},
		isActive: func(unitName string) (bool, error) {
			r.isActiveCalls = append(r.isActiveCalls, unitName)
			if r.isActiveErr != nil {
				return false, r.isActiveErr
			}
			return !r.isActiveInactive, nil
		},
	}
}

// withFakeSystemd substitutes the production linuxSystemd seam with the
// recording fake and returns it. Restoration goes through t.Cleanup.
// This package's tests do not run in parallel (t.Parallel is not used),
// so the global substitution is safe. iamt131 uses it too: on Linux an
// install without this substitution would run a REAL systemctl from the
// test binary.
func withFakeSystemd(t *testing.T) *systemdRecorder {
	t.Helper()
	rec := &systemdRecorder{}
	prev := linuxSystemd
	linuxSystemd = rec.setup()
	t.Cleanup(func() { linuxSystemd = prev })
	return rec
}

// TestIAMT177_UnitFileCarriesSpecHardening — the unit-contents canary:
// every hardening directive from SPEC §3.5 must be present verbatim.
//
// Canary: delete the "ProtectSystem=strict" line (or any other one
// listed) from gatewayUnitFile in cmd/iamtunnel/gateway.go — the test
// turns red on the corresponding assertion below with the missing
// directive's name.
func TestIAMT177_UnitFileCarriesSpecHardening(t *testing.T) {
	const bin = "/usr/local/bin/iamtunnel"
	const dataDir = "/var/lib/iamtunnel"
	unit := gatewayUnitFile(bin, dataDir, 2222, "gw.example.test")

	for _, directive := range []string{
		// SPEC §3.5: "a systemd unit with hardening: ProtectSystem=strict,
		// ProtectHome=yes, PrivateTmp=yes, NoNewPrivileges=yes,
		// ReadWritePaths=/var/lib/iamtunnel, AmbientCapabilities= empty".
		"ProtectSystem=strict\n",
		"ProtectHome=yes\n",
		"PrivateTmp=yes\n",
		"NoNewPrivileges=yes\n",
		"ReadWritePaths=" + dataDir + "\n",
		"AmbientCapabilities=\n",
		// "Runs as the iamtunnel user, not as root".
		"User=iamtunnel\n",
		"Group=iamtunnel\n",
		// RUNBOOK §1.3 (the normative example, the same unit): the
		// gateway's clock is the source of truth (SPEC §6.4), hence
		// time-sync before start.
		"After=network-online.target time-sync.target\n",
		"Wants=network-online.target time-sync.target\n",
		"LimitNOFILE=65536\n",
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("IAMT-177: the unit does NOT contain the %q directive from SPEC §3.5.\nunit:\n%s", directive, unit)
		}
	}

	// ExecStart runs the same binary install put there, with the same
	// data directory, port and public host (IAMT-202); --data-dir,
	// --port and --public-host come from the render, not from defaults.
	if !strings.Contains(unit, "ExecStart="+bin+" gateway run --data-dir "+dataDir+" --port 2222 --public-host gw.example.test\n") {
		t.Errorf("IAMT-177: ExecStart does not assemble the run command with binary/directory/port/public-host.\nunit:\n%s", unit)
	}
	// The port is rendered, not hardwired: another port means another unit.
	other := gatewayUnitFile(bin, dataDir, 2300, "gw.example.test")
	if !strings.Contains(other, "--port 2300") || strings.Contains(other, "--port 2222") {
		t.Errorf("IAMT-177: the unit's port does not follow the argument (2300):\n%s", other)
	}
	// The data directory is parameterized too: ReadWritePaths must follow it.
	custom := gatewayUnitFile(bin, "/srv/iamt", 2222, "gw.example.test")
	if !strings.Contains(custom, "ReadWritePaths=/srv/iamt\n") {
		t.Errorf("IAMT-177: ReadWritePaths does not follow the data dir (/srv/iamt):\n%s", custom)
	}
	// IAMT-202: --public-host is parameterized too — a different public
	// host yields a different ExecStart, otherwise the unit has no way
	// to tell gateway run which address to hand out in connection
	// strings.
	otherHost := gatewayUnitFile(bin, dataDir, 2222, "other.example.test")
	if !strings.Contains(otherHost, "--public-host other.example.test") {
		t.Errorf("IAMT-202: --public-host in ExecStart does not follow the argument (other.example.test):\n%s", otherHost)
	}
	if strings.Contains(otherHost, "--public-host gw.example.test") {
		t.Errorf("IAMT-202: ExecStart did not swap --public-host to other.example.test:\n%s", otherHost)
	}
}

// TestIAMT177_SequenceCreatesUserWritesUnitEnablesStarts — the
// sequence canary: the user is checked and created only when absent,
// the directory's ownership is handed to the service user (IAMT-199),
// the unit is written exactly once, then daemon-reload → enable →
// start in that order.
//
// Canary: change the order in setupSystemd (say, start before enable
// or chown after the unit) or drop any of the steps — the
// corresponding journal's assertion turns red with the actual sequence
// in the error text.
func TestIAMT177_SequenceCreatesUserWritesUnitEnablesStarts(t *testing.T) {
	t.Run("user already exists", func(t *testing.T) {
		rec := &systemdRecorder{} // userExistsResult == nil: the user exists
		if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test"); err != nil {
			t.Fatalf("setupSystemd: %v", err)
		}
		if len(rec.userExistsCalls) != 1 || rec.userExistsCalls[0] != "iamtunnel" {
			t.Fatalf("userExists was called differently: %v", rec.userExistsCalls)
		}
		if len(rec.createUserCalls) != 0 {
			t.Fatalf("an existing user must not be recreated, yet useradd was called: %v", rec.createUserCalls)
		}
		// IAMT-199: even with an existing user the directory's ownership
		// is still handed over — install created the data as root, and
		// without the chown step the unit starts under iamtunnel and
		// cannot open state.lock.
		if len(rec.chownDirCalls) != 1 || rec.chownDirCalls[0] != "/var/lib/iamtunnel iamtunnel:iamtunnel" {
			t.Fatalf("chownDir was called differently than once as \"/var/lib/iamtunnel iamtunnel:iamtunnel\": %v", rec.chownDirCalls)
		}
		if rec.unitPath != "/etc/systemd/system/iamtunnel-gateway.service" {
			t.Fatalf("the unit is not written to /etc/systemd/system under the name from RUNBOOK §1.3: %q", rec.unitPath)
		}
		want := gatewayUnitFile("/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test")
		if rec.unitContent != want {
			t.Fatalf("the wrong unit reached disk:\nwant:\n%s\ngot:\n%s", want, rec.unitContent)
		}
		wantSeq := []string{"daemon-reload", "enable iamtunnel-gateway.service", "start iamtunnel-gateway.service"}
		if len(rec.systemctlCalls) != 3 || rec.systemctlCalls[0] != wantSeq[0] || rec.systemctlCalls[1] != wantSeq[1] || rec.systemctlCalls[2] != wantSeq[2] {
			t.Fatalf("the systemctl sequence is not \"daemon-reload → enable → start\": %v", rec.systemctlCalls)
		}
	})

	t.Run("user missing is created once with home at the data dir", func(t *testing.T) {
		rec := &systemdRecorder{userExistsResult: errors.New("id: no such user")}
		if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test"); err != nil {
			t.Fatalf("setupSystemd: %v", err)
		}
		if len(rec.createUserCalls) != 1 || rec.createUserCalls[0] != "iamtunnel /var/lib/iamtunnel" {
			t.Fatalf("createUser was called differently than once as \"iamtunnel /var/lib/iamtunnel\": %v", rec.createUserCalls)
		}
		if len(rec.chownDirCalls) != 1 {
			t.Fatalf("chownDir after user creation must happen exactly once: %v", rec.chownDirCalls)
		}
		if len(rec.systemctlCalls) != 3 {
			t.Fatalf("systemctl after user creation must run the full path: %v", rec.systemctlCalls)
		}
	})
}

// TestIAMT308_SystemdInstallRefusesWhenUnitIsNotActive is the systemd
// half of the IAMT-308/310 family canary: "systemctl start" can return
// success the instant the unit's process forks, well before it has had a
// chance to hit its own fatal error and crash — systemdInstallTail must
// poll "systemctl is-active" after start and refuse (a named, non-nil
// error) when the unit never answers active.
//
// Canary: drop the isActive check after systemctl start in
// systemdInstallTail — this check goes red (err == nil, a refusal
// expected). The second canary (round 2, a real three-machine report):
// wrap this call in a retry loop AT THE systemdInstallTail LEVEL — the
// len(rec.isActiveCalls) == 1 check turns red: the seam must call
// isActive exactly once, and waiting/re-polling is the job of the
// production linuxSystemd isActive implementation (waitForLiveness
// inside it), not of the sequence. Otherwise the platform-neutral test
// TestIAMT258_ServiceSequence... (the same fake, the same contract)
// sees several steps where IAMT-258 pins exactly one.
func TestIAMT308_SystemdInstallRefusesWhenUnitIsNotActive(t *testing.T) {
	rec := &systemdRecorder{isActiveInactive: true}
	err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test")
	if err == nil {
		t.Fatal("setupSystemd must refuse when systemctl never reports the unit active after start")
	}
	if !strings.Contains(err.Error(), "started") || !strings.Contains(err.Error(), "does not report it active") {
		t.Fatalf("refusal text must say the unit was started but is not active: %v", err)
	}
	if len(rec.isActiveCalls) != 1 {
		t.Fatalf("systemdInstallTail must call isActive exactly once (waiting is the PRODUCT implementation's job, not the sequence's): got %d calls", len(rec.isActiveCalls))
	}
}

// TestIAMT312_RepeatInstallOnRunningUnitSucceeds documents that Linux has
// no IAMT-312-shaped hole: "systemctl start" on an already-active unit is
// idempotent by design (systemd itself answers success, not an error) —
// unlike Windows' StartService, which answers ERROR_SERVICE_ALREADY_
// RUNNING for the exact same situation and, before round 3, made
// setupGatewayService refuse a healthy repeated install. The fake models
// "systemctl start" the same way on every call because the real command
// genuinely behaves that way; there is no separate state to simulate.
// This test exists to name the scenario explicitly (round-3 request:
// cover it on all three OSes at the seam level) rather than leave the
// proof implicit in the ordinary happy-path test above.
func TestIAMT312_RepeatInstallOnRunningUnitSucceeds(t *testing.T) {
	rec := &systemdRecorder{} // a repeat install: unit already exists and is already active
	if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test"); err != nil {
		t.Fatalf("setupSystemd must succeed when the unit is already running: %v", err)
	}
	wantSeq := []string{"daemon-reload", "enable iamtunnel-gateway.service", "start iamtunnel-gateway.service"}
	if !reflect.DeepEqual(rec.systemctlCalls, wantSeq) {
		t.Fatalf("systemctl sequence = %v, want %v", rec.systemctlCalls, wantSeq)
	}
	if len(rec.isActiveCalls) != 1 {
		t.Fatalf("the post-start liveness check must still run exactly once: got %d calls", len(rec.isActiveCalls))
	}
}

// TestIAMT177_FailureStopsSequenceAndNamesTheStep — a failure of any
// step stops the sequence and is named to the operator.
//
// Canary: make an error message anonymous (say, return err without the
// envErrf wrapper) or keep going after a failure — the error-text/
// journal-tail assertions turn red.
func TestIAMT177_FailureStopsSequenceAndNamesTheStep(t *testing.T) {
	t.Run("create user fails", func(t *testing.T) {
		rec := &systemdRecorder{userExistsResult: errors.New("no such user"), createUserResult: errors.New("useradd: permission denied")}
		err := setupSystemd(rec.setup(), "/b", "/var/lib/iamtunnel", 2222, "gw.example.test")
		if err == nil {
			t.Fatal("the useradd failure was swallowed")
		}
		if !strings.Contains(err.Error(), "create the \"iamtunnel\" service user") {
			t.Fatalf("the error does not name the user-creation step: %v", err)
		}
		if rec.unitContent != "" || len(rec.systemctlCalls) != 0 {
			t.Fatalf("after a useradd failure the sequence must stop: unit=%q systemctl=%v", rec.unitContent, rec.systemctlCalls)
		}
		if len(rec.chownDirCalls) != 0 {
			t.Fatalf("after a useradd failure the chownDir step does not run: %v", rec.chownDirCalls)
		}
	})

	t.Run("chown dir fails", func(t *testing.T) {
		// IAMT-199: a failure of the directory-ownership transfer stops
		// the sequence and does NOT run systemctl (otherwise the unit
		// starts under iamtunnel without rights to state.lock and
		// crashes).
		rec := &systemdRecorder{chownDirResult: errors.New("chown: invalid user: 'iamtunnel'")}
		err := setupSystemd(rec.setup(), "/b", "/var/lib/iamtunnel", 2222, "gw.example.test")
		if err == nil {
			t.Fatal("the chownDir failure was swallowed")
		}
		if !strings.Contains(err.Error(), "transfer ownership of /var/lib/iamtunnel to iamtunnel:iamtunnel") {
			t.Fatalf("the error does not name the ownership-transfer step: %v", err)
		}
		if len(rec.chownDirCalls) != 1 {
			t.Fatalf("the chownDir step must have run exactly once: %v", rec.chownDirCalls)
		}
		if rec.unitContent != "" {
			t.Fatalf("after a chownDir failure the unit must not be written: %q", rec.unitContent)
		}
		if len(rec.systemctlCalls) != 0 {
			t.Fatalf("after a chownDir failure systemctl must not be called: %v", rec.systemctlCalls)
		}
	})

	t.Run("write unit fails", func(t *testing.T) {
		rec := &systemdRecorder{writeUnitResult: errors.New("read-only file system")}
		err := setupSystemd(rec.setup(), "/b", "/var/lib/iamtunnel", 2222, "gw.example.test")
		if err == nil || !strings.Contains(err.Error(), "write the systemd unit") {
			t.Fatalf("the error does not name the unit-write step: %v", err)
		}
		if len(rec.systemctlCalls) != 0 {
			t.Fatalf("after a unit-write failure systemctl must not be called: %v", rec.systemctlCalls)
		}
		if len(rec.chownDirCalls) != 1 {
			t.Fatalf("chownDir must run BEFORE the unit write (between user and unit): %v", rec.chownDirCalls)
		}
	})

	t.Run("systemctl fails", func(t *testing.T) {
		rec := &systemdRecorder{systemctlResult: errors.New("System has not been booted with systemd")}
		err := setupSystemd(rec.setup(), "/b", "/var/lib/iamtunnel", 2222, "gw.example.test")
		if err == nil || !strings.Contains(err.Error(), "systemctl daemon-reload") {
			t.Fatalf("the error does not name the systemctl step: %v", err)
		}
		if len(rec.systemctlCalls) != 1 {
			t.Fatalf("after the first systemctl failure nothing may continue: %v", rec.systemctlCalls)
		}
	})
}

// TestIAMT177_HostTouchesOnlyItsOwnSeam — the invariant first named
// "a non-Linux host does not touch the systemd seam", strengthened in
// IAMT-258 to the mutual form, and in IAMT-259 to three seams: install
// on a host OS goes only through THAT OS's seam (Linux — systemd,
// Windows — the SCM service, macOS — launchd), the foreign seams get
// zero calls, and on a host without service integration none is
// touched. The old pinned text "requires a Linux host" no longer
// exists — the Windows and macOS halves of install are legitimate as
// of IAMT-258/259 (SPEC §3.5.1).
func TestIAMT177_HostTouchesOnlyItsOwnSeam(t *testing.T) {
	sd := withFakeSystemd(t)
	svc := withFakeGatewayService(t)
	ld := withFakeLaunchd(t)
	dir := t.TempDir()
	// IAMT-202: install requires --public-host — all seams are legitimate here.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	switch runtime.GOOS {
	case "linux":
		if code != exitOK {
			t.Fatalf("install on Linux must succeed (exitOK), got %d; errs=%q", code, errs)
		}
		if len(sd.userExistsCalls) == 0 || len(sd.systemctlCalls) == 0 {
			t.Fatalf("install on Linux must go through the systemd seam: userExists=%v systemctl=%v", sd.userExistsCalls, sd.systemctlCalls)
		}
		if len(svc.serviceExistsCalls) != 0 || svc.createdSpec != nil {
			t.Fatalf("the Linux path must not touch the SCM service seam: serviceExists=%v created=%v", svc.serviceExistsCalls, svc.createdSpec != nil)
		}
		if len(ld.bootstrapCalls) != 0 || len(ld.writePlistCalls) != 0 {
			t.Fatalf("the Linux path must not touch the launchd seam: bootstrap=%v writePlist=%v", ld.bootstrapCalls, ld.writePlistCalls)
		}
	case "windows":
		if code != exitOK {
			t.Fatalf("install on Windows must succeed (exitOK), got %d; errs=%q", code, errs)
		}
		if len(svc.serviceExistsCalls) != 1 || svc.createdSpec == nil || len(svc.startCalls) != 1 {
			t.Fatalf("install on Windows must go through the service seam: serviceExists=%v created=%v start=%v", svc.serviceExistsCalls, svc.createdSpec != nil, svc.startCalls)
		}
		if !strings.Contains(out, "the firewall was not touched") {
			t.Fatalf("the Windows install must print that the firewall is untouched and the port-opening command; out=%q", out)
		}
		if len(sd.userExistsCalls) != 0 || len(sd.systemctlCalls) != 0 || sd.unitContent != "" {
			t.Fatalf("the Windows path must not touch the systemd seam: userExists=%v systemctl=%v unitWritten=%v",
				sd.userExistsCalls, sd.systemctlCalls, sd.unitContent != "")
		}
		if len(ld.bootstrapCalls) != 0 || len(ld.writePlistCalls) != 0 {
			t.Fatalf("the Windows path must not touch the launchd seam: bootstrap=%v writePlist=%v", ld.bootstrapCalls, ld.writePlistCalls)
		}
	case "darwin":
		if code != exitOK {
			t.Fatalf("install on macOS must succeed (exitOK), got %d; errs=%q", code, errs)
		}
		if len(ld.bootstrapCalls) != 1 || len(ld.writePlistCalls) != 1 || len(ld.createUserCalls) != 1 {
			t.Fatalf("install on macOS must go through the launchd seam: bootstrap=%v writePlist=%v createUser=%v", ld.bootstrapCalls, ld.writePlistCalls, ld.createUserCalls)
		}
		if !strings.Contains(out, "the firewall was not touched") {
			t.Fatalf("the macOS install must print that the firewall is untouched and the Application Firewall command; out=%q", out)
		}
		if len(sd.userExistsCalls) != 0 || len(sd.systemctlCalls) != 0 || sd.unitContent != "" {
			t.Fatalf("the macOS path must not touch the systemd seam: userExists=%v systemctl=%v unitWritten=%v",
				sd.userExistsCalls, sd.systemctlCalls, sd.unitContent != "")
		}
		if len(svc.serviceExistsCalls) != 0 || svc.createdSpec != nil {
			t.Fatalf("the macOS path must not touch the SCM service seam: serviceExists=%v created=%v", svc.serviceExistsCalls, svc.createdSpec != nil)
		}
	default:
		if code == exitOK || code != exitEnv {
			t.Fatalf("install on %s must refuse (exitEnv), got %d; out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
		if !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("the refusal must name all three supported OSes: %q", errs)
		}
		if len(sd.systemctlCalls) != 0 || len(svc.serviceExistsCalls) != 0 || len(ld.bootstrapCalls) != 0 {
			t.Fatalf("a host without service integration must not touch any seam: systemctl=%v serviceExists=%v bootstrap=%v", sd.systemctlCalls, svc.serviceExistsCalls, ld.bootstrapCalls)
		}
	}
}
