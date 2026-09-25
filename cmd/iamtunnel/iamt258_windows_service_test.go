package main

// iamt258_windows_service_test.go — IAMT-258 (SPEC §3.5.1): the Windows
// half of install/uninstall — the iamtunnel-gateway SCM service under the
// virtual account NT SERVICE\iamtunnel-gateway, delayed auto-start, three
// restarts 10 s apart, an idempotent repeat install and an idempotent
// uninstall that leaves the data directory untouched. Everything goes
// through the windowsServiceSetup seam: no test binary ever touches the
// real service database (in the test binary the seam's production calls
// panic — gateway_service_windows.go), exactly like the Linux half with
// systemdSetup (IAMT-177).
//
// The file is deliberately platform-neutral: sequences and clean builds
// are checked on any host OS; the Windows specifics (ImagePath escaping,
// svc.Handler under the SCM) live in iamt258_windows_service_windows_test.go.

import (
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// serviceRecorder — a fake of the windowsServiceSetup seam: it logs every
// call and returns the assigned results. The result fields are filled in
// by the test BEFORE the sequence runs; the log fields are read
// afterwards.
type serviceRecorder struct {
	// call logs
	serviceExistsCalls []string
	createdSpec        *gatewayServiceSpec
	changedSpec        *gatewayServiceSpec
	startCalls         []string
	runningCalls       []string
	waitRunningCalls   []string
	stopCalls          []string
	deleteCalls        []string
	hardenedDirs       []string
	hardenedExeDirs    []string
	hardenedExeFiles   []string
	// replaceACLSeen logs the boolean the CLI passed to hardenDir and
	// hardenExeDir at each call (IAMT-315): tests assert install
	// passes the flag through and that the seam's hardenDir /
	// hardenExeDir see it unchanged. The seam calls both — one entry
	// per call — and a single install produces two entries in this
	// order: hardenExeDir first, then hardenDir (IAMT-312 round 6).
	replaceACLSeen []bool
	// presentAtHarden is what the data directory held when hardenDir
	// was called, one listing per call (R2-CX F-05: the directory must
	// be locked before the first secret is written into it).
	presentAtHarden [][]string

	// order — a through-log of step ORDER (the individual fields' logs do
	// not show the relative order).
	order []string

	// assigned results (nil = success/none)
	existsResult bool
	existsErr    error
	createResult error
	changeResult error
	startResult  error
	// runningResult/runningErr — snapshot answer for serviceRunning
	// (uninstall's "is it still busy?" check).
	runningResult bool
	runningErr    error
	// waitRunningResult/waitRunningErr — answer for waitRunning
	// (install's IAMT-312 "did it reach RUNNING?" check). Separate from
	// runningResult/runningErr on purpose: setupGatewayService calls
	// waitRunning, teardownGatewayService calls serviceRunning, and a
	// test must be able to set one without silently affecting the other.
	waitRunningResult bool
	waitRunningErr    error
	stopResult        error
	deleteResult      error
	hardenResult      error
	hardenExeResult   error
}

func (r *serviceRecorder) setup() windowsServiceSetup {
	return windowsServiceSetup{
		serviceExists: func(name string) (bool, error) {
			r.serviceExistsCalls = append(r.serviceExistsCalls, name)
			r.order = append(r.order, "exists")
			return r.existsResult, r.existsErr
		},
		createService: func(spec gatewayServiceSpec) error {
			cp := spec
			r.createdSpec = &cp
			r.order = append(r.order, "create")
			return r.createResult
		},
		changeService: func(spec gatewayServiceSpec) error {
			cp := spec
			r.changedSpec = &cp
			r.order = append(r.order, "change")
			return r.changeResult
		},
		startService: func(name string) error {
			r.startCalls = append(r.startCalls, name)
			r.order = append(r.order, "start")
			return r.startResult
		},
		serviceRunning: func(name string) (bool, error) {
			r.runningCalls = append(r.runningCalls, name)
			r.order = append(r.order, "running")
			return r.runningResult, r.runningErr
		},
		// waitRunning: exactly one call per invocation, no internal retry
		// — the fake stands in for a real implementation that already
		// did its own waiting (IAMT-258 round 2); a test that wants to
		// see several attempts belongs at the production seam, not here.
		waitRunning: func(name string) (bool, error) {
			r.waitRunningCalls = append(r.waitRunningCalls, name)
			r.order = append(r.order, "waitRunning")
			return r.waitRunningResult, r.waitRunningErr
		},
		stopService: func(name string) error {
			r.stopCalls = append(r.stopCalls, name)
			r.order = append(r.order, "stop")
			return r.stopResult
		},
		deleteService: func(name string) error {
			r.deleteCalls = append(r.deleteCalls, name)
			r.order = append(r.order, "delete")
			return r.deleteResult
		},
		hardenDir: func(dir string, replaceACL bool, _ io.Writer) (func(), error) {
			var present []string
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					present = append(present, e.Name())
				}
			}
			r.presentAtHarden = append(r.presentAtHarden, present)
			r.hardenedDirs = append(r.hardenedDirs, dir)
			r.replaceACLSeen = append(r.replaceACLSeen, replaceACL)
			r.order = append(r.order, "harden")
			return func() {}, r.hardenResult
		},
		hardenExeDir: func(dir, exePath string, replaceACL bool, _ io.Writer) error {
			r.hardenedExeDirs = append(r.hardenedExeDirs, dir)
			r.hardenedExeFiles = append(r.hardenedExeFiles, exePath)
			r.replaceACLSeen = append(r.replaceACLSeen, replaceACL)
			r.order = append(r.order, "hardenExe")
			return r.hardenExeResult
		},
	}
}

// withFakeGatewayService swaps the production windowsService seam for a
// recording fake and returns it. Restoration goes through t.Cleanup; the
// package's tests do not run in parallel, so the global substitution is
// safe. On non-Windows hosts the substitution is harmless: the seam is
// never reached, and calling the helper defuses the production seam's
// panic should a test drive the CLI path that on Windows must go through
// this seam.
func withFakeGatewayService(t *testing.T) *serviceRecorder {
	t.Helper()
	// runningResult/waitRunningResult: true — the shared default for
	// every CLI-level test that never heard of IAMT-312's post-start
	// liveness check and just wants install/uninstall to succeed; the
	// check itself is pinned directly by
	// TestIAMT258_ServiceSequenceFailureStopsAndNamesTheStep's "started
	// but never reports running" subtest.
	rec := &serviceRecorder{runningResult: true, waitRunningResult: true}
	prev := windowsService
	windowsService = rec.setup()
	t.Cleanup(func() { windowsService = prev })
	return rec
}

// TestIAMT258_ServiceSpecMatchesSpec351 — the service spec's canary:
// every assignment of SPEC §3.5.1 is visible in a clean build of
// gatewayServiceSpecFor (the service name, the virtual account instead of
// LocalSystem, delayed auto-start, three restarts 10 s apart, the command
// line "gateway run --data-dir --port --public-host").
//
// Canary: change any value in gatewayServiceSpecFor or in
// gateway_service.go's constants (say, LocalSystem instead of
// NT SERVICE\iamtunnel-gateway, two recovery actions instead of three,
// a 30 s delay instead of 10 s) — the corresponding assertion below turns
// red, naming the spec field in the error text.
func TestIAMT258_ServiceSpecMatchesSpec351(t *testing.T) {
	spec := gatewayServiceSpecFor("/opt/iamtunnel/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test")

	if spec.Name != "iamtunnel-gateway" {
		t.Errorf("Name = %q, wanted iamtunnel-gateway (SPEC §3.5.1)", spec.Name)
	}
	if spec.DisplayName != "iamtunnel gateway" {
		t.Errorf("DisplayName = %q, wanted \"iamtunnel gateway\"", spec.DisplayName)
	}
	if spec.Description == "" {
		t.Error("Description is empty — in services.msc the service shows no description")
	}
	// §3.5.1: the service runs NOT under LocalSystem but under its own
	// virtual account — the directory's DACL expects precisely that
	// account's SID (IAMT-257).
	if spec.Account != `NT SERVICE\iamtunnel-gateway` {
		t.Errorf("Account = %q, wanted NT SERVICE\\iamtunnel-gateway (not LocalSystem — SPEC §3.5.1)", spec.Account)
	}
	if !spec.DelayedAutoStart {
		t.Error("DelayedAutoStart = false — SPEC §3.5.1 requires delayed auto-start")
	}
	if spec.ExePath != "/opt/iamtunnel/iamtunnel" {
		t.Errorf("ExePath = %q — the service must run the same binary that install executed", spec.ExePath)
	}
	wantArgs := []string{"gateway", "run", "--data-dir", "/var/lib/iamtunnel", "--port", "2222", "--public-host", "gw.example.test"}
	if !reflect.DeepEqual(spec.Args, wantArgs) {
		t.Errorf("Args = %v, wanted %v (the service command line from §3.5.1)", spec.Args, wantArgs)
	}
	// §3.5.1: "restart after 10 s, three times".
	if len(spec.Recovery) != 3 {
		t.Fatalf("Recovery = %d actions, wanted 3 (§3.5.1: restart after 10 s, three times)", len(spec.Recovery))
	}
	for i, r := range spec.Recovery {
		if r.RestartAfter != 10*time.Second {
			t.Errorf("Recovery[%d].RestartAfter = %v, wanted 10s (§3.5.1)", i, r.RestartAfter)
		}
	}
	// Parametricity: the port and the public host follow install's
	// arguments rather than being baked into the build.
	other := gatewayServiceSpecFor("/b", "/d", 2400, "other.example.test")
	if !reflect.DeepEqual(other.Args, []string{"gateway", "run", "--data-dir", "/d", "--port", "2400", "--public-host", "other.example.test"}) {
		t.Errorf("Args do not follow install's parameters: %v", other.Args)
	}
}

// TestIAMT258_FirewallHintMatchesSpec351 — the firewall hint verbatim
// from SPEC §3.5.1, with install's port; install itself touches no
// network firewall on any OS.
//
// Canary: change one character in gatewayFirewallHint (or forget to
// substitute the port) — the comparison against the reference line turns
// red.
func TestIAMT258_FirewallHintMatchesSpec351(t *testing.T) {
	const want = `New-NetFirewallRule -DisplayName "iamtunnel gateway" -Direction Inbound -Protocol TCP -LocalPort 2222 -Action Allow`
	if got := gatewayFirewallHint(2222); got != want {
		t.Errorf("gatewayFirewallHint(2222) =\n  %s\nwanted verbatim from SPEC §3.5.1:\n  %s", got, want)
	}
	if got := gatewayFirewallHint(2400); !strings.Contains(got, "-LocalPort 2400 ") {
		t.Errorf("the hint does not follow install's port: %s", got)
	}
}

// TestIAMT258_ServiceSequenceCreatesThenStarts — the sequence canary:
// directory ACL → service lookup → CREATE (not update) → start, in that
// order.
//
// Canary: reorder the steps in setupGatewayService (say, create the
// service before hardening the ACL) or drop any step — the comparison of
// rec.order against the expected sequence turns red (the error shows the
// actual order).
func TestIAMT258_ServiceSequenceCreatesThenStarts(t *testing.T) {
	rec := &serviceRecorder{waitRunningResult: true}
	spec := gatewayServiceSpecFor("/b/i", "/srv/gw", 2222, "gw.example.test")
	if _, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil); err != nil {
		t.Fatalf("setupGatewayService: %v", err)
	}
	wantOrder := []string{"hardenExe", "harden", "exists", "create", "start", "waitRunning"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("install sequence = %v, wanted %v (binary ACL → data ACL → exists? → create → start → check it is alive)", rec.order, wantOrder)
	}
	if !reflect.DeepEqual(rec.hardenedExeDirs, []string{"/b"}) {
		t.Errorf("the ACL was applied to something other than install's binary directory (IAMT-312): %v", rec.hardenedExeDirs)
	}
	// IAMT-312 round 5: the directory's ACL inheritance does not reach an
	// already existing exe — the ACL must be applied to the binary file
	// itself, separately from the directory.
	if !reflect.DeepEqual(rec.hardenedExeFiles, []string{"/b/i"}) {
		t.Errorf("the ACL was applied to something other than install's binary file itself (IAMT-312 round 5): %v", rec.hardenedExeFiles)
	}
	if !reflect.DeepEqual(rec.hardenedDirs, []string{"/srv/gw"}) {
		t.Errorf("the ACL was applied to something other than install's data directory: %v", rec.hardenedDirs)
	}
	if !reflect.DeepEqual(rec.serviceExistsCalls, []string{"iamtunnel-gateway"}) {
		t.Errorf("serviceExists was called differently: %v", rec.serviceExistsCalls)
	}
	if rec.createdSpec == nil {
		t.Fatal("no new service was created (createService was not called)")
	}
	if !reflect.DeepEqual(*rec.createdSpec, spec) {
		t.Errorf("createService got a different spec:\n %+v\nwanted:\n %+v", *rec.createdSpec, spec)
	}
	if rec.changedSpec != nil {
		t.Errorf("changeService was called although the service is absent: %+v", *rec.changedSpec)
	}
	if !reflect.DeepEqual(rec.startCalls, []string{"iamtunnel-gateway"}) {
		t.Errorf("start was called differently: %v", rec.startCalls)
	}
}

// TestIAMT258_ServiceSequenceRepeatInstallUpdatesInPlace — a repeat
// install (the service already exists) updates it in place with the same
// spec and starts it again: §3.5's idempotency, not a second service and
// not a failure.
//
// Canary: drop the exists/changeService branch (a repeat install would
// fall into createService and fail on a live machine) or fail to pass
// the new spec into changeService — the rec.order/changedSpec comparison
// turns red.
func TestIAMT258_ServiceSequenceRepeatInstallUpdatesInPlace(t *testing.T) {
	rec := &serviceRecorder{existsResult: true, waitRunningResult: true}
	spec := gatewayServiceSpecFor("/b/i", "/srv/gw", 2300, "another.example.test")
	if _, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil); err != nil {
		t.Fatalf("repeat setupGatewayService: %v", err)
	}
	wantOrder := []string{"hardenExe", "harden", "exists", "change", "start", "waitRunning"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("repeat install sequence = %v, wanted %v", rec.order, wantOrder)
	}
	if rec.createdSpec != nil {
		t.Errorf("the repeat install CREATED a service again: %+v", *rec.createdSpec)
	}
	if rec.changedSpec == nil {
		t.Fatal("the repeat install did not update the existing service")
	}
	if !reflect.DeepEqual(*rec.changedSpec, spec) {
		t.Errorf("changeService got a different spec (the new --public-host/--port must reach the service):\n %+v\nwanted:\n %+v", *rec.changedSpec, spec)
	}
	if !reflect.DeepEqual(rec.startCalls, []string{"iamtunnel-gateway"}) {
		t.Errorf("after the update the service must be started: %v", rec.startCalls)
	}
}

// TestIAMT312_RepeatInstallOnRunningServiceSucceeds is the round-3
// canary: a real Windows box repeated `gateway install` on an already
// installed, already RUNNING service (the ordinary upgrade path —
// replace the exe, run install again) and startService answered
// ERROR_SERVICE_ALREADY_RUNNING. Round 2's setupGatewayService treated
// any startService error as fatal, so this exact, healthy case refused
// with exit 3 ("An instance of the service is already running") even
// though the service was never in danger — contradicting both `gateway
// install --help`'s own promise ("updated in place") and the refusal
// text's own remedy ("repeat the install").
//
// Starting a service that is already running is not a failure — the
// goal state is already reached — so setupGatewayService must now
// return (alreadyRunning=true, err=nil), still having called
// changeService to update the persisted configuration, and without
// touching IAMT-258's sequence contract (waitRunning is still called
// exactly once, still confirms the service is actually RUNNING).
//
// Canary: return setupGatewayService to refusing unconditionally on any
// startService error (drop the errors.Is(serr, errServiceAlreadyRunning)
// check) — the "setupGatewayService must succeed" below turns red.
func TestIAMT312_RepeatInstallOnRunningServiceSucceeds(t *testing.T) {
	rec := &serviceRecorder{existsResult: true, startResult: errServiceAlreadyRunning, waitRunningResult: true}
	spec := gatewayServiceSpecFor("/b/i", "/srv/gw", 2022, "127.0.0.1")
	alreadyRunning, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
	if err != nil {
		t.Fatalf("setupGatewayService must succeed when the service is already running: %v", err)
	}
	if !alreadyRunning {
		t.Fatal("setupGatewayService must report alreadyRunning=true when startService answers ERROR_SERVICE_ALREADY_RUNNING")
	}
	wantOrder := []string{"hardenExe", "harden", "exists", "change", "start", "waitRunning"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("IAMT-258's sequence contract must survive: order = %v, want %v", rec.order, wantOrder)
	}
	if rec.changedSpec == nil {
		t.Fatal("the persisted configuration must still be updated (changeService) even though nothing needed restarting")
	}
	if !reflect.DeepEqual(*rec.changedSpec, spec) {
		t.Errorf("changeService got the wrong spec:\n %+v\nwant\n %+v", *rec.changedSpec, spec)
	}
}

// TestIAMT312_RepeatInstallWithUnreadableNewExeFailsEvenIfOldServiceIsRunning
// is the round-5 canary for review finding 1: a repeated install replaces
// iamtunnel.exe with a copy the service account cannot read (ACL not yet
// fixed), then updates ImagePath, then starts the still-live OLD process
// — startService legitimately answers ERROR_SERVICE_ALREADY_RUNNING for
// that old process, and waitRunning legitimately observes it as RUNNING.
// None of that says anything about whether the NEW ImagePath can ever
// start again. setupGatewayService must therefore refuse before any of
// that — at the hardenExeDir step, which is the one call that touches
// the new exe's own ACL directly, independent of what the SCM's current
// running process happens to be.
//
// Canary: skip the hardenExeDir error check (or continue the sequence
// after it) — with startResult=errServiceAlreadyRunning and
// waitRunningResult=true install stops turning red, even though the new
// ImagePath is unreadable to the service.
func TestIAMT312_RepeatInstallWithUnreadableNewExeFailsEvenIfOldServiceIsRunning(t *testing.T) {
	rec := &serviceRecorder{
		existsResult:      true,
		hardenExeResult:   errors.New("access denied"),
		startResult:       errServiceAlreadyRunning,
		waitRunningResult: true,
	}
	spec := gatewayServiceSpecFor("/b/i", "/srv/gw", 2022, "127.0.0.1")
	_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
	if err == nil {
		t.Fatal("setupGatewayService must NOT succeed: the new exe's ACL was never fixed, so the still-live OLD process reaching RUNNING proves nothing about the NEW ImagePath (IAMT-312 round 5)")
	}
	if !strings.Contains(err.Error(), "read+execute on the binary") {
		t.Fatalf("the error does not name the binary ACL step: %v", err)
	}
	if !reflect.DeepEqual(rec.order, []string{"hardenExe"}) {
		t.Fatalf("after the binary ACL failure the sequence must stop before reaching change/start/waitRunning: %v", rec.order)
	}
}

// TestIAMT258_ServiceSequenceFailureStopsAndNamesTheStep — a failure of
// any step stops the sequence and is named to the operator by name.
//
// Canary: make the message anonymous (return err without envErrf) or
// keep the sequence going after a failure — the assertions about the
// error text / rec.order tail turn red.
func TestIAMT258_ServiceSequenceFailureStopsAndNamesTheStep(t *testing.T) {
	spec := gatewayServiceSpecFor("/b", "/srv/gw", 2222, "gw.example.test")

	t.Run("harden exe dir fails", func(t *testing.T) {
		rec := &serviceRecorder{hardenExeResult: errors.New("access denied")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "read+execute on the binary") {
			t.Fatalf("the error does not name the binary ACL step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe"}) {
			t.Fatalf("after the binary ACL failure the sequence must stop: %v", rec.order)
		}
	})

	t.Run("harden fails", func(t *testing.T) {
		rec := &serviceRecorder{hardenResult: errors.New("access denied")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "apply the data-directory ACL") {
			t.Fatalf("the error does not name the directory ACL step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden"}) {
			t.Fatalf("after the ACL failure the sequence must stop: %v", rec.order)
		}
	})

	t.Run("lookup fails", func(t *testing.T) {
		rec := &serviceRecorder{existsErr: errors.New("access denied")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "look up the iamtunnel-gateway service") {
			t.Fatalf("the error does not name the service lookup step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden", "exists"}) {
			t.Fatalf("after a lookup failure there is no going on: %v", rec.order)
		}
	})

	t.Run("create fails", func(t *testing.T) {
		rec := &serviceRecorder{createResult: errors.New("access denied")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "create the iamtunnel-gateway service") {
			t.Fatalf("the error does not name the service creation step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden", "exists", "create"}) {
			t.Fatalf("after a creation failure start must not be called: %v", rec.order)
		}
	})

	t.Run("update fails on repeat install", func(t *testing.T) {
		rec := &serviceRecorder{existsResult: true, changeResult: errors.New("access denied")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "update the existing iamtunnel-gateway service") {
			t.Fatalf("the error does not name the service update step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden", "exists", "change"}) {
			t.Fatalf("after an update failure start must not be called: %v", rec.order)
		}
	})

	t.Run("start fails", func(t *testing.T) {
		rec := &serviceRecorder{startResult: errors.New("the service did not respond")}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "start the iamtunnel-gateway service") {
			t.Fatalf("the error does not name the service start step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden", "exists", "create", "start"}) {
			t.Fatalf("the whole sequence should have gone through up to start: %v", rec.order)
		}
	})

	// TestIAMT312 canary: starting can succeed while the service is
	// already crash-looping (live Windows box: "Access is denied" only
	// surfaced on the FIRST real read from the service process, well
	// after StartService itself returned success) — install must poll
	// serviceRunning and refuse when it never says RUNNING.
	// IAMT-258 round 2 (real live run on all three OSes): the FIRST
	// version of this canary called waitForLiveness AROUND the seam call
	// (setup.serviceRunning), which retried the FAKE up to five times —
	// turning "reaches the running check once" into
	// [... "running" "running" "running" "running" "running"] and
	// breaking this very test's own order assertion, plus its darwin/
	// linux siblings. Waiting is now the PRODUCT implementation's job
	// (gateway_service_windows.go's real waitRunning polls internally);
	// the seam is a single call, named waitRunning and distinct from
	// serviceRunning (uninstall's instant snapshot), so the recorder
	// sees exactly one step here.
	t.Run("started but never reports running", func(t *testing.T) {
		rec := &serviceRecorder{waitRunningResult: false}
		_, err := setupGatewayService(rec.setup(), spec, "/b", "/srv/gw", false, nil)
		if err == nil || !strings.Contains(err.Error(), "is not reporting SERVICE_RUNNING") {
			t.Fatalf("IAMT-312: the error does not name the absence of SERVICE_RUNNING: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden", "exists", "create", "start", "waitRunning"}) {
			t.Fatalf("the sequence should have reached the waitRunning check exactly once: %v", rec.order)
		}
		if len(rec.waitRunningCalls) != 1 {
			t.Fatalf("setupGatewayService must call waitRunning exactly once (waiting is the PRODUCT implementation's job, not the sequence's): got %d calls", len(rec.waitRunningCalls))
		}
	})
}

// TestIAMT312_ExeUnreachableByServiceAccount is the IAMT-312 Part 1
// canary: a real Windows box created and started a service pointed at
// C:\Users\Admin\iamtunnel.exe without complaint, and only "sc start"
// itself failed with Access is denied — the virtual service account
// cannot read into another user's profile by default. install must
// refuse before ever touching the SCM when the binary sits there.
//
// Canary: drop the profile-root comparison in exeUnreachableByServiceAccount
// (say, always return false) — the "must refuse" assertions below turn
// red.
func TestIAMT312_ExeUnreachableByServiceAccount(t *testing.T) {
	env := map[string]string{"USERPROFILE": `C:\Users\Admin`}

	cases := []struct {
		name    string
		exePath string
		want    bool
	}{
		{"exe directly in Admin's profile", `C:\Users\Admin\iamtunnel.exe`, true},
		{"exe in a subfolder of Admin's profile", `C:\Users\Admin\Downloads\iamtunnel.exe`, true},
		{"exe in a DIFFERENT user's profile", `C:\Users\bob\iamtunnel.exe`, true},
		{"case-insensitive match", `c:\users\admin\iamtunnel.exe`, true},
		{"exe in Program Files — RUNBOOK §1.5's remedy", `C:\Program Files\iamtunnel\iamtunnel.exe`, false},
		{"exe in ProgramData", `C:\ProgramData\iamtunnel\iamtunnel.exe`, false},
		{"a user folder name that only shares a prefix", `C:\Users\Administrator2\iamtunnel.exe`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exeUnreachableByServiceAccount(tc.exePath, env); got != tc.want {
				t.Errorf("exeUnreachableByServiceAccount(%q) = %v, want %v", tc.exePath, got, tc.want)
			}
		})
	}

	// A missing %USERPROFILE% (exactly the shape of this package's own
	// CLI test harness, testsupport.PlatformDataEnv — no USERPROFILE key
	// at all) must never refuse: it has nothing trustworthy to compare
	// against, and a real elevated console always has %USERPROFILE% set.
	// Guessing a default here would make every CLI-level `gateway
	// install` test that reaches the real Windows branch refuse, because
	// the compiled go test binary itself always lives under the actual
	// machine's C:\Users.
	noProfileEnv := map[string]string{}
	if exeUnreachableByServiceAccount(`C:\Users\whoever\iamtunnel.exe`, noProfileEnv) {
		t.Error("a missing USERPROFILE env var must not make the check refuse — it has nothing to compare against")
	}
}

// TestIAMT258_UninstallStopsDeletesAndIsIdempotent — the uninstall
// sequence: no service → "nothing to do" (false, nil); present and
// running → stop, then delete; present and not running → delete without
// stop; a stop failure does NOT lead to delete (a running service must
// not be deleted).
//
// Canary: swap the stop/delete order, remove the idempotency branch (a
// missing service would become an error) or call delete after a failed
// stop — the rec.order comparison of the corresponding subtest turns red.
func TestIAMT258_UninstallStopsDeletesAndIsIdempotent(t *testing.T) {
	t.Run("absent service is a nothing-to-do", func(t *testing.T) {
		rec := &serviceRecorder{} // existsResult == false
		removed, err := teardownGatewayService(rec.setup(), "iamtunnel-gateway")
		if err != nil || removed {
			t.Fatalf("a missing service = (false, nil), got (%v, %v)", removed, err)
		}
		if !reflect.DeepEqual(rec.order, []string{"exists"}) {
			t.Fatalf("nothing but the lookup may be called: %v", rec.order)
		}
	})

	t.Run("running service is stopped then deleted", func(t *testing.T) {
		rec := &serviceRecorder{existsResult: true, runningResult: true}
		removed, err := teardownGatewayService(rec.setup(), "iamtunnel-gateway")
		if err != nil || !removed {
			t.Fatalf("wanted (true, nil), got (%v, %v)", removed, err)
		}
		wantOrder := []string{"exists", "running", "stop", "delete"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("uninstall sequence = %v, wanted %v", rec.order, wantOrder)
		}
	})

	t.Run("stopped service is deleted without a stop", func(t *testing.T) {
		rec := &serviceRecorder{existsResult: true, runningResult: false}
		removed, err := teardownGatewayService(rec.setup(), "iamtunnel-gateway")
		if err != nil || !removed {
			t.Fatalf("wanted (true, nil), got (%v, %v)", removed, err)
		}
		wantOrder := []string{"exists", "running", "delete"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("the stop of a non-running service must not be called: %v, wanted %v", rec.order, wantOrder)
		}
	})

	t.Run("stop failure prevents delete", func(t *testing.T) {
		rec := &serviceRecorder{existsResult: true, runningResult: true, stopResult: errors.New("timeout")}
		_, err := teardownGatewayService(rec.setup(), "iamtunnel-gateway")
		if err == nil || !strings.Contains(err.Error(), "stop the iamtunnel-gateway service") {
			t.Fatalf("the error does not name the stop step: %v", err)
		}
		if !reflect.DeepEqual(rec.order, []string{"exists", "running", "stop"}) {
			t.Fatalf("after a stop failure the service must not be deleted: %v", rec.order)
		}
	})

	t.Run("delete failure is named", func(t *testing.T) {
		rec := &serviceRecorder{existsResult: true, runningResult: false, deleteResult: errors.New("access denied")}
		_, err := teardownGatewayService(rec.setup(), "iamtunnel-gateway")
		if err == nil || !strings.Contains(err.Error(), "delete the iamtunnel-gateway service") {
			t.Fatalf("the error does not name the delete step: %v", err)
		}
	})
}

// TestIAMT258_SystemdUninstallSequence — the Linux half of uninstall
// (SPEC §3.5.1): disable --now → remove the unit file → daemon-reload; no
// unit — "nothing to do". Symmetric to the Windows half and through the
// same systemdSetup seam install uses (IAMT-177).
//
// Canary: reorder uninstallSystemdUnit (say, remove the unit before
// disable) or drop daemon-reload — the rec.order comparison of the
// corresponding subtest turns red.
func TestIAMT258_SystemdUninstallSequence(t *testing.T) {
	const unitPath = "/etc/systemd/system/iamtunnel-gateway.service"

	t.Run("absent unit is a nothing-to-do", func(t *testing.T) {
		rec := &systemdRecorder{} // unitExistsResult == false
		removed, err := uninstallSystemdUnit(rec.setup())
		if err != nil || removed {
			t.Fatalf("a missing unit = (false, nil), got (%v, %v)", removed, err)
		}
		if !reflect.DeepEqual(rec.order, []string{"unitExists"}) {
			t.Fatalf("nothing but the unit lookup may be called: %v", rec.order)
		}
	})

	t.Run("present unit is disabled removed and reloaded in order", func(t *testing.T) {
		rec := &systemdRecorder{unitExistsResult: true}
		removed, err := uninstallSystemdUnit(rec.setup())
		if err != nil || !removed {
			t.Fatalf("wanted (true, nil), got (%v, %v)", removed, err)
		}
		wantOrder := []string{
			"unitExists",
			"systemctl: disable --now iamtunnel-gateway.service",
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

	t.Run("disable failure stops before remove", func(t *testing.T) {
		rec := &systemdRecorder{unitExistsResult: true, systemctlResult: errors.New("System has not been booted with systemd")}
		_, err := uninstallSystemdUnit(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "systemctl disable --now iamtunnel-gateway.service") {
			t.Fatalf("the error does not name the disable step: %v", err)
		}
		if len(rec.removeUnitCalls) != 0 {
			t.Fatalf("after a disable failure the unit must not be removed: %v", rec.removeUnitCalls)
		}
	})

	t.Run("remove failure stops before daemon-reload", func(t *testing.T) {
		rec := &systemdRecorder{unitExistsResult: true, removeUnitResult: errors.New("permission denied")}
		_, err := uninstallSystemdUnit(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "remove the unit file") {
			t.Fatalf("the error does not name the unit removal step: %v", err)
		}
		for _, c := range rec.systemctlCalls {
			if strings.Contains(c, "daemon-reload") {
				t.Errorf("after a unit removal failure daemon-reload must not be called: %v", rec.systemctlCalls)
			}
		}
		if rec.order[len(rec.order)-1] != "removeUnit" {
			t.Fatalf("after a unit removal failure the sequence must stop: %v", rec.order)
		}
	})

	t.Run("daemon-reload failure is named", func(t *testing.T) {
		rec := &systemdRecorder{unitExistsResult: true, failDaemonReload: true}
		_, err := uninstallSystemdUnit(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "systemctl daemon-reload") {
			t.Fatalf("the error does not name the daemon-reload step: %v", err)
		}
		if !reflect.DeepEqual(rec.removeUnitCalls, []string{unitPath}) {
			t.Errorf("the unit must have been removed before the daemon-reload failure: %v", rec.removeUnitCalls)
		}
	})
}

// TestIAMT258_UninstallCLIReportsIdempotently — the CLI level of
// uninstall on a host with its own service half: no service → exitOK and
// "nothing to do"; present → exitOK, "stopped and removed" and the line
// about the untouched data directory (§3.5.1's promise visible to the
// operator).
//
// Canary: make a missing service an error or drop the untouched-directory
// line — the corresponding assertion turns red; bring back the old
// "requires a Linux host" refusal — the exit code comparison turns red.
func TestIAMT258_UninstallCLIReportsIdempotently(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "linux":
		t.Run("absent is nothing-to-do", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				rec := withFakeGatewayService(t)
				out, errs, code := drive(t, "gateway", "uninstall", "--data-dir", t.TempDir())
				if code != exitOK || !strings.Contains(out, "not installed; nothing to do") {
					t.Fatalf("uninstall without a service: code=%d out=%q errs=%q, wanted exitOK and \"nothing to do\"", code, out, errs)
				}
				if !reflect.DeepEqual(rec.order, []string{"exists"}) {
					t.Fatalf("nothing but the lookup may reach the seam: %v", rec.order)
				}
			} else {
				rec := withFakeSystemd(t)
				out, errs, code := drive(t, "gateway", "uninstall", "--data-dir", t.TempDir())
				if code != exitOK || !strings.Contains(out, "not installed; nothing to do") {
					t.Fatalf("uninstall without a unit: code=%d out=%q errs=%q, wanted exitOK and \"nothing to do\"", code, out, errs)
				}
				if !reflect.DeepEqual(rec.order, []string{"unitExists"}) {
					t.Fatalf("nothing but the unit lookup may reach the seam: %v", rec.order)
				}
			}
		})

		t.Run("installed reports removal and untouched data", func(t *testing.T) {
			dir := t.TempDir()
			if runtime.GOOS == "windows" {
				rec := &serviceRecorder{existsResult: true, runningResult: false}
				prev := windowsService
				windowsService = rec.setup()
				t.Cleanup(func() { windowsService = prev })
				out, errs, code := drive(t, "gateway", "uninstall", "--data-dir", dir)
				if code != exitOK || !strings.Contains(out, "stopped and removed") {
					t.Fatalf("uninstall of the service: code=%d out=%q errs=%q, wanted exitOK and \"stopped and removed\"", code, out, errs)
				}
				if !strings.Contains(out, dir+" was not touched") {
					t.Fatalf("the output must name the untouched data directory %s: out=%q", dir, out)
				}
				if !reflect.DeepEqual(rec.order, []string{"exists", "running", "delete"}) {
					t.Fatalf("uninstall sequence = %v", rec.order)
				}
			} else {
				rec := &systemdRecorder{unitExistsResult: true}
				prev := linuxSystemd
				linuxSystemd = rec.setup()
				t.Cleanup(func() { linuxSystemd = prev })
				out, errs, code := drive(t, "gateway", "uninstall", "--data-dir", dir)
				if code != exitOK || !strings.Contains(out, "stopped and removed") {
					t.Fatalf("uninstall of the unit: code=%d out=%q errs=%q, wanted exitOK and \"stopped and removed\"", code, out, errs)
				}
				if !strings.Contains(out, dir+" was not touched") {
					t.Fatalf("the output must name the untouched data directory %s: out=%q", dir, out)
				}
				if len(rec.systemctlCalls) != 2 {
					t.Fatalf("disable and daemon-reload must have gone through: %v", rec.systemctlCalls)
				}
			}
		})

	default:
		// macOS eventually got its own service half (IAMT-259): its
		// CLI uninstall is covered by the iamt259 tests; skipped here.
		t.Skipf("IAMT-258: CLI uninstall with a service half is checked on a Windows/Linux host; here %s (macOS — in the iamt259 tests; other hosts — the no-integration refusal is pinned in TestIAMT177_HostTouchesOnlyItsOwnSeam)", runtime.GOOS)
	}
}
