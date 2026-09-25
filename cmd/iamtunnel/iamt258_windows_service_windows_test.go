//go:build windows

// iamt258_windows_service_windows_test.go — the Windows-specific part
// of IAMT-258 (SPEC §3.5.1) that the platform-neutral file cannot
// cover: assembling the ImagePath by the Windows command-line rules and
// the service's svc.Handler behavior under a Stop command from the SCM.
// Both tests are pure: neither opens the service database nor starts a
// service.

package main

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// TestIAMT312_ServiceUpdateConfigSetsServiceType is the IAMT-312 canary:
// ChangeServiceConfig's dwServiceType parameter accepts only
// SERVICE_NO_CHANGE or a real SERVICE_* type — never 0, which is what
// mgr.Config{} leaves in the field when it is not set explicitly. A live
// repeat install hit exactly that gap and every update failed with
// ERROR_INVALID_PARAMETER (87, "The parameter is incorrect"), leaving
// "sc qc" showing the service's OLD BinaryPathName forever — the
// refusal's own promise ("a repeated install updates in place and starts
// again") was false.
//
// Canary: return ServiceType in gatewayServiceUpdateConfig to the
// unset (zero) value — the comparison below against
// windows.SERVICE_WIN32_OWN_PROCESS turns red.
func TestIAMT312_ServiceUpdateConfigSetsServiceType(t *testing.T) {
	spec := gatewayServiceSpecFor(`C:\Program Files\iamtunnel\iamtunnel.exe`, `C:\ProgramData\iamtunnel\gateway`, 2222, "gw.example.test")
	cfg := gatewayServiceUpdateConfig(spec)
	if cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
		t.Fatalf("IAMT-312: ServiceType = %#x, want SERVICE_WIN32_OWN_PROCESS (%#x) — 0 or SERVICE_NO_CHANGE only differ by one being rejected by ChangeServiceConfig with ERROR_INVALID_PARAMETER", cfg.ServiceType, windows.SERVICE_WIN32_OWN_PROCESS)
	}
	// The rest of the config must still match the spec — this fix must
	// not silently drop any other field UpdateConfig needs.
	if cfg.ServiceStartName != spec.Account || cfg.DisplayName != spec.DisplayName || cfg.Description != spec.Description {
		t.Fatalf("gatewayServiceUpdateConfig dropped a field: %+v (spec: %+v)", cfg, spec)
	}
	if !cfg.DelayedAutoStart || cfg.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		t.Fatalf("gatewayServiceUpdateConfig must keep delayed autostart and the unrestricted per-service SID (SPEC §3.5.1): %+v", cfg)
	}
	wantPath := gatewayServiceBinaryPathName(spec.ExePath, spec.Args)
	if cfg.BinaryPathName != wantPath {
		t.Fatalf("BinaryPathName = %q, want the quoted form %q (spec's ExePath has a space)", cfg.BinaryPathName, wantPath)
	}
}

// TestIAMT312_ClassifyStartServiceError is the round-3 canary: a real
// Windows box repeated `gateway install` on an already-running service
// (replace the exe, run install again — the ordinary upgrade path) and
// sv.Start() answered ERROR_SERVICE_ALREADY_RUNNING (1056). Windows
// treats that as a request error, but the goal state ("the service is
// running") is already reached, so it must translate to
// errServiceAlreadyRunning — the sentinel setupGatewayService recognizes
// as success — instead of propagating a real Windows errno that a
// platform-neutral sequence function/test could not even name (this
// package's own errServiceAlreadyRunning deliberately avoids importing
// golang.org/x/sys/windows outside of windows-only files).
//
// Canary: drop the translation of ERROR_SERVICE_ALREADY_RUNNING in
// classifyStartServiceError (return err as is) — the first comparison
// below turns red.
func TestIAMT312_ClassifyStartServiceError(t *testing.T) {
	if got := classifyStartServiceError(windows.ERROR_SERVICE_ALREADY_RUNNING); got != errServiceAlreadyRunning {
		t.Fatalf("classifyStartServiceError(ERROR_SERVICE_ALREADY_RUNNING) = %v, want errServiceAlreadyRunning", got)
	}
	other := windows.ERROR_ACCESS_DENIED
	if got := classifyStartServiceError(other); got != error(other) {
		t.Fatalf("classifyStartServiceError must pass through any other error unchanged: got %v, want %v", got, other)
	}
	if got := classifyStartServiceError(nil); got != nil {
		t.Fatalf("classifyStartServiceError(nil) = %v, want nil", got)
	}
}

// TestIAMT258_ServiceImagePathEscapesSpacesAndQuotes — the ImagePath
// changeService writes into the SCM is assembled with the same escaping
// (syscall.EscapeArg on every element) that mgr.CreateService applies
// at creation: a path with spaces is wrapped in quotes, quotes inside
// an argument are escaped, trailing backslashes are doubled before the
// closing quote — otherwise the SCM would cut the service's command
// line apart. An element without spaces, tabs, quotes, or backslashes
// comes back verbatim: no quotes and no doubling (see EscapeArg in
// syscall).
//
// Canary: assemble the ImagePath by plain concatenation without
// EscapeArg (or escape only the exe, forgetting the arguments) — the
// comparison against the reference string turns red: a
// "C:\Program Files" path would be cut into two tokens.
func TestIAMT258_ServiceImagePathEscapesSpacesAndQuotes(t *testing.T) {
	got := gatewayServiceBinaryPathName(`C:\Program Files\iamtunnel\iamtunnel.exe`,
		gatewayServiceArguments(`C:\ProgramData\my gateway`, 2222, "gw.example.test"))
	want := `"C:\Program Files\iamtunnel\iamtunnel.exe" gateway run --data-dir "C:\ProgramData\my gateway" --port 2222 --public-host gw.example.test`
	if got != want {
		t.Fatalf("ImagePath =\n  %s\nwant (every element escaped, SPEC §3.5.1):\n  %s", got, want)
	}

	// Quotes inside an argument are escaped; an argument without spaces
	// is not wrapped in quotes (the same assembly as mgr.CreateService).
	q := gatewayServiceBinaryPathName("iam", []string{`x "y"`})
	if wantQ := `iam "x \"y\""`; q != wantQ {
		t.Fatalf("quote escaping: %s, want %s", q, wantQ)
	}

	// A path's trailing backslashes are doubled before the closing
	// quote, otherwise \" "swallows" the separator and the service's
	// path is cut short. The doubling is part of the CLOSING-quote
	// logic, so it must be checked on the very path that makes the
	// quotes appear at all: for a path without spaces EscapeArg returns
	// the string verbatim and there is nothing to double.
	b := gatewayServiceBinaryPathName(`C:\dir with space\`, nil)
	if wantB := `"C:\dir with space\\"`; b != wantB {
		t.Fatalf("trailing backslashes: %s, want %s", b, wantB)
	}
}

// TestIAMT258_ServiceHandlerStopsViaSCMStop — the service's
// svc.Handler: Start → StartPending → Running with
// AcceptStop|AcceptShutdown; an svc.Stop command moves the service to
// StopPending, closes the same stop channel SIGTERM closes in console
// mode (the graceful drain is identical), and yields a clean exit
// (false, 0).
//
// Canary: drop the stop-channel close in the Stop branch (or wait for
// serve to exit forcibly) — the handler hangs or returns (true, 1):
// the StopPending read times out or the exit-code comparison turns
// red.
func TestIAMT258_ServiceHandlerStopsViaSCMStop(t *testing.T) {
	settings := config.Defaults()
	settings.Port = 0 // ephemeral port: the test does not hold a fixed one
	settings.PublicHost = "127.0.0.1"

	h := &gatewayServiceHandler{dir: t.TempDir(), settings: settings}
	requests := make(chan svc.ChangeRequest, 1)
	changes := make(chan svc.Status, 8)
	type execResult struct {
		svcSpecific bool
		code        uint32
	}
	result := make(chan execResult, 1)
	go func() {
		a, b := h.Execute(nil, requests, changes)
		result <- execResult{a, b}
	}()

	if st := <-changes; st.State != svc.StartPending {
		t.Fatalf("first state = %d, want StartPending", st.State)
	}
	st := <-changes
	if st.State != svc.Running || st.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Fatalf("second state = %d (accepts=%d), want Running with AcceptStop|AcceptShutdown", st.State, st.Accepts)
	}

	// The Stop command arrives while serve has not finished yet: the
	// stop channel is closed only in this handler branch, so the path
	// StopPending → graceful drain → clean exit is deterministic.
	requests <- svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: st}
	if st := <-changes; st.State != svc.StopPending {
		t.Fatalf("on Stop, want StopPending, got %d", st.State)
	}
	r := <-result
	if r.svcSpecific || r.code != 0 {
		t.Fatalf("a clean Stop must yield (false, 0), got (%v, %d)", r.svcSpecific, r.code)
	}
}
