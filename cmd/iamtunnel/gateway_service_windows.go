//go:build windows

// gateway_service_windows.go — the production implementation of the
// service seam (windowsService) and the "gateway run" service mode
// under SCM (SPEC §3.5.1). In a test binary every seam call panics:
// tests must substitute the seam with the recording fake
// (withFakeGatewayService), the way withFakeSystemd does for the Linux
// half — no test ever touches the real machine's service database.

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

const (
	// gatewayRecoveryResetPeriod is how many seconds without a failure
	// it takes for the SCM to reset the service's failure counter. SPEC
	// §3.5.1 assigns three restarts 10 seconds apart but says nothing
	// about a reset; a full day without failures means the "three
	// times" is about consecutive failures, not the machine's whole
	// lifetime.
	gatewayRecoveryResetPeriod = 86400
	// gatewayServiceStopTimeout is the upper bound for waiting on
	// SERVICE_STOPPED at uninstall. Stopping the service leads into the
	// same graceful drain as SIGTERM and can last as long as sessions
	// are still winding down; uninstall is not obliged to wait longer
	// than a minute — the operator will repeat the command.
	gatewayServiceStopTimeout = 60 * time.Second
)

// guardProductionSCM keeps the production seam from running inside a
// test binary: substituting the seam is each test's own duty when it
// exercises install/uninstall, and a missed substitution must fail
// loudly rather than touch the real service database (the same scheme
// as internal/server/run_windows.go).
func guardProductionSCM(op string) {
	if testing.Testing() {
		panic("iamtunnel gateway: the production Windows service seam (" + op + ") ran inside a test binary — substitute windowsService with withFakeGatewayService like the Linux systemd seam")
	}
}

// connectSCM opens the service database with rights sufficient for
// installing and managing the gateway service. Each seam opens its own
// connection and closes it before returning — no shared state between
// steps.
func connectSCM() (*mgr.Mgr, error) {
	return mgr.Connect()
}

// runningGatewayServicePort is deliberately read-only. Unlike install and
// uninstall it does not pass through guardProductionSCM: status must be able
// to inspect the live service declaration, and querying it changes nothing.
func runningGatewayServicePort() (int, error) {
	m, err := connectSCM()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	sv, err := m.OpenService(gatewayServiceName)
	if err != nil {
		return 0, err
	}
	defer sv.Close()
	cfg, err := sv.Config()
	if err != nil {
		return 0, err
	}
	return parseGatewayServicePort(cfg.BinaryPathName)
}

// windowsServiceQuery opens name, queries its current status once, and
// hands the result to isMatch. Shared by serviceRunning (uninstall's
// "still busy?" snapshot) and waitRunning (install's "reached RUNNING?"
// poll target) so both read the SCM the same way and differ only in
// which svc.State counts as a match.
func windowsServiceQuery(name string, isMatch func(svc.Status) bool) (bool, error) {
	m, err := connectSCM()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	sv, err := m.OpenService(name)
	if err != nil {
		return false, err
	}
	defer sv.Close()
	st, err := sv.Query()
	if err != nil {
		return false, err
	}
	return isMatch(st), nil
}

// applyRecovery writes the recovery actions from the specification
// (§3.5.1: restart after 10s, three times). It is used both at creation
// and at update — a repeat install must refresh the recovery rules
// along with the rest of the configuration.
func applyRecovery(sv *mgr.Service, recovery []gatewayServiceRecovery) error {
	if len(recovery) == 0 {
		return nil
	}
	actions := make([]mgr.RecoveryAction, 0, len(recovery))
	for _, r := range recovery {
		actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: r.RestartAfter})
	}
	return sv.SetRecoveryActions(actions, gatewayRecoveryResetPeriod)
}

// windowsService is the production seam: real SCM calls through x/sys.
// The account is the virtual NT SERVICE\iamtunnel-gateway (the password
// is empty per the virtual-account rules); the UNRESTRICTED SID type
// gives the service token a per-service SID, which the directory ACL
// already expects (IAMT-257).
var windowsService = windowsServiceSetup{
	serviceExists: func(name string) (bool, error) {
		guardProductionSCM("serviceExists")
		m, err := connectSCM()
		if err != nil {
			return false, err
		}
		defer m.Disconnect()
		sv, err := m.OpenService(name)
		if err != nil {
			if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
				return false, nil
			}
			return false, err
		}
		_ = sv.Close()
		return true, nil
	},
	createService: func(spec gatewayServiceSpec) error {
		guardProductionSCM("createService")
		m, err := connectSCM()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		cfg := mgr.Config{
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
			SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
			ServiceStartName: spec.Account,
			Password:         "",
			DisplayName:      spec.DisplayName,
			Description:      spec.Description,
		}
		// mgr.CreateService escapes every argument through
		// syscall.EscapeArg and assembles the ImagePath
		// "<exe> gateway run --data-dir ... --port ... --public-host ...".
		sv, err := m.CreateService(spec.Name, spec.ExePath, cfg, spec.Args...)
		if err != nil {
			return err
		}
		defer sv.Close()
		return applyRecovery(sv, spec.Recovery)
	},
	changeService: func(spec gatewayServiceSpec) error {
		guardProductionSCM("changeService")
		m, err := connectSCM()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		sv, err := m.OpenService(spec.Name)
		if err != nil {
			return err
		}
		defer sv.Close()
		if err := sv.UpdateConfig(gatewayServiceUpdateConfig(spec)); err != nil {
			return err
		}
		return applyRecovery(sv, spec.Recovery)
	},
	startService: func(name string) error {
		guardProductionSCM("startService")
		m, err := connectSCM()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		sv, err := m.OpenService(name)
		if err != nil {
			return err
		}
		defer sv.Close()
		return classifyStartServiceError(sv.Start())
	},
	serviceRunning: func(name string) (bool, error) {
		guardProductionSCM("serviceRunning")
		// StartPending/ContinuePending counts as "still running" for
		// uninstall: requesting a stop is allowed and right. One
		// snapshot, no waiting — uninstall has nothing to wait for, the
		// service either already runs or it does not.
		return windowsServiceQuery(name, func(st svc.Status) bool {
			return st.State == svc.Running || st.State == svc.StartPending || st.State == svc.ContinuePending
		})
	},
	// waitRunning is the install half of the same question (IAMT-312):
	// "start" answers success as soon as the SCM has ACCEPTED the
	// request, not once the process has settled, so what is needed here
	// is exactly svc.Running (not StartPending — otherwise install could
	// report success over a service that never reached RUNNING) and
	// polling with waiting (waitForLiveness) inside THIS call — the seam
	// itself stays a single call (IAMT-258, round 2), and waiting is the
	// production implementation's duty.
	waitRunning: func(name string) (bool, error) {
		guardProductionSCM("waitRunning")
		return waitForLiveness(func() (bool, error) {
			return windowsServiceQuery(name, func(st svc.Status) bool {
				return st.State == svc.Running
			})
		})
	},
	stopService: func(name string) error {
		guardProductionSCM("stopService")
		m, err := connectSCM()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		sv, err := m.OpenService(name)
		if err != nil {
			return err
		}
		defer sv.Close()
		if _, err := sv.Control(svc.Stop); err != nil {
			// The service may have managed to stop by itself between Query and Control.
			if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
				return nil
			}
			return err
		}
		// The graceful drain lasts as long as sessions are winding down;
		// wait for SERVICE_STOPPED with a bound and report honestly if
		// the allotted time was not enough.
		deadline := time.Now().Add(gatewayServiceStopTimeout)
		for {
			st, err := sv.Query()
			if err != nil {
				return err
			}
			if st.State == svc.Stopped {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the service did not reach SERVICE_STOPPED within %s (a graceful drain may still be in progress — repeat the uninstall once it stops)", gatewayServiceStopTimeout)
			}
			time.Sleep(250 * time.Millisecond)
		}
	},
	deleteService: func(name string) error {
		guardProductionSCM("deleteService")
		m, err := connectSCM()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		sv, err := m.OpenService(name)
		if err != nil {
			return err
		}
		defer sv.Close()
		return sv.Delete()
	},
	hardenDir: func(dir string, replaceACL bool, report io.Writer) (func(), error) {
		guardProductionSCM("hardenDir")
		// A seam, not a direct pass-through of hardenGatewayDirACL:
		// without this wrapper a test binary that forgot to substitute
		// the seam would not panic — it would lock the test user out of
		// their own t.TempDir() with a hardened DACL.
		//
		return hardenGatewayDataDirForService(dir, replaceACL, report)
	},
	hardenExeDir: func(dir, exePath string, replaceACL bool, report io.Writer) error {
		guardProductionSCM("hardenExeDir")
		if err := hardenGatewayExeDirACL(dir, replaceACL, report); err != nil {
			return err
		}
		// IAMT-312 round 5: the directory ACL's (OI)(CI) inheritance
		// only reaches objects created AFTER this call — an exe that
		// already exists there keeps whatever ACL it had before. Harden
		// the file directly so a repeat install can never persist an
		// ImagePath the service account cannot read. replaceACL is the
		// IAMT-315 opt-in: the same contract as for the data dir. report
		// is the same writer as for the data directory; every drop
		// report goes into one stream.
		return hardenGatewayExeFileACL(exePath, replaceACL, report)
	},
}

// gatewayServiceBinaryPathName assembles the ImagePath from the binary
// and the arguments, escaping EVERY element by the Windows rules
// (syscall.EscapeArg) — the same assembly mgr.CreateService performs
// for a new service, so create and change produce byte-identical
// ImagePaths. A path with spaces is wrapped in quotes; quotes inside an
// argument are escaped.
func gatewayServiceBinaryPathName(exePath string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, syscall.EscapeArg(exePath))
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// gatewayServiceUpdateConfig is the pure half of changeService: the
// mgr.Config an install repeat sends to UpdateConfig. Split out so the
// one field that broke on a live Windows box — ServiceType — can be
// pinned by a plain struct-literal test instead of a real ChangeServiceConfig
// call.
//
// IAMT-312: ChangeServiceConfig's dwServiceType parameter only accepts
// SERVICE_NO_CHANGE (0xffffffff) or a real SERVICE_* type constant —
// never the Go zero value 0 that mgr.Config{} leaves here when the field
// is not set explicitly. A live repeat install hit exactly that:
// ChangeServiceConfig returned ERROR_INVALID_PARAMETER (87, "The
// parameter is incorrect") on every call, so the update failed
// atomically and "sc qc" kept showing the OLD BinaryPathName — the
// refusal's own promise ("a repeated install updates in place") was
// false. windows.SERVICE_WIN32_OWN_PROCESS matches what mgr.CreateService
// itself defaults ServiceType to for a brand new service, so create and
// a later update agree on the same type.
func gatewayServiceUpdateConfig(spec gatewayServiceSpec) mgr.Config {
	return mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		ServiceStartName: spec.Account,
		Password:         "",
		DisplayName:      spec.DisplayName,
		Description:      spec.Description,
		// The same ImagePath assembly as CreateService (there the mgr
		// escapes by itself): BinaryPathName carries the full command
		// line, including arguments, always through syscall.EscapeArg —
		// a path with spaces (for example,
		// "C:\Program Files\iamtunnel\...") goes out quoted both at
		// create and at update.
		BinaryPathName: gatewayServiceBinaryPathName(spec.ExePath, spec.Args),
	}
}

// classifyStartServiceError is the pure half of startService, split out
// so the one translation that matters on a live box — recognizing
// ERROR_SERVICE_ALREADY_RUNNING — can be pinned by a plain error-value
// test instead of a real StartService call.
//
// IAMT-312 round 3: a repeat install of an already-running service (the
// ordinary upgrade path — replace the exe, run install again) called
// sv.Start() and got back ERROR_SERVICE_ALREADY_RUNNING (1056). Windows
// treats "start" on a running service as a request error, but the goal
// state setupGatewayService actually wants ("the service is running")
// is already reached, so this is translated to errServiceAlreadyRunning
// — the platform-neutral sentinel setupGatewayService recognizes as
// success, not a failure. Any other error (including nil) passes
// through unchanged.
func classifyStartServiceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return errServiceAlreadyRunning
	}
	return err
}

// runGatewayServiceIfSCM is the "gateway run" entry under SCM (SPEC
// §3.5.1): when the process was started by the service control manager,
// there are no console signals; svc.Run takes over until the service
// ends. A console start (and a test binary) gets (false, nil) and
// continues down the signal path unchanged.
func runGatewayServiceIfSCM(dir string, settings config.Settings) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("gateway run: check whether this process runs under the service control manager: %w", err)
	}
	if !isSvc {
		return false, nil
	}
	return true, svc.Run(gatewayServiceName, &gatewayServiceHandler{dir: dir, settings: settings})
}

// gatewayServiceHandler is the gateway service's svc.Handler.
// Stop/Shutdown close the same stop channel SIGTERM closes in console
// mode, so the graceful drain (Gateway.Drain: no new connections are
// accepted, the live ones get the "gateway is restarting" line, it
// waits for them up to gatewayDrainTimeout; then Gateway.Close cuts the
// rest — SPEC §3.5, IAMT-466) is identical on both platforms.
type gatewayServiceHandler struct {
	dir      string
	settings config.Settings
}

func (h *gatewayServiceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := gatewayServeWithSettings(h.dir, h.settings, nil, stop)
		done <- err
	}()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// The drain (IAMT-466) takes up to gatewayDrainTimeout: the
				// SCM is told so, rather than left to think the stop hung.
				changes <- svc.Status{State: svc.StopPending, WaitHint: uint32((gatewayDrainTimeout + 10*time.Second) / time.Millisecond)}
				close(stop)
				if err := <-done; err != nil {
					return true, 1
				}
				return false, 0
			}
		case err := <-done:
			// serve ended on its own (port taken, disk unavailable): the
			// SCM sees the failure and restarts the service per the
			// §3.5.1 recovery rules.
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
