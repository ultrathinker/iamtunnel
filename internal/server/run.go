package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// ErrServiceCheckNotApplicable is the sentinel a platform's service
// probe returns when asking the OS is not applicable or not possible
// there: the Windows half does not need the probe (its sshd is an SCM
// service queried through QueryServiceStatusEx), the macOS half
// degrades to it when launchctl itself cannot answer (run_darwin.go),
// and the remaining Unixes are the "not supported yet" stub
// (run_other.go). CheckSSHD treats it as "let the dial decide" —
// never as a refusal — so a platform whose probe is unavailable is
// still gated by the thing that actually matters.
var ErrServiceCheckNotApplicable = errors.New("sshd service status check is not applicable on this platform")

// sshdStartHint is what to tell the operator when 127.0.0.1:22 does not
// answer. The daemon and the action are the same everywhere; the way it
// is switched on is not — systemd/SCM on Linux and Windows, Remote
// Login on macOS — so every platform file declares its own sentence
// (run_linux.go, run_windows.go, run_darwin.go, run_other.go). Keeping
// the declaration per platform means a new platform cannot be added
// without deciding what to tell its operator.

// CheckSSHD verifies that the local sshd service is running and listening on
// targetAddr before any connection to the gateway is made (SPEC §3.2: QueryServiceStatusEx + dial).
// If checkService is nil, it uses defaultCheckSSHDService.
func CheckSSHD(targetAddr string, checkService func() error) error {
	if checkService == nil {
		checkService = defaultCheckSSHDService
	}
	if err := checkService(); err != nil && !errors.Is(err, ErrServiceCheckNotApplicable) {
		return fmt.Errorf("sshd service check failed: %w", err)
	}
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return fmt.Errorf("sshd on %s is not reachable — %s: %w", targetAddr, sshdStartHint, err)
	}
	_ = conn.Close()
	return nil
}

// CheckSSHDConfig is the public form of the Unix
// "sshd -T -C user=<osUser>" pre-flight (SPEC §3.2.1): the
// check is a no-op on every platform that does not implement
// it (Windows does not need it — %ProgramData%\ssh is the only
// authorised_keys file sshd reads there; the remaining Unixes
// are the "not supported yet" stub in run_other.go).
// nil checkFn means "use the platform default" —
// defaultCheckSSHDConfig on Linux (run_linux.go) and on macOS
// (run_darwin.go, IAMT-263), nil-returns-ok on Windows.
//
// On both Unix platforms the default probes sshd -T for
// `pubkeyauthentication yes` and a `authorizedkeysfile` that ends
// with `.ssh/authorized_keys`; both conditions failing is the most
// common operator configuration mistake (a custom AuthorizedKeysFile
// set without aligning the door's --key-file), and surfacing it
// before any tunnel connect keeps the operator out of a
// "the door opens but sshd silently rejects" dead end. Only the
// refusal wording differs: each platform names its own way of
// reloading the daemon.
func CheckSSHDConfig(osUser string, checkFn func(string) error) error {
	return checkSSHDConfigPlatform(osUser, checkFn)
}

// Run drives the machine's whole outbound life: sweep, dial, serve,
// repeat with a growing backoff on every ordinary disconnect, forever,
// until ctx is cancelled. It is the production entry point; tests that
// want fine-grained control over a single connection call Dial and Serve
// directly instead.
//
// This function draws a hard line between the two failure classes it
// handles differently:
//
//   - a fingerprint mismatch is not a network hiccup — "a mismatch means
//     refusal and a clear message, no trust on first contact" — so Run
//     returns immediately, without a single further attempt;
//   - anything else (refused connection, timeout, lost tunnel, control
//     error) gets "repeated attempts with a growing pause, but no
//     infinite storm" — retried forever with a capped, jittered,
//     exponentially growing delay.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.setDefaults(); err != nil {
		return err
	}

	delay := cfg.BackoffBase
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := sweepBeforeConnect(cfg); err != nil {
			cfg.logf("run: SweepStale before connect failed: %v", err)
		}

		m, err := Dial(ctx, cfg)
		if err != nil {
			if errors.Is(err, ErrFingerprintMismatch) {
				cfg.logf("run: %v — refusing to retry", err)
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			cfg.logf("run: dial failed, retrying in %s: %v", delay, err)
			if !sleepOrDone(ctx, delay) {
				return ctx.Err()
			}
			delay = nextBackoff(delay, cfg.BackoffMax)
			continue
		}

		delay = cfg.BackoffBase // a connection that got this far resets the backoff
		if cfg.StatusSink != nil {
			cfg.StatusSink(m)
		}
		serveErr := m.Serve(ctx)
		if cfg.StatusSink != nil {
			cfg.StatusSink(nil)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		cfg.logf("run: tunnel ended, reconnecting in %s: %v", delay, serveErr)
		if !sleepOrDone(ctx, delay) {
			return ctx.Err()
		}
		delay = nextBackoff(delay, cfg.BackoffMax)
	}
}

// sweepBeforeConnect removes every door line before the very first
// connection attempt too, not only reconnects (SPEC §3.2: "Start:
// SweepStale"); a crash on a previous run leaves exactly the same kind of
// stale line a mid-life reconnect does.
func sweepBeforeConnect(cfg Config) error {
	dc, err := newDoorController(&cfg)
	if err != nil {
		return err
	}
	_, err = dc.sweepStale()
	return err
}

// nextBackoff doubles the delay, caps it at max, and applies +/-20%
// jitter so many machines reconnecting to the same gateway after a
// shared outage do not arrive in lockstep.
func nextBackoff(delay, max time.Duration) time.Duration {
	next := delay * 2
	if next > max || next <= 0 {
		next = max
	}
	jitter := time.Duration(float64(next) * (0.8 + 0.4*rand.Float64()))
	if jitter <= 0 {
		jitter = next
	}
	return jitter
}

// sleepOrDone waits for d or ctx cancellation, whichever comes first.
// Reports whether the wait completed normally (false means ctx was
// cancelled and the caller should stop).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
