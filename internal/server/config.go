package server

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// Config is everything one Machine needs to run. Every dependency the
// automaton or the transport could otherwise reach for is a field here
// (a value supplied once, at construction), never a package variable —
// the same discipline internal/gateway/core.Config and internal/winkeys.
// Door already use, and one this package does not break with an
// exported setter or a build tag.
type Config struct {
	// GatewayAddr is "host:port" the machine dials outbound (SPEC §3.2:
	// the machine is behind NAT, it always calls out).
	GatewayAddr string
	// GatewayFingerprint is the "SHA256:<43 base64>" fingerprint pinned
	// at registration. It is compared byte-for-byte against the host
	// key the gateway presents; there is no first-contact trust and no
	// path that ever overwrites it from the network (SPEC §6.2).
	GatewayFingerprint string
	// MachineID is the bare id (no "machine:" prefix); the SSH username
	// is built as "machine:" + MachineID.
	MachineID string
	// MachineKey signs the machine's own SSH login to the gateway.
	MachineKey ssh.Signer

	// KeyFile is the path to the authorized_keys-shaped file the door
	// installs its line into. It is always a parameter — this package
	// never resolves a real sshd configuration path.
	KeyFile string
	// DoorLockPath is the cross-process lock file's path. On Linux and
	// Darwin SPEC §3.2.1 requires the lock to live in the server's data
	// directory (where the user cannot hold it), so cmd/iamtunnel fills
	// this in from <server-dir>/door.lock at start time. On Windows it
	// is left empty — the platform layer derives <KeyFile>.lock from
	// KeyFile, preserving the historical layout. Tests may pass any
	// path inside t.TempDir().
	DoorLockPath string
	// OwnerUID / OwnerGID are the file owner for the authorised keys
	// file (linux/darwin only). cmd/iamtunnel resolves them via
	// os/user.Lookup at start time and threads them through Config so
	// winkeys can fchown(2) the tmp file before the rename without
	// touching the user database from a test binary. On Windows they
	// stay zero — sshd's Match Group administrators identity owns the
	// file, not iamtunnel.
	OwnerUID int
	OwnerGID int
	// OSUser is the gateway-bound OS user the key file belongs to
	// (linux/darwin only). cmd/iamtunnel reads it from enrolment.json
	// and threads it through Config so server.Start can call
	// sshd -T -C user=<OSUser> without re-reading it; the server
	// role surfaces it to sshdTOutputFn's match config. On Windows
	// it stays empty — sshd reads the well-known ProgramData\ssh\
	// administrators_authorized_keys file unconditionally, so the
	// runtime config probe is a no-op there.
	OSUser string
	// TargetAddr is where an accepted iamtunnel-target channel is
	// spliced to — production points this at 127.0.0.1:22; tests point
	// it at a loopback fake. Always a parameter, never a constant.
	TargetAddr string
	// DoorwatchExe is the executable SpawnWatchdog re-execs as
	// "<exe> server doorwatch <id> <pid> <keyfile> <max-wait-ms> <journal-path>"
	// (winkeys.SpawnWatchdog).
	DoorwatchExe string
	// SpawnWatchdog is the watchdog constructor. Defaults to
	// winkeys.SpawnWatchdog; tests may substitute a fake so unit tests
	// of the control protocol do not have to spawn a real process. This
	// is a constructor-supplied collaborator exactly like
	// core.Config.NewDoor in the gateway automaton — not a runtime
	// switch, since the ordering it is used under (spawn before write,
	// stop after confirmed close) is enforced by this package's code,
	// not by the collaborator.
	//
	// lockPath / ownerUID / ownerGID are the unix-platform fields the
	// door layer's validateOptionsPlatform requires (linux/darwin;
	// IAMT-94/198/246 sentinel gate). They are threaded into
	// SpawnWatchdog because the doorwatch subprocess ends up calling
	// NewDoorWithOptions on its end and the same rules apply there.
	// On Windows these are forwarded but ignored by the platform
	// implementation (validateOptionsPlatform is a no-op); on Linux
	// they are required and used; on Darwin they are likewise
	// required but the SpawnWatchdog half is still the IAMT-263 stub.
	SpawnWatchdog func(exe, doorID, keyFile string, parentPID int, maxWait time.Duration, journalPath, lockPath string, ownerUID, ownerGID int) (*winkeys.Watchdog, error)
	// WatchdogJournal is the path of the audit log the doorwatch
	// subprocess writes its layer-3 cleanup event into. Empty means
	// "no journal" — the spawned child uses noopSink and the cleanup
	// event is dropped, the same as the previous sink=nil behaviour.
	// In production this points at events.jsonl in the machine data
	// directory; tests MUST pass a path under t.TempDir() explicitly.
	WatchdogJournal string
	// Sink receives winkeys door audit events. Optional.
	Sink winkeys.Sink
	// Logger receives one-line diagnostic strings for conditions that
	// must not fail an otherwise-successful operation (PROTOCOL §5.2:
	// a watchdog-stop failure after a confirmed close is logged locally
	// and does not turn removed:true into an error). Optional.
	Logger func(string)

	// MaxDoorIdle/MaxDoorHard are the machine's own ceilings (SPEC
	// §3.2/§6.4): a door.open asking for more is refused outright, and
	// once granted, the machine closes the door on its own monotonic
	// timer even if the gateway never asks — it has the right to refuse
	// a gateway request that exceeds them.
	MaxDoorIdle time.Duration
	MaxDoorHard time.Duration

	// Keepalive parameters for both the active probe this machine sends
	// and the passive responder it runs (PROTOCOL §5: symmetric).
	Keepalive sshx.Keepalive

	DialTimeout      time.Duration
	HandshakeTimeout time.Duration

	// ControlLineMax bounds one control-channel JSON line in bytes
	// (PROTOCOL §5.1: 16 KiB). Required parser hardening, not policy.
	ControlLineMax int
	// ControlJSONDepth bounds JSON nesting depth accepted from the
	// control channel, independent of encoding/json's own much larger
	// internal guard.
	ControlJSONDepth int

	// BackoffBase/BackoffMax bound the reconnect backoff Run uses after
	// a transport loss: a growing pause, never an unbounded storm, never
	// an infinite pause either.
	BackoffBase time.Duration
	BackoffMax  time.Duration

	// StatusSink, if non-nil, is handed the live *Machine the instant Run
	// connects (right after a successful Dial), and nil the instant that
	// Machine stops serving (transport lost, or ctx cancelled) — never
	// anything in between. It exists so a caller that does not own the
	// connect loop itself (cmd/iamtunnel's control-status handler,
	// IAMT-182) can still answer "is the door open right now" honestly,
	// without a second copy of the reconnect loop and without Run handing
	// back the *Machine directly (which would outlive the one connection
	// it belongs to). Optional: nil means nobody is asking.
	StatusSink func(*Machine)
}

// Default bounds, chosen the same way PROTOCOL §1.5 documents its own
// numbers: explicit decisions recorded here, not implied by a library.
const (
	DefaultMaxDoorIdle      = 15 * time.Minute
	DefaultMaxDoorHard      = 8 * time.Hour
	DefaultDialTimeout      = 10 * time.Second
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultControlLineMax   = 16 * 1024
	DefaultControlJSONDepth = 16
	DefaultBackoffBase      = 1 * time.Second
	DefaultBackoffMax       = 30 * time.Second
)

// WatchdogLifetimeSlack is how much longer than MaxDoorHard the
// doorwatch subprocess waits before it gives up on its parent. The
// watchdog's whole point is to outlive the door — MaxDoorHard+slack
// covers (a) the time between SpawnWatchdog returning and the child
// reaching WaitForSingleObject, (b) drift between the server's hard
// timer and the wall clock the child sees, and (c) the natural
// floor a Windows timer can resolve to. Five minutes is the same
// slack the previous hard-coded 5-minute cap left between "watchdog
// exits" and "door is hard-closed", just now in the right direction
// (IAMT-130). The slack is a package-level constant rather than a
// Config field: it is an implementation detail of how the watchdog
// process is started, not a deployment knob the operator tunes.
const WatchdogLifetimeSlack = 5 * time.Minute

// WatchdogLifetime is the value the watchdog constructor passes as
// its maxWait: the door's full legal lifetime plus the safety slack.
// Production callers get it via Config.WatchdogLifetime(); tests can
// call it on a Config literal with setDefaults already applied.
func (c *Config) WatchdogLifetime() time.Duration {
	hard := c.MaxDoorHard
	if hard <= 0 {
		hard = DefaultMaxDoorHard
	}
	return hard + WatchdogLifetimeSlack
}

func (c *Config) setDefaults() error {
	if c.GatewayAddr == "" {
		return errors.New("server: GatewayAddr is required")
	}
	if c.GatewayFingerprint == "" {
		return errors.New("server: GatewayFingerprint is required (no first-contact trust)")
	}
	if c.MachineID == "" {
		return errors.New("server: MachineID is required")
	}
	if c.MachineKey == nil {
		return errors.New("server: MachineKey is required")
	}
	if c.KeyFile == "" {
		return errors.New("server: KeyFile is required")
	}
	if c.TargetAddr == "" {
		return errors.New("server: TargetAddr is required")
	}
	if c.SpawnWatchdog == nil {
		if c.DoorwatchExe == "" {
			return errors.New("server: DoorwatchExe is required when SpawnWatchdog is not overridden")
		}
		// Default SpawnWatchdog is the winkeys factory, full stop. The
		// previous implementation built a closure that re-derived
		// WatchdogLifetime() and re-read WatchdogJournal here and then
		// silently ignored the caller's values (the `_ = mw; _ = jp`
		// shims). That meant there were two sources of truth for the
		// same two values: one inside setDefaults and one inside door.go.
		// They happened to agree because MaxDoorHard/WatchdogJournal
		// are not mutated between setDefaults and door.open, but the
		// closure's defence against that mutation was never tested —
		// IAMT-130's canary was aimed at the door.go call site, the
		// closure in this file was not on its radar at all.
		//
		// The structural fix is to delegate straight through: the
		// caller (door.go) is the single place that computes and hands
		// over WatchdogLifetime() and WatchdogJournal, and there is
		// no parallel computation here to drift from. A future
		// regression that reintroduced a capturing closure would split
		// the source of truth in two again — the IAMT-139
		// "DefaultSpawnWatchdogIsWinkeysSpawnWatchdog" test pins it.
		c.SpawnWatchdog = winkeys.SpawnWatchdog
	}
	if c.MaxDoorIdle <= 0 {
		c.MaxDoorIdle = DefaultMaxDoorIdle
	}
	if c.MaxDoorHard <= 0 {
		c.MaxDoorHard = DefaultMaxDoorHard
	}
	if c.MaxDoorHard <= c.MaxDoorIdle {
		return errors.New("server: MaxDoorHard must exceed MaxDoorIdle")
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.ControlLineMax <= 0 {
		c.ControlLineMax = DefaultControlLineMax
	}
	if c.ControlJSONDepth <= 0 {
		c.ControlJSONDepth = DefaultControlJSONDepth
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = DefaultBackoffBase
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = DefaultBackoffMax
	}
	if c.BackoffMax < c.BackoffBase {
		c.BackoffMax = c.BackoffBase
	}
	return nil
}

func (c *Config) logf(format string, args ...any) {
	if c.Logger == nil {
		return
	}
	c.Logger(fmt.Sprintf(format, args...))
}
