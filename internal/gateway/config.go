package gateway

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// SessionInfo is what the runtime knows about a session at the moment it must
// open a recording. It is passed to Config.NewRecording so a test can inject a
// fake or failing recorder without a package-level switch.
type SessionInfo struct {
	Person    string
	Machine   string
	OSUser    string
	SessionID string
	Cols      int
	Rows      int
	// Exec is true only for an exec request that arrived without pty-req:
	// such a session gets the lossless exec recording. Command is the exact
	// SSH exec command whenever the session was started by one - also after
	// a pty-req ("ssh -t gw command"), where the recording is a terminal
	// one and carries the command in its header and .meta (IAMT-454).
	Exec    bool
	Command string
}

// RiskAction specifies how the gateway handles a non-green pre-flight
// command verdict. It is deliberately a policy choice of the gateway owner:
// the classifier is a guard against accidents, not a security boundary.
type RiskAction string

const (
	RiskActionLog   RiskAction = "log"
	RiskActionWarn  RiskAction = "warn"
	RiskActionAsk   RiskAction = "ask"
	RiskActionBlock RiskAction = "block"
)

// RiskClassifier selects which pre-flight verdict source the gateway trusts.
// rules is the compatibility/default path; ai and both require the external
// classifier key and pay its request budget before an undecided exec runs.
type RiskClassifier string

const (
	RiskClassifierRules RiskClassifier = "rules"
	RiskClassifierAI    RiskClassifier = "ai"
	RiskClassifierBoth  RiskClassifier = "both"
)

// Config wires the runtime to the already-accepted packages and to time. Every
// knob a test needs to vary (clock, timeouts, the recording constructor) is a
// constructor argument here - never a package variable, exported setter or
// field that product code could be talked into mutating after the fact.
type Config struct {
	// Store is the persisted state: people, machines, grants (state.json).
	Store *state.Store
	// Log is the append-only event journal (events.jsonl).
	Log *events.Log
	// HostKey is the gateway's own SSH host key, presented to every peer.
	HostKey ssh.Signer

	// Now returns the gateway's notion of the current time (SPEC 6.4: the
	// gateway's clock is the single source of truth). Defaults to time.Now.
	Now func() time.Time

	// PublicHost/PublicPort are what the admin role hands out in a
	// connection string or enrol code (SPEC §3.1, §3.4): the address a
	// remote client or machine should dial, which is not always the
	// address this process happens to be listening on (NAT, a reverse
	// proxy, a different public DNS name). Left empty/zero, admin_role.go
	// still renders a string - just not one anyone outside a test can
	// dial - which is why "gateway install" is expected to set these.
	PublicHost string
	PublicPort int

	AuthLimits auth.AuthLimits
	ACLLimits  acl.Limits
	RateConfig auth.RateConfig

	// Pairing holds the PIN-pairing numbers (PROTOCOL §1.5, §3.4 —
	// IAMT-323): PIN length, window TTL, and the rate-limit numbers of the
	// dedicated pairing limiter. Defaults are applied per field in
	// setDefaults; the numbers are v1 protocol parameters, not constants.
	Pairing PairingConfig

	// DoorIdle/DoorHard are the deadlines the gateway proposes on door.open;
	// the machine enforces its own local ceilings independently (PROTOCOL
	// §5.1) - the gateway cannot violate the machine's ceiling by lying here,
	// it can only ask for something the machine may refuse.
	DoorIdle time.Duration
	DoorHard time.Duration

	// Control-channel timeouts (PROTOCOL §1.5 numbers as defaults).
	ControlAcceptTimeout time.Duration
	DoorOpenTimeout      time.Duration
	DoorCloseTimeout     time.Duration
	DoorStatusTimeout    time.Duration

	// DoorStatusBackoff is the pause before the door.status that follows an
	// unanswered one, doubling with every further miss; DoorStatusMaxMisses
	// unanswered in a row end the machine's epoch unless a session is live
	// on it (PROTOCOL §1.5, §5.2; IAMT-457).
	DoorStatusBackoff   time.Duration
	DoorStatusMaxMisses int

	// AuthSuccessQuiet is how long a login is not journaled again for the
	// same username, key and host: one auth.success, and the rest counted
	// in one more when the quiet ends (IAMT-452, auth_quiet.go).
	AuthSuccessQuiet time.Duration
	// JournalRotateBytes is the size at which the gateway rotates its own
	// events.jsonl into an archive beside it (IAMT-452).
	JournalRotateBytes int64
	// JournalArchiveRetentionDays is how old a rotated journal archive may
	// grow before the sweep prunes it (R4 F-11): the timestamp in the
	// archive's name is its age, and every pruning is journaled (PROTOCOL
	// §8: every deletion is an event). Zero or negative means the default.
	JournalArchiveRetentionDays int
	// JournalArchiveMaxCount is how many rotated journal archives the
	// retention keeps, newest first, regardless of age (R4 F-11) - the
	// bound that holds even when archives arrive faster than days pass.
	// Zero or negative means the default.
	JournalArchiveMaxCount int

	// Version is the running build as gateway.status reports it (IAMT-466):
	// after an update, the one way to see from outside which build answers.
	Version string

	// SessionSetupTimeout bounds channel-open through first shell/exec
	// result (PROTOCOL §1.4: 20 seconds).
	SessionSetupTimeout time.Duration

	// SSHDProbeTimeout is the single wall-clock budget for both sshd-probe
	// phases. It is configurable at construction so tests do not wait 20s.
	SSHDProbeTimeout time.Duration

	// Keepalive drives the gateway→machine probe (PROTOCOL §5). Numbers
	// mirror DefaultKeepaliveInterval/DefaultKeepaliveMisses; the field is
	// set by the test fixture so it can be tightened to milliseconds.
	Keepalive sshx.Keepalive

	// HumanKeepalive drives the gateway→human probe (PROTOCOL §4.2). The
	// same sshx.Keepalive.Probe is used with Name="keepalive@openssh.com"
	// because §4.1 already lists that name on the wire; only the numbers
	// (20 s, 3 misses, 60 s + delivery detection, 90 s reaction) and the
	// mechanism are symmetric with §5. Defaults are filled by setDefaults
	// when the field is zero.
	HumanKeepalive sshx.Keepalive

	// RiskAction is the one ordered consequence setting for non-green
	// exec-only verdicts. The ladder is log → warn → ask → block: log journals,
	// warn runs with a warning, ask requires a one-time human approval for red,
	// and block refuses red. Yellow remains a warning under ask and block. It
	// defaults to warn so an upgrade never silently stops an owner's automation.
	RiskAction RiskAction

	// RiskClassifier selects the source of the pre-flight verdict. It defaults
	// to rules. ai asks the external classifier for every exec; both combines
	// the local and external verdicts, with the local red path already decided
	// before any external request is needed.
	RiskClassifier RiskClassifier

	// RecentCommandsMax bounds how many entries the pair's recent-command
	// buffer (IAMT-409) keeps per person+machine pair. Defaults to 10; the
	// state layer clamps it to its own ceiling (state.MaxRecentCommands).
	RecentCommandsMax int
	// RecentCommandsBudget bounds the pair's buffer in characters of command
	// + response + exit text. When it runs out, oldest entries are dropped
	// and the newest entry is truncated with an ellipsis. Defaults to 2000.
	RecentCommandsBudget int

	// ExternalRiskObservationEnabled is the old configuration seam. A runtime
	// caller that leaves RiskClassifier empty and sets this flag gets both;
	// settings loaded through the compatibility layer make that choice explicit.
	ExternalRiskObservationEnabled bool
	// ExternalRiskObservationKeyFile keeps its old name for config compatibility
	// even though the external service is now an active classifier.
	ExternalRiskObservationKeyFile string
	// externalRiskClassifier is constructed only after a non-empty key file
	// has been read at startup. Keeping it private prevents a runtime caller
	// from bypassing the key-file requirement.
	externalRiskClassifier risk.ExternalClassifier
	// externalRiskClassifierFactory is a package-test seam for runtime key
	// replacement. Production leaves it nil and uses the Typesafe client;
	// tests can construct a local classifier without making network calls.
	externalRiskClassifierFactory func(string) risk.ExternalClassifier
	// externalRiskKeyFingerprint is metadata derived at startup from the
	// active key. It is never the key itself and is persisted into State by
	// Gateway.New.
	externalRiskKeyFingerprint string

	// RecordingBaseDir is where recordings/<machine>/... is rooted.
	RecordingBaseDir string

	// DataDir is the gateway's own data directory — the one holding
	// state.json, events.jsonl and the host key file. It is what the
	// lifecycle commands (PROTOCOL §6 gateway.backup /
	// gateway.rotate-hostkey, internal/gateway/lifecycle.go and
	// admin_lifecycle.go) operate on: remote backups land under
	// <DataDir>/backups and rotation rewrites the host key in place.
	// Empty means "not wired": the gateway still runs, but those two
	// commands refuse with E_INTERNAL instead of guessing a directory.
	// Production wiring (cmd/iamtunnel gatewayRuntimeConfig) always sets
	// it; tests that never exercise the lifecycle commands may leave it
	// unset.
	DataDir string
	// Diagnostics receives the few lines an operator must see even when
	// the audit journal is the thing that broke: one line each time the
	// journal stops or starts being written again (IAMT-451). The CLI
	// points it at the service's stderr; nil writes nothing.
	Diagnostics io.Writer
	// NewRecording builds the recorder for one session. Defaults to a
	// record.Recorder rooted at RecordingBaseDir; a test replaces this to
	// observe recorder failures or to avoid the filesystem entirely -
	// exactly the "inject the dependency through a constructor" seam
	// instead of a product-code switch.
	NewRecording func(SessionInfo) (core.Recording, error)

	// RecordingRetentionDays is the age limit for old recordings.
	// Sessions older than this are pruned by the periodic rotation sweep.
	// Zero means "do not prune by age" - useful in tests, never in
	// production: production always wires this from the
	// recordings_retention_days config setting (default 90 days, IAMT-130
	// guards against hard-coding the number in code).
	RecordingRetentionDays int
	// RecordingRotatePercent is the filesystem-fullness threshold that triggers
	// size-based rotation. The periodic sweep prunes oldest recordings while the
	// filesystem holding recordings is at or above this percent. Zero disables
	// size-based rotation. Range 1..99; production wires it from the
	// historically named recordings_disk_stop_percent config setting (default 85).
	RecordingRotatePercent int
	// RecordingRefusePercent is the disk-usage threshold at which the
	// gateway refuses new sessions outright (PROTOCOL §8,
	// recordingRefusePercent). Must be strictly greater than
	// RecordingRotatePercent and at most 99; default 95 when zero.
	// NewRecording consults this before opening a recording and fails
	// with E_RECORDING_DISK_FULL when the disk has crossed it.
	RecordingRefusePercent int
	// RecordingRotationInterval is the period of the background rotation
	// sweep. Zero disables the periodic sweep (one shot at New time
	// still runs, so a long-lived test that sets zero is not silently
	// broken: it is just self-cleaning on startup and at Close). Default
	// one minute in production; tests tighten it to milliseconds.
	RecordingRotationInterval time.Duration
}

// PairingConfig groups the PIN-pairing parameters (PROTOCOL §1.5, §3.4).
type PairingConfig struct {
	// PINDigits is the exact length of the numeric pairing PIN (v1: 6,
	// leading zeros allowed).
	PINDigits int
	// WindowTTL is how long one pairing window stays open once issued
	// (v1: 2 minutes). Expiry is enforced at exec time against the
	// gateway's clock, not at the handshake.
	WindowTTL time.Duration
	// Rate parameterises the dedicated pairing limiter (the same
	// auth.RateLimiter machinery the handshake limiter uses, a second
	// instance). The pairing path records every failure per ADDRESS
	// (known=false), so MaxKnownFailures exists only because
	// NewRateLimiter requires it positive; the meaningful numbers are
	// MaxUnknownFailures (v1: 3 wrong PINs from one address) and
	// AddrBanDuration (v1: 3 minutes).
	Rate auth.RateConfig
}

func (c *Config) setDefaults() error {
	if c.Store == nil {
		return fmt.Errorf("gateway: Config.Store is required")
	}
	if c.Log == nil {
		return fmt.Errorf("gateway: Config.Log is required")
	}
	if c.HostKey == nil {
		return fmt.Errorf("gateway: Config.HostKey is required")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.AuthLimits.HandshakeTimeout <= 0 {
		c.AuthLimits.HandshakeTimeout = 20 * time.Second
	}
	if c.RateConfig.MaxKnownFailures <= 0 {
		c.RateConfig = auth.RateConfig{
			MaxKnownFailures:   10,
			MaxUnknownFailures: 10,
			Window:             5 * time.Minute,
			PairBanDuration:    15 * time.Minute,
			AddrBanDuration:    15 * time.Minute,
		}
	}
	// Pairing defaults are PROTOCOL §1.5's v1 numbers (IAMT-323): 6-digit
	// PIN, 2-minute window, 3 wrong PINs per address inside the limiter's
	// 5-minute window → 3-minute pairing ban. MaxKnownFailures is unused
	// in production — the pairing path records every failure as unknown —
	// but must stay positive for the limiter's constructor.
	if c.Pairing.PINDigits <= 0 {
		c.Pairing.PINDigits = 6
	}
	if c.Pairing.WindowTTL <= 0 {
		c.Pairing.WindowTTL = 2 * time.Minute
	}
	if c.Pairing.Rate.MaxKnownFailures <= 0 {
		c.Pairing.Rate = auth.RateConfig{
			MaxKnownFailures:   3,
			MaxUnknownFailures: 3,
			Window:             5 * time.Minute,
			PairBanDuration:    3 * time.Minute,
			AddrBanDuration:    3 * time.Minute,
		}
	}
	if c.DoorIdle <= 0 {
		c.DoorIdle = 15 * time.Minute
	}
	if c.DoorHard <= c.DoorIdle {
		c.DoorHard = 8 * time.Hour
	}
	if c.ControlAcceptTimeout <= 0 {
		c.ControlAcceptTimeout = 10 * time.Second
	}
	if c.DoorOpenTimeout <= 0 {
		c.DoorOpenTimeout = 10 * time.Second
	}
	if c.DoorCloseTimeout <= 0 {
		c.DoorCloseTimeout = 5 * time.Second
	}
	if c.DoorStatusTimeout <= 0 {
		c.DoorStatusTimeout = 5 * time.Second
	}
	if c.DoorStatusBackoff <= 0 {
		c.DoorStatusBackoff = time.Second
	}
	if c.DoorStatusMaxMisses <= 0 {
		c.DoorStatusMaxMisses = 5
	}
	if c.AuthSuccessQuiet <= 0 {
		c.AuthSuccessQuiet = 10 * time.Minute
	}
	if c.JournalRotateBytes <= 0 {
		c.JournalRotateBytes = 64 << 20
	}
	if c.JournalArchiveRetentionDays <= 0 {
		c.JournalArchiveRetentionDays = 30
	}
	if c.JournalArchiveMaxCount <= 0 {
		c.JournalArchiveMaxCount = 20
	}
	if c.SessionSetupTimeout <= 0 {
		c.SessionSetupTimeout = 20 * time.Second
	}
	// HumanKeepalive defaults: 20 s interval, 3 misses, openssh.com name.
	// PROBE NAMING: keepalive@openssh.com is the OpenSSH convention and is
	// already on the wire for the client→gateway direction in §4.1; using
	// the same name for the gateway→human direction is the simplest wire
	// surface and matches what a typical iamtunnel client (or any OpenSSH-
	// conforming client) already knows how to answer. Symmetry with §5 is
	// about the mechanism (Probe with the same numbers) and the policy
	// (same interval/misses), not about reusing the §5-only name.
	if c.HumanKeepalive.Interval <= 0 {
		c.HumanKeepalive.Interval = 20 * time.Second
	}
	if c.HumanKeepalive.MaxMisses <= 0 {
		c.HumanKeepalive.MaxMisses = 3
	}
	if c.HumanKeepalive.Name == "" {
		c.HumanKeepalive.Name = "keepalive@openssh.com"
	}
	if c.RiskAction == "" {
		c.RiskAction = RiskActionWarn
	}
	if !validRiskAction(c.RiskAction) {
		return fmt.Errorf("gateway: invalid RiskAction %q", c.RiskAction)
	}
	if c.RiskClassifier == "" {
		if c.ExternalRiskObservationEnabled {
			c.RiskClassifier = RiskClassifierBoth
		} else {
			c.RiskClassifier = RiskClassifierRules
		}
	}
	if !validRiskClassifier(c.RiskClassifier) {
		return fmt.Errorf("gateway: invalid RiskClassifier %q", c.RiskClassifier)
	}
	if c.RecentCommandsMax <= 0 {
		// The card's default. Anything above state.MaxRecentCommands is
		// clamped by the state layer on every write, so the ceiling here is
		// a warning-shaped clamp, not a second source of truth.
		c.RecentCommandsMax = 10
	}
	if c.RecentCommandsBudget <= 0 {
		c.RecentCommandsBudget = 2000
	}
	if c.RiskClassifier != RiskClassifierRules {
		// datafile.ReadFile, not os.ReadFile: this path holds a secret, and
		// datafile is what refuses a symlink or a hard link planted at the
		// name (gate 16, IAMT-332). A key read through a planted link is a
		// key handed to whoever planted it.
		key, err := datafile.ReadFile(c.ExternalRiskObservationKeyFile)
		if err != nil {
			return fmt.Errorf("gateway: read external risk observation key file %q: %w", c.ExternalRiskObservationKeyFile, err)
		}
		if stringKey := strings.TrimSpace(string(key)); stringKey != "" {
			c.externalRiskKeyFingerprint = externalRiskKeyFingerprint(stringKey)
			if c.externalRiskClassifierFactory != nil {
				c.externalRiskClassifier = c.externalRiskClassifierFactory(stringKey)
			} else {
				c.externalRiskClassifier = risk.NewExternalClassifier(stringKey)
			}
		} else {
			return fmt.Errorf("gateway: external risk observation key file %q is empty", c.ExternalRiskObservationKeyFile)
		}
	}
	// PROTOCOL §4.2 (IAMT-220): a real OpenSSH peer answers an unknown
	// global request with request failure, and that failure still proves
	// the transport and the human are alive. This is a protocol default,
	// not an opt-in switch, so it is forced unconditionally rather than
	// gated on the field's zero value like Interval/MaxMisses/Name above —
	// there is no reading of "false" here that a caller could legitimately
	// mean. §5's machine-side c.Keepalive is untouched and keeps
	// FailureIsAlive == false: there, only our own agent answers, and
	// failure is a protocol violation.
	c.HumanKeepalive.FailureIsAlive = true
	if c.SSHDProbeTimeout <= 0 {
		c.SSHDProbeTimeout = 20 * time.Second
	}
	if c.RecordingBaseDir == "" {
		c.RecordingBaseDir = "recordings"
	}
	// The recordings root is a gateway-owned runtime directory. Create it at
	// startup, before the disk gate asks the OS for its volume statistics:
	// a fresh install legitimately has no recordings yet, whereas a failure to
	// create this directory is a real error and must still fail closed.
	if err := os.MkdirAll(c.RecordingBaseDir, 0o700); err != nil {
		return fmt.Errorf("gateway: create recordings directory %s: %w", c.RecordingBaseDir, err)
	}
	// RecordingRefusePercent default is PROTOCOL §8's recordingRefusePercent.
	// Range and ordering are checked in New, not here: a zero here means
	// "use the documented default", a non-zero here means the caller (or
	// a test) pinned a value and we leave it alone.
	if c.RecordingRefusePercent == 0 {
		c.RecordingRefusePercent = 95
	}
	if c.RecordingRotationInterval == 0 {
		c.RecordingRotationInterval = time.Minute
	}
	if c.NewRecording == nil {
		base, now, refusePct := c.RecordingBaseDir, c.Now, c.RecordingRefusePercent
		c.NewRecording = func(si SessionInfo) (core.Recording, error) {
			// PROTOCOL §8: refuse a fresh recording when the volume has
			// crossed recordingRefusePercent. Done here, before
			// record.NewRecorder touches the filesystem - the recorder's own
			// MkdirAll would also catch an ENOSPC, but only after the gate
			// has already accepted the session; this check is the one the
			// RUNBOOK §6 line 11 "session recording" actually promises.
			if refuse, _, err := record.ShouldRefuseNewRecording(base, refusePct); err != nil {
				return nil, fmt.Errorf("recording: cannot read disk stats for %s: %w", base, err)
			} else if refuse {
				return nil, ErrRecordingDiskFull
			}
			recordCfg := record.SessionConfig{
				BaseDir:      base,
				Machine:      si.Machine,
				Person:       si.Person,
				OSUser:       si.OSUser,
				SessionID:    si.SessionID,
				Cols:         si.Cols,
				Rows:         si.Rows,
				Clock:        clockFunc(now),
				SubdirLayout: true,
				Command:      si.Command,
			}
			if si.Exec {
				return record.NewExecRecorder(record.ExecConfig{SessionConfig: recordCfg, Command: si.Command})
			}
			return record.NewRecorder(recordCfg)
		}
	}
	return nil
}

func validRiskAction(action RiskAction) bool {
	switch action {
	case RiskActionLog, RiskActionWarn, RiskActionAsk, RiskActionBlock:
		return true
	default:
		return false
	}
}

func validRiskClassifier(classifier RiskClassifier) bool {
	switch classifier {
	case RiskClassifierRules, RiskClassifierAI, RiskClassifierBoth:
		return true
	default:
		return false
	}
}

// clockFunc adapts a Now func into a record.Clock without a package variable.
type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

// ErrRecordingDiskFull is returned by the default NewRecording factory when
// the recordings volume has crossed RecordingRefusePercent. It is the
// in-process form of the E_RECORDING_DISK_FULL internal code PROTOCOL.md
// §6 lists; human_role.go maps it onto session.drop with
// result: "recording: <message>", the same shape as every other "recording: …"
// reason today.
//
// A test that wants to assert the refuse path without spinning the real
// gateway can swap Config.NewRecording; production code reaches the error
// only through this factory.
var ErrRecordingDiskFull = fmt.Errorf("disk full beyond refuse threshold")
