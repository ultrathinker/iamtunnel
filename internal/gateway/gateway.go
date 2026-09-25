package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// Gateway is the runtime: it accepts SSH connections, tells machine logins
// from human logins, drives the door automaton over the control channel and
// bridges human sessions to the target through the already-written packages.
// It contains no door policy of its own - see machine_conn.go, which turns
// wire events into core.Input and executes exactly what core.Machine.Apply
// returns.
type Gateway struct {
	cfg   Config
	authH *auth.Handler
	aclE  *acl.Engine
	rate  *auth.RateLimiter
	// riskLive is the one runtime source read by every classified command
	// and by gateway.status. It is replaced atomically so a live switch is
	// visible to the next command without interrupting existing sessions.
	riskLive        atomic.Pointer[riskModeState]
	riskModeWriteMu sync.Mutex
	// riskSourceLive is the same arrangement for WHICH checkers judge a
	// command (rules / ai / both). Until 21.09.2026 that choice could be
	// made only in the settings file, with a restart -- the one risk
	// setting with no live control, and the more consequential of the two.
	riskSourceLive    atomic.Pointer[riskSourceState]
	riskSourceWriteMu sync.Mutex
	// riskApprovals are deliberately in-memory: an approval is a short-lived
	// continuation of a live gateway interaction, not durable access state.
	// Restarting the gateway therefore discards every pending approval.
	riskApprovalMu  sync.Mutex
	riskApprovals   map[string]*riskApproval
	riskApprovalSeq atomic.Uint64
	// externalRiskMu protects the live classifier pointer and its metadata.
	// A command takes a snapshot before it calls the service, so replacing the
	// key cannot interrupt an in-flight classification.
	externalRiskMu sync.RWMutex
	// externalRiskKeyWriteMu serializes probe/write/state transactions. The
	// network probe runs outside externalRiskMu so current sessions continue.
	externalRiskKeyWriteMu sync.Mutex
	// pairRate is the pairing limiter (PROTOCOL §3.4, IAMT-323): a second
	// instance of the same auth.RateLimiter machinery, with its own Config.
	// It counts wrong pairing PINs per ADDRESS and never interacts with
	// g.rate: an address banned from pairing can still log in as itself,
	// and a banned handshake address is not banned from pairing.
	pairRate *auth.RateLimiter
	view     *stateView
	reg      *registry
	pureCB   func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)

	// live names the recording each session in progress is writing into,
	// so that a session can be watched while it is still happening
	// (IAMT-338). A finished session is found by walking the recordings
	// directory; a live one cannot be, because its `.meta` does not
	// exist yet and its file name is not derivable from outside. See
	// live_tail.go.
	live liveRecordings

	// probeDeadlineFn is the sshd probe's test-only budget seam (IAMT-304).
	// It is unexported and nil in production, and deliberately NOT a Config
	// field: a Config knob is a public statement about the product, and
	// "phase two may use a deadline of its own" is not one — a non-zero
	// public field would have let a deployer hand the probe two budgets
	// where PROTOCOL §7 gives it one. The probe consults the seam at each
	// wait it bounds by its own budget (the reservation context and phase
	// two's connection) and ignores a returned deadline later than the
	// shared one, so a test can place the budget deterministically without
	// ever making the probe outlive the deadline it announced. See
	// Gateway.probeDeadline and sshd_probe.go.
	probeDeadlineFn func(shared time.Time) time.Time

	// phaseOneObserveFn is the sshd probe's test-only phase-one seam
	// (IAMT-304 round 6). It is unexported and nil in production; when
	// set, observeSSHDHostKey calls it instead of doing the real thing -
	// opening iamtunnel-target and running an SSH key exchange against
	// the target sshd through two relays. That handshake's own duration
	// is real network and cryptographic work, which nothing in this
	// package's control (a fake clock least of all) can bound or make
	// deterministic; a test whose actual subject is what happens AFTER
	// phase one (the door.open timeout / late-reply path) has no reason
	// to also inherit phase one's variance, and every wall-clock guard a
	// test builds around "wait for phase one to finish, then..." is a
	// guess at a duration this seam makes unnecessary to guess at all.
	// See TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor.
	phaseOneObserveFn func(mc *machineConn, deadline time.Time) (string, error)

	// enrolHMAC is the HMAC-SHA-256 key used to hash enrol/bootstrap
	// secrets before they are written to state.json (PROTOCOL §3.2,
	// §3.3 — see state.HashEnrolSecret and state.LoadOrCreateEnrolHMACKey).
	// It is loaded by New and lives for the lifetime of the gateway;
	// rotating it is a deliberate restart-the-gateway operation, not a
	// runtime toggle - no product switch may be able to disable the
	// hashing invariant, and this field has no setter.
	enrolHMAC state.EnrolHMACKey

	mu        sync.Mutex
	ln        net.Listener
	closed    bool
	wg        sync.WaitGroup
	sweepStop chan struct{}
	// conns holds the raw transport of every accepted connection whose
	// handleConn goroutine is still running. Close closes them: the one
	// goroutine shape that cannot end on its own is a peer that keeps its
	// transport and goes silent (IAMT-51 observation 3 - a machine that
	// never answers door.status keeps the §5.2 reconciliation retrying, for
	// as long as a session is live on it since IAMT-457), and the death of
	// the underlying connection is the one thing every wait in this runtime
	// is guaranteed to notice.
	conns map[net.Conn]struct{}

	// keyConns is every person connection being served, with the key it
	// authenticated with: a key taken away takes its connections with it
	// (IAMT-449, key_conns.go).
	keyConnsMu sync.Mutex
	keyConns   map[*keyConn]struct{}

	// audit is whether the audit journal is being written (IAMT-451,
	// audit_health.go); auditPublishMu orders its publications, and
	// journalAppendFn is the test-only seam in front of Log.Append, nil in
	// production.
	audit           auditHealth
	auditPublishMu  sync.Mutex
	journalAppendFn atomic.Pointer[func(events.Event) error]
	// auditClosed is set by Close: from then on the audit state is no
	// longer published (publishAudit).
	auditClosed atomic.Bool

	// authQuiet remembers which logins were journaled lately (IAMT-452,
	// auth_quiet.go).
	authQuiet authQuiet

	// authDeny is the refused attempts' half of the same quiet period (R4
	// F-11, auth_quiet.go): same host and refusal kind folds to one line,
	// the rest counted until the period ends.
	authDeny authDenyQuiet

	// drainState is the gentle half of stopping (IAMT-466, drain.go).
	drainState

	// probesWG tracks sshd-probe goroutines started by handleMachine.
	// They are NOT counted in g.wg: handleMachine launches them with `go`
	// precisely so it can return and start serving the machine's channels
	// while the probe runs in the background, and the probe's
	// finishSSHDProbe writes events.jsonl + state.json at the very end of
	// its lifetime. Close must wait for them after g.wg.Wait — otherwise
	// a probe still running while Close has returned can create a
	// state.json.tmp.<pid>.<nanos> file under the gateway's data dir
	// *after* every other cleanup has run, and the t.TempDir cleanup that
	// follows closes the test with "directory is not empty" (IAMT-161).
	probesWG       sync.WaitGroup
	probesInFlight atomic.Int64 // exposed to tests in the same package via the unexported field

	// IAMT-172: the same in-flight accounting probesInFlight does for the
	// sshd probe, for the two connection-scoped writers Close waits for
	// under g.wg. serveCommandSession is launched by handleCommand,
	// proxyChannelRequests by serveHumanSession; both write events.jsonl
	// (and resize the recording) at the end of their lifetime, so a
	// fire-and-forget launch can land a write after Close has returned.
	// Each counter is incremented synchronously at the launch site —
	// before the `go` statement, so the count is visible without a
	// scheduler tick — and decremented by the goroutine itself before its
	// g.wg.Done (LIFO defers), which makes "Close returned while a counter
	// is non-zero" mean exactly "Close did not wait for its own writer".
	// Tests in this package read the fields directly; nothing is exported
	// and nothing can switch the behaviour off.
	serveCmdInFlight  atomic.Int64 // serveCommandSession goroutines launched, not yet returned
	proxyReqsInFlight atomic.Int64 // proxyChannelRequests goroutines launched, not yet returned

	epoch uint64 // atomic counter, one tunnelEpoch per accepted machine connection
}

// New wires the runtime to its collaborators. Every collaborator is either
// passed in through cfg or built here from cfg's values - nothing is a
// package-level variable a test could not otherwise reach.
func New(cfg Config) (*Gateway, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	startupRisk, startupRiskWarning := loadRiskMode(cfg)
	startupSource, startupSourceWarning := loadRiskSource(cfg)
	enrolHMAC := cfg.Store.EnrolHMACKey()
	if enrolHMAC.IsZero() {
		// state.OpenForRead deliberately returns a Store without the HMAC key:
		// inspection must not read or create enrol-hmac.key. That Store is valid
		// for reading state, but never for a live gateway; otherwise the first
		// bootstrap or enrol request reaches HashEnrolSecret and panics instead
		// of refusing the bad runtime construction at startup.
		return nil, fmt.Errorf("gateway: enrol HMAC key is zero; refusing startup before bootstrap or enrol requests")
	}
	reg := newRegistry()
	view := &stateView{store: cfg.Store, reg: reg}

	authH, err := auth.NewHandler(view, cfg.AuthLimits)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	aclE, err := acl.NewEngine(view, cfg.ACLLimits)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	// acl.Engine tracks grants itself, in memory (acl/acl.go: AddGrant/
	// Revoke) - state.Store's persisted Grant list is a separate fact the
	// acl.View interface deliberately does not expose (View only answers
	// PersonExists/MachineExists/MachineVerified/MachineOnline). The two are
	// wired together here, once, at startup: every persisted grant is
	// loaded into the engine before the gateway accepts a connection.
	// Indefinite grants (gr.Until == nil) are loaded with Until == nil;
	// grants that expired while the gateway was offline are skipped.
	// Any AddGrant failure fails New loudly instead of vanishing quietly.
	//
	// The "skipped on expiry" branch used to be silent —
	// the gateway silently dropped the entry. It is now recorded in
	// the journal as an EventAdminOp with actor "gateway": an
	// administrator reviewing events.jsonl will see the exact grant and
	// the exact reason it never came back up.
	type droppedGrant struct {
		person, machine string
		expiredAt       time.Time
	}
	var dropped []droppedGrant
	for _, gr := range cfg.Store.Get().Grants {
		var until *time.Time
		if gr.Until != nil {
			u := gr.Until.Time.UTC()
			if !u.After(cfg.Now()) {
				// The grant has already expired while the gateway was down.
				// We skip it (re-AddGrant'ing it would only fail) but we
				// must NOT keep the operator in the dark: this exact
				// branch is the same kind of "silence"
				// already removed by failing AddGrant above. The event
				// is emitted once, below, after g is constructed.
				dropped = append(dropped, droppedGrant{person: gr.Person, machine: gr.Machine, expiredAt: u})
				continue
			}
			until = &u
		}
		if err := aclE.AddGrant(acl.Grant{
			Person:  gr.Person,
			Machine: gr.Machine,
			Until:   until,
			Caps:    gr.Caps,
		}, cfg.Now()); err != nil {
			return nil, fmt.Errorf("gateway: failed to load grant %s -> %s: %w", gr.Person, gr.Machine, err)
		}
	}

	g := &Gateway{
		cfg:           cfg,
		authH:         authH,
		aclE:          aclE,
		view:          view,
		reg:           reg,
		enrolHMAC:     enrolHMAC,
		riskApprovals: make(map[string]*riskApproval),
		conns:         make(map[net.Conn]struct{}),
		sweepStop:     make(chan struct{}),
	}
	g.audit.since = cfg.Now()
	// Keep the durable key metadata in step with the key that was actually
	// loaded. This is metadata only; the secret never enters State. Older
	// state files have a nil field and are upgraded additively here.
	if err := g.syncExternalRiskKeyState(); err != nil {
		return nil, fmt.Errorf("gateway: persist external risk key metadata: %w", err)
	}
	g.riskLive.Store(&startupRisk)
	if startupRiskWarning != nil {
		// F-05 (round-1 review, 24.09.2026): the ignored switch keeps its
		// one event, and what it ignored moves out of a prose sentence
		// into fields: file, value, reason - with the effective mode
		// beside them, so the entry answers "what was refused" and "what
		// is in force" without a reader parsing either out of the other.
		details := startupRiskWarning.details()
		details["mode"], details["source"] = string(startupRisk.mode), startupRisk.source
		g.appendEvent(events.Event{
			Type:    events.EventAdminOp,
			Actor:   "gateway",
			Object:  riskModeFileName,
			Result:  "risk.mode:startup-ignored",
			Details: details,
		})
	}
	g.riskSourceLive.Store(&startupSource)
	if startupSourceWarning != nil {
		details := startupSourceWarning.details()
		details["classifier"], details["source"] = string(startupSource.classifier), startupSource.source
		g.appendEvent(events.Event{
			Type:    events.EventAdminOp,
			Actor:   "gateway",
			Object:  riskSourceFileName,
			Result:  "risk.source:startup-ignored",
			Details: details,
		})
	}
	// One EventAdminOp per dropped grant. actor="gateway" (the gateway
	// itself decided to skip the entry, so it logs as the actor). Result
	// carries the human-readable reason so the journal reads naturally
	// without anyone having to grep the Details map.
	for _, d := range dropped {
		g.appendEvent(events.Event{
			Type:    events.EventAdminOp,
			Actor:   "gateway",
			Object:  d.person + " -> " + d.machine,
			Result:  "grant.skip:expired",
			Details: map[string]interface{}{"expiredAt": d.expiredAt.UTC().Format(time.RFC3339)},
		})
	}

	// Rotation wiring (IAMT-144). Validate the two thresholds here, not in
	// setDefaults, so a misconfigured Config cannot pass validation and then
	// reach sweepRecordings with a bad pair. The defaults themselves are
	// applied in setDefaults (RecordingRefusePercent=95,
	// RecordingRotationInterval=1m); RecordingRetentionDays and
	// RecordingRotatePercent arrives from the historically named
	// recordings_disk_stop_percent Settings key and may be
	// zero in a test fixture that deliberately disables one or the other.
	//
	// These four checks read nothing but cfg, and they run BEFORE
	// auth.NewRateLimiter below for that reason. They used to run after it,
	// and NewRateLimiter starts the A-3 sweeper goroutine the moment it is
	// called - so every rejection here returned (nil, err), which leaves the
	// caller no handle at all, and orphaned a live sweeper for the lifetime
	// of the process. A single New with RecordingRefusePercent equal to
	// recordings_disk_stop_percent was enough to leak one; that is the
	// reduced repro goleak bisected to
	// (TestIAMT144_RefuseOrderingRejected, iamt144_recording_rotation_test.go).
	// Rejecting a bad config before anything is allocated is both the fix
	// and the cheaper order: no goroutine is spun up for a startup that was
	// always going to fail.
	if cfg.RecordingRefusePercent <= cfg.RecordingRotatePercent {
		return nil, fmt.Errorf("gateway: recordingRefusePercent=%d must be strictly greater than recordings_disk_stop_percent=%d (PROTOCOL §8)",
			cfg.RecordingRefusePercent, cfg.RecordingRotatePercent)
	}
	if cfg.RecordingRefusePercent > 99 {
		return nil, fmt.Errorf("gateway: RecordingRefusePercent=%d must be ≤ 99", cfg.RecordingRefusePercent)
	}
	if cfg.RecordingRotatePercent < 0 || cfg.RecordingRotatePercent > 99 {
		return nil, fmt.Errorf("gateway: recordings_disk_stop_percent=%d must be in 0..99", cfg.RecordingRotatePercent)
	}
	if cfg.RecordingRetentionDays < 0 {
		return nil, fmt.Errorf("gateway: RecordingRetentionDays=%d must be ≥ 0", cfg.RecordingRetentionDays)
	}

	// IAMT-165: a "recording" meta still on disk at startup is a leftover
	// from a previous process that died before finalizing it — after a
	// restart none of them can be live, the gateway is the single owner of
	// recordings. Repair them to "aborted" BEFORE the first rotation sweep
	// (started at the end of this function), so that sweep can already
	// age-prune them instead of protecting them forever (the kill -9
	// self-DoS, IAMT-4 finding H3). A repair failure fails New loudly: a
	// recordings tree the gateway could not repair would silently re-create
	// the immortal-orphan state.
	//
	// The CALL sits above NewRateLimiter for the same reason as the four
	// checks: it takes only cfg.RecordingBaseDir, and its failure branch is
	// another (nil, err) that used to orphan a sweeper. What cannot move up
	// with it is the EVENT loop - that needs g.appendEvent - so the repair
	// result is carried down and written below, in the journal order it has
	// always had: the grant.skip lines first, then these.
	repaired, err := record.AbortOrphanedRecordings(cfg.RecordingBaseDir, orphanedRecordingExitReason)
	if err != nil {
		return nil, fmt.Errorf("gateway: abort orphaned recordings: %w", err)
	}

	rate, err := auth.NewRateLimiter(cfg.RateConfig, g)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	// The pairing limiter (IAMT-323) is built right after the main one so
	// the two share the same lifecycle discipline below: between here and
	// "return g, nil" nothing may fail without the started-defer closing
	// both sweepers. Its config is validated by the same constructor.
	pairRate, err := auth.NewRateLimiter(cfg.Pairing.Rate, g)
	if err != nil {
		rate.Close()
		return nil, fmt.Errorf("gateway: pairing rate limiter: %w", err)
	}
	// After this point New owns a running goroutine that only Close can
	// stop, and every error return from here would hand the caller a nil
	// *Gateway - i.e. no handle to close. The reordering above means there
	// is nothing left between here and "return g, nil" that can fail, so
	// this guard fires only on a panic today. It is kept anyway: it is what
	// makes the property survive the next validation someone adds in the
	// wrong place, which is exactly how this bug was born.
	started := false
	defer func() {
		if !started {
			rate.Close()
			pairRate.Close()
		}
	}()
	g.rate = rate
	g.pairRate = pairRate
	g.pureCB = authH.PublicKeyCallback()

	for _, base := range repaired {
		g.appendEvent(events.Event{
			Type:    events.EventAdminOp,
			Actor:   "gateway",
			Object:  base,
			Result:  "recording.abort:gateway restart",
			Details: map[string]interface{}{"status": "aborted", "exitReason": orphanedRecordingExitReason},
		})
	}

	// The audit state goes into the data directory at every start, so what
	// `gateway status` reads there is this run's, not a failure the last
	// run left behind (IAMT-451).
	g.publishAudit(false)

	g.wg.Add(1)
	go g.sweepExpired()
	g.wg.Add(1)
	go g.sweepRecordings()
	started = true
	return g, nil
}

// grantSweepInterval bounds the additional time a live session can survive
// after its grant expires. One second is short enough for an access deadline
// to be meaningful while keeping an idle gateway effectively idle.
const grantSweepInterval = time.Second

// orphanedRecordingExitReason is written into the metadata of every
// "recording"-status session found at startup (IAMT-165): after a restart
// the previous owner is gone, so the honest exit reason is the restart
// itself, not a guess about when the session actually died.
const orphanedRecordingExitReason = "gateway restart"

// sweepExpired makes grant expiry an action of the gateway rather than an
// event that must be triggered by a later human request. It is started with
// every Gateway and is stopped before Close waits for workers.
func (g *Gateway) sweepExpired() {
	defer g.wg.Done()
	ticker := time.NewTicker(grantSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := g.cfg.Now()
			g.aclE.SweepExpired(now)
			// The door's hard deadline is kept on this side too (IAMT-461):
			// the same clock and the same tick as grant expiry.
			for _, mc := range g.reg.all() {
				mc.enforceHardDeadline(now)
			}
			// And the journal's growth (IAMT-452): the counts of logins and
			// refusals not written one by one, the rotation by size, and the
			// archives' retention (R4 F-11) - rotation without retention only
			// moves where the disk fills.
			g.flushAuthQuiet(now)
			g.flushAuthDenyQuiet(now)
			g.rotateJournalIfLarge(now)
			g.pruneJournalArchives(now)
		case <-g.sweepStop:
			return
		}
	}
}

// sweepRecordings is the recording-rotation background loop (IAMT-144).
// It runs once at startup, then on a ticker, until the gateway is closed.
// Each pass delegates to record.Rotate with the age and disk thresholds
// that arrived through Config — no literal numbers live in this file.
//
// Errors from Rotate are logged and swallowed: a one-pass failure must
// not crash the gateway (the next tick will retry), and there is no
// caller waiting on a return value. Errors from diskStats during the
// percent threshold lookup cause Rotate to return an error which is then
// logged; the refuse check in NewRecording uses the same primitive, so a
// persistent stats failure surfaces as E_RECORDING_DISK_FULL on every
// session until the operator intervenes, not as silent data loss.
func (g *Gateway) sweepRecordings() {
	defer g.wg.Done()

	interval := g.cfg.RecordingRotationInterval
	runOnce := func() {
		result, err := record.Rotate(record.RotateConfig{
			Dir:                  g.cfg.RecordingBaseDir,
			MaxAge:               time.Duration(g.cfg.RecordingRetentionDays) * 24 * time.Hour,
			MaxTotalBytesPercent: g.cfg.RecordingRotatePercent,
			Clock:                clockFunc(g.cfg.Now),
		})
		if err != nil {
			g.appendEvent(events.Event{
				Type:   events.EventAdminOp,
				Actor:  "gateway",
				Object: "recordings",
				Result: "rotation.error: " + err.Error(),
			})
			return
		}
		// Rotation is the gateway's own act, not an admin's, and PROTOCOL §8
		// explicitly says every deletion is an event: every deleted session
		// becomes its own admin.op line, naming the session path so an
		// administrator can correlate with the journal if a specific file
		// disappears unexpectedly.
		for _, deleted := range result.DeletedSessions {
			g.appendEvent(events.Event{
				Type:   events.EventAdminOp,
				Actor:  "gateway",
				Object: deleted,
				Result: "rotation.prune",
				Details: map[string]interface{}{
					"bytesFreed":             result.BytesFreed,
					"remainingBytes":         result.RemainingBytes,
					"remainingCount":         result.RemainingSessions,
					"oversizedSingle":        result.OversizedSingleSession,
					"diskStillOverThreshold": result.DiskStillOverThreshold,
				},
			})
		}
		// M-12: the recordings id→path cache and hash memos may name
		// files this pass removed. A lookup still re-checks its cached
		// path before trusting it, so this is hygiene — dead ids must
		// not accumulate for the life of the process — not a
		// correctness dependency.
		if len(result.DeletedSessions) > 0 {
			invalidateRecordingsIndex()
		}
	}

	runOnce()

	if interval <= 0 {
		// Zero interval: startup sweep ran, no ticker. Tests that pin
		// interval=0 still get the self-cleaning behaviour and the
		// canary that breaks the loop will only see that one shot.
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runOnce()
		case <-g.sweepStop:
			return
		}
	}
}

// Serve accepts connections from ln until it is closed or Close is called.
// It always returns a non-nil error (net.Listener's contract on Accept).
//
// A Close that has already completed when Serve is entered - the SCM or
// systemd stop arriving within the first milliseconds of startup, before
// the goroutine carrying Serve has run its first instruction - is honored
// here rather than raced past (IAMT-273): Serve closes ln and returns
// instead of parking in Accept with no Close left to interrupt it.
func (g *Gateway) Serve(ln net.Listener) error {
	// The registration of ln and the read of the closed flag share one
	// mutex hold with Close's flag flip, so exactly one of two orders can
	// happen. Serve first: Close finds ln here and closes it, and the
	// Accept loop below ends with the listener's own error. Close first:
	// Close completed without ever seeing this listener (it snapshots g.ln
	// under the same mutex), so serving on would park Accept forever - the
	// flag is already set and a second Close is a no-op. Serve closes ln
	// itself (it would otherwise leak) and returns; either order leaves the
	// same invariant standing: once Close has returned, no Accept of this
	// gateway is or ever will be blocked.
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("gateway: serve %s: the gateway is already closed: %w", ln.Addr(), net.ErrClosed)
	}
	g.ln = ln
	g.mu.Unlock()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go g.handleConn(raw)
	}
}

// Close stops accepting new connections, ends every live connection and
// waits for the in-flight handlers to finish their own teardown paths.
//
// Ending the connections is what makes Close return at all. Before the
// transport cut this method waited on handlers that cannot end on their
// own: a machine whose tunnel lives but which never answers door.status
// keeps its reconciliation loop (PROTOCOL §5.2) - and exactly that machine
// must not stop a systemd daemon from shutting down, because a daemon
// killed by the stop timeout takes every live session and every unfinalized
// recording with it (IAMT-68).
//
// What happens to a live human session is decided here, once: it is cut
// immediately, and its recording is finalized as aborted by the same
// teardown path that cuts it. Letting sessions "sit" is not an option -
// the process is going away, so the cut would only move to process exit,
// where nothing finalizes the recording; the transcript must be complete
// on disk by the time Close returns, and Close's Wait guarantees exactly
// that (see TestCloseReturnsInEveryLiveState).
//
// The guarantee extends forward in time too (IAMT-273): a Serve that only
// starts after Close has returned finds the flag set under g.mu, closes its
// listener and refuses to accept - so "Close returned" means "this gateway
// accepts nothing, now and at any later point".
func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.auditClosed.Store(true)
	ln := g.ln
	conns := make([]net.Conn, 0, len(g.conns))
	for c := range g.conns {
		conns = append(conns, c)
	}
	// The expiry sweeper is stopped under the same mutex as the flag, so
	// the close happens exactly once; it is one of the workers g.wg.Wait()
	// below waits for, not a second thing to wait on.
	close(g.sweepStop)
	g.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	// Machine connections first, the automaton's way: teardown applies
	// TransportLost once, fails every outstanding reservation ticket,
	// cancels the bridge contexts and unregisters - that is also what lets
	// a human session end with its recording finalized instead of torn.
	for _, mc := range g.reg.all() {
		mc.teardown("gateway-close")
	}
	// Then the raw transports: mid-handshake peers, human and command
	// connections, and any handler parked on a silent peer - every one of
	// their waits fails the moment the transport dies.
	for _, c := range conns {
		_ = c.Close()
	}
	g.wg.Wait()
	// sshd-probe goroutines (IAMT-161) are launched with `go` from
	// handleMachine and are not counted in g.wg — handleMachine returns
	// immediately so it can serve the machine's channels while the probe
	// runs to completion (and writes state.json + events.jsonl at the very
	// end). Without this wait Close can return while a probe is still
	// mid-Store.Update, leaving a state.json.tmp.<pid>.<nanos> file
	// behind after t.TempDir cleanup has started — TempDir RemoveAll then
	// fails with "directory is not empty". Wait here, after g.wg, so the
	// only writer that can be alive at the moment Close returns is one
	// that started *after* Close observed g.closed.
	g.probesWG.Wait()
	// The rate limiter's sweeper (IAMT-314) is stopped here and not a line
	// earlier. It is the one background goroutine of this gateway that is
	// owned by another package, and its only callers are the handshake
	// handlers - Allow, RecordFailure and RecordSuccess in authAttempt - so
	// it must outlive them: stopping it before g.wg.Wait() would tear down
	// a limiter that a handler still mid-handshake is entitled to consult.
	// It is equally not left to the process: auth.RateLimiter.Close closes
	// sweepStop and then waits on sweepDone, which sweepLoop closes on its
	// way out, so once this returns no sweep is in flight and the goroutine
	// is gone - which is what lets internal/gateway be checked by goleak at
	// all. New always builds one, so g.rate is never nil here.
	g.rate.Close()
	// The pairing limiter's sweeper (IAMT-323) is the same shape: one
	// background goroutine owned by the auth package, consulted by the
	// pairing handshake wrapper and the admin.pair exec, so it also must
	// outlive g.wg.Wait. Close is idempotent, matching the contract the
	// main limiter relies on.
	g.pairRate.Close()
	// A handler that was mid-handshake when the transports were cut could
	// still have registered a machine connection after the first sweep; no
	// registration can happen anymore once every handler has been waited
	// for, so this sweep is the final one.
	for _, mc := range g.reg.all() {
		mc.teardown("gateway-close")
	}
	// IAMT-304 round 6: auth.NewRateLimiter's own sweepLoop goroutine was
	// never stopped here - fine in production (one gateway process, one
	// RateLimiter, for the process's whole life - see RateLimiter.Close's
	// own doc comment), but every test's newFixture builds and discards a
	// whole Gateway, and none of those sweepLoop goroutines ever exited.
	// A goroutine dump taken from a live flake of
	// TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor under `-race
	// -count=50` found several hundred of them still parked in select -
	// one full RateConfig.Window-period ticker per leaked fixture,
	// accumulating scheduler and GC bookkeeping for the rest of that test
	// binary's run and starving whatever ran after them, exactly the
	// "what does a sibling leave alive" review asked to name.
	g.rate.Close()
	return err
}

// handleConn completes one SSH handshake and routes the resulting identity
// to the machine or human path. Both paths own the connection from here on.
func (g *Gateway) handleConn(raw net.Conn) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = raw.Close()
		return
	}
	g.conns[raw] = struct{}{}
	// The Add lives under the same mutex as Close's flag flip: either this
	// handler is in the WaitGroup before Close proceeds to its Wait, or it
	// observes closed here and leaves without touching the WaitGroup.
	g.wg.Add(1)
	g.mu.Unlock()
	defer g.wg.Done()
	defer g.forgetConn(raw)

	sconn, chans, reqs, id, err := g.finishHandshake(raw)
	if err != nil {
		return
	}
	switch id.Subject.Role {
	case auth.RoleMachine:
		g.handleMachine(sconn, chans, reqs, id.Subject.Name)
	case auth.RolePerson:
		// id.Subject.Name is the person's own name (VerifyLogin already
		// proved they own it); the machine half of a session login
		// ("<person>:<machine>") only exists in the raw SSH username, which
		// auth.Identity deliberately does not carry further. The key's
		// fingerprint goes along: the connection is good only while the
		// key is still the person's (IAMT-449).
		g.handleHuman(sconn, chans, reqs, sconn.User(), id.Fingerprint)
	case auth.RoleEnrol:
		// Subject.Name is empty on this role since 1.3 (lookup.go): an
		// invitation names no machine, so there is nothing to carry. The
		// key fingerprint is the only identity the handshake established,
		// and it is what the enrol journal entries are attributed to. The
		// handler re-checks the pending entry against the secret inside
		// the exec body, because the SSH handshake only proved the key
		// matched - the secret itself is what authorises the write.
		g.handleEnrol(sconn, chans, reqs, id.Fingerprint)
	case auth.RoleBootstrap:
		g.handleBootstrap(sconn, chans, reqs)
	case auth.RolePairing:
		// The subject is empty on this role (PROTOCOL §3.4): the client is
		// nobody until the PIN lands. Its key fingerprint is the
		// rate-limiting identity of the one "admin.pair" attempt; the
		// window binding is the identity of the window the handshake
		// admitted it for (F-12).
		binding, ok := auth.PairingWindowBinding(sconn.Permissions)
		if !ok {
			// pairingKeyCallback mints the binding with the role itself, so
			// a pairing connection without one did not come from this
			// binary's handshake. Refuse it rather than grade a PIN the
			// connection cannot be held to anything for.
			_ = sconn.Close()
			return
		}
		g.handlePairing(sconn, chans, reqs, id.Fingerprint, binding)
	default:
		_ = sconn.Close()
	}
}

// finishHandshake runs the SSH handshake to completion and returns the
// channel/request streams needed to actually serve the connection.
//
// auth.Handler.FinishAuth cannot be reused here: it calls ssh.NewServerConn
// but discards the returned <-chan ssh.NewChannel and <-chan *ssh.Request
// (see auth/auth.go), which makes it usable only for authentication-only
// integration tests, never for a connection the runtime goes on to serve.
// The sequence below
// reproduces FinishAuth's logic (deadline, NewServerConn, identity
// extraction, VerifyLogin, event sink calls) with the streams kept.
func (g *Gateway) finishHandshake(conn net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, auth.Identity, error) {
	type offeredAuth struct {
		user   string
		fp     string
		reason string
	}
	var (
		offeredMu sync.Mutex
		offered   []offeredAuth
	)

	cfg := g.authH.ServerConfig(g.cfg.HostKey)
	cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := auth.Fingerprint(key)
		user := c.User()
		perm, err := g.publicKeyCallback(c, key)
		if err != nil {
			offeredMu.Lock()
			offered = append(offered, offeredAuth{
				user:   user,
				fp:     fp,
				reason: err.Error(),
			})
			offeredMu.Unlock()
			return nil, err
		}
		return perm, nil
	}

	// The handshake deadline is a real socket deadline (net.Conn.SetDeadline
	// is a wall-clock OS primitive), so it is computed from actual wall time
	// even though every other timestamp in this package comes from the
	// injected Config.Now - conflating the two would let a test's simulated
	// clock instantly time out a real, live TCP handshake. auth.Handler.
	// FinishAuth's own tests make the same choice (they always pass
	// time.Now(), never a fake clock, to this exact call).
	_ = conn.SetDeadline(g.authH.HandshakeDeadline(time.Now()))

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	addr := conn.RemoteAddr().String()
	if err != nil {
		_ = conn.Close()
		offeredMu.Lock()
		attempts := append([]offeredAuth(nil), offered...)
		offeredMu.Unlock()
		if len(attempts) == 0 {
			g.AuthDenied(addr, "", "", "handshake or key authentication failed")
		} else {
			for _, a := range attempts {
				g.AuthDenied(addr, a.user, a.fp, a.reason)
			}
		}
		return nil, nil, nil, auth.Identity{}, err
	}

	user := sconn.User()
	id, idErr := auth.ExtractIdentity(sconn.Permissions)
	if idErr == nil {
		if _, verr := auth.VerifyLogin(sconn.Permissions, user); verr != nil {
			idErr = verr
		}
	}
	if idErr != nil {
		_ = sconn.Close()
		g.AuthDenied(addr, user, id.Fingerprint, idErr.Error())
		return nil, nil, nil, auth.Identity{}, idErr
	}

	_ = conn.SetDeadline(time.Time{})
	g.AuthAccepted(addr, user, id.Fingerprint, id.Subject.Name, id.Subject.Role)
	return sconn, chans, reqs, id, nil
}

// publicKeyCallback wraps the pure auth.Handler callback with rate limiting
// (SPEC §6.1, PROTOCOL §1.4). The pure callback itself stays untouched and
// side-effect free, as its doc comment requires: rate limiting is the
// "explicit collaborator" that comment names, wired here rather than inside
// the auth package.

// The two rate-limit refusals are named errors so the refusal fold (R4
// F-11, auth_quiet.go) can class them by their prefix: the rendered text
// embeds the ban's deadline, and a reason that changed every attempt
// would defeat the fold's bucket.
var (
	errAuthRateLimited    = errors.New("auth: address or key rate limited")
	errPairingRateLimited = errors.New("auth: address rate limited")
)

func (g *Gateway) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	addr := conn.RemoteAddr().String()
	fp := auth.Fingerprint(key)
	now := g.cfg.Now()

	// PROTOCOL §3.4 (IAMT-323): the pairing login resolves outside the
	// persistent state — the pairing client carries its own future-admin
	// key, which stateView.Resolve cannot know and must not learn. The
	// branch sits in front of the main limiter on purpose: pairing PIN
	// attempts are billed on the dedicated pairing limiter only, so an
	// address guessing PINs is not banned from its own login and vice
	// versa.
	if conn.User() == "pairing" {
		return g.pairingKeyCallback(addr, fp, now)
	}

	// Counted per host, not per ip:port (IAMT-446): a reconnect gets a new
	// source port, and a limiter keyed by it gave every reconnect a fresh
	// counter - key spray was never banned, and a ban was one reconnect
	// from gone. An IPv6 host is its /64 here (peerHost, M-13), for the
	// same reason one step further. The event journal still gets the full
	// ip:port.
	host := peerHost(addr)
	if d := g.rate.Allow(host, fp, now); !d.Allow {
		return nil, fmt.Errorf("%w until %s", errAuthRateLimited, d.Until)
	}
	perm, err := g.pureCB(conn, key)
	if err != nil {
		g.rate.RecordFailure(host, fp, g.view.knownFingerprint(fp), now)
		return nil, err
	}
	g.rate.RecordSuccess(host, fp, now)
	return perm, nil
}

// pairingKeyCallback answers the SSH layer for the byte-exact username
// "pairing" (PROTOCOL §3.4, IAMT-323). While a pairing window is open,
// any well-formed key is accepted as role "pairing" — the key itself
// proves nothing yet, the PIN in the exec body does. A closed or expired
// window is refused exactly like an unknown key, word for word, so a
// probe cannot tell whether the gateway even has the pairing feature.
// Neither refusal records a failure: attempts are counted only when a
// PIN is actually graded (pairing_role.go), and a banned address is
// refused before the window is even looked at.
func (g *Gateway) pairingKeyCallback(addr, fp string, now time.Time) (*ssh.Permissions, error) {
	// Same normalization as the exec path (peerHost): the handshake
	// refusal for a banned address must key by the machine, or a reconnect
	// with a fresh source port would walk past the ban the exec path just
	// earned (IAMT-330).
	addr = peerHost(addr)
	if d := g.pairRate.Allow(addr, fp, now); !d.Allow {
		return nil, fmt.Errorf("%w until %s", errPairingRateLimited, d.Until)
	}
	st := g.cfg.Store.Get()
	if st.PairingPending == nil || !st.PairingPending.Expires.After(now) {
		// Same rendering the pure callback produces for an unregistered
		// key (auth.ErrUnknownKey), so the refusal is indistinguishable
		// from key-spray against a closed window.
		return nil, fmt.Errorf("%w: %s", auth.ErrUnknownKey, fp)
	}
	// F-12 (round-1 review 24.09.2026): the login is admitted for THIS
	// window, and the hex of its secret hash rides along in Permissions -
	// the only channel back through NewServerConn. The exec layer holds
	// the connection to that identity: a window replaced or stopped while
	// the connection sits open makes the connection stale, and a stale
	// connection is refused without grading anything, so its wrong PINs
	// can never be spent on a window it never saw.
	return auth.PairingPermissions(fp, hex.EncodeToString(st.PairingPending.SecretHash[:])), nil
}

// maxLoginJournalBytes is the longest SSH username PROTOCOL §2.1 accepts:
// two parts of at most 32 bytes and the colon between them. A name that
// long or shorter reaches the journal whole; only one the parser refuses
// anyway is ever clipped (IAMT-447).
const maxLoginJournalBytes = 65

// maxAuthReasonJournalBytes bounds the refusal text of an auth.failure.
// Refusals quote the username they turned down; a legitimate one - two
// names and a sentence around them - fits several times over.
const maxAuthReasonJournalBytes = 256

// AuthAccepted implements auth.EventSink. The same login, key and host is
// journaled once per AuthSuccessQuiet, the rest counted (IAMT-452,
// auth_quiet.go).
func (g *Gateway) AuthAccepted(addr, user, fingerprint, subject string, role auth.Role) {
	k := authQuietKey{login: user, fingerprint: fingerprint, host: quietHost(addr)}
	write, summary := g.authQuiet.admit(k, addr, subject, role, g.cfg.Now(), g.cfg.AuthSuccessQuiet)
	if summary != nil {
		g.appendEvent(authSuccessEvent(summary.addr, user, fingerprint, summary.subject, summary.role, summary))
	}
	if write {
		g.appendEvent(authSuccessEvent(addr, user, fingerprint, subject, role, nil))
	}
}

// AuthDenied implements auth.EventSink. The same host and refusal kind is
// journaled once per AuthSuccessQuiet, the rest counted, and the count is
// written when the quiet period ends (R4 F-11, auth_quiet.go): the port is
// on the internet by construction, and a line per offered key or per TCP
// connect was the flood's write path into the journal - a disk it fills
// refuses every session and every mutating command for everyone (IAMT-451).
// A slow brute force still earns its line per attempt: each lands outside
// the quiet period.
func (g *Gateway) AuthDenied(addr, user, fingerprint, reason string) {
	t := events.EventAuthFailure
	if fingerprint == "" {
		// R1-CX F-03: a whole-handshake failure before any key resolved to
		// an identity has no fingerprint - none was offered. Dropping the
		// attempt here (the auth.failure validator demands a fingerprint)
		// hid exactly the sweep a brute force opens with; the
		// fingerprint-less auth.handshake_failure records it, keyed by
		// address alone. Both pre-key callers - this package's
		// finishHandshake and auth.FinishAuth's own - go through this
		// branch, so the gap closes in one place.
		t = events.EventAuthHandshakeFailure
	}
	// Nothing has authenticated here: the username and every refusal that
	// quotes it are the sender's to size, up to an SSH packet, once per key
	// offered - which is exactly why the fold classes by the refusal's
	// kind, never its full text (IAMT-447).
	k := authDenyKey{host: quietHost(addr), kind: authDenyKind(t, reason)}
	write, summary := g.authDeny.admit(k, addr, user, fingerprint, reason, g.cfg.Now(), g.cfg.AuthSuccessQuiet)
	if summary != nil {
		g.appendEvent(authDenyEvent(k.kind, *summary))
	}
	if write != nil {
		g.appendEvent(authDenyEvent(k.kind, *write))
	}
}

// RateExceeded implements auth.EventSink.
func (g *Gateway) RateExceeded(addr, fingerprint string, until time.Time) {
	if fingerprint == "" {
		return
	}
	g.appendEvent(events.Event{
		Type:        events.EventAuthFailure,
		Actor:       addr,
		Object:      addr,
		Result:      "rate limited until " + until.UTC().Format(time.RFC3339),
		Address:     addr,
		Fingerprint: fingerprint,
	})
}

// forgetConn drops a finished handler's transport from the shutdown set.
func (g *Gateway) forgetConn(raw net.Conn) {
	g.mu.Lock()
	delete(g.conns, raw)
	g.mu.Unlock()
}

// appendEvent journals one entry. A write that fails is not dropped any
// more: it turns the gateway's audit state to failing until a write
// succeeds again (IAMT-451, audit_health.go).
func (g *Gateway) appendEvent(e events.Event) {
	_ = g.appendEventChecked(e)
}

// appendEventChecked is appendEvent for a caller whose next step depends
// on the line being on disk (R4 review N-07: a watch is served only once
// its session.watch is written). The audit health is noted the same way.
func (g *Gateway) appendEventChecked(e events.Event) error {
	e.Time = state.NewZonedTime(g.cfg.Now())
	err := g.journalAppend(e)
	g.noteAudit(err, e)
	return err
}

func (g *Gateway) nextEpoch() uint64 {
	return atomic.AddUint64(&g.epoch, 1)
}

// HostKey returns the SSH signer the gateway presents to peers. The
// test harness in test/e2e uses it to pin HostKeyCallback when
// driving the enrol and bootstrap wire paths (where the strict
// fingerprint pin required by client/admin packages would otherwise
// have to be reconstructed from disk).
func (g *Gateway) HostKey() ssh.Signer {
	return g.cfg.HostKey
}

// Reg returns the live machine-connection registry. Exported for
// the e2e test that asserts a freshly-enrolled machine reaches the
// "online" state.
func (g *Gateway) Reg() *registry { return g.reg }

// InFlightProbes is intentionally NOT exported — the test in this package
// reads g.probesInFlight directly. (Exposing it on the production gateway
// was round 1's mistake; round 2 removes it.)

// ProbeWaitCount was removed for the same reason — its only purpose was
// to give the test a hook into Close, and the round-2 canary verifies the
// behavior (probe done at Close-return) rather than the implementation
// (Close called Wait).
