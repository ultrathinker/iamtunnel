package server

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// winkeysID adapts a PROTOCOL §1.3 door id — a lower-case RFC 4122 UUID,
// 36 bytes with 4 dashes — to the identifier internal/winkeys.Marker
// actually accepts: winkeys.IsOurs requires exactly 32 hex characters
// immediately after the marker, with no dashes (see winkeys/doors.go).
// The two accepted packages disagree on this shape — the gateway's own
// core/door.go generates door ids as dashed UUIDs and sends exactly that
// string over the wire, while winkeys, written and tested independently,
// only ever expected a bare 32-hex identifier. Neither package is
// rewritten to match, so this adapter is the seam: every wire
// response and every in-memory comparison in this file uses the original
// dashed id unchanged; only the four calls that cross into winkeys/
// doorwatch — Install, Remove, SweepStale's currentDoorID and the
// SpawnWatchdog argument the watchdog will later Remove() with — go
// through winkeysID first. A UUID's 36 bytes minus its 4 dashes is
// exactly 32, so no information is lost.
func winkeysID(uuid string) string { return strings.ReplaceAll(uuid, "-", "") }

// door.go: the machine's own judgement over one door.* request. The
// machine does not decide when to open the door; it checks that the
// request makes sense, then either executes it or refuses with a named
// reason.
// All policy the machine is allowed to apply is here: key shape, deadline
// order, its own idle/hard ceilings. Nothing here decides *whether* a
// human should reach the machine — that is the gateway's call, carried in
// through door.open as a fait accompli this code only validates for shape
// and its own limits.
//
// doorController serialises every winkeys.Door call through dc.mu and is
// the single owner of the watchdog handle and the two self-close timers;
// nothing outside this file touches winkeys directly.
type doorController struct {
	cfg  *Config
	door *winkeys.Door

	mu          sync.Mutex
	installed   bool
	id          string
	pubKeyB64   string
	fingerprint string
	watchdog    *winkeys.Watchdog
	hardTimer   *time.Timer
	idleTimer   *time.Timer

	// lastActivity is read/written without dc.mu (atomic) because
	// touch() is called from the hot byte-copy loop of every open
	// target channel; taking the door lock there would serialise
	// human traffic through door bookkeeping for no benefit.
	lastActivity atomic.Int64
}

func newDoorController(cfg *Config) (*doorController, error) {
	opts := winkeys.DoorOptions{
		LockPath: cfg.DoorLockPath,
		OwnerUID: cfg.OwnerUID,
		OwnerGID: cfg.OwnerGID,
		// The registration this server IS, which is what tags every
		// door line it writes and bounds every sweep it runs (1.4).
		// Config.MachineID is already required (config.go's validate),
		// so there is no case where this server knows how to reach a
		// gateway but cannot say which registration it is.
		//
		// Without it, two people running their own server on one
		// Windows machine share `administrators_authorized_keys` — the
		// one file sshd reads for administrators — and the second to
		// start sweeps the first's LIVE door away, disconnecting them
		// mid-session with nothing anywhere saying why.
		Owner: cfg.MachineID,
	}
	d, err := winkeys.NewDoorWithOptions(cfg.KeyFile, cfg.Sink, opts)
	if err != nil {
		return nil, err
	}
	return &doorController{cfg: cfg, door: d}, nil
}

// touch records tunnel activity for the idle timer (SPEC §6.4: "the
// server — by tunnel bytes").
func (dc *doorController) touch() { dc.lastActivity.Store(time.Now().UnixNano()) }

// isInstalled reports whether a door line is on record right now,
// straight from the in-memory flag every door.* handler already
// serialises through dc.mu (IAMT-182: the live window's only honest
// local signal that someone may currently be inside — who exactly, and
// until when, is known only to the gateway; docs/PROTOCOL.md §5.2/§5.4).
// Named apart from the dc.installed field: Go does not allow a method
// and a field of the same type to share a name.
func (dc *doorController) isInstalled() bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.installed
}

// sweepStale removes every door line unconditionally. It is what Start and
// every reconnect do before the tunnel is even dialled (SPEC §3.2): a
// crash can leave a line behind, and a fresh connection has no door of its
// own yet to preserve.
func (dc *doorController) sweepStale() (int, error) {
	return dc.door.SweepStale("")
}

// open handles one door.open request end to end: parse, validate shape,
// validate against this machine's own ceilings, then — and only then —
// touch the filesystem. Every return path is a controlResponse; open never
// returns a bare error; a message that fails validation is a normal,
// expected outcome (PROTOCOL §5.1's own error codes), not a fault.
func (dc *doorController) open(req controlRequest) controlResponse {
	if req.Door == nil {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", "door.open requires a door object")
	}
	if !validDoorID(req.Door.ID) {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", "door.id is not a well-formed UUID")
	}
	base64Body, fingerprint, err := decodeDoorPubKey(req.Door.PubKey)
	if err != nil {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", err.Error())
	}
	opened, idle, hard, err := parseDoorDeadlines(req.Door.Opened, req.Door.IdleDeadline, req.Door.HardDeadline)
	if err != nil {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", err.Error())
	}
	idleWindow := idle.Sub(opened)
	hardWindow := hard.Sub(opened)
	if idleWindow > dc.cfg.MaxDoorIdle {
		return errorResponse(req.ID, "E_CONTROL_DOOR_LIMIT", "idle deadline exceeds this machine's own ceiling")
	}
	if hardWindow > dc.cfg.MaxDoorHard {
		return errorResponse(req.ID, "E_CONTROL_DOOR_LIMIT", "hard deadline exceeds this machine's own ceiling")
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.installed {
		if dc.id == req.Door.ID {
			if dc.pubKeyB64 == base64Body {
				// PROTOCOL §5.1: same id, same key -> idempotent success.
				return okResponse(req.ID, doorOpenResult{DoorID: dc.id, Installed: true, PublicKeyFingerprint: dc.fingerprint})
			}
			return errorResponse(req.ID, "E_CONTROL_DOOR_MISMATCH", "door id already installed with a different key")
		}
		return errorResponse(req.ID, "E_CONTROL_DOOR_CONFLICT", "a different door is already installed")
	}

	// PROTOCOL §5.2 / doorwatch.go: the watchdog is spawned BEFORE the
	// door line is written, never after.
	//
	// The unix-side fields (LockPath/OwnerUID/OwnerGID) are forwarded
	// here because the spawned subprocess calls
	// NewDoorWithOptions on its end and the same
	// validateOptionsPlatform gate (linux/darwin) refuses a Door
	// built without them. DoorLockPath comes from cfg; OwnerUID/GID
	// were filled in at server-start time by cmd/iamtunnel's
	// lookupOwner (rec.OSUser → user.Lookup). On Windows the three
	// new parameters are accepted but ignored by the platform
	// implementation (validateOptionsPlatform is a no-op).
	wd, err := dc.cfg.SpawnWatchdog(dc.cfg.DoorwatchExe, winkeysID(req.Door.ID), dc.cfg.KeyFile, os.Getpid(), dc.cfg.WatchdogLifetime(), dc.cfg.WatchdogJournal, dc.cfg.DoorLockPath, dc.cfg.OwnerUID, dc.cfg.OwnerGID)
	if err != nil {
		return errorResponse(req.ID, "E_INTERNAL", "failed to start the door watchdog: "+err.Error())
	}
	if err := dc.door.Install(winkeysID(req.Door.ID), base64Body); err != nil {
		if serr := wd.Stop(); serr != nil {
			dc.cfg.logf("open: watchdog stop after failed install: %v", serr)
		}
		return errorResponse(req.ID, "E_INTERNAL", "failed to install the door line: "+err.Error())
	}

	dc.installed = true
	dc.id = req.Door.ID
	dc.pubKeyB64 = base64Body
	dc.fingerprint = fingerprint
	dc.watchdog = wd
	dc.touch()
	dc.armTimersLocked(idleWindow, hardWindow)

	return okResponse(req.ID, doorOpenResult{DoorID: dc.id, Installed: true, PublicKeyFingerprint: dc.fingerprint})
}

// close removes exactly the named door line and is idempotent (PROTOCOL
// §5.1: "a missing line yields {removed:true}") — winkeys.Door.Remove
// already has that contract. PROTOCOL §5.1 also requires reason validation
// against the fixed dictionary and returns E_CONTROL_DOOR_MISMATCH when the
// request names a door ID different from the currently installed door.
func (dc *doorController) close(req controlRequest) controlResponse {
	if !proto.ValidDoorCloseReason(req.Reason) {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", fmt.Sprintf("invalid door.close reason %q", req.Reason))
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.installed && dc.id != "" && req.DoorID != dc.id && winkeysID(req.DoorID) != winkeysID(dc.id) {
		return errorResponse(req.ID, "E_CONTROL_DOOR_MISMATCH", "door id mismatch")
	}

	diskInstalled, diskDoorID, _, err := parseDiskDoorStatus(dc.cfg.KeyFile, dc.cfg.MachineID)
	if err == nil && diskInstalled {
		if diskDoorID != "" && req.DoorID != diskDoorID && winkeysID(req.DoorID) != winkeysID(diskDoorID) {
			return errorResponse(req.ID, "E_CONTROL_DOOR_MISMATCH", "door id mismatch")
		}
	}

	if err := dc.door.Remove(winkeysID(req.DoorID)); err != nil {
		return errorResponse(req.ID, "E_INTERNAL", "failed to remove the door line: "+err.Error())
	}

	if dc.installed && (dc.id == req.DoorID || winkeysID(dc.id) == winkeysID(req.DoorID)) {
		dc.stopSelfLocked("close")
	}

	return okResponse(req.ID, doorCloseResult{DoorID: req.DoorID, Removed: true})
}

// parseDiskDoorStatus inspects the authorized keys file on disk to determine
// whether a door line of THIS registration - active or stale - is currently
// present (PROTOCOL §5.1 / §5.2).
//
// The line is read with winkeys' own parser (DoorLineID), and the answer
// covers the lines this registration may act on and no others (IAMT-444):
//
//   - a valid line tagged with owner (untagged, when owner is "") is this
//     server's door: installed, its id reconstructed as an RFC 4122 dashed
//     UUID, so the gateway can close it by id;
//   - a valid line tagged with ANOTHER owner is another person's door on a
//     shared machine (1.4). It is invisible here: this registration may
//     neither close nor sweep it (winkeys.Door.ownsLine), and reporting it
//     sent the gateway round a loop it could not leave - close or sanitize,
//     hear "done", ask again, see the same line - while the registration
//     never came online and the journal gained an entry per round trip;
//   - an untagged line (a build older than 1.4) beside a tagged owner, or a
//     corrupted line, is installed with an empty doorID, so the gateway
//     sends door.sanitize(reason: "corrupted"), whose sweep takes exactly
//     those. Such a line cannot be closed by id: Remove only removes a line
//     that carries this registration's tag.
//
// The first version matched the marker and then demanded nothing but blanks
// after the 32-hex id, so a 1.4 line - "<id> iamtunnel-owner=<name>" - came
// back with an empty id whoever had written it, this server's own live door
// included.
//
// The read is datafile.ReadFile (IAMT-332 round nine): a symlink or FIFO
// planted at the authorized_keys name — the server directory is
// attacker-reachable under the documented sudo server runs — is refused
// instead of being read through or wedged on. The caller treats every
// error as "no disk status", exactly as it did for a missing file, so a
// refusal degrades to the same fallback, just without following the
// plant.
func parseDiskDoorStatus(keyFile, owner string) (installed bool, doorID string, fingerprint string, err error) {
	if keyFile == "" {
		return false, "", "", nil
	}
	data, err := datafile.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", "", nil
		}
		return false, "", "", err
	}

	lines := strings.Split(string(data), "\n")
	prefix := winkeys.Options + " ssh-ed25519 "
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		if !winkeys.LooksLikeDoorLine(line) {
			continue
		}
		hexID, lineOwner, valid := winkeys.DoorLineID(line)
		switch {
		case !valid:
			// Corrupted: installed, but not addressable by id.
			return true, "", "", nil
		case lineOwner != owner && lineOwner != "":
			continue // another registration's door: see the doc comment
		case lineOwner != owner:
			// Untagged, from a build older than 1.4: installed, but a
			// server that tags its own lines cannot Remove it by id.
			return true, "", "", nil
		}
		hexID = strings.ToLower(hexID)
		doorID = fmt.Sprintf("%s-%s-%s-%s-%s", hexID[0:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:32])

		rest := line[len(prefix):]
		keyB64 := rest[:strings.IndexByte(rest, ' ')]
		if blob, decErr := decodeBase64Strict(keyB64); decErr == nil {
			if pk, pkErr := ssh.ParsePublicKey(blob); pkErr == nil {
				fingerprint = ssh.FingerprintSHA256(pk)
			}
		}
		return true, doorID, fingerprint, nil
	}
	return false, "", "", nil
}

// status reports exactly the marker/id and fingerprint of the door installed
// on disk (PROTOCOL §5.1 / §5.2). It inspects the actual key file on disk
// first to detect stale/external door lines across restarts, reconnects, or
// failed teardowns.
func (dc *doorController) status(req controlRequest) controlResponse {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	diskInstalled, diskDoorID, diskFP, err := parseDiskDoorStatus(dc.cfg.KeyFile, dc.cfg.MachineID)
	if err != nil {
		dc.cfg.logf("status: inspect disk key file %s: %v", dc.cfg.KeyFile, err)
		if !dc.installed {
			return okResponse(req.ID, doorStatusResult{Installed: false})
		}
		return okResponse(req.ID, doorStatusResult{Installed: true, DoorID: dc.id, PublicKeyFingerprint: dc.fingerprint})
	}

	if !diskInstalled {
		return okResponse(req.ID, doorStatusResult{Installed: false})
	}

	resID := diskDoorID
	if dc.installed && dc.id != "" && (dc.id == diskDoorID || winkeysID(dc.id) == winkeysID(diskDoorID)) {
		resID = dc.id
	}
	resFP := diskFP
	if resFP == "" && dc.installed && (dc.id == diskDoorID || winkeysID(dc.id) == winkeysID(diskDoorID)) {
		resFP = dc.fingerprint
	}
	return okResponse(req.ID, doorStatusResult{
		Installed:            true,
		DoorID:               resID,
		PublicKeyFingerprint: resFP,
	})
}

// sanitize removes every door line unconditionally, including one whose
// marker is corrupted or whose id this controller does not recognise
// (PROTOCOL §5.1: door.sanitize's safety rests entirely on the gateway
// only ever sending it from its own Closed state, where it holds no key
// of its own; this controller does not second-guess that and simply
// sweeps).
//
// The response carries the count of removed lines so the gateway's
// events.jsonl record of door.sanitize says how many lines of admin
// access were just wiped (IAMT-103: the operation that deletes every
// marked line without naming one id is the one the journal must speak
// the loudest about). A zero-count success is a valid outcome: a sweep
// of an already-clean file is not an error, and the gateway treats it
// as such.
func (dc *doorController) sanitize(req controlRequest) controlResponse {
	if req.Reason != proto.DoorSanitizeCorrupted {
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", `door.sanitize reason must be "corrupted"`)
	}
	removed, err := dc.door.SweepStale("")
	if err != nil {
		return errorResponse(req.ID, "E_INTERNAL", "sanitize failed: "+err.Error())
	}

	dc.mu.Lock()
	dc.stopSelfLocked("sanitize")
	dc.mu.Unlock()

	dc.cfg.logf("door.sanitize: removed %d lines (reason: %s)", removed, req.Reason)
	return okResponse(req.ID, sanitizeResult{Sanitized: true, Removed: removed})
}

// teardown is called once, when the tunnel to the gateway is gone for any
// reason (control read error, keepalive loss, context cancellation): the
// live server removes its own line rather than leaving it for the next
// SweepStale (PROTOCOL §5.2 layer 2).
func (dc *doorController) teardown(reason string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if !dc.installed {
		return
	}
	id := dc.id
	if err := dc.door.Remove(winkeysID(id)); err != nil {
		dc.cfg.logf("teardown(%s): failed to remove door %s: %v", reason, id, err)
		return
	}
	dc.stopSelfLocked(reason)
}

// armTimersLocked schedules the machine's own monotonic idle and hard
// closes (SPEC §3.2: "it has the right to refuse a request... and
// additionally closes the door on a monotonic ceiling... independent
// of the gateway's clock or good faith"). Must be called with dc.mu held.
//
// Both timers are armed as pure durations measured from "now" on this
// machine's own clock, deliberately never by comparing the gateway's
// "opened"/deadline timestamps against this machine's own idea of the
// current time: the gateway and the machine are two different clocks, and
// PROTOCOL's own words are "independent of the gateway's clock..." —
// the machine's ceiling must hold even against a gateway whose clock
// disagrees with this machine's, not just one that is malicious.
// Comparing an absolute gateway-issued deadline to a local time.Now()
// would make the schedule a function of clock skew, which can easily
// be minutes in a test fixture with a synthetic clock and is not zero
// even between two real, correctly NTP-synced hosts.
// hardWindow/idleWindow are pure durations
// (hard.Sub(opened), idle.Sub(opened)) that never depend on any clock
// alignment between the two sides — only on the gateway's own three
// timestamps being self-consistent, which parseDoorDeadlines already
// checked. checkIdle re-arms idleWindow relative to whenever activity was
// last observed; hardWindow fires once, unconditionally.
func (dc *doorController) armTimersLocked(idleWindow, hardWindow time.Duration) {
	id := dc.id
	dc.hardTimer = time.AfterFunc(hardWindow, func() { dc.selfClose(id, "hard") })
	dc.idleTimer = time.AfterFunc(idleWindow, func() { dc.checkIdle(id, idleWindow) })
}

// checkIdle re-arms itself for the remaining window if activity happened
// since it was scheduled, rather than closing on a fixed wall-clock point —
// idle means "inactive for the window", not "window elapsed since open".
func (dc *doorController) checkIdle(id string, window time.Duration) {
	dc.mu.Lock()
	if !dc.installed || dc.id != id {
		dc.mu.Unlock()
		return
	}
	elapsed := time.Since(time.Unix(0, dc.lastActivity.Load()))
	if elapsed >= window {
		dc.mu.Unlock()
		dc.selfClose(id, "idle")
		return
	}
	remaining := window - elapsed
	dc.idleTimer = time.AfterFunc(remaining, func() { dc.checkIdle(id, window) })
	dc.mu.Unlock()
}

// selfClose is the machine acting entirely on its own initiative: no
// control-channel request drives it, so there is no request id to answer
// and nothing to send the gateway — the wire protocol has no
// machine-to-gateway notification for this. The next door.status the
// gateway sends (initial, reconciliation, or idle-triggered on its own
// side) simply observes installed:false.
func (dc *doorController) selfClose(id, reason string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if !dc.installed || dc.id != id {
		return
	}
	if err := dc.door.Remove(winkeysID(id)); err != nil {
		dc.cfg.logf("self-close(%s): failed to remove door %s: %v", reason, id, err)
		return
	}
	dc.stopSelfLocked(reason)
}

// stopSelfLocked stops the watchdog and both timers and clears the
// in-memory record. Must be called with dc.mu held; does not touch the
// filesystem itself — every caller removes the line first.
func (dc *doorController) stopSelfLocked(reason string) {
	if dc.watchdog != nil {
		if err := dc.watchdog.Stop(); err != nil {
			// PROTOCOL §5.1: a watchdog-stop failure after a confirmed
			// close/sanitize/teardown does not turn the result into an
			// error — the line is already gone, which is the invariant
			// that matters. It is only logged locally.
			dc.cfg.logf("%s: doorwatch stop failed for door %s: %v", reason, dc.id, err)
		}
		dc.watchdog = nil
	}
	if dc.hardTimer != nil {
		dc.hardTimer.Stop()
		dc.hardTimer = nil
	}
	if dc.idleTimer != nil {
		dc.idleTimer.Stop()
		dc.idleTimer = nil
	}
	dc.installed = false
	dc.id = ""
	dc.pubKeyB64 = ""
	dc.fingerprint = ""
}
