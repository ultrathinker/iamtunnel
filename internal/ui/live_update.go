//go:build windows || linux || darwin

package ui

import "time"

// The narrow channel the periodic status poll speaks through
// (21.09.2026).
//
// WHAT WAS WRONG. The poll used to hand over a whole Snapshot. It could
// not build one — it only knows three things: whether the server on this
// machine is running, who this machine is on its gateway, and what the
// gateway is holding for this person. So cmd/iamtunnel kept a second,
// shadow copy of the entire window state (`base`, under its own mutex)
// and every action wrote its result into BOTH the frame and that copy.
// Miss one of those writes and the tick three seconds later drew the
// shadow over the real thing.
//
// That is not a hypothetical. The maintainer opened History on 21.09.2026,
// saw the sessions there, and watched them vanish a second and a half later,
// again and again: the history page was revised into the frame and the
// shadow had never heard of it. Setup.Detail had the same hole and had
// had it longer. Both were the same mistake, made twice, in a place the
// compiler cannot see — a forgotten assignment is not a type error.
//
// WHAT IS RIGHT. The frame IS the state. Nobody else keeps a copy, so
// there is nothing to forget to update. The poll says only what it
// actually learned, in a type that can hold only that, and the frame
// merges those fields and touches nothing else. A field that no longer
// appears in LiveUpdate cannot be blanked by a tick — the class of
// defect is gone rather than guarded.
//
// The canary that used to read the source for missing shadow-writes was
// deleted with the shadow. Its replacement is two ordinary tests of
// ApplyLiveUpdate, which is the difference between watching for a mistake
// and making it unavailable.

// LiveUpdate is everything the periodic poll learns, and nothing else.
//
// It is deliberately not a Snapshot with most fields left at zero:
// "unset" and "empty" are the same value in Go, and a type that CAN
// carry a blank history page is a type somebody will eventually blank a
// history page with.
type LiveUpdate struct {
	// Server is this machine's own control status, dialled directly.
	Server ServerState

	// Identity is who this machine is on its gateway, re-read from the
	// saved connection on every tick (IAMT-389), and IdentityKnown says
	// whether that read succeeded. It is authoritative precisely because
	// it comes from the file rather than from this window's memory of its
	// own actions -- a connection restored by the CLI, or by a second
	// window, shows up here without anybody telling this window about it.
	//
	// THE PAIR EXISTS FOR THE REASON THE HELD PAIR DOES, and it was
	// missing for a day (22.09.2026, found in review). A nil Identity
	// meant BOTH "this machine has joined nobody" and "the saved
	// connection could not be read" -- a permission change on the
	// directory, a half-written file, a symlink the reader refuses. The
	// second is not knowledge of the first, and the window answered it by
	// offering to make the machine an administrator of a gateway it was
	// already an administrator of. That is the same "unknown rendered as
	// false" mistake IAMT-311 removed from the server facts, one layer
	// over.
	//
	// IdentityKnown false leaves whatever the window already believed.
	Identity      *AdminIdentity
	IdentityKnown bool

	// At is when this tick STARTED reading what it carries -- stamped
	// before the first read, not when the tick is delivered.
	//
	// A tick is not instantaneous: it reads a file, then asks the gateway
	// a question that can take seconds or hang. An action finishing
	// inside that window is NEWER than the tick already in flight, and
	// applying the tick afterwards puts back what the person has just
	// changed. The observed sequence, verbatim: the tick reads alice,
	// stalls on the held request, the person presses FORGET twice and the
	// card goes blank -- and then the stalled tick lands and the card
	// says alice again.
	//
	// So a tick states WHEN it looked, and the frame ignores a look older
	// than its own last deliberate write of the same fact. A zero At is
	// treated as "no claim about when", which keeps a caller that does
	// not set it (a test, an older build) from silently winning.
	//
	// A switch of gateway is such a write for both facts at once (R1-CX
	// F-16): a tick that looked before it read who this machine is and
	// what is held on the gateway the window has left. That is also why
	// At precedes the FIRST read and not only the held request: a look
	// that began before a switch or a forget must not pass for one that
	// began after it.
	At time.Time

	// Held is what the gateway is holding for this person, and HeldKnown
	// says whether the question could be asked at all.
	//
	// The two are separate because a failed read is not an empty answer.
	// The gateway being briefly unreachable is not evidence that nothing
	// is held, and blanking the list would retract a question the person
	// may be halfway through reading — with a five-minute clock on it.
	Held      []HeldCommand
	HeldKnown bool
}

// ApplyLiveUpdate merges one poll's findings into the window's state.
//
// It touches only what the poll actually learned. Server is replaced
// whole because the poll is its sole author and fills every field of it;
// everything else is written field by field, for the reason spelled out
// in zz_canary_partial_update_test.go — an answer that knows about
// part of a structure and replaces all of it silently blanks the part it
// was never told about.
//
// Safe from any goroutine: it goes through the same single handover
// every other revision uses, so no frame draws half of one reality and
// half of another.
func (f *Frame) ApplyLiveUpdate(u LiveUpdate) {
	f.reviseSnapshot(func(s *Snapshot) {
		s.Server = u.Server
		// Identity: only when the tick could actually read it, and only
		// when it looked AFTER this window last changed it on purpose.
		//
		// identityWrittenAt is read HERE, inside the single lock
		// reviseSnapshot holds while it calls this, and not in a check
		// before the call. Two lock acquisitions would leave a gap: a
		// forget landing between the check and the write would pass the
		// guard that exists to stop exactly that, and the guard would be
		// a smaller version of the defect it was written for.
		//
		// Nor when it looked before the window last switched gateways
		// (R1-CX F-16): then both answers are about the gateway it left.
		sameGateway := u.At.IsZero() || u.At.After(f.gatewaySwitchedAt)
		if u.IdentityKnown && sameGateway && (u.At.IsZero() || u.At.After(f.identityWrittenAt)) {
			s.Admin.ThisMachine = u.Identity
			s.Client.Configured = u.Identity != nil
		}
		if u.HeldKnown && sameGateway {
			s.Client.Held = u.Held
		}
	})
}

// wroteIdentity records that an action of this window has just changed
// who this machine is, and revises the frame in the same breath.
//
// The stamp is what makes a tick already in flight lose to it: that tick
// read the file before this call, so its answer is about a world that no
// longer exists. Both callers are deliberate, confirmed acts -- forgetting
// an identity (twice-confirmed) and claiming one -- which is exactly the
// set that must not be undone by a slow poll.
func (f *Frame) wroteIdentity(edit func(*Snapshot)) {
	f.mu.Lock()
	f.identityWrittenAt = time.Now()
	f.mu.Unlock()
	f.reviseSnapshot(edit)
}
