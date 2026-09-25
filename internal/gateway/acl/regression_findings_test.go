package acl

import (
	"errors"
	"testing"
	"time"
)

// TestFinding_R1_RevokeSurvivesConcurrentOrPastOpen walks the race condition
// and time comparison flaw in checkLocked (acl.go:261).
//
// When Revoke runs at tRevoke, it sets g.RevokedAt = tRevoke, collects active
// sessions, kills them and releases the lock. If an OpenSession request arrives
// with a timestamp tOpen such that tOpen.Before(tRevoke) is true (e.g. concurrent
// connection where time was sampled immediately before Revoke acquired the lock,
// or clock jitter/backwards step by NTP/timesyncd), checkLocked evaluates:
//
//	!now.Before(*g.RevokedAt) -> false
//
// As a result, checkLocked returns ReasonNone, OpenSession registers a new live
// session on the revoked grant, and the session survives because Revoke has
// already completed its collection pass.
func TestFinding_R1_RevokeSurvivesConcurrentOrPastOpen(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	tRevoke := base.Add(10 * time.Minute)
	n, err := e.Revoke("alice", "win01", tRevoke)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if n != 0 {
		t.Fatalf("Revoke killed %d sessions, want 0", n)
	}

	// Concurrent open sampled time 1ms earlier, or clock adjusted backwards:
	tOpen := tRevoke.Add(-time.Millisecond)
	s, err := e.OpenSession("alice", "win01", tOpen, nil)
	if err == nil {
		t.Fatalf("OpenSession succeeded on revoked grant: session %v is live", s.ID)
	}
	var de *DenyError
	if !errors.As(err, &de) || de.Reason != DenyGrantRevoked {
		t.Fatalf("OpenSession err = %v, want DenyError{DenyGrantRevoked}", err)
	}
}

// TestFinding_R2_SweepExpiredIgnoresRevokedGrant proves that the periodic
// sweeper (SweepExpired, acl.go:327) completely ignores grant revocation.
//
// If a session is live on a grant whose RevokedAt is set, SweepExpired
// checks only `!now.Before(g.Until)` at acl.go:332. It never checks
// `g.RevokedAt != nil`. As a result, the background sweeper (SPEC §6.4:
// 1-second ticker) never tears down sessions on revoked grants, leaving
// them active until the original grant expiration deadline (Until).
func TestFinding_R2_SweepExpiredIgnoresRevokedGrant(t *testing.T) {
	e := newTest(t)
	grantStd(t, e) // alice -> win01 until base+1h

	killed := make(chan DenyReason, 1)
	mustOpen(t, e, "alice", "win01", base, func(r DenyReason) { killed <- r })

	// Grant is marked revoked at base+10m
	e.mu.Lock()
	tRevoke := base.Add(10 * time.Minute)
	e.grants[grantKey{"alice", "win01"}].RevokedAt = &tRevoke
	e.mu.Unlock()

	// 15 minutes after revocation, periodic 1s ticker runs SweepExpired:
	tSweep := base.Add(25 * time.Minute)
	n := e.SweepExpired(tSweep)
	if n != 1 {
		t.Fatalf("SweepExpired killed %d sessions on revoked grant, want 1", n)
	}
}

// TestFinding_R3_RevokeReturnsZeroKilledForNilCallback proves that Revoke
// calculates its return value as `len(notes)` rather than `len(ids)` (acl.go:233).
//
// When a session is opened with `onRevoke == nil` (which OpenSession explicitly
// supports), killLocked does not append an entry to `notes`. Revoke therefore
// returns 0 killed sessions even though the session was indeed killed and removed
// from e.sessions. This corrupts admin accounting (cmdGrantsRevoke logs
// `killedSessions: 0` in events.jsonl, SPEC §3.5).
func TestFinding_R3_RevokeReturnsZeroKilledForNilCallback(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	// Session opened with onRevoke == nil:
	mustOpen(t, e, "alice", "win01", base, nil)

	tRevoke := base.Add(10 * time.Minute)
	n, err := e.Revoke("alice", "win01", tRevoke)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke returned %d killed sessions, want 1 (session was killed but had nil onRevoke)", n)
	}
}

// TestFinding_R4_ZeroSessionIDCanBecomeLiveAndUnclosable proves that nextID
// counter wrap-around (acl.go:294) causes SessionID{0} to be issued.
//
// Because SessionID.Valid() returns `id.n > 0` (acl.go:85), a zero SessionID
// reports Valid() == false. When the owner or admin attempts to end the session:
// - Close(id) returns false immediately at acl.go:310 without taking the lock;
// - Kill(id) returns false immediately at acl.go:377 without taking the lock;
// - String() renders "session:<invalid>", which ParseSessionID rejects.
// The session remains live forever in e.sessions, permanently leaking perPerson
// and perMachine limits and locking legitimate users out forever.
func TestFinding_R4_ZeroSessionIDCanBecomeLiveAndUnclosable(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	// Simulate counter at maximum uint64:
	e.mu.Lock()
	e.nextID = ^uint64(0)
	e.mu.Unlock()

	s, err := e.OpenSession("alice", "win01", base, nil)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if !s.ID.Valid() {
		t.Fatalf("Engine issued session with invalid/zero ID: %v (n=%d)", s.ID, s.ID.Uint64())
	}
	if !e.Close(s.ID, base) {
		t.Fatalf("Close failed for live session %v", s.ID)
	}
}

// TestFinding_R5_ParseSessionIDAcceptsNonCanonical proves that ParseSessionID
// accepts non-canonical numeric encodings such as leading zeros (acl.go:348).
//
// String() produces "session:<positive integer>" in canonical decimal representation
// without leading zeros. However, ParseSessionID accepts inputs like "session:01",
// which breaks canonical identifier round-tripping and permits session aliasing
// in admin operations and audit logs.
func TestFinding_R5_ParseSessionIDAcceptsNonCanonical(t *testing.T) {
	raw := "session:01"
	id, err := ParseSessionID(raw)
	if err == nil {
		t.Fatalf("ParseSessionID(%q) accepted non-canonical input; parsed as %v (which stringifies as %q)",
			raw, id, id.String())
	}
}

// TestFinding_R6_SpecDiscrepancy_OptionalUntil proves the disagreement between
// SPEC §4.3 and internal/gateway/acl (acl.go:53, 193).
//
// SPEC §4.3 explicitly specifies:
//
//	`until` is optional; an absent until is distinct from a zero time.
//
// However, acl.go:53 declares "The deadline is mandatory", and validateGrant
// rejects any grant without a future deadline at acl.go:193. Consequently,
// indefinite grants are rejected by the ACL engine and dropped on startup
// by gateway.go:87.
func TestFinding_R6_SpecDiscrepancy_OptionalUntil(t *testing.T) {
	e := newTest(t)
	// SPEC §4.3: until is optional:
	g := Grant{Person: "alice", Machine: "win01", Caps: []string{"shell"}}
	if err := e.AddGrant(g, base); err != nil {
		t.Fatalf("AddGrant rejected grant with optional until: %v", err)
	}
	d := e.Check("alice", "win01", base)
	if !d.Allowed {
		t.Fatalf("Check on indefinite grant: allowed = false, reason = %v", d.Reason)
	}
}
