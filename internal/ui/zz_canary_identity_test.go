//go:build windows

package ui

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Three canaries on one theme: WHO THIS MACHINE IS on its gateway.
//
// All three were written from independent review findings
// (the night of 22.09.2026), and all three are about the same
// failure: identity lacked what the list of held commands has.
// HeldKnown distinguishes "nothing is held" from "could not ask";
// identity had no such distinction at all, and neither had any order
// in time.

// 1. An unreadable answer is not a negative answer.
//
// client.LoadConnection fails for two unrelated reasons: nothing is
// saved, OR it is saved and cannot be read -- the directory's
// permissions changed, the file was half-appended to, the file was
// replaced by a symlink the reader rightly refuses to open. Both
// reasons collapsed into nil, and the window declared the first
// having met only the second: it offered to make the machine the
// administrator of the gateway it was already the administrator of.
//
// This is the same "unknown drawn as false" mistake IAMT-311 removed
// from the server facts, one layer up.
func TestCanary_UnreadableIdentityIsNotAnAbsentIdentity(t *testing.T) {
	f, err := NewFrame(FrameConfig{Enrolled: true, HasAdminRights: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.reviseSnapshot(func(s *Snapshot) {
		s.Admin.ThisMachine = &AdminIdentity{Person: "alice", Gateway: "gw.example:2222"}
		s.Client.Configured = true
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}

	// The tick could not read the saved connection.
	f.ApplyLiveUpdate(LiveUpdate{IdentityKnown: false, At: time.Now()})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.snap.Admin.ThisMachine == nil {
		t.Fatal("a tick that failed to read the connection wiped the machine's identity -- " +
			"the Admin tab will offer to become the administrator of a gateway the machine already administers")
	}
	if !f.snap.Client.Configured {
		t.Fatal("a tick that failed to read the connection declared the machine unconfigured")
	}

	// But an established fact of "nothing is saved" MUST be erased:
	// otherwise a forgotten identity never disappears.
	f.ApplyLiveUpdate(LiveUpdate{IdentityKnown: true, At: time.Now()})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.snap.Admin.ThisMachine != nil {
		t.Fatalf("the tick established there is no connection, yet the identity remains: %+v",
			f.snap.Admin.ThisMachine)
	}
}

// 2. A tick that LOOKED before the person pressed loses.
//
// The observed sequence, verbatim: a tick reads alice, gets stuck
// on the request for held commands to the gateway, the person
// confirms FORGET twice, the card goes dark -- and then the stuck
// tick lands and writes alice again. Until the next tick (longer,
// with the request hung) the window states the machine is still the
// administrator of that gateway. That is a security statement, and
// it is false.
func TestCanary_StaleTickLosesToADeliberateWrite(t *testing.T) {
	f, err := NewFrame(FrameConfig{Enrolled: true, HasAdminRights: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	// The tick looked at the disk HERE.
	looked := time.Now()

	// ...and while it hung on the gateway, the person forgot the
	// identity.
	f.wroteIdentity(func(s *Snapshot) {
		s.Admin.ThisMachine = nil
		s.Client.Configured = false
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}

	// Now the tick lands -- with the old truth.
	f.ApplyLiveUpdate(LiveUpdate{
		Identity:      &AdminIdentity{Person: "alice", Gateway: "gw.example:2222"},
		IdentityKnown: true,
		At:            looked,
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.snap.Admin.ThisMachine != nil {
		t.Fatalf("the stale tick brought back the forgotten identity %+v -- the window again names a gateway "+
			"the person has just, with confirmation, left", f.snap.Admin.ThisMachine)
	}

	// But a tick that looked AFTER still wins: a connection restored
	// from the command line or from a second window must reach here
	// without anybody's permission.
	f.ApplyLiveUpdate(LiveUpdate{
		Identity:      &AdminIdentity{Person: "bob", Gateway: "gw.example:2222"},
		IdentityKnown: true,
		At:            time.Now(),
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.snap.Admin.ThisMachine == nil || f.snap.Admin.ThisMachine.Person != "bob" {
		t.Fatalf("the fresh tick never landed: %+v -- this is how the window stops noticing a connection "+
			"made behind its back", f.snap.Admin.ThisMachine)
	}
}

// 3. A spent one-time token stops looking unspent.
//
// A successful claim or pair writes the connection, but the identity
// used to arrive only with the next tick -- for up to three seconds
// the "Become an administrator" card stood on screen after its string
// had already been spent. A second press spends nothing and gets a
// refusal from a gateway that is right; it is the card that is not.
func TestCanary_SpentClaimStopsLookingUnspent(t *testing.T) {
	f := newBareFrame(t)

	who := &AdminIdentity{Person: "alice", Gateway: "203.0.113.10:2022"}
	done := make(chan struct{})
	f.cfg.Actions.AdminClaim = func(ref, token string) (string, *AdminIdentity, error) {
		defer close(done)
		return "This machine is now an administrator.", who, nil
	}
	f.cfg.Actions.AdminPairClaim = func(ref, pin string) (string, *AdminIdentity, error) {
		t.Error("the claim string went to the pair action")
		return "", nil, nil
	}

	f.editor(ctlAdminPairJoin).SetText(
		"iamtunnel-claim://203.0.113.10:2022#" + identityCanaryFingerprint + ":" + identityCanaryToken)
	f.joinAsAdmin()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no action was called")
	}
	awaitSaid(t, f, ctlAdminPairJoin, design.GoodKey)

	// reviseSnapshot parks the value; a Layout pass moves it into f.snap.
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}

	if f.snap.Admin.ThisMachine == nil {
		t.Fatal("after the spent claim string the window still does not know who this machine is -- " +
			"the card will offer to spend it a second time, and the gateway will refuse")
	}
	if f.snap.Admin.ThisMachine.Person != who.Person {
		t.Errorf("identity = %+v, want %+v", f.snap.Admin.ThisMachine, who)
	}
	if !f.snap.Client.Configured {
		t.Error("the connection is written, yet the window considers the machine unconfigured")
	}

	// And a stale tick must not tear down this just-received identity.
	f.ApplyLiveUpdate(LiveUpdate{IdentityKnown: true, At: time.Now().Add(-time.Minute)})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}
	if f.snap.Admin.ThisMachine == nil {
		t.Fatal("a stale tick erased the identity received from the claim string")
	}
}

const (
	identityCanaryFingerprint = "SHA256:QkNrqPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo"
	identityCanaryToken       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
