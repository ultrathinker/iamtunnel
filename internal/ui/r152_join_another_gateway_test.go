package ui

import (
	"testing"
	"time"
)

// A claim line pasted into the Client tab's "add another gateway" box is
// spent as a claim (1.52): on 29.09.2026 the box refused it, and the
// Admin tab would take it only after the machine forgot the gateway it
// was already on.
func TestR152_ClientBoxSpendsAClaimLineAsAClaim(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Admin.ThisMachine = &AdminIdentity{Person: "admin", Gateway: "198.51.100.7:2022"}

	claimed := make(chan [2]string, 1)
	f.cfg.Actions.AdminClaim = func(ref, token string) (string, *AdminIdentity, error) {
		claimed <- [2]string{ref, token}
		return "ok", &AdminIdentity{Person: "admin", Gateway: "203.0.113.10:2022"}, nil
	}
	f.cfg.Actions.SaveConnection = func(line, name string, replace bool) (string, error) {
		t.Errorf("the claim line went to SaveConnection as a connection string: %q", line)
		return "", nil
	}

	f.editor(ctlClientSave).SetText(
		"iamtunnel-claim://203.0.113.10:2022#" + claimRouteFingerprint + ":" + claimRouteToken)
	f.saveConnectionString(false)

	select {
	case got := <-claimed:
		if want := "203.0.113.10:2022#" + claimRouteFingerprint; got[0] != want || got[1] != claimRouteToken {
			t.Fatalf("claim got ref %q token %q, want %q and the token", got[0], got[1], want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the claim action was never called")
	}

	// The machine's identity is now the NEW gateway's, and the box that
	// held the one-time line is empty.
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		var gw string
		if f.pending != nil && f.pending.Admin.ThisMachine != nil {
			gw = f.pending.Admin.ThisMachine.Gateway
		} else if f.snap.Admin.ThisMachine != nil {
			gw = f.snap.Admin.ThisMachine.Gateway
		}
		f.mu.Unlock()
		if gw == "203.0.113.10:2022" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("identity gateway = %q after the claim, want the new gateway", gw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if txt := f.editor(ctlClientSave).Text(); txt != "" {
		t.Fatalf("the spent claim line is still in the box: %q", txt)
	}
}
