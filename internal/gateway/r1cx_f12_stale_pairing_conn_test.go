package gateway

// R1-CX F-12 (review of 22-23.09): a pairing connection was bound to
// nothing. The SSH handshake admitted any well-formed key while SOME window
// was open; the "admin.pair" exec that followed was graded against WHATEVER
// window was open by then. A window replaced in between - a second
// pairing.start while connections opened for the first one are still held -
// therefore collects those connections' wrong PINs: ten held connections
// sending ten wrong PINs burn the NEW window (PairingWindowMissLimit)
// without the new PIN ever being graded, which is exactly the burn the
// window's miss counter exists to make meaningful (M-13). PairingPending
// has no generation a connection could have remembered; the fix binds the
// connection to the identity of the window that admitted it (the hash in
// ssh.Permissions, the only channel back through the handshake) and refuses
// the stale connection without debiting anything - there is no window left
// that its PIN could be a guess at.

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// r1cxF12PairingDial completes the SSH handshake as "pairing" and returns
// the open connection with nothing exec'd on it yet - the held connection
// of the finding's scenario: admitted while one window was open, idle
// across its replacement.
func r1cxF12PairingDial(t *testing.T, f *fixture, key ssh.Signer) *ssh.Client {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "pairing",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pairing login: %v", err)
	}
	return conn
}

// r1cxF12PairExec runs the one "admin.pair" exec a pairing connection is
// allowed and reads the response line back as the wire envelope.
func r1cxF12PairExec(t *testing.T, conn *ssh.Client, body []byte) iamt143WireEnvelope {
	t.Helper()
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("pairing session: %v", err)
	}
	defer ch.Close()
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"admin.pair"}))
	if err != nil || !ok {
		t.Fatalf("admin.pair exec request: ok=%v err=%v", ok, err)
	}
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write admin.pair body: %v", err)
	}
	_ = ch.CloseWrite()
	buf := make([]byte, 8192)
	var acc strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, rerr := ch.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
			if strings.Contains(acc.String(), "\n") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	var env iamt143WireEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(acc.String())), &env); err != nil {
		t.Fatalf("admin.pair response is not JSON: %v; raw=%q", err, acc.String())
	}
	return env
}

// f12PairBody marshals one admin.pair body.
func f12PairBody(t *testing.T, pin, pubkey, name string) []byte {
	t.Helper()
	raw, err := json.Marshal(pairingRequest{Proto: 1, Pin: pin, Pubkey: pubkey, Name: name})
	if err != nil {
		t.Fatalf("marshal admin.pair body: %v", err)
	}
	return raw
}

func TestR1CX_F12_HeldPairingConnectionsDoNotDebitTheWindowThatReplacedTheirs(t *testing.T) {
	t.Run("a wrong pin from a held connection", func(t *testing.T) {
		f := newFixture(t, nil)
		seedPairingWindow(t, f, "111111", time.Hour)
		held := r1cxF12PairingDial(t, f, genSigner(t))
		defer held.Close()

		// The replacement: a new window replaces the one this connection
		// was admitted for (PROTOCOL §3.4 - no observer ever sees two open
		// windows), and the old PIN stops working the instant it lands.
		pairingStartDirect(t, f, "alice")

		resp := r1cxF12PairExec(t, held, f12PairBody(t, "222222", authorizedLine(genSigner(t).PublicKey()), "f12a"))

		st := f.store.Get()
		if st.PairingPending == nil {
			t.Fatalf("the replaced window was burned by a wrong PIN graded from a connection the handshake had admitted for the window it replaced (F-12)")
		}
		if st.PairingPending.Misses != 0 {
			t.Fatalf("the replaced window absorbed %d miss(es) from a connection admitted for the previous window: ten such held connections reach PairingWindowMissLimit and burn a window whose PIN was never graded (F-12)", st.PairingPending.Misses)
		}
		if resp.Error == nil || resp.Error.Code != "E_PAIRING_INACTIVE" {
			t.Fatalf("the stale connection's wrong PIN was answered %+v, want the stale-window refusal E_PAIRING_INACTIVE - the connection must be told its window is gone, not that a PIN was wrong (F-12)", resp.Error)
		}
	})

	t.Run("the old pin does not grade against the new window either", func(t *testing.T) {
		f := newFixture(t, nil)
		seedPairingWindow(t, f, "333333", time.Hour)
		held := r1cxF12PairingDial(t, f, genSigner(t))
		defer held.Close()
		pairingStartDirect(t, f, "alice")

		// The correct OLD pin on the held connection: the old window is
		// gone, so there is nothing this pin could open - the answer must
		// be the stale-window refusal, never a grading against the window
		// that replaced this connection's.
		resp := r1cxF12PairExec(t, held, f12PairBody(t, "333333", authorizedLine(genSigner(t).PublicKey()), "f12b"))

		st := f.store.Get()
		if st.PairingPending == nil {
			t.Fatalf("the replaced window was burned by the old window's own correct PIN, graded from a held connection (F-12)")
		}
		if st.PairingPending.Misses != 0 {
			t.Fatalf("the replaced window absorbed %d miss(es) from the old window's correct PIN being graded against it (F-12)", st.PairingPending.Misses)
		}
		if resp.Error == nil || resp.Error.Code != "E_PAIRING_INACTIVE" {
			t.Fatalf("the stale connection's old PIN was answered %+v, want the stale-window refusal E_PAIRING_INACTIVE (F-12)", resp.Error)
		}
	})

	t.Run("a fresh client still pairs after the replacement", func(t *testing.T) {
		f := newFixture(t, nil)
		seedPairingWindow(t, f, "444444", time.Hour)
		held := r1cxF12PairingDial(t, f, genSigner(t))
		defer held.Close()
		newPin := pairingStartDirect(t, f, "alice").Pin

		// The held connection sends its wrong pin first. Whatever it costs
		// must come out of nothing: its window is gone, there is no PIN to
		// grade, so neither the window's miss counter nor the per-address
		// limiter may be billed for it.
		resp := r1cxF12PairExec(t, held, f12PairBody(t, "555555", authorizedLine(genSigner(t).PublicKey()), "f12c"))
		if resp.Error == nil || resp.Error.Code != "E_PAIRING_INACTIVE" {
			t.Fatalf("the held connection's wrong PIN was answered %+v, want E_PAIRING_INACTIVE (F-12)", resp.Error)
		}

		// Two deliberate wrong PINs against the NEW window, from the same
		// host the held connection came from: with the held attempt not
		// billed, that is two failures - one below the pairing ban.
		host, _, err := net.SplitHostPort(f.addr)
		if err != nil {
			t.Fatalf("split fixture addr: %v", err)
		}
		legitKey := genSigner(t)
		line := authorizedLine(legitKey.PublicKey())
		for _, pin := range []string{"000000", "999999"} {
			_, cerr := runPairingAt(f, net.JoinHostPort(host, "5555"), fingerprintOf(t, legitKey.PublicKey()), pin, line)
			wantPairingRefusal(t, "deliberate wrong pin against the new window", cerr, "E_PAIRING_PIN_INVALID", 2)
		}

		// The legitimate client reconnects - a fresh handshake, admitted
		// for the new window - and pairs with the new PIN. If the held
		// connection's attempt was billed, this handshake is the fourth
		// failure from the address and is locked out instead.
		fresh := r1cxF12PairingDial(t, f, legitKey)
		defer fresh.Close()
		done := r1cxF12PairExec(t, fresh, f12PairBody(t, newPin, line, "f12admin"))
		if done.Error != nil {
			t.Fatalf("the legitimate pairing after the replacement failed with %s (%s): the held connection's attempt was billed to this address (F-12)", done.Error.Code, done.Error.Message)
		}
		st := f.store.Get()
		if st.PairingPending != nil {
			t.Fatalf("a successful pairing left the window open")
		}
		paired := false
		for _, p := range st.People {
			if p.Name == "f12admin" && p.Role == "admin" {
				paired = true
			}
		}
		if !paired {
			t.Fatalf("the fresh client's pairing answered ok but created no admin f12admin")
		}
	})
}
