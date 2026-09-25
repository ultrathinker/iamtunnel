package admin

// R2-CX F-06: PROTOCOL §1.1 - before its first application operation a
// client MUST run whoami as the version preflight, the one request allowed
// before the gateway's version is known, and stop on an incompatible
// answer. admin.Conn - the CLI's admin commands and the window's Admin tab
// both run on it - sent the chosen command first: people.add, grants.revoke
// or any other change went to a gateway whose version nobody had asked,
// and an incompatibility surfaced, if at all, only in the answer to a
// change already made. The logins that carry one command of their own -
// enrol, bootstrap, pairing - refuse whoami and are not preflighted.

import (
	"sync"
	"testing"
	"time"
)

// r2cxWhoamiOK is a v1 gateway's answer to whoami.
const r2cxWhoamiOK = `{"proto":1,"caps":[],"ok":true,"result":{"subject":"alice","role":"admin","serverTime":"2026-09-12T10:00:00Z","person":"alice"}}` + "\n"

// r2cxPeopleAddOK is a v1 gateway's answer to people.add.
const r2cxPeopleAddOK = `{"proto":1,"caps":[],"ok":true,"result":{"name":"bob","role":"user","keys":[]}}` + "\n"

// r2cxRecordingGateway answers whoami with whoami and everything else with
// other, and remembers the order the commands came in.
func r2cxRecordingGateway(t *testing.T, whoami string) (*fakeGateway, func() []string) {
	t.Helper()
	personKey := genSigner(t)
	var mu sync.Mutex
	var seen []string
	fg := newFakeGatewayForWhoami(t, personKey, func(command string, _ []byte) []byte {
		mu.Lock()
		seen = append(seen, command)
		mu.Unlock()
		if command == "whoami" {
			return []byte(whoami)
		}
		return []byte(r2cxPeopleAddOK)
	})
	return fg, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestR2CX_F06_TheFirstCommandOnAConnectionIsTheWhoamiPreflight(t *testing.T) {
	fg, seen := r2cxRecordingGateway(t, r2cxWhoamiOK)
	c := dialFake(t, fg, fg.personKey)
	if _, err := c.PeopleAdd("bob", "user", []string{"ssh-ed25519 AAAA bob"}); err != nil {
		t.Fatalf("people.add: %v", err)
	}
	if _, err := c.PeopleAdd("bob", "user", []string{"ssh-ed25519 AAAA bob"}); err != nil {
		t.Fatalf("people.add, again: %v", err)
	}
	got := seen()
	if len(got) == 0 || got[0] != "whoami" {
		t.Fatalf("the gateway saw %v: an application command went first, with no whoami before it (PROTOCOL §1.1: the version preflight comes before the first application operation)", got)
	}
	if n := r2cxCount(got, "whoami"); n != 1 {
		t.Errorf("the gateway saw %v: %d whoami on one connection, want the one preflight", got, n)
	}
}

func TestR2CX_F06_AGatewayThatFailsThePreflightGetsNoApplicationCommand(t *testing.T) {
	for _, c := range []struct{ name, whoami string }{
		{"refused as too new for it", `{"proto":1,"caps":[],"ok":false,"error":{"code":"E_PROTO_CLIENT_NEWER","message":"x"},"minProto":1}` + "\n"},
		{"answers in another protocol", `{"proto":2,"caps":[],"ok":true,"result":{}}` + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fg, seen := r2cxRecordingGateway(t, c.whoami)
			conn := dialFake(t, fg, fg.personKey)
			if _, err := conn.PeopleAdd("bob", "user", []string{"ssh-ed25519 AAAA bob"}); err == nil {
				t.Fatal("people.add succeeded on a gateway whose version preflight failed")
			}
			for _, cmd := range seen() {
				if cmd != "whoami" {
					t.Fatalf("the gateway saw %v: %q was sent after the preflight had failed", seen(), cmd)
				}
			}
		})
	}
}

// enrol, bootstrap and pairing carry exactly one command each and refuse
// whoami (PROTOCOL §1.1, §3.4): theirs goes first.
func TestR2CX_F06_TheOneCommandLoginsAreNotPreflighted(t *testing.T) {
	for _, login := range []string{"enrol", "bootstrap", "pairing"} {
		t.Run(login, func(t *testing.T) {
			fg, seen := r2cxRecordingGateway(t, r2cxWhoamiOK)
			c, err := Dial(Peer{Addr: fg.ln.Addr().String(), Fingerprint: fingerprintFor(t, fg.hostSigner.PublicKey())}, login, fg.personKey, 3*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { _ = c.Close() })
			_, _ = c.Exec("the-one-command", map[string]any{"proto": 1})
			if got := seen(); len(got) != 1 || got[0] != "the-one-command" {
				t.Fatalf("a %s login sent %v, want its one command alone", login, got)
			}
		})
	}
}

func r2cxCount(list []string, s string) int {
	n := 0
	for _, v := range list {
		if v == s {
			n++
		}
	}
	return n
}
