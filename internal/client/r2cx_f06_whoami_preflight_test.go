package client_test

// R2-CX F-06, the person's side: machines.mine - the Client tab's list and
// "client machines" - is an application command like any admin one, and
// PROTOCOL §1.1 puts the whoami version preflight before the first of
// them on a command-login connection. It went first, alone.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func r2cxRecordingFake(t *testing.T, whoami []byte) (*fakeGateway, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	fg := newFakeGateway(t, func(command string, _ []byte) []byte {
		mu.Lock()
		seen = append(seen, command)
		mu.Unlock()
		if command == "whoami" {
			return whoami
		}
		return canonicalMachinesMineOK()
	})
	return fg, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestR2CX_F06_MachinesAsksWhoamiFirst(t *testing.T) {
	fg, seen := r2cxRecordingFake(t, []byte(`{"proto":1,"caps":[],"ok":true,"result":{"subject":"alice","role":"user","serverTime":"2026-09-12T10:00:00Z","person":"alice"}}`))
	if _, err := client.Machines(context.Background(), t.TempDir(), connToFake(fg, "alice"), testSigner(t), 3*time.Second); err != nil {
		t.Fatalf("Machines: %v", err)
	}
	if got := seen(); len(got) != 2 || got[0] != "whoami" || got[1] != "machines.mine" {
		t.Fatalf("the gateway saw %v, want [whoami machines.mine]: the version preflight comes before the first application command (PROTOCOL §1.1)", got)
	}
}

func TestR2CX_F06_MachinesStopsOnAFailedPreflight(t *testing.T) {
	for _, c := range []struct{ name, whoami string }{
		{"refused as too new for it", `{"proto":1,"caps":[],"ok":false,"error":{"code":"E_PROTO_CLIENT_NEWER","message":"x"},"minProto":1}`},
		{"answers in another protocol", `{"proto":2,"caps":[],"ok":true,"result":{}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			fg, seen := r2cxRecordingFake(t, []byte(c.whoami))
			if _, err := client.Machines(context.Background(), t.TempDir(), connToFake(fg, "alice"), testSigner(t), 3*time.Second); err == nil {
				t.Fatal("Machines succeeded against a gateway whose version preflight failed")
			}
			for _, cmd := range seen() {
				if cmd != "whoami" {
					t.Fatalf("the gateway saw %v: %q was sent after the preflight had failed", seen(), cmd)
				}
			}
		})
	}
}
