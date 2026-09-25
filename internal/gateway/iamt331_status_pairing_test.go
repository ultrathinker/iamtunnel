package gateway

// IAMT-331: gateway.status said nothing about the pairing window. A
// window could be stopped, consumed by a successful pair, or replaced
// from the far side, and every other administrator's card kept drawing
// a live-looking PIN until its own timer ran out — the one end of the
// window's life no local timer can see. The status is where the gateway
// already tells everything else about itself; the window's state
// belongs there. The PIN does not: it travels once, in pairing.start's
// reply, and is not journaled or repeated anywhere.

import (
	"encoding/json"
	"testing"
	"time"
)

func iamt331StatusPairing(t *testing.T, f *fixture) (active bool, expires string, said bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"proto": 1})
	result, cerr := cmdGatewayStatus(f.gw, "root", f.clock.Now(), body)
	if cerr != nil {
		t.Fatalf("cmdGatewayStatus: %v", cerr)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal status result: %v", err)
	}
	var st struct {
		Pairing *struct {
			Active  bool   `json:"active"`
			Expires string `json:"expires"`
		} `json:"pairing"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if st.Pairing == nil {
		return false, "", false
	}
	return st.Pairing.Active, st.Pairing.Expires, true
}

func TestIAMT331_GatewayStatusCarriesItsPairingWindow(t *testing.T) {
	t.Run("no window is a stated no", func(t *testing.T) {
		f := newFixture(t, nil)
		addPerson(t, f, "root", "admin", genSigner(t))

		active, _, said := iamt331StatusPairing(t, f)
		if !said {
			t.Fatal("gateway.status does not say whether its pairing window is open — the far side of the window is invisible to every other administrator (IAMT-331)")
		}
		if active {
			t.Errorf("pairing.active = true with no window opened, want a stated no")
		}
	})

	t.Run("an open window is the stated yes, with its expiry", func(t *testing.T) {
		f := newFixture(t, nil)
		addPerson(t, f, "root", "admin", genSigner(t))
		ttl := time.Hour
		seedPairingWindow(t, f, "424242", ttl)
		want := f.clock.Now().Add(ttl)

		active, expires, said := iamt331StatusPairing(t, f)
		if !said || !active {
			t.Fatalf("pairing says active=%v (said=%v), want an open window — the gateway has one, and every other administrator's card is drawing a PIN that dies the moment this one is consumed", active, said)
		}
		got, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			t.Fatalf("pairing.expires = %q is not RFC3339: %v", expires, err)
		}
		if !got.Equal(want) {
			t.Errorf("pairing.expires = %s, want the window's own expiry %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}
