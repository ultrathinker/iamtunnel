package admin

// IAMT-331: the client dropped gateway.status's pairing word on the
// floor — the field did not exist, so a window ended from the far side
// never reached the card that was drawing its PIN. The struct must
// carry the answer through, and an older gateway's silence must stay
// nil, not turn into a stated "no".

import (
	"strings"
	"testing"
)

func TestIAMT331_TheClientCarriesThePairingWord(t *testing.T) {
	line := `{"proto":1,"ok":true,"result":{"online":true,"pairing":{"active":true,"expires":"2026-09-24T12:02:00Z"}}}`
	raw, err := decodeResponse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	var st GatewayStatusResult
	if err := unmarshalResult(raw, &st); err != nil {
		t.Fatalf("unmarshalResult: %v", err)
	}
	if st.Pairing == nil {
		t.Fatal("the client dropped the gateway's pairing word: Pairing is nil while the reply carried one (IAMT-331)")
	}
	if !st.Pairing.Active {
		t.Errorf("Pairing.Active = false, want true")
	}
	if st.Pairing.Expires != "2026-09-24T12:02:00Z" {
		t.Errorf("Pairing.Expires = %q, want the window's own expiry verbatim", st.Pairing.Expires)
	}
}

func TestIAMT331_TheClientKeepsAnOlderGatewaySilence(t *testing.T) {
	line := `{"proto":1,"ok":true,"result":{"online":true}}`
	raw, err := decodeResponse(strings.NewReader(line))
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	var st GatewayStatusResult
	if err := unmarshalResult(raw, &st); err != nil {
		t.Fatalf("unmarshalResult: %v", err)
	}
	if st.Pairing != nil {
		t.Errorf("Pairing = %+v on a reply without the field, want nil — silence is not a stated no", *st.Pairing)
	}
}
