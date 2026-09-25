package client_test

// garbage_test.go: garbage from the gateway in response — long,
// truncated, with unknown fields, with foreign types — must never be a
// panic, only a clear refusal for each. Every case below feeds
// internal/client's Machines() a different kind of malformed gateway
// response through fakeGateway and asserts two things: it returns a
// named error (never a panic — go test itself would report a panic as
// a failure, so a green run here already proves that half), and the
// error text is not empty gibberish.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func assertGarbageIsRefusedCleanly(t *testing.T, name string, body []byte) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		fg := newFakeGateway(t, func(command string, request []byte) []byte {
			return body
		})
		cs := connToFake(fg, "alice")
		dir := t.TempDir()

		// The whole point: this call must return, not panic. testing.T
		// turns a panic into a failed (and stopped) test on its own, so
		// reaching the assertions below already is the main proof.
		_, err := client.Machines(context.Background(), dir, cs, testSigner(t), time.Second)
		if err == nil {
			t.Fatalf("garbage response accepted as valid: %q", body)
		}
		if strings.TrimSpace(err.Error()) == "" {
			t.Fatal("garbage response produced an empty error message")
		}
	})
}

func TestGarbageGatewayResponses(t *testing.T) {
	longMachines := bytes.Repeat([]byte(`{"id":"m","name":"m","until":"2026-01-01T00:00:00Z","online":true,"state":"verified","sshdListening":true,"doorOpen":false},`), 40000)
	long := append([]byte(`{"proto":1,"caps":[],"ok":true,"result":{"machines":[`), longMachines...)
	long = append(long, []byte(`{"id":"last","name":"last","until":"2026-01-01T00:00:00Z","online":true,"state":"verified","sshdListening":true,"doorOpen":false}]}}`)...)

	full := canonicalMachinesMineOKBytes()
	truncated := full[:len(full)/2]

	cases := []struct {
		name string
		body []byte
	}{
		{"too-long", long},
		{"truncated", truncated},
		{"unknown-field", []byte(`{"proto":1,"caps":[],"ok":true,"result":{"machines":[],"totallyUnknownField":123}}`)},
		{"wrong-type-until", []byte(`{"proto":1,"caps":[],"ok":true,"result":{"machines":[{"id":"m","name":"m","until":12345,"online":true,"state":"verified","sshdListening":true,"doorOpen":false}]}}`)},
		{"wrong-type-machines", []byte(`{"proto":1,"caps":[],"ok":true,"result":{"machines":"not-an-array"}}`)},
		{"not-json-at-all", []byte("\x00\x01binary garbage \xff\xfe not json")},
		{"empty-body", []byte("")},
		{"trailing-garbage-after-object", []byte(`{"proto":1,"caps":[],"ok":true,"result":{"machines":[]}}` + "\nEXTRA-TEXT-NOT-JSON")},
		{"missing-proto", []byte(`{"caps":[],"ok":true,"result":{"machines":[]}}`)},
		{"result-wrong-type-entirely", []byte(`{"proto":1,"caps":[],"ok":true,"result":"just a string, not an object"}`)},
	}
	for _, tc := range cases {
		assertGarbageIsRefusedCleanly(t, tc.name, tc.body)
	}
}

func canonicalMachinesMineOKBytes() []byte { return canonicalMachinesMineOK() }
