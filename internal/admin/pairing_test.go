package admin

// pairing_test.go: the client half of the PIN-pairing commands (IAMT-323/
// IAMT-326) against the same fakeGateway double the other commands use.
// What only the client can prove: the exact request each wrapper puts on the
// wire (PROTOCOL §6 field names, proto:1), the response shapes it decodes,
// and that a named pairing refusal comes back as a *CommandError a CLI can
// branch on. The gateway's own behaviour of these commands is the gateway
// package's business (pairing_role_test.go there).

import (
	"encoding/json"
	"testing"
)

// TestPairing_CommandsRequestShapeAndResponseDecoding pins the wire contract
// of all three pairing wrappers in one table: what each sends, what it
// accepts back.
func TestPairing_CommandsRequestShapeAndResponseDecoding(t *testing.T) {
	personKey := genSigner(t)

	t.Run("pairing.start", func(t *testing.T) {
		var gotReq map[string]any
		fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
			if command != "pairing.start" {
				return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_EXEC_UNKNOWN","message":"x"}}` + "\n")
			}
			_ = json.Unmarshal(body, &gotReq)
			return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"pin":"012345","expires":"2026-09-12T10:02:00Z","ref":"gw.test:2222#SHA256-abc"}}` + "\n")
		})
		c := dialFake(t, fg, personKey)
		start, err := c.PairingStart()
		if err != nil {
			t.Fatalf("pairing.start: %v", err)
		}
		if start.Pin != "012345" || start.Expires != "2026-09-12T10:02:00Z" {
			t.Fatalf("pairing.start result = %+v, want pin 012345 and the expiry it carried", start)
		}
		if gotReq["proto"] != float64(1) {
			t.Fatalf("pairing.start request was %+v, want proto:1 and nothing else mandatory", gotReq)
		}
		if len(gotReq) != 1 {
			t.Fatalf("pairing.start request carried extra fields: %+v", gotReq)
		}
	})

	t.Run("pairing.stop", func(t *testing.T) {
		var gotReq map[string]any
		fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
			if command != "pairing.stop" {
				return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_EXEC_UNKNOWN","message":"x"}}` + "\n")
			}
			_ = json.Unmarshal(body, &gotReq)
			return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"stopped":true}}` + "\n")
		})
		c := dialFake(t, fg, personKey)
		stopped, err := c.PairingStop()
		if err != nil {
			t.Fatalf("pairing.stop: %v", err)
		}
		if !stopped {
			t.Fatalf("pairing.stop decoded stopped=false, want true")
		}
		if gotReq["proto"] != float64(1) || len(gotReq) != 1 {
			t.Fatalf("pairing.stop request was %+v, want exactly proto:1", gotReq)
		}
	})

	t.Run("admin.pair", func(t *testing.T) {
		var gotReq map[string]any
		const pin = "654321"
		const pub = "ssh-ed25519 AAAAc3bzaC1lZDI1NTE1 new-admin"
		fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
			if command != "admin.pair" {
				return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_EXEC_UNKNOWN","message":"x"}}` + "\n")
			}
			_ = json.Unmarshal(body, &gotReq)
			return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"person":"fp-1234","role":"admin"}}` + "\n")
		})
		c := dialFake(t, fg, personKey)
		res, err := c.PairClaim(pin, pub)
		if err != nil {
			t.Fatalf("admin.pair: %v", err)
		}
		if res.Person != "fp-1234" || res.Role != "admin" {
			t.Fatalf("admin.pair result = %+v, want person fp-1234 role admin", res)
		}
		if gotReq["proto"] != float64(1) || gotReq["pin"] != pin || gotReq["pubkey"] != pub {
			t.Fatalf("admin.pair request was %+v, want proto:1, the PIN and the pubkey line", gotReq)
		}
		if len(gotReq) != 3 {
			t.Fatalf("admin.pair request carried extra fields: %+v", gotReq)
		}
	})
}

// TestPairing_MalformedResultIsACleanError: an honest envelope whose result
// has the wrong shape (a numeric PIN, a string where a bool belongs, an
// unknown field) must come back as an error, never a panic or a half-filled
// struct - the same strict-shape guarantee unmarshalResult gives every other
// command, here for the pairing decoders. A result that is shape-valid but
// semantically empty (a missing person field) is a different matter: the
// package's contract is shape strictness, the same one admin.claim's
// identical result type already ships with.
func TestPairing_MalformedResultIsACleanError(t *testing.T) {
	personKey := genSigner(t)
	cases := []struct {
		name    string
		command string
		raw     string
		run     func(c *Conn) error
	}{
		{
			name:    "pairing.start result pin is a number",
			command: "pairing.start",
			raw:     `{"proto":1,"caps":[],"ok":true,"result":{"pin":123456}}`,
			run: func(c *Conn) error {
				_, err := c.PairingStart()
				return err
			},
		},
		{
			name:    "pairing.stop result stopped is a string",
			command: "pairing.stop",
			raw:     `{"proto":1,"caps":[],"ok":true,"result":{"stopped":"yes"}}`,
			run: func(c *Conn) error {
				_, err := c.PairingStop()
				return err
			},
		},
		{
			name:    "admin.pair result carries an unknown field",
			command: "admin.pair",
			raw:     `{"proto":1,"caps":[],"ok":true,"result":{"person":"fp-1","role":"admin","token":"surprise"}}`,
			run: func(c *Conn) error {
				_, err := c.PairClaim("123456", "ssh-ed25519 AAAA x")
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
				if command != tc.command {
					t.Fatalf("client sent %q, want %q", command, tc.command)
				}
				return []byte(tc.raw + "\n")
			})
			c := dialFake(t, fg, personKey)
			if err := tc.run(c); err == nil {
				t.Fatalf("malformed result decoded without an error: %s", tc.raw)
			}
		})
	}
}

// TestPairing_NamedRefusalSurfacesAsCommandError: the gateway's typed pairing
// refusals must reach the CLI as a *CommandError carrying the wire code, so
// cmd/iamtunnel can print the right hint without string matching.
func TestPairing_NamedRefusalSurfacesAsCommandError(t *testing.T) {
	personKey := genSigner(t)
	cases := []struct {
		name    string
		code    string
		command string
		run     func(c *Conn) error
	}{
		{"wrong pin", "E_PAIRING_PIN_INVALID", "admin.pair", func(c *Conn) error {
			_, err := c.PairClaim("000000", "ssh-ed25519 AAAA x")
			return err
		}},
		{"locked out", "E_PAIRING_LOCKED", "admin.pair", func(c *Conn) error {
			_, err := c.PairClaim("000000", "ssh-ed25519 AAAA x")
			return err
		}},
		{"no window", "E_PAIRING_INACTIVE", "pairing.start", func(c *Conn) error {
			_, err := c.PairingStart()
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
				if command != tc.command {
					t.Fatalf("client sent %q, want %q", command, tc.command)
				}
				return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"` + tc.code + `","message":"pairing refused"}}` + "\n")
			})
			c := dialFake(t, fg, personKey)
			err := tc.run(c)
			if err == nil {
				t.Fatalf("%s decoded as success, want a refusal", tc.code)
			}
			ce, ok := err.(*CommandError)
			if !ok {
				t.Fatalf("error is not a *CommandError: %v (%T)", err, err)
			}
			if ce.Code != tc.code {
				t.Fatalf("command error code = %q, want %q", ce.Code, tc.code)
			}
		})
	}
}
