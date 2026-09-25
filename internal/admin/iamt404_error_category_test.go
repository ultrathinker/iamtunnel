package admin

// IAMT-404 canary: the client keeps the risk.key reply's failure
// category from the §1.2 error envelope onto the CommandError it hands
// its callers. Without it the category dies at the decode boundary and
// the window has nothing machine-readable to read — the exact state
// IAMT-404 was filed against.

import (
	"strings"
	"testing"
)

func TestIAMT404_TheClientKeepsTheReplyCategory(t *testing.T) {
	t.Run("an envelope that names the category keeps it", func(t *testing.T) {
		line := `{"proto":1,"caps":[],"ok":false,"error":{"code":"E_RISK_KEY_REJECTED","message":"new key rejected by the classifier service (HTTP 401; key invalid or expired)","category":"rejected"}}`
		_, err := decodeResponse(strings.NewReader(line))
		ce, ok := err.(*CommandError)
		if !ok {
			t.Fatalf("decode = %v, want a CommandError", err)
		}
		if ce.Category != "rejected" {
			t.Fatalf("the decoded CommandError carries category %q, want %q — the wire's machine-readable class is dropped at the client boundary (IAMT-404)", ce.Category, "rejected")
		}
	})
	t.Run("an envelope without one still decodes, empty", func(t *testing.T) {
		line := `{"proto":1,"caps":[],"ok":false,"error":{"code":"E_RISK_KEY_REJECTED","message":"classifier service unavailable while probing the new key (HTTP 503)"}}`
		_, err := decodeResponse(strings.NewReader(line))
		ce, ok := err.(*CommandError)
		if !ok {
			t.Fatalf("decode = %v, want a CommandError", err)
		}
		if ce.Category != "" {
			t.Fatalf("an error body without a category decoded as %q, want empty", ce.Category)
		}
	})
}
