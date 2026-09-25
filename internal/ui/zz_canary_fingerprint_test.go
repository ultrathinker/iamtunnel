//go:build windows || linux || darwin

package ui

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
)

// Canary: the fingerprint the client shows is THE SAME one the
// administrator sees.
//
// 21.09.2026. The Client -> Key tab showed the key itself and nothing
// else, while at the other end of the call the administrator looks at
// a fingerprint: on Admin -> People, on Set up, in the connection
// line. Two people on the phone had, on one side, 68 base64
// characters and, on the other, a "SHA256:..." -- with nothing to
// compare until somebody pasted the whole blob.
//
// The fingerprint is now on screen, and this canary checks the only
// thing that matters about it: it matches the gateway's count byte
// for byte. A second, home-grown parse of the same format is where
// the two halves of one product start to drift apart on what a key
// is.
func TestCanary_ClientFingerprintMatchesTheGateway(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))

	want := auth.Fingerprint(sshPub)
	got := publicKeyFingerprint(line)
	if got != want {
		t.Errorf("the client shows %q, the gateway counts %q -- nothing to compare over the phone", got, want)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("the fingerprint lacks the familiar prefix: %q", got)
	}

	// With a comment at the end of the line -- as in authorized_keys.
	if got := publicKeyFingerprint(strings.TrimSpace(line) + " alice@laptop"); got != want {
		t.Errorf("a comment in the line threw off the fingerprint: %q, want %q", got, want)
	}

	// Garbage yields emptiness, not a guess: a WRONG fingerprint is
	// worse than none, because its entire meaning is in the comparison.
	for _, bad := range []string{"", "   ", "not a key", "ssh-ed25519 !!!!"} {
		if got := publicKeyFingerprint(bad); got != "" {
			t.Errorf("publicKeyFingerprint(%q) = %q -- stay silent on an unparsed line", bad, got)
		}
	}
}
