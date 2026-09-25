package admin

// R1-CX F-08, the administrator's half: every admin command - the CLI's
// and the window's alike - opened its channel with ssh.Conn.OpenChannel,
// which waits for the gateway's answer without any limit. Dial's timeout
// bounded the TCP connect and the handshake (IAMT-450) and nothing after.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

func TestR1CX_F08_AnAdminCommandGivesUpOnAGatewayThatNeverOpensTheChannel(t *testing.T) {
	peer := testsupport.NewSilentChannelPeer(t)
	// A second, not less: under -race and a loaded host the handshake
	// itself must fit, and the 5s bound below still catches a wait with
	// no limit.
	const timeout = time.Second
	conn, err := Dial(Peer{Addr: peer.Addr, Fingerprint: fingerprintFor(t, peer.HostKey.PublicKey())}, "alice", genSigner(t), timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := conn.Whoami()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("whoami succeeded against a gateway that never answers a channel open")
		}
		if !conn.Broken() {
			t.Error("the connection whose channel open went unanswered is not marked broken: the window would send its next command down it again")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("an admin command is still waiting for a gateway that never answers a channel open, 5s into a %v timeout", timeout)
	}
}
