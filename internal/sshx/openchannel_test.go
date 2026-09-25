package sshx

// openchannel_test.go: OpenChannelWithDeadline (IAMT-450) does not wait
// on a silent peer past the deadline, and does not leave a channel on
// the other side that opened only after it stopped being waited for.

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestOpenChannelWithDeadline_GivesUpAndClosesALateChannel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(mustSigner(t))

	// The peer answers the channel-open only on release, and then
	// waits for the opening side to close the channel.
	release := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		sconn, chans, reqs, err := ssh.NewServerConn(raw, srvCfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		n, ok := <-chans
		if !ok {
			return
		}
		<-release
		ch, creqs, err := n.Accept()
		if err != nil {
			return
		}
		go ssh.DiscardRequests(creqs)
		_, _ = io.Copy(io.Discard, ch)
		close(closed)
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), insecureClientConfig("u"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	start := time.Now()
	_, _, err = OpenChannelWithDeadline(client, "late", start.Add(200*time.Millisecond), nil)
	if !errors.Is(err, ErrOpenChannelTimeout) {
		t.Fatalf("an unanswered open returned %v after %v, want ErrOpenChannelTimeout", err, time.Since(start))
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the channel the peer accepted after the deadline is still open: nobody on the opening side owns it")
	}
}
