package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// channel_rejection_codes_test.go pins the exact refusal code strings this
// machine sends to the gateway inside SSH_MSG_CHANNEL_OPEN_FAILURE. The
// pre-existing tests (TestServe_InitialPayloadRejected...,
// TestReviewFINDING_ChannelOpenWithInitialPayloadRejected,
// TestServe_DuplicateControlChannelRejectedFirstStaysAlive) only assert that
// OpenChannel failed — they stay green no matter what string the rejection
// carries, which is how "E_CHANNEL_INITIAL_PAYLOAD" and the phrase
// "unexpected channel type" survived next to PROTOCOL §6.1's
// E_TARGET_CHANNEL_INVALID. These subtests compare the code verbatim, so a
// renamed, mistyped or re-phrased refusal goes red here.
//
// The codes are protocol dictionary entries (PROTOCOL §6.1:
// "E_TARGET_CHANNEL_INVALID means a wrong name, initial payload, or
// direction for a machine channel-open"; §5.1: "the second [control
// channel] is rejected with channel failure
// E_CONTROL_CHANNEL_DUPLICATE"), not free text.
func TestChannelOpenRejectionsCarryProtocolCodes(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)
	sc := gw.wait(t)

	// The one legal control channel must be open before the duplicate branch
	// is reachable; the payload refusals below must not consume it.
	first, firstReqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err != nil {
		t.Fatalf("open the legal control channel: %v", err)
	}
	defer first.Close()
	go ssh.DiscardRequests(firstReqs)

	for _, tc := range []struct {
		name    string
		channel string
		payload []byte
		want    string
	}{
		{"control with initial payload", "iamtunnel-control", []byte("attacker-controlled-bytes"), "E_TARGET_CHANNEL_INVALID"},
		{"target with initial payload", "iamtunnel-target", []byte("attacker-controlled-bytes"), "E_TARGET_CHANNEL_INVALID"},
		{"unknown channel type", "iamtunnel-unknown", nil, "E_TARGET_CHANNEL_INVALID"},
		{"second control channel", "iamtunnel-control", nil, "E_CONTROL_CHANNEL_DUPLICATE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, _, err := sc.OpenChannel(tc.channel, tc.payload)
			if err == nil {
				_ = ch.Close()
				t.Fatalf("%s was accepted; want a rejection carrying %s", tc.channel, tc.want)
			}
			var oce *ssh.OpenChannelError
			if !errors.As(err, &oce) {
				t.Fatalf("rejection of %s is %T (%v), want *ssh.OpenChannelError", tc.channel, err, err)
			}
			if oce.Message != tc.want {
				t.Fatalf("rejection code = %q, want exactly %q per the PROTOCOL §6.1 dictionary", oce.Message, tc.want)
			}
		})
	}
}
