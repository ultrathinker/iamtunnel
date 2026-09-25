package gateway

// R1-CX F-15 (review of 22-23.09): pairing, the bootstrap claim and
// the enrolment checked the audit journal only BEFORE the work --
// IAMT-451's refusal. The record the role writes at the end -- the
// pairing's admin.op, the claim's bootstrap:ok, the enrolment's
// enrol.verified -- could be the very write the journal lost, and the
// role still answered ok: the administrator, the key or the machine was
// left in force with the client told "ok" and nothing on record, a
// weaker guarantee than runCommand gives an ordinary admin command.
// runAuditedRole gives the three roles the same post-check.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// r1cxF15PairingLine drives the real pairing serve path: one SSH login as
// "pairing" (an open window admits the key), one admin.pair exec, one
// response line.
func r1cxF15PairingLine(t *testing.T, f *fixture, key ssh.Signer, body []byte) string {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "pairing",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pairing login: %v", err)
	}
	defer conn.Close()
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("pairing session: %v", err)
	}
	defer ch.Close()
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"admin.pair"}))
	if err != nil || !ok {
		t.Fatalf("admin.pair exec request: ok=%v err=%v", ok, err)
	}
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write admin.pair body: %v", err)
	}
	_ = ch.CloseWrite()
	buf := make([]byte, 8192)
	var acc strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, rerr := ch.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
			if strings.Contains(acc.String(), "\n") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	return acc.String()
}

func TestR1CX_F15_OneShotRolesAnswerForTheirOwnLostRecord(t *testing.T) {
	t.Run("pairing", func(t *testing.T) {
		f := newFixture(t, nil)
		hash := state.HashEnrolSecret(f.gw.enrolHMAC, []byte("111111"))
		if err := f.store.Update(func(st *state.State) error {
			st.PairingPending = &state.PairingPending{
				SecretHash: hash,
				Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
			}
			return nil
		}); err != nil {
			t.Fatalf("seed pairing window: %v", err)
		}
		newAdmin := genSigner(t)
		lost := func(e events.Event) error {
			if e.Type == events.EventAdminOp && e.Actor == "pairing" && e.Result == "admin.pair:ok" {
				return errors.New("write events.jsonl: there is not enough space on the disk")
			}
			return f.log.Append(e)
		}
		f.gw.journalAppendFn.Store(&lost)
		defer f.gw.journalAppendFn.Store(nil)

		body, err := json.Marshal(pairingRequest{
			Proto:  1,
			Pin:    "111111",
			Pubkey: authorizedLine(newAdmin.PublicKey()),
			Name:   "newadmin",
		})
		if err != nil {
			t.Fatalf("marshal admin.pair body: %v", err)
		}
		resp := r1cxF15PairingLine(t, f, genSigner(t), body)
		if !strings.Contains(resp, "E_AUDIT_UNAVAILABLE") {
			t.Fatalf("the pairing answered %q with its own journal record lost, want E_AUDIT_UNAVAILABLE", resp)
		}
		if !strings.Contains(resp, "carried out") {
			t.Errorf("the pairing is in force, but the answer does not say so: %q", resp)
		}
	})

	t.Run("bootstrap", func(t *testing.T) {
		f := newFixture(t, nil)
		const secret = "iamt-f15-bootstrap-secret"
		eph, err := config.DeriveEphemeralSigner(secret, config.BootstrapKeySalt)
		if err != nil {
			t.Fatalf("derive bootstrap signer: %v", err)
		}
		adminKey := genSigner(t)
		setIAMT143BootstrapPending(t, f, secret, authorizedLine(eph.PublicKey()))
		lost := func(e events.Event) error {
			if e.Type == events.EventAdminOp && e.Actor == "bootstrap" && e.Result == "bootstrap:ok" {
				return errors.New("write events.jsonl: there is not enough space on the disk")
			}
			return f.log.Append(e)
		}
		f.gw.journalAppendFn.Store(&lost)
		defer f.gw.journalAppendFn.Store(nil)

		res, status := iamt143Exec(t, f.addr, "bootstrap", eph, "admin.claim", bootstrapRequest{
			Proto: 1, Bootstrap: secret, Pubkey: authorizedLine(adminKey.PublicKey()),
		})
		if res.OK || res.Error == nil || res.Error.Code != "E_AUDIT_UNAVAILABLE" {
			t.Fatalf("the bootstrap claim answered %+v (exit %d) with its own journal record lost, want E_AUDIT_UNAVAILABLE", res, status)
		}
	})

	t.Run("enrol", func(t *testing.T) {
		f := newFixture(t, nil)
		const secret = "iamt-f15-enrol-secret"
		eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("derive enrol signer: %v", err)
		}
		ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))
		if err := f.store.Update(func(st *state.State) error {
			st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
				Name:       "f15-machine",
				SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
				PublicKey:  ephPub,
				Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
			})
			return nil
		}); err != nil {
			t.Fatalf("seed pending enrolment: %v", err)
		}
		lost := func(e events.Event) error {
			if e.Type == events.EventEnrolVerified {
				return errors.New("write events.jsonl: there is not enough space on the disk")
			}
			return f.log.Append(e)
		}
		f.gw.journalAppendFn.Store(&lost)
		defer f.gw.journalAppendFn.Store(nil)

		machineKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, machineKey)
		if !strings.Contains(resp, "E_AUDIT_UNAVAILABLE") {
			t.Fatalf("the enrolment answered %q with its own journal record lost, want E_AUDIT_UNAVAILABLE", resp)
		}
		if !strings.Contains(resp, "carried out") {
			t.Errorf("the enrolment is in force, but the answer does not say so: %q", resp)
		}
	})
}
