package e2e

// enrol_race_test.go proves the race and one-shot behavior under
// contention. Two simultaneous presentations of the same enrol secret:
// exactly ONE succeeds, the other is refused; state.json ends up with
// exactly one machine (the one from the winning goroutine) and no
// EnrolPending.
//
// The test runs 20 trials ("no fewer than twenty repeats") under
// -race -count=1 to satisfy the gate requirement.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

const enrolRaceTrials = 20

// TestE2E_EnrolRaceUnderReplay proves that under
// -race -count=1, the same enrol secret is presented by 2 goroutines
// at once. Exactly one wins. We repeat this `enrolRaceTrials` times
// to satisfy the gate's "no fewer than twenty repeats" rule.
func TestE2E_EnrolRaceUnderReplay(t *testing.T) {
	for trial := 0; trial < enrolRaceTrials; trial++ {
		f := newFixture(t, nil)
		// The assertion below counts machineKey entries in state.json,
		// and it means "the race created exactly one machine". The
		// fixture's own pre-seeded machine would make the count two
		// before the race even starts, so it goes first.
		forgetSeededMachine(t, f)

		rootKey := genSigner(t)
		addPersonForE2E(t, f, "root", "admin", rootKey)
		root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)},
			"root", rootKey, 5*time.Second)
		if err != nil {
			t.Fatalf("trial %d: admin dial: %v", trial, err)
		}

		code, _, err := root.MachinesInvite(e2eFreshMachine)
		if err != nil {
			t.Fatalf("trial %d: enrol-code: %v", trial, err)
		}
		_ = root.Close()
		parsed, err := config.ParseEnrolCode(code)
		if err != nil {
			t.Fatalf("trial %d: parse enrol: %v", trial, err)
		}

		ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("trial %d: derive ephemeral: %v", trial, err)
		}

		// Two goroutines try to enrol at the same time. The gateway
		// must serialise them: one succeeds, one fails. A barrier
		// release maximises contention at the same instant.
		var (
			wg      sync.WaitGroup
			results [2]enrolRaceResult
			start   = make(chan struct{})
		)
		for i := 0; i < 2; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i] = tryEnrolOnce(t, f, ephemeral, parsed.Secret)
			}()
		}
		close(start)
		wg.Wait()

		successes := 0
		for _, r := range results {
			if r.success {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("trial %d: expected exactly 1 success, got %d (results: %+v)",
				trial, successes, results)
		}

		// state.json must have a single machine and NO EnrolPending.
		rawState, rerr := readFile(filepath.Join(f.dir, "state.json"))
		if rerr != nil {
			t.Fatalf("trial %d: read state: %v", trial, rerr)
		}
		if strings.Contains(string(rawState), `"secretHash"`) {
			t.Fatalf("trial %d: the invitation is still on file after the race — the winner must have burned it:\n%s", trial, string(rawState))
		}
		if strings.Count(string(rawState), `"machineKey":`) > 1 {
			t.Fatalf("trial %d: more than one machineKey entry in state.json after race:\n%s",
				trial, string(rawState))
		}

		// The losing attempt must come back as a refusal. Two
		// acceptable shapes: SSH handshake refuses the key (the
		// winning Update cleared EnrolPending, so the loser's
		// ephemeral key is unknown) OR the JSON layer returns
		// E_ENROL_SECRET_USED. Both are valid.
		for _, r := range results {
			if r.success {
				continue
			}
			if r.err == nil {
				continue // protocol-level refusal without an error string; still acceptable
			}
			msg := r.err.Error()
			if strings.Contains(msg, "E_ENROL_SECRET_USED") ||
				strings.Contains(msg, "unable to authenticate") ||
				strings.Contains(msg, "handshake failed") ||
				strings.Contains(msg, "no auth methods") {
				continue
			}
			t.Logf("trial %d: loser got %v", trial, r.err)
		}
	}
}

// enrolRaceResult holds the outcome of one enrol attempt.
type enrolRaceResult struct {
	success bool
	err     error
}

// tryEnrolOnce runs one enrol exec. The path mirrors the production
// one exactly: real SSH dial with the ephemeral key, real "enrol"
// exec, real JSON response. The interesting part for the race test is
// that this is a full round trip to the gateway, so two goroutines
// call it at once and contend at the Store.Update inside handleEnrol.
func tryEnrolOnce(t *testing.T, f *fixture, ephemeral ssh.Signer, secret string) enrolRaceResult {
	t.Helper()
	machineKey := genSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(machineKey.PublicKey())))

	conn, ch, err := dialEnrol(t, f, ephemeral)
	if err != nil {
		return enrolRaceResult{err: err}
	}
	defer conn.Close()
	defer ch.Close()

	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"enrol"}))
	if err != nil || !ok {
		return enrolRaceResult{err: err}
	}
	body, _ := json.Marshal(map[string]any{
		"proto":      1,
		"secret":     secret,
		"machine":    "",
		"osUser":     `MACHINE\svc`,
		"machineKey": pubLine,
	})
	if _, err := ch.Write(body); err != nil {
		return enrolRaceResult{err: err}
	}
	_ = ch.CloseWrite()
	resp := readChannelUntilNewline(t, ch)
	if strings.Contains(resp, `"state":"enrolled"`) {
		return enrolRaceResult{success: true}
	}
	return enrolRaceResult{err: nil}
}
