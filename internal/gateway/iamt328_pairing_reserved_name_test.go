package gateway

// iamt328_pairing_reserved_name_test.go — IAMT-323/IAMT-328:
//
//   "a person named `pairing` cannot be created (`E_PERSON_NAME_RESERVED`)" — the
//   second half of the §2.2 row for `pairing:win01` (PROTOCOL §2.2).
//
// The parser half of that row lives in
// internal/gateway/auth/iamt328_username_pairing_test.go: the grammar keeps
// accepting the bytes because the SSH layer intercepts them first. This
// file pins the gateway half: the person name "pairing" is in
// reservedPersonNames, so people.add refuses it as E_PERSON_NAME_RESERVED
// and no person named "pairing" can ever exist for a pairing-login's key
// lookup to find — the §2.2 promise that the login dies as an unknown key.
//
// IAMT-336 / 1.3 added a second half: the machine name "pairing" must
// also be refused when claimed by an enrol body. TestMachinesEnrolCodeIsArgumentless
// exercises that path (see the sub-test "enrol-body-refuses-pairing-name").

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestPeopleAddRefusesThePairingName(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	_, err := root.PeopleAdd("pairing", "admin", []string{pubKeyLine(t)})
	if err == nil {
		t.Fatal("people.add(\"pairing\"): want a refusal — the login is owned by the pairing role (§3.4)")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("people.add(\"pairing\"): error does not name the reservation: %v", err)
	}

	people, err := root.PeopleList()
	if err != nil {
		t.Fatalf("people.list: %v", err)
	}
	for _, p := range people {
		if p.Name == "pairing" {
			t.Fatalf("a refused people.add(\"pairing\") left a trace: %+v", people)
		}
	}
}

func TestMachinesEnrolCodeReservesTheLoginLiterals(t *testing.T) {
	// The reservation this file exists for (PROTOCOL §2.1) has moved
	// twice, and both moves were right.
	//
	// 1.3 took the name off `machines.enrol-code` entirely, so there was
	// no name parameter left to reserve and the check lived only at
	// redeem time. 1.4 gives the command a name again — but the
	// administrator's name for the registration, not the machine's own
	// hostname, which is the fact he could not have known. So the check
	// comes back HERE, where the person who typed the name is standing,
	// and stays at redeem time too: state.json is a file, and a
	// hand-edited entry must not be able to mint a login role.
	//
	// "pairing", "enrol", "bootstrap" and "machine" are all real SSH
	// usernames this gateway resolves to a ROLE (lookup.go). A machine
	// record under one of them would sit in the same namespace as a
	// login role.
	f := newFixture(t, func(cfg *Config) {
		cfg.PublicHost = "127.0.0.1"
		cfg.PublicPort = 2222
	})
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// An ordinary name works and yields a usable code.
	code, expires, err := root.MachinesInvite("office-pc")
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	if code == "" || expires == "" {
		t.Fatalf("machines.enrol-code returned empty fields: code=%q expires=%q", code, expires)
	}
	if _, perr := config.ParseEnrolCode(code); perr != nil {
		t.Fatalf("machines.enrol-code returned an unparseable code %q: %v", code, perr)
	}

	// Every login literal is refused at mint time, in front of the
	// administrator who typed it.
	for _, bad := range []string{"pairing", "enrol", "bootstrap", "machine"} {
		if _, _, err := root.MachinesInvite(bad); err == nil {
			t.Errorf("machines.enrol-code accepted the reserved login name %q", bad)
		}
	}
	// And so is a name the grammar refuses.
	if _, _, err := root.MachinesInvite("Pc-Dana"); err == nil {
		t.Error("machines.enrol-code accepted a name with capitals")
	}

	// Defence in depth: an invitation that somehow carries a reserved
	// name — written straight into state.json, past the mint check —
	// is still refused when it is redeemed.
	t.Run("redeeming-a-reserved-name-is-refused", func(t *testing.T) {
		const secret = "test-enrol-secret-pairing-name"
		eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("derive ephemeral: %v", err)
		}
		ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))

		stErr := f.store.Update(func(st *state.State) error {
			st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
				Name:       "pairing",
				SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
				PublicKey:  ephPub,
				Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
			})
			return nil
		})
		if stErr != nil {
			t.Fatalf("update state with PendingEnrolment: %v", stErr)
		}

		pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, pubLine)
		if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
			t.Fatalf("enrol claiming reserved name \"pairing\": want E_ENROL_SECRET_INVALID, got %q", resp)
		}
	})
}

// doEnrolViaWire is the test-side counterpart of iamt135's removed
// helper. It opens one SSH session as "enrol" with the HKDF-derived
// signer, runs the "enrol" exec with the exact body shape runEnrol
// decodes (enrol_role.go's enrolRequest), and returns the JSON
// response line. Used by TestMachinesEnrolCodeReservesTheLoginLiterals to
// exercise runEnrolFromPending without going through the e2e
// package's fixtures.
//
// If the SSH handshake itself refuses the ephemeral key (the secret
// was already consumed and the entry is gone from the registry), the
// function returns an empty string rather than failing the calling
// test — many IAMT-336 scenarios, notably single-use enforcement,
// intentionally drive exactly this handshake refusal and need to
// observe "no second machine" without a hard failure here.
func doEnrolViaWire(t *testing.T, f *fixture, eph ssh.Signer, secret, machine, osUser, machineKey string) string {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "enrol",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(eph)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		// The handshake refused the ephemeral key — the secret is
		// already consumed. This is itself a valid "no second
		// machine" signal for the single-use and other tests.
		return ""
	}
	defer conn.Close()
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("enrol session: %v", err)
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
	}{"enrol"}))
	if err != nil || !ok {
		t.Fatalf("enrol exec request: ok=%v err=%v", ok, err)
	}
	body, _ := json.Marshal(map[string]any{
		"proto":      1,
		"secret":     secret,
		"machine":    machine,
		"osUser":     osUser,
		"machineKey": machineKey,
	})
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write enrol body: %v", err)
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
