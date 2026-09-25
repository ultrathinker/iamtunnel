package gateway

// admin_scenarios_test.go covers the acceptance gates that are the admin
// role's own responsibility, end to end: a real *admin.Conn (the admin
// client package) dials the real Gateway of this package's
// own harness_test.go fixture over a real TCP+SSH connection and issues
// real exec commands. Each test's comment names its gate; the gates not
// reachable from this role are gate 4 and the CLI half of gate 6/7.

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func addPerson(t *testing.T, f *fixture, name, role string, key ssh.Signer) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: name, Role: role,
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, key.PublicKey()), Pub: authorizedLine(key.PublicKey()), Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add person %s: %v", name, err)
	}
}

func gatewayFingerprint(f *fixture) string {
	return auth.Fingerprint(f.gw.cfg.HostKey.PublicKey())
}

func dialAdmin(t *testing.T, f *fixture, person string, key ssh.Signer) *admin.Conn {
	t.Helper()
	conn, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprint(f)}, person, key, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial as %s: %v", person, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// ---- gate 1: a non-admin cannot run a single admin command, in any group ---

func TestAdmin_NonAdminCannotRunAnyAdminCommand(t *testing.T) {
	f := newFixture(t, nil)
	// f.person ("alice") is seeded by the fixture with role "user".
	c := dialAdmin(t, f, f.person, f.personKey)

	calls := map[string]func() error{
		"people.list":     func() error { _, err := c.PeopleList(); return err },
		"people.add":      func() error { _, err := c.PeopleAdd("newbie", "user", []string{pubKeyLine(t)}); return err },
		"machines.list":   func() error { _, _, err := c.MachinesList(); return err },
		"machines.remove": func() error { return c.MachinesRemove(f.machineID) },
		"machines.rekey": func() error {
			_, _, err := c.MachinesRekey(f.machineID, fingerprintOf(t, genSigner(t).PublicKey()))
			return err
		},
		"grants.grant":        func() error { _, err := c.GrantsGrant(f.person, f.machineID, futureRFC3339(f)); return err },
		"grants.revoke":       func() error { _, err := c.GrantsRevoke(f.person, f.machineID); return err },
		"grants.list":         func() error { _, err := c.GrantsList("", ""); return err },
		"sessions.active":     func() error { _, err := c.SessionsActive(); return err },
		"sessions.kill":       func() error { return c.SessionsKill("session:1", "") },
		"recordings.list":     func() error { _, err := c.RecordingsList("", "", ""); return err },
		"gateway.fingerprint": func() error { _, err := c.GatewayFingerprint(); return err },
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: a non-admin person succeeded; want a refusal", name)
		}
	}

	// The connection itself, and whoami specifically, must still work -
	// otherwise a failing test above could just mean "the wire is down",
	// not "admin commands are refused".
	who, err := c.Whoami()
	if err != nil {
		t.Fatalf("whoami (open to any role) failed: %v", err)
	}
	if who.Role != "user" {
		t.Fatalf("whoami role = %q, want %q", who.Role, "user")
	}
}

// ---- gate 2: a grant actually lets a person in; none blocks them ----------

func TestAdmin_GrantActuallyControlsAccess(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	carolKey := genSigner(t)
	addPerson(t, f, "carol", "user", carolKey)
	root := dialAdmin(t, f, "root", rootKey)

	// Before any grant: carol is denied exactly like scenario 3.
	client, err := dialHuman(t, f.addr, "carol", f.machineID, carolKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	line := readAll(t, ch, 2*time.Second)
	if !strings.Contains(line, "Access to this machine is currently unavailable") {
		t.Fatalf("carol without a grant: want the generic denial, got %q", line)
	}
	_ = client.Close()

	if _, err := root.GrantsGrant("carol", f.machineID, futureRFC3339(f), "shell"); err != nil {
		t.Fatalf("grants.grant: %v", err)
	}

	client2, err := dialHuman(t, f.addr, "carol", f.machineID, carolKey)
	if err != nil {
		t.Fatalf("dial after grant: %v", err)
	}
	defer client2.Close()
	hs := openHumanSession(t, client2, f)
	hs.shell(t)
	const marker = "hello-after-grant"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("carol with a grant: echo missing marker, got %q", got)
	}

	list, err := root.GrantsList("carol", "")
	if err != nil {
		t.Fatalf("grants.list: %v", err)
	}
	if len(list) != 1 || list[0].Machine != f.machineID {
		t.Fatalf("grants.list after grant = %+v, want one grant for %s", list, f.machineID)
	}
}

// ---- gate 3: revoke kills the live session immediately, not just future ones

func TestAdmin_RevokeKillsLiveSessionImmediately(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "session did not become active before revoke", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	killed, err := root.GrantsRevoke(f.person, f.machineID)
	if err != nil {
		t.Fatalf("grants.revoke: %v", err)
	}
	if killed != 1 {
		t.Fatalf("grants.revoke terminatedSessions = %d, want 1", killed)
	}

	text := readAll(t, hs.ch, 2*time.Second)
	if !strings.Contains(text, "grant was revoked") && !strings.Contains(text, "grant expired") {
		t.Fatalf("human was not told the session ended by revoke, got %q", text)
	}
	waitUntil(t, "door did not close after revoke ended the only session", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	// A second revoke of the same, now-gone grant is a clean "not found",
	// never a crash and never a silent success.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err == nil {
		t.Fatal("second revoke of an already-revoked grant: want an error, got success")
	}
}

// ---- gate 3 (sessions.kill path): admin can end one session by id --------

func TestAdmin_SessionsKillEndsTheNamedSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	active, err := root.SessionsActive()
	if err != nil {
		t.Fatalf("sessions.active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("sessions.active = %+v, want exactly one live session", active)
	}
	if err := root.SessionsKill(active[0].ID, "admin test"); err != nil {
		t.Fatalf("sessions.kill: %v", err)
	}

	text := readAll(t, hs.ch, 2*time.Second)
	// IAMT-440: the line is the kill's own; this check used to accept the
	// revoke's text, which was the defect.
	if !strings.Contains(text, "an administrator ended this session") {
		t.Fatalf("human was not disconnected by sessions.kill, got %q", text)
	}
	// The grant itself is untouched: sessions.kill ends one session, it is
	// not a revoke - a fresh dial must still be allowed in.
	waitUntil(t, "door did not close after sessions.kill ended the only session", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	client2, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial after sessions.kill: %v", err)
	}
	defer client2.Close()
	hs2 := openHumanSession(t, client2, f)
	hs2.shell(t)
}

// ---- gate 5: a recording is never handed to an unauthorized caller -------

func TestAdmin_RecordingNotGivenToUnauthorizedPerson(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)
	mallory := genSigner(t)
	addPerson(t, f, "mallory", "user", mallory)
	nonAdmin := dialAdmin(t, f, "mallory", mallory)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	const marker = "hello-recorded-for-admin-fetch"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = readUntil(t, hs.ch, marker)
	_ = hs.ch.Close()
	waitUntil(t, "session did not close on the machine side", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	waitForTranscript(t, f.recordingsDir())

	// A non-admin cannot even list, let alone fetch.
	if _, err := nonAdmin.RecordingsList("", "", ""); err == nil {
		t.Fatal("recordings.list: a non-admin person succeeded; want a refusal")
	}

	// waitForTranscript only guarantees the .txt file landed; .meta.json
	// (what recordings.list scans for) is written a moment later by the
	// same finalize() call, so poll rather than racing it.
	var list []admin.RecordingView
	waitUntil(t, "recordings.list never saw the finished recording", func() bool {
		var lerr error
		list, lerr = root.RecordingsList(f.machineID, "", "")
		return lerr == nil && len(list) == 1
	})

	// The decisive check: a non-admin must be refused even when asking for
	// the *real*, currently-existing recording id - not just a made-up one,
	// which could be rejected as "not found" for the wrong reason and hide
	// a missing authorization check entirely.
	if _, err := nonAdmin.RecordingsFetch(list[0].ID, "txt", 0, 4096); err == nil {
		t.Fatal("recordings.fetch: a non-admin person fetched a real recording; want a refusal")
	}
	if _, err := nonAdmin.RecordingsFetch("whatever-id", "txt", 0, 4096); err == nil {
		t.Fatal("recordings.fetch: a non-admin person succeeded on a bogus id; want a refusal")
	}

	chunk, err := root.RecordingsFetch(list[0].ID, "txt", 0, 1<<20)
	if err != nil {
		t.Fatalf("recordings.fetch as admin: %v", err)
	}
	data, derr := decodeBase64(chunk.Data)
	if derr != nil {
		t.Fatalf("recordings.fetch: response data does not decode as base64: %v", derr)
	}
	if !strings.Contains(string(data), marker) {
		t.Fatalf("fetched transcript missing marker, got %q", string(data))
	}

	// An unrelated id (a hash that was never issued) is a clean not-found,
	// not a path someone could walk to a different file.
	if _, err := root.RecordingsFetch("not-a-real-id", "txt", 0, 4096); err == nil {
		t.Fatal("recordings.fetch with a bogus id: want an error, got success")
	}
}

// ---- gate 7: an invalid value is always rejected, named, never defaulted -

func TestAdmin_InvalidValuesAreRejectedWithAClearMessage(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	if _, err := root.PeopleAdd("Not Valid Name", "user", []string{pubKeyLine(t)}); err == nil {
		t.Fatal("people.add with an invalid name: want a refusal")
	} else if !strings.Contains(err.Error(), "name") {
		t.Fatalf("people.add invalid name: error does not name the problem: %v", err)
	}

	if _, err := root.PeopleAdd("bobby", "superuser", []string{pubKeyLine(t)}); err == nil {
		t.Fatal("people.add with an invalid role: want a refusal")
	} else if !strings.Contains(err.Error(), "role") {
		t.Fatalf("people.add invalid role: error does not name the problem: %v", err)
	}

	if _, err := root.GrantsGrant(f.person, f.machineID, "not-a-time"); err == nil {
		t.Fatal("grants.grant with an unparsable until: want a refusal")
	}

	if _, err := root.GrantsGrant(f.person, f.machineID, f.clock.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("grants.grant with until in the past: want a refusal, not a silently-accepted grant")
	}

	// Confirm none of the rejected calls left a trace: people.list must
	// still show only the seeded person and root, and grants.list only
	// the fixture's own pre-seeded grant.
	people, err := root.PeopleList()
	if err != nil {
		t.Fatalf("people.list: %v", err)
	}
	for _, p := range people {
		if p.Name == "bobby" || strings.Contains(p.Name, "Not Valid") {
			t.Fatalf("a rejected people.add left a trace: %+v", people)
		}
	}
}

// ---- gate 8 (server side): garbage input never panics the connection ----

func TestAdmin_UnknownAndMalformedRequestsNeverPanicTheGateway(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)

	// Raw, hand-crafted exec calls: unknown command, unknown field, wrong
	// JSON type, truncated JSON, empty body. Each must come back as a
	// clean CommandError/transport error, and the connection must still
	// be usable afterwards for the next call - proof that nothing on the
	// gateway side panicked and took the goroutine's stack trace with it.
	c := dialAdmin(t, f, "root", rootKey)
	rawCalls := []struct {
		name string
		cmd  string
		body any
	}{
		{"unknown command", "people.nonexistent", map[string]any{"proto": 1}},
		{"unknown field", "people.list", map[string]any{"proto": 1, "bogusField": 123}},
		{"wrong type", "grants.grant", map[string]any{"proto": 1, "person": 42, "machine": f.machineID, "until": "x", "caps": []string{"shell"}}},
		{"missing proto", "whoami", map[string]any{}},
		{"empty object", "people.add", map[string]any{}},
	}
	for _, rc := range rawCalls {
		if _, err := c.Exec(rc.cmd, rc.body); err == nil {
			t.Errorf("%s: want an error, got success", rc.name)
		}
	}
	// The connection must still answer whoami after all of that.
	if _, err := c.Whoami(); err != nil {
		t.Fatalf("whoami after malformed requests: %v (gateway connection did not survive)", err)
	}
}

// ---- helpers --------------------------------------------------------------

func futureRFC3339(f *fixture) string {
	return f.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339)
}

func pubKeyLine(t *testing.T) string {
	t.Helper()
	return authorizedLine(genSigner(t).PublicKey())
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
