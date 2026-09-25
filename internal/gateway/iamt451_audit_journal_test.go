package gateway

// IAMT-451: appendEvent threw the journal's answer away -
// `_ = g.cfg.Log.Append(e)`. A journal that could not write (a full disk,
// a file gone read-only, a failed fsync, an event it refused) let grants,
// revocations and logins go through with nothing on record, and nothing
// anywhere said so: not the command, not gateway.status, not the service
// log. The journal is the product's one account of who did what; a
// gateway that goes on granting access while it cannot keep that account
// is granting access nobody will ever be able to check.

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func iamt451HasGrant(f *fixture, person, machine string) bool {
	for _, g := range f.store.Get().Grants {
		if g.Person == person && g.Machine == machine {
			return true
		}
	}
	return false
}

// iamt451BreakJournal closes the journal under the running gateway: from
// here every append fails, the way a full disk or a file gone read-only
// fails it.
func iamt451BreakJournal(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.log.Close(); err != nil {
		t.Fatalf("close the journal: %v", err)
	}
}

func TestIAMT451_ACommandIsNotCarriedOutWhileTheJournalCannotWrite(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	iamt451BreakJournal(t, f)
	// The login's own auth.success is the first write that fails.
	root := dialAdmin(t, f, "root", rootKey)

	_, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f))
	if iamt451HasGrant(f, "bob", f.machineID) {
		t.Fatalf("grants.grant was carried out while the audit journal could not write (err=%v): bob may enter %s and nothing records who allowed it", err, f.machineID)
	}
	var ce *admin.CommandError
	if !errors.As(err, &ce) || ce.Code != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("the refusal is %v, want E_AUDIT_UNAVAILABLE", err)
	}
}

func TestIAMT451_AChangeTheJournalDidNotRecordIsNotReportedAsDone(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)
	if _, err := root.Whoami(); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	// The journal breaks between the login and the command: nothing has
	// failed yet when the command starts, and its own record is the first
	// write that does.
	iamt451BreakJournal(t, f)

	_, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f))
	var ce *admin.CommandError
	if !errors.As(err, &ce) || ce.Code != "E_AUDIT_UNAVAILABLE" {
		t.Fatalf("grants.grant answered %v with its own journal entry lost, want E_AUDIT_UNAVAILABLE saying so", err)
	}
	if iamt451HasGrant(f, "bob", f.machineID) && !strings.Contains(ce.Message, "carried out") {
		t.Errorf("the grant is in force, but the refusal does not say the change was made: %q", ce.Message)
	}
}

func TestIAMT451_GatewayStatusSaysTheJournalIsNotWriting(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	iamt451BreakJournal(t, f)
	root := dialAdmin(t, f, "root", rootKey)

	raw, err := root.Exec("gateway.status", map[string]any{"proto": 1})
	var st struct {
		Audit *struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"audit"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	if err != nil || st.Audit == nil || st.Audit.OK || st.Audit.Error == "" {
		t.Fatalf("gateway.status does not say the audit journal is failing (err=%v, audit=%+v): an operator has nowhere to see it", err, st.Audit)
	}
}

func TestIAMT451_NoNewSessionWhileTheJournalCannotWrite(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	iamt451BreakJournal(t, f)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err == nil && ok {
		ok, err = hs.ch.SendRequest("shell", true, nil)
	}
	started := err == nil && ok
	mc, _ := f.gw.reg.get(f.machineID)
	snap := mc.doorMachine.Snapshot()
	if started || snap.Sessions != 0 || snap.Reservations != 0 {
		t.Fatalf("a session to %s was started while the audit journal could not record it (shell accepted=%v, sessions=%d, reservations=%d)", f.machineID, started, snap.Sessions, snap.Reservations)
	}
}

// readOnlyCommands are the commands that write nothing to the journal:
// what an operator needs to find out what is wrong, and nothing else.
var iamt451ReadOnlyCommands = map[string]bool{
	"whoami": true, "machines.mine": true, "people.list": true, "people.connection-string": true,
	"machines.list": true, "grants.list": true, "sessions.active": true, "sessions.history": true,
	"recordings.list": true, "gateway.status": true, "gateway.fingerprint": true,
	"goal.current": true, "goal.history": true, "goal.list": true, "risk.check": true, "risk.pending": true,
}

func TestIAMT451_EveryCommandThatWritesTheJournalIsRefusedWhileItCannot(t *testing.T) {
	f := newFixture(t, nil)
	addPerson(t, f, "root", "admin", genSigner(t))
	iamt451BreakJournal(t, f)
	f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "root", Object: "journal", Result: "probe:ok"})

	for _, name := range CommandNames() {
		_, cerr := f.gw.runCommand("root", name, []byte(`{"proto":1}`))
		refused := cerr != nil && cerr.code == "E_AUDIT_UNAVAILABLE"
		if iamt451ReadOnlyCommands[name] {
			if refused {
				t.Errorf("%s writes nothing to the journal and is what an operator needs meanwhile, but it was refused", name)
			}
			continue
		}
		if !refused {
			t.Errorf("%s ran while the audit journal could not write (answer: %v)", name, cerr)
		}
	}
}

func TestIAMT451_TheGatewayWritesItsAuditStateBesideItsData(t *testing.T) {
	f := newFixture(t, nil)
	iamt451BreakJournal(t, f)
	f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "root", Object: "journal", Result: "probe:ok"})

	var health struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
	}
	raw, err := state.ReadDataFile(filepath.Join(f.gw.cfg.DataDir, "audit-health.json"))
	if err == nil {
		err = json.Unmarshal(raw, &health)
	}
	if err != nil || health.OK == nil || *health.OK || health.Error == "" {
		t.Fatalf("the data directory does not say the audit journal is failing (err=%v, ok=%v): on the gateway's own machine `gateway status` and the Gateway tab have nothing to show", err, health.OK)
	}
}

// iamt451Lines is a Diagnostics writer the test can read while the
// gateway writes to it.
type iamt451Lines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *iamt451Lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *iamt451Lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// A journal that comes back takes the gateway back with it: the refusals
// stop at the first write that succeeds, and the service log says both
// when it stopped and when it came back, with what was lost in between.
func TestIAMT451_WhenTheJournalWritesAgainSoDoesTheGateway(t *testing.T) {
	diag := &iamt451Lines{}
	f := newFixture(t, func(c *Config) { c.Diagnostics = diag })
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))

	full := func(events.Event) error {
		return errors.New("write events.jsonl: there is not enough space on the disk")
	}
	f.gw.journalAppendFn.Store(&full)
	root := dialAdmin(t, f, "root", rootKey)
	if _, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f)); err == nil {
		t.Fatal("precondition: grants.grant ran while the journal could not write")
	}

	f.gw.journalAppendFn.Store(nil)
	f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "root", Object: "journal", Result: "probe:ok"})
	if _, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f)); err != nil {
		t.Fatalf("grants.grant is still refused after the journal wrote again: %v", err)
	}
	log := diag.String()
	if !strings.Contains(log, "NOT being written") || !strings.Contains(log, "not enough space on the disk") {
		t.Errorf("the service log does not say the journal stopped, and why:\n%s", log)
	}
	if !strings.Contains(log, "written again") {
		t.Errorf("the service log does not say the journal came back:\n%s", log)
	}
	h, found, err := ReadAuditHealth(f.gw.cfg.DataDir)
	if err != nil || !found || !h.OK || h.LostWrites == 0 {
		t.Errorf("the data directory's audit state after the recovery is %+v (found=%v, err=%v), want ok with the lost writes counted", h, found, err)
	}
}
