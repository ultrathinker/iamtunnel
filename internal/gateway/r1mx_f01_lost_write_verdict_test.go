package gateway

// F-01 of the round-1 review (24.09.2026): runCommand took a
// snapshot of the GLOBAL lost-write counter before a command and compared
// it after. The counter moves for ANY journal write the gateway loses -
// another administrator's command, a session on another machine, a
// rejected login - so a command whose own record was written could be
// answered "carried out, but the audit journal could not record it". The
// verdict is about a record that exists, and the administrator reading it
// is told his change is nowhere on record.
//
// The two tests below are the two halves of the property the fix has to
// keep: a parallel administrator's failure is NOT this command's verdict
// (the finding), and this command's OWN lost record still IS (IAMT-451's
// contract, which the fix must not weaken).

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1MXF01_AnotherAdministratorsLostWriteIsNotThisCommandsVerdict(t *testing.T) {
	f := newFixture(t, nil)
	rootKey, otherKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "other", "admin", otherKey)
	addPerson(t, f, "bob", "user", genSigner(t))

	root := dialAdmin(t, f, "root", rootKey)
	other := dialAdmin(t, f, "other", otherKey)

	// Two administrators, two commands, one second - and the disk fills up
	// between them: the journal refuses the record OTHER's command writes,
	// while root's own record goes in as usual. The two seams below put
	// that failure exactly between root's snapshot and root's verdict, the
	// window F-01 is about, instead of leaving the interleaving to the
	// scheduler.
	//
	// root parks at the audit watch (afterAuditWatchFn, F-03 of the
	// round-2 review), which is after its snapshot and before its body -
	// and, since R2-CX F-10, before the accessPublishMu its state write
	// and its record are published under. That last part matters here:
	// other's machines.rename takes that mutex too, so a root parked
	// inside it would hold the other administrator's command out and the
	// two would never overlap. The window this test is about is the one
	// between the snapshot and the verdict, and that one is still open.
	var rootAtSeam, otherFailed = make(chan struct{}), make(chan struct{})
	var onceRoot, onceOther sync.Once
	var seamGaveUp atomic.Bool
	afterAuditWatchFn = func(person, command string) {
		if person != "root" || command != "grants.grant" {
			return
		}
		onceRoot.Do(func() { close(rootAtSeam) })
		select {
		case <-otherFailed:
		case <-time.After(10 * time.Second):
			// No hang: the test says what went wrong instead.
			seamGaveUp.Store(true)
		}
	}
	defer func() { afterAuditWatchFn = nil }()

	// Only the other administrator's own record is the seam's business: the
	// logins' auth.success lines are the journal's ordinary work, and one
	// of those failing would refuse a command before it ran - a different
	// situation from the one this test is about, and the two logins are
	// still in flight when the seam goes in.
	seam := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Actor == "other" {
			onceOther.Do(func() {
				<-rootAtSeam
				close(otherFailed)
			})
			return errors.New("write events.jsonl: there is not enough space on the disk")
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	var wg sync.WaitGroup
	var otherErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		otherErr = other.MachinesRename(f.machineID, "renamed-by-other")
	}()

	// root's own journal entry is written - the lost write is other's.
	if _, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f)); err != nil {
		t.Errorf("grants.grant was recorded in the journal, but it answered %v: the lost write was another administrator's, and the answer tells root that a grant he made is nowhere on record (F-01)", err)
	}
	wg.Wait()
	if seamGaveUp.Load() {
		t.Fatalf("the other administrator's command never wrote its own record (it answered %v), so the two commands never overlapped", otherErr)
	}
	var ce *admin.CommandError
	if !errors.As(otherErr, &ce) || ce.Code != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("the administrator whose own record was lost answered %v, want E_AUDIT_UNAVAILABLE", otherErr)
	}

	// What makes that verdict a lie: root's record really is in the
	// journal, and the journal is still able to write (one write was
	// refused, the disk is not broken).
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read the admin-op journal: %v", err)
	}
	recorded := false
	for _, e := range evs {
		if e.Actor == "root" && e.Result == "grants.grant:ok" && e.Object == "bob -> "+f.machineID {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("root's grant is not in the journal at all, so this test proves nothing: %+v", evs)
	}
}

func TestR1MXF01_ThisCommandsOwnLostRecordIsStillReported(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)
	if _, err := root.Whoami(); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	// The journal is fine when the command starts; the record this command
	// writes itself is the write that fails. The command's own record, not
	// every line with this actor: the login's auth.success may still be in
	// flight, and a journal already failing when the command starts is a
	// different answer (IAMT-451's refusal, not this one).
	full := func(e events.Event) error {
		if e.Type == events.EventAdminOp {
			return errors.New("write events.jsonl: there is not enough space on the disk")
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&full)
	defer f.gw.journalAppendFn.Store(nil)

	_, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f))
	var ce *admin.CommandError
	if !errors.As(err, &ce) || ce.Code != "E_AUDIT_UNAVAILABLE" {
		t.Fatalf("grants.grant answered %v with its own journal entry lost, want E_AUDIT_UNAVAILABLE", err)
	}
	if !strings.Contains(ce.Message, "carried out") {
		t.Errorf("the grant is in force, but the answer does not say the change was made: %q", ce.Message)
	}
}
