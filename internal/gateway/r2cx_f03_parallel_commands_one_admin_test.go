package gateway

// R2-CX F-03 of the round-2 review (24.09.2026), medium: the fix
// that made a command's verdict about its OWN lost record (R1-MX F-01,
// round 1) keyed that record by the person the command is run for - so
// two commands of ONE administrator running at the same time shared one
// counter. The first one's line is refused, the second one's line is in
// the journal and readable, and the second is answered "carried out, but
// the audit journal could not record it" anyway: a verdict about a record
// that exists, again, one level down. A script that retries on that
// answer repeats work that was recorded the first time.
//
// The record a command writes about itself is the one it names: logAdminOp
// writes "<op>:<result>" (people.add:ok), so the lost write says which
// command it belongs to, and the watch names the pair.

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR2CXF03_ALostWriteOfOneCommandIsNotAnotherOfTheSameAdmin(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)

	// One administrator, two channels, two commands at once - and the
	// journal refuses exactly one record: the one people.add writes about
	// itself. grants.grant's own record goes in as usual.
	//
	// The park is after grants.grant's watch is open and before it has
	// done anything, so its verdict is already looking at the counter
	// people.add is about to move (the seam F-03 asks for).
	var atWatch, addFailed = make(chan struct{}), make(chan struct{})
	var onceWatch, onceAdd sync.Once
	var seamGaveUp atomic.Bool
	afterAuditWatchFn = func(person, command string) {
		if person != "root" || command != "grants.grant" {
			return
		}
		onceWatch.Do(func() { close(atWatch) })
		select {
		case <-addFailed:
		case <-time.After(10 * time.Second):
			// No hang: the test says what went wrong instead.
			seamGaveUp.Store(true)
		}
	}
	defer func() { afterAuditWatchFn = nil }()

	seam := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "people.add:ok" {
			onceAdd.Do(func() {
				<-atWatch
				close(addFailed)
			})
			return errors.New("write events.jsonl: there is not enough space on the disk")
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	grantDone := make(chan error, 1)
	go func() {
		_, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f))
		grantDone <- err
	}()
	<-atWatch

	// While grants.grant is parked, the same administrator's other command
	// runs and loses its own record.
	_, addErr := root.PeopleAdd("carol", "user", []string{authorizedLine(genSigner(t).PublicKey())})
	var addCE *admin.CommandError
	if !errors.As(addErr, &addCE) || addCE.Code != "E_AUDIT_UNAVAILABLE" {
		t.Fatalf("people.add answered %v with its own record lost, want E_AUDIT_UNAVAILABLE (IAMT-451)", addErr)
	}

	grantErr := <-grantDone
	if seamGaveUp.Load() {
		t.Fatalf("people.add never reached the journal (it answered %v), so the two commands never overlapped", addErr)
	}
	if grantErr != nil {
		t.Errorf("grants.grant answered %v although its own record was written: the loss belonged to another command of the same administrator, and the answer says a grant that is on record is nowhere on record (F-03)", grantErr)
	}

	// What makes that verdict a lie: the grant's record really is in the
	// journal.
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
		t.Fatalf("the grant's own record is not in the journal at all, so this test proves nothing: %+v", evs)
	}
}
