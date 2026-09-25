package gateway

// r4_f10_admin_op_details_test.go — R4 F-10.
//
// A successful admin operation was journalled without what it was about:
// "people.add backup ok" did not say backup became an administrator, nor
// with which key; people.keys.add/remove did not name the key; grants.grant
// did not say shell or exec; machines.enrol-code named no machine. The
// refusal lines carried those fields, the success lines did not - and
// "who made whom an admin, with which key" is exactly what the journal is
// read for afterwards.

import (
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func r4f10Op(t *testing.T, f *fixture, result string) events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin.op: %v", err)
	}
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Result == result {
			return evs[i]
		}
	}
	t.Fatalf("no admin.op with result %q in the journal", result)
	return events.Event{}
}

func r4f10Run(t *testing.T, f *fixture, verb string, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	if _, cerr := f.gw.runCommand("root", verb, raw); cerr != nil {
		t.Fatalf("%s: %v", verb, cerr)
	}
}

func TestR4F10_SuccessfulAdminOpsSayWhatTheyDid(t *testing.T) {
	f := newFixture(t, nil)
	addPerson(t, f, "root", "admin", genSigner(t))
	backupKey := authorizedLine(genSigner(t).PublicKey())
	backupFP, _ := state.ComputeFingerprint(backupKey)

	r4f10Run(t, f, "people.add", map[string]any{"proto": 1, "name": "backup", "role": "admin", "keys": []string{backupKey}})
	e := r4f10Op(t, f, "people.add:ok")
	if e.Details["role"] != "admin" {
		t.Fatalf("R4 F-10: people.add does not say backup became an admin: details=%v", e.Details)
	}
	if fps, _ := e.Details["fingerprints"].([]any); len(fps) != 1 || fps[0] != backupFP {
		t.Fatalf("people.add does not name backup's key: details=%v", e.Details)
	}

	extra := authorizedLine(genSigner(t).PublicKey())
	extraFP, _ := state.ComputeFingerprint(extra)
	r4f10Run(t, f, "people.keys.add", map[string]any{"proto": 1, "name": "backup", "pubkey": extra})
	if e := r4f10Op(t, f, "people.keys.add:ok"); e.Details["fingerprint"] != extraFP {
		t.Fatalf("people.keys.add does not name the key: details=%v", e.Details)
	}
	r4f10Run(t, f, "people.keys.remove", map[string]any{"proto": 1, "name": "backup", "fingerprint": extraFP})
	if e := r4f10Op(t, f, "people.keys.remove:ok"); e.Details["fingerprint"] != extraFP {
		t.Fatalf("people.keys.remove does not name the key: details=%v", e.Details)
	}

	r4f10Run(t, f, "grants.grant", map[string]any{"proto": 1, "person": "backup", "machine": f.machineID, "until": "", "caps": []string{"shell"}})
	if caps, _ := r4f10Op(t, f, "grants.grant:ok").Details["caps"].([]any); len(caps) != 1 || caps[0] != "shell" {
		t.Fatalf("grants.grant does not say shell or exec: caps=%v", caps)
	}

	r4f10Run(t, f, "machines.enrol-code", map[string]any{"proto": 1, "name": "web01"})
	e = r4f10Op(t, f, "machines.enrol-code:ok")
	if e.Object != "web01" || e.Details["expires"] == nil {
		t.Fatalf("machines.enrol-code does not name the machine and the expiry: object=%q details=%v", e.Object, e.Details)
	}
}
