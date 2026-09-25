package gateway

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// D-2a: renaming people and machines -- people.rename / machines.rename.
//
// Before these verbs, fixing a typo in a person's name or giving a
// machine a sensible label was only possible by deleting the record and
// recreating it -- and deletion takes grants, goals and keys along. people.rename changes the
// person's name and moves everything stored by name (grants, goals) in one
// record; open sessions of the old name are closed by the engine at
// re-issue -- by the revocation rules. machines.rename changes only the label:
// grants, goals and the journal refer to the immutable machine id, so
// the access engine is not touched at all. Journal rows under the old
// name are not rewritten -- the journal is honest about the past.

func TestD2a_PeopleRename(t *testing.T) {
	cmd, ok := commandTable["people.rename"]
	if !ok {
		t.Fatal("the gateway does not know people.rename: there is no way to fix a person's name " +
			"other than deleting the record together with its grants, goals and keys, " +
			"yet the CLI, the window, SPEC §7.2 and PROTOCOL §6 all promise this command")
	}
	if !cmd.adminOnly {
		t.Fatal("people.rename is not adminOnly: whoever dials in could change their own name")
	}

	f := newFixture(t, nil)
	vm2Key := genSigner(t)
	key := authorizedLine(vm2Key.PublicKey())
	hk := authorizedLine(f.sshd.signer.PublicKey())
	user := `MACHINE\svc`
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "bob", Role: "user"})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm2", Name: "ubu-box", State: "verified",
			MachineKey: key, SSHDHostKey: &hk,
			OSUser: user, RequestedOSUser: user, VerifiedOSUser: &user,
			OSUserStatus: state.OSUserStatusVerified,
		})
		_, err := st.SetGoal(f.person, f.machineID, "reinstalling the site", f.clock.Now())
		return err
	}); err != nil {
		t.Fatalf("seed bob/goal: %v", err)
	}

	type renameResponse struct {
		From               string `json:"from"`
		To                 string `json:"to"`
		TerminatedSessions int    `json:"terminatedSessions"`
	}
	rename := func(from, to string) (renameResponse, *cmdError) {
		body, err := json.Marshal(map[string]any{"proto": 1, "from": from, "to": to})
		if err != nil {
			t.Fatalf("marshal people.rename body: %v", err)
		}
		res, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body)
		if cerr != nil {
			return renameResponse{}, cerr
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal people.rename result: %v", err)
		}
		var out renameResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("people.rename result does not decode as its documented shape: %v", err)
		}
		return out, nil
	}
	engineHas := func(person string) bool {
		return len(f.gw.aclE.GrantsFor(person, f.clock.Now())) > 0
	}

	t.Run("rename moves the person, the grants and the goal in one piece", func(t *testing.T) {
		res, cerr := rename("alice", "alicia")
		if cerr != nil {
			t.Fatalf("people.rename alice->alicia: %v", cerr)
		}
		if res.From != "alice" || res.To != "alicia" {
			t.Fatalf("people.rename answered %q -> %q, want alice -> alicia", res.From, res.To)
		}
		if res.TerminatedSessions != 0 {
			t.Fatalf("terminatedSessions=%d with no live sessions -- news of extra tear-downs", res.TerminatedSessions)
		}
		st := f.store.Get()
		if !st.HasPerson("alicia") || st.HasPerson("alice") {
			t.Fatal("the person did not move in state: alicia must exist, alice must not")
		}
		found := false
		for _, g := range st.Grants {
			if g.Person == "alicia" && g.Machine == f.machineID {
				found = true
			}
			if g.Person == "alice" {
				t.Fatalf("a grant of the old name alice remains in state -> %s", g.Machine)
			}
		}
		if !found {
			t.Fatal("the grant did not move to alicia -- the rename took the access away")
		}
		goal, ok := st.GoalFor("alicia", f.machineID)
		if !ok || goal.Current != "reinstalling the site" {
			t.Fatalf("the goal did not move to alicia: %+v (found=%v)", goal, ok)
		}
		if !engineHas("alicia") {
			t.Fatal("no live alicia grant in the access engine -- the engine was not re-issued")
		}
		if engineHas("alice") {
			t.Fatal("a live grant of the old name alice remains in the engine")
		}
	})

	t.Run("rename to a taken name is E_CONFLICT", func(t *testing.T) {
		if _, cerr := rename("alicia", "bob"); cerr == nil || cerr.code != "E_CONFLICT" {
			t.Fatalf("people.rename onto a taken name: %v, want E_CONFLICT", cerr)
		}
	})

	t.Run("rename to a reserved name is E_PERSON_NAME_RESERVED", func(t *testing.T) {
		if _, cerr := rename("alicia", "enrol"); cerr == nil || cerr.code != "E_PERSON_NAME_RESERVED" {
			t.Fatalf("people.rename onto a reserved name: %v, want E_PERSON_NAME_RESERVED", cerr)
		}
	})

	t.Run("rename of an unknown person is E_NOT_FOUND", func(t *testing.T) {
		if _, cerr := rename("nobody", "newname"); cerr == nil || cerr.code != "E_NOT_FOUND" {
			t.Fatalf("people.rename of an unknown person: %v, want E_NOT_FOUND", cerr)
		}
	})

	t.Run("a concurrent revoke in the publish gap cannot resurrect the renamed grant", func(t *testing.T) {
		var parked int32
		entered := make(chan struct{})
		proceed := make(chan struct{})
		accessPublishPause = func() {
			if atomic.CompareAndSwapInt32(&parked, 0, 1) {
				close(entered)
				<-proceed
			}
		}
		defer func() { accessPublishPause = nil }()

		renDone := make(chan *cmdError, 1)
		go func() {
			_, cerr := rename("alicia", "dave")
			renDone <- cerr
		}()

		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("the rename never reached the seam between state and the engine -- the pause is in the wrong place")
		}

		rev, ok := commandTable["grants.revoke"]
		if !ok {
			t.Fatal("grants.revoke disappeared from the test")
		}
		revDone := make(chan *cmdError, 1)
		go func() {
			body, err := json.Marshal(map[string]any{"proto": 1, "person": "dave", "machine": f.machineID})
			if err != nil {
				revDone <- errf("E_JSON_INVALID", 3, "%v", err)
				return
			}
			_, cerr := rev.run(f.gw, "admin", f.clock.Now(), body)
			revDone <- cerr
		}()

		// Wait for the revocation BEFORE the pause closes. Without
		// serialization the revocation completes in full -- removing the dave
		// grant from state and not finding it in the engine -- and then the
		// rename's re-issue resurrects it after the revocation: that is the deterministic red.
		// With serialization the revocation waits on the mutex while the rename
		// is parked, so this is an honest timeout, not a wait for the result.
		var revRes *cmdError
		var revGot bool
		select {
		case revRes = <-revDone:
			revGot = true
		case <-time.After(2 * time.Second):
		}

		close(proceed)
		if cerr := <-renDone; cerr != nil {
			t.Fatalf("rename alicia->dave: %v", cerr)
		}
		if !revGot {
			revRes = <-revDone
		}
		if revRes != nil {
			t.Fatalf("grants.revoke during the rename pause: %v", revRes)
		}

		st := f.store.Get()
		for _, g := range st.Grants {
			if g.Person == "dave" || g.Person == "alicia" {
				t.Fatalf("a grant %s -> %s remains in state after the revocation", g.Person, g.Machine)
			}
		}
		if engineHas("dave") {
			t.Fatal("the engine holds a live dave grant: the revocation that went through during the pause between state and the engine resurrected after the rename re-issue")
		}
		if engineHas("alicia") {
			t.Fatal("a live grant of the intermediate name alicia remains in the engine")
		}
	})
}

func TestD2a_MachinesRename(t *testing.T) {
	cmd, ok := commandTable["machines.rename"]
	if !ok {
		t.Fatal("the gateway does not know machines.rename: there is no way to give a machine a sensible label " +
			"other than deleting the record together with its grants, " +
			"yet the CLI, the window, SPEC §7.2 and PROTOCOL §6 all promise this command")
	}
	if !cmd.adminOnly {
		t.Fatal("machines.rename is not adminOnly")
	}

	f := newFixture(t, nil)
	vm2Key := genSigner(t)
	key := authorizedLine(vm2Key.PublicKey())
	hk := authorizedLine(f.sshd.signer.PublicKey())
	user := `MACHINE\svc`
	if err := f.store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm2", Name: "ubu-box", State: "verified",
			MachineKey: key, SSHDHostKey: &hk,
			OSUser: user, RequestedOSUser: user, VerifiedOSUser: &user,
			OSUserStatus: state.OSUserStatusVerified,
		})
		return nil
	}); err != nil {
		t.Fatalf("seed vm2: %v", err)
	}

	type renameResponse struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	rename := func(id, name string) (renameResponse, *cmdError) {
		body, err := json.Marshal(map[string]any{"proto": 1, "id": id, "name": name})
		if err != nil {
			t.Fatalf("marshal machines.rename body: %v", err)
		}
		res, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body)
		if cerr != nil {
			return renameResponse{}, cerr
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal machines.rename result: %v", err)
		}
		var out renameResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("machines.rename result does not decode as its documented shape: %v", err)
		}
		return out, nil
	}

	t.Run("rename changes the label, not the identity", func(t *testing.T) {
		res, cerr := rename("vm1", "win-box")
		if cerr != nil {
			t.Fatalf("machines.rename vm1->win-box: %v", cerr)
		}
		if res.ID != "vm1" || res.Name != "win-box" {
			t.Fatalf("machines.rename answered %+v, want {vm1 win-box}", res)
		}
		st := f.store.Get()
		m, ok := st.MachineByID("vm1")
		if !ok || m.Name != "win-box" {
			t.Fatalf("machine vm1: name=%q (found=%v), want win-box under the immutable id", m.Name, ok)
		}
		grantAlive := false
		for _, g := range st.Grants {
			if g.Person == f.person && g.Machine == "vm1" {
				grantAlive = true
			}
		}
		if !grantAlive {
			t.Fatal("the grant vanished from state after the machine label rename")
		}
		if len(f.gw.aclE.GrantsFor(f.person, f.clock.Now())) == 0 {
			t.Fatal("the engine lost the grant after the machine label rename")
		}
	})

	t.Run("name collisions are E_CONFLICT", func(t *testing.T) {
		if _, cerr := rename("vm1", "ubu-box"); cerr == nil || cerr.code != "E_CONFLICT" {
			t.Fatalf("machines.rename onto a taken name: %v, want E_CONFLICT", cerr)
		}
		if _, cerr := rename("vm1", "vm2"); cerr == nil || cerr.code != "E_CONFLICT" {
			t.Fatalf("machines.rename onto another machine's id: %v, want E_CONFLICT", cerr)
		}
	})

	t.Run("bad or reserved name is E_JSON_INVALID", func(t *testing.T) {
		if _, cerr := rename("vm1", "WIN-BOX"); cerr == nil || cerr.code != "E_JSON_INVALID" {
			t.Fatalf("machines.rename with an invalid name: %v, want E_JSON_INVALID", cerr)
		}
		if _, cerr := rename("vm1", "enrol"); cerr == nil || cerr.code != "E_JSON_INVALID" {
			t.Fatalf("machines.rename onto a reserved name: %v, want E_JSON_INVALID", cerr)
		}
	})

	t.Run("unknown machine is E_NOT_FOUND", func(t *testing.T) {
		if _, cerr := rename("no-such-machine", "whatever"); cerr == nil || cerr.code != "E_NOT_FOUND" {
			t.Fatalf("machines.rename of an unknown machine: %v, want E_NOT_FOUND", cerr)
		}
	})
}
