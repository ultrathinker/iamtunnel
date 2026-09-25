package gateway

import "testing"

// The canary: the grants.set-caps answer is parsed by a REAL client.
//
// On 21.09.2026 the maintainer pressed "Make it exec only" and got, in
// red: "result does not match the expected shape: json: unknown field
// "caps"". By then the gateway had already changed the grant -- the
// error happened while parsing the ANSWER, that is, the work was done
// and the person was told it had failed.
//
// The cause: admin.unmarshalResult parses strictly, an unknown field
// is an error. That is correct: a client silently swallowing an
// unknown field will keep working while drifting away from the
// gateway. The price is that the struct must repeat the answer in full
// -- and only two of its three fields were declared.
//
// The canary walks the real wire with the real client instead of
// comparing JSON against a rewritten sample: a rewritten sample is a
// second copy of the truth, and it drifts exactly the way the struct
// drifted. Add a field to the gateway's answer and forget the client
// -- it turns red right here.
func TestCanary_SetCapsAnswerParsesInTheRealClient(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// The fixture already granted alice -> vm1. Narrowing to exec.
	was, killed, err := root.GrantsSetCaps(f.person, f.machineID, "exec")
	if err != nil {
		t.Fatalf("grants.set-caps %s -> %s: %v", f.person, f.machineID, err)
	}
	if was != "shell" {
		t.Errorf("the previous mode = %q, want \"shell\" (the fixture grants the default)", was)
	}
	if killed != 0 {
		t.Errorf("sessions closed = %d, want 0: the fixture has no open terminals", killed)
	}

	// And back: the extension must parse too.
	was, _, err = root.GrantsSetCaps(f.person, f.machineID, "shell")
	if err != nil {
		t.Fatalf("grants.set-caps back to shell: %v", err)
	}
	if was != "exec" {
		t.Errorf("the previous mode = %q, want \"exec\" -- the first change did not stick", was)
	}

	// A repeat of the same mode: the gateway answers with the same shape
	// and touches nothing. A separate path in the code, a separate chance
	// to drift.
	was, killed, err = root.GrantsSetCaps(f.person, f.machineID, "shell")
	if err != nil {
		t.Fatalf("grants.set-caps to the same mode: %v", err)
	}
	if was != "shell" || killed != 0 {
		t.Errorf("the repeat of the same mode returned was=%q killed=%d, want shell and 0", was, killed)
	}
}
