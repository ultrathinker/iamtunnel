package client_test

import (
	"errors"
	"os"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

func testConn() config.ConnString {
	return config.ConnString{Host: "gw.example", Port: 2222, Person: "alice", Fingerprint: "SHA256:" + repeat43('A')}
}

func repeat43(b byte) string {
	out := make([]byte, 43)
	for i := range out {
		out[i] = b
	}
	return string(out)
}

func TestSaveLoadConnectionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cs := testConn()
	if err := client.SaveConnection(dir, cs, false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != cs {
		t.Fatalf("round trip = %+v, want %+v", got, cs)
	}
}

func TestLoadConnectionMissingIsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := client.LoadConnection(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing connection: err = %v, want errors.Is(..., os.ErrNotExist)", err)
	}
}

// TestSaveConnectionRefusesAChangedGatewayKey is what the old
// "refuses silent overwrite" test became on 22.09.2026, and the change
// is worth stating plainly because it LOOSENED a guard.
//
// The guard used to fire on any second connection, because the file had
// room for exactly one and a second one destroyed the first. That is no
// longer true: gateways are a list now (IAMT-430), and a person with a
// personal gateway and a work gateway is the case the product is for,
// not a mistake to catch.
//
// What was always the dangerous case, and was hidden inside the other
// one, is this: the same person on the same gateway, presenting a
// DIFFERENT host key. That is not somewhere new to connect to, it is
// the same address with a different lock, and it reads either as "the
// gateway was rebuilt" or as "somebody is standing between you and it".
// A person must say which. So this test still asserts the actual
// outcome -- a named refusal, and nothing changed on disk -- but on the
// case that deserves it.
//
// Proved by breaking product code.
func TestSaveConnectionRefusesAChangedGatewayKey(t *testing.T) {
	dir := t.TempDir()
	first := testConn()
	if err := client.SaveConnection(dir, first, false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	rekeyed := first
	rekeyed.Fingerprint = "SHA256:" + repeat43('B')

	err := client.SaveConnection(dir, rekeyed, false)
	if err == nil {
		t.Fatal("save without --replace over a CHANGED GATEWAY KEY: want an error, got nil")
	}
	var cfe *config.Error
	if !errors.As(err, &cfe) || cfe.Class != config.ClassUser {
		t.Fatalf("save without --replace: err = %v, want a ClassUser *config.Error", err)
	}

	got, lerr := client.LoadConnection(dir)
	if lerr != nil {
		t.Fatalf("reload after refused save: %v", lerr)
	}
	if got != first {
		t.Fatalf("refused save touched disk: got %+v, want unchanged %+v", got, first)
	}

	set, serr := client.LoadConnections(dir)
	if serr != nil {
		t.Fatalf("load set: %v", serr)
	}
	if len(set.Gateways) != 1 {
		t.Fatalf("a refused re-key left %d gateways saved, want 1 — it must not become a second entry", len(set.Gateways))
	}
}

// A SECOND gateway is simply remembered, and becomes the current one.
// This was requested on 22.09.2026, asserted here in one test.
func TestSaveConnectionRemembersASecondGateway(t *testing.T) {
	dir := t.TempDir()
	personal := testConn()
	if err := client.SaveConnection(dir, personal, false); err != nil {
		t.Fatalf("first save: %v", err)
	}

	work := config.ConnString{Host: "work.example", Port: 2022, Person: "dana", Fingerprint: "SHA256:" + repeat43('C')}
	if err := client.SaveConnection(dir, work, false); err != nil {
		t.Fatalf("saving a SECOND gateway must need no --replace: %v", err)
	}

	set, err := client.LoadConnections(dir)
	if err != nil {
		t.Fatalf("load set: %v", err)
	}
	if len(set.Gateways) != 2 {
		t.Fatalf("saved %d gateways, want 2 — the second must not have eaten the first", len(set.Gateways))
	}
	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}
	if got != work {
		t.Errorf("current = %+v, want the one just saved %+v", got, work)
	}

	// And back again, by name, without re-pasting anything.
	names := []string{}
	for _, g := range set.Gateways {
		names = append(names, g.Name)
	}
	if _, err := client.SelectConnection(dir, names[0]); err != nil {
		t.Fatalf("switching back to %q: %v", names[0], err)
	}
	got, err = client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("load current after switching: %v", err)
	}
	if got != personal {
		t.Errorf("after switching back: current = %+v, want %+v", got, personal)
	}
}

// The file every version up to 1.38 wrote must open without ceremony.
// A person who upgrades finds their gateway where they left it.
func TestLoadConnectionsMigratesTheOldSingleRecord(t *testing.T) {
	dir := t.TempDir()
	body := `{"Host":"gw.example","Port":2222,"Person":"alice","Fingerprint":"SHA256:` + repeat43('A') + `"}`
	if err := os.WriteFile(client.ConnectionPath(dir), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("the 1.38 file did not open: %v", err)
	}
	if got != testConn() {
		t.Errorf("migrated connection = %+v, want %+v", got, testConn())
	}

	set, err := client.LoadConnections(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Gateways) != 1 {
		t.Fatalf("the old record became %d gateways, want 1", len(set.Gateways))
	}
	if set.Gateways[0].Name == "" {
		t.Error("the migrated gateway has no name — nothing could ever switch to it")
	}
	if set.Current != set.Gateways[0].Name {
		t.Errorf("current = %q, want the one gateway there is (%q)", set.Current, set.Gateways[0].Name)
	}

	// Nothing was rewritten merely by reading it: a downgrade back to
	// 1.38 must still find its own file until something actually saves.
	raw, rerr := os.ReadFile(client.ConnectionPath(dir))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(raw) != body {
		t.Errorf("reading the old file rewrote it:\n%s", raw)
	}
}

// Forgetting one of several hands over to another rather than leaving
// the machine connected to nothing.
func TestForgetConnectionFallsBackToTheNextGateway(t *testing.T) {
	dir := t.TempDir()
	a := testConn()
	b := config.ConnString{Host: "work.example", Port: 2022, Person: "dana", Fingerprint: "SHA256:" + repeat43('C')}
	if err := client.SaveConnection(dir, a, false); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveConnection(dir, b, false); err != nil {
		t.Fatal(err)
	}

	had, err := client.ForgetConnection(dir) // drops b, the current one
	if err != nil || !had {
		t.Fatalf("forget: had=%v err=%v", had, err)
	}
	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("after forgetting one of two: %v", err)
	}
	if got != a {
		t.Errorf("current = %+v, want the remaining gateway %+v", got, a)
	}

	had, err = client.ForgetConnection(dir) // drops the last one
	if err != nil || !had {
		t.Fatalf("forget the last: had=%v err=%v", had, err)
	}
	if _, err := client.LoadConnection(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("with nothing left, load = %v, want os.ErrNotExist — the same news as never configured", err)
	}
}

func TestSaveConnectionReplaceOverwrites(t *testing.T) {
	dir := t.TempDir()
	first := testConn()
	if err := client.SaveConnection(dir, first, false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	second := first
	second.Person = "bob"
	if err := client.SaveConnection(dir, second, true); err != nil {
		t.Fatalf("save with --replace: %v", err)
	}
	got, err := client.LoadConnection(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got != second {
		t.Fatalf("after --replace: got %+v, want %+v", got, second)
	}
}

// TestSaveConnectionIdenticalValueNeedsNoReplace matches PROTOCOL §3.1:
// "on re-import the client replaces ... this is idempotent" — the
// exact same string can always be re-saved without --replace.
func TestSaveConnectionIdenticalValueNeedsNoReplace(t *testing.T) {
	dir := t.TempDir()
	cs := testConn()
	if err := client.SaveConnection(dir, cs, false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := client.SaveConnection(dir, cs, false); err != nil {
		t.Fatalf("idempotent re-save without --replace: %v", err)
	}
}

func TestLoadConnectionCorruptFileIsNamedError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(client.ConnectionPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	_, err := client.LoadConnection(dir)
	if err == nil {
		t.Fatal("corrupt connection.json: want an error")
	}
	var cfe *config.Error
	if !errors.As(err, &cfe) || cfe.Class != config.ClassEnv {
		t.Fatalf("corrupt connection.json: err = %v, want a ClassEnv *config.Error", err)
	}
}

func TestLoadConnectionUnknownFieldIsRejected(t *testing.T) {
	dir := t.TempDir()
	body := `{"Host":"gw","Port":2222,"Person":"alice","Fingerprint":"SHA256:` + repeat43('A') + `","Extra":true}`
	if err := os.WriteFile(client.ConnectionPath(dir), []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := client.LoadConnection(dir); err == nil {
		t.Fatal("connection.json with an unknown field: want an error, got nil")
	}
}
