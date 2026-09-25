package gateway

// IAMT-440 (extra), machines.set-user. PROTOCOL §6 gives its answer as
// {id,requestedOsUser,osUserStatus:"pending",state:"enrolled"}; the gateway
// answered {id,osUser} - a shape no document names. And a name it refused
// was told to be DOMAIN\name or MACHINE\name, though since 1.1 a Linux or
// macOS machine is entered as a local POSIX name, which the gateway
// accepts: an administrator of such a machine who mistyped one was sent to
// look for a Windows domain.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestIAMT440_SetUserAnswersInTheShapePROTOCOLGives(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	raw, err := root.Exec("machines.set-user", map[string]any{"proto": 1, "id": f.machineID, "osUser": `MACHINE\other`})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"id": f.machineID, "requestedOsUser": `MACHINE\other`, "osUserStatus": "pending", "state": "enrolled"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("machines.set-user answered %v, PROTOCOL §6 says %v", got, want)
	}
}

func TestIAMT440_SetUserRefusalNamesBothFormsOfAnOSUser(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	_, err := root.Exec("machines.set-user", map[string]any{"proto": 1, "id": f.machineID, "osUser": "Alice"})
	var refused *admin.CommandError
	if !errors.As(err, &refused) {
		t.Fatalf("an OS user of neither form was answered %v, want a refusal", err)
	}
	for _, want := range []string{`DOMAIN\name`, "POSIX"} {
		if !strings.Contains(refused.Message, want) {
			t.Errorf("the refusal does not name %q: %s", want, refused.Message)
		}
	}
}
