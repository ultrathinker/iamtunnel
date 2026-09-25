package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// IAMT-444: door.status answers for this registration's door lines and no
// others. On a Windows machine two people's servers share one
// administrators_authorized_keys; the owner tag says whose line is whose.
// status used to report the first door line in the file, whoever's it
// was, and could not read the 1.4 tail at all: "<id> iamtunnel-owner=x"
// failed its "only blanks after the id" check, so every tagged line - the
// server's own live door included - came back with an empty id. Another
// person's open door then kept the gateway sanitizing and asking again
// forever, and the registration never came online (see the gateway's
// iamt444_two_registrations_test.go for that loop, driven end to end).

const (
	iamt444Mine    = "vm2"
	iamt444Other   = "vm1"
	iamt444MineHex = "22222222222222222222222222222222"
	iamt444MineID  = "22222222-2222-2222-2222-222222222222"
	iamt444OtherID = "11111111111111111111111111111111"
)

func iamt444Status(t *testing.T, lines ...string) doorStatusResult {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	if err := os.WriteFile(keyFile, []byte(strings.Join(lines, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dc, err := newDoorController(&Config{
		MachineID:     iamt444Mine,
		KeyFile:       keyFile,
		DoorLockPath:  filepath.Join(tree.Home, "door.lock"),
		DoorwatchExe:  "unused-in-unit-tests",
		MaxDoorIdle:   DefaultMaxDoorIdle,
		MaxDoorHard:   DefaultMaxDoorHard,
		OwnerUID:      testUIDForDoor(),
		OwnerGID:      testGIDForDoor(),
		SpawnWatchdog: noopSpawnWatchdog,
	})
	if err != nil {
		t.Fatalf("newDoorController: %v", err)
	}
	resp := dc.status(controlRequest{ID: "s", Op: "door.status"})
	if !resp.OK {
		t.Fatalf("door.status failed: %+v", resp.Error)
	}
	var got doorStatusResult
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("decode door.status: %v", err)
	}
	return got
}

func TestIAMT444_DoorStatusAnswersForThisRegistrationOnly(t *testing.T) {
	mine := winkeys.FormatLineOwned(iamt444MineHex, winkeys.TestKey, iamt444Mine)
	other := winkeys.FormatLineOwned(iamt444OtherID, winkeys.TestKey, iamt444Other)
	legacy := winkeys.FormatLine(iamt444OtherID, winkeys.TestKey)
	corrupt := winkeys.Options + " ssh-ed25519 " + winkeys.TestKey + " " + winkeys.Marker + "not-an-id"
	admin := "ssh-ed25519 " + winkeys.TestKey + " admin@example"

	cases := []struct {
		name          string
		lines         []string
		wantInstalled bool
		wantID        string
	}{
		{"its own tagged line is its door, by id", []string{admin, mine}, true, iamt444MineID},
		{"another registration's open door is not its business", []string{admin, other}, false, ""},
		{"its own line is found past another registration's", []string{other, mine}, true, iamt444MineID},
		{"a line from before 1.4 is there but not addressable by id", []string{legacy}, true, ""},
		{"a corrupted line is there but not addressable by id", []string{corrupt}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iamt444Status(t, tc.lines...)
			if got.Installed != tc.wantInstalled || got.DoorID != tc.wantID {
				t.Errorf("door.status = installed:%v doorId:%q, want installed:%v doorId:%q", got.Installed, got.DoorID, tc.wantInstalled, tc.wantID)
			}
		})
	}
}
