package server

import (
	"os"
	"strings"
	"testing"
)

// ORCHESTRATOR PROBE: the dangerous shape is a VALID ed25519 key (so the line
// really does grant admin access) whose iamtunnel-door marker is damaged.
func TestOrchProbe_ValidKeyDamagedMarkerIsRemoved(t *testing.T) {
	const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8s0mDZPHNDCTL6bk0m0Fg2fNLGMEBPRNlBmK6Ky0Y"
	for _, marker := range []string{
		"iamtunnel-door=zzzz",
		"iamtunnel-door=",
		"iamtunnel-door=0b9e3f2a6c1d4e7a9b3d1a2b3c4d5e6",
		"iamtunnel-door=0b9e3f2a6c1d4e7a9b3d1a2b3c4d5e6fXX",
	} {
		line := `restrict,pty,from="127.0.0.1" ` + validKey + " " + marker
		dc, keyFile := newTestDoorController(t, nil)
		if err := os.WriteFile(keyFile, []byte(line+"\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := dc.sanitize(controlRequest{ID: "z", Op: "door.sanitize", Reason: "corrupted"}); !r.OK {
			t.Fatalf("%s: sanitize refused: %+v", marker, r.Error)
		}
		b, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "iamtunnel-door") {
			t.Errorf("marker %q: line with a VALID key survived sanitize: %q", marker, string(b))
		}
	}
}

// ORCHESTRATOR PROBE: widening the sweep is exactly where the first invariant
// is easiest to break. A foreign admin key must survive byte-for-byte even when
// it merely LOOKS like ours.
func TestOrchProbe_ForeignKeysSurviveTheWiderSweep(t *testing.T) {
	const foreignKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBt3QWFFmVmXQwYRk5t5F0y0Zq3F0YnJdNKPvTnQbEsW"
	foreign := []string{
		foreignKey + " owner@pc1",
		foreignKey + " comment mentioning iamtunnel-door in prose",
		foreignKey + " iamtunnel-doorway=notours",
		"# a comment line mentioning iamtunnel-door=zzzz",
		"",
		foreignKey + " backup@vps",
	}
	for _, damaged := range []string{"iamtunnel-door=zzzz", "iamtunnel-door="} {
		ours := `restrict,pty,from="127.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZ8s0mDZPHNDCTL6bk0m0Fg2fNLGMEBPRNlBmK6Ky0Y ` + damaged
		// our damaged line sits in the middle, so order preservation is tested too
		lines := append([]string{}, foreign[:3]...)
		lines = append(lines, ours)
		lines = append(lines, foreign[3:]...)
		before := strings.Join(lines, "\r\n") + "\r\n"
		want := strings.Join(append(append([]string{}, foreign[:3]...), foreign[3:]...), "\r\n") + "\r\n"

		dc, keyFile := newTestDoorController(t, nil)
		if err := os.WriteFile(keyFile, []byte(before), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := dc.sanitize(controlRequest{ID: "z", Op: "door.sanitize", Reason: "corrupted"}); !r.OK {
			t.Fatalf("%s: sanitize refused: %+v", damaged, r.Error)
		}
		got, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("marker %q: foreign lines were not preserved byte-for-byte\n want %q\n got  %q", damaged, want, string(got))
		}
	}
}
