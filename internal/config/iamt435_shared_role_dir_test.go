package config

import (
	"strings"
	"testing"
)

// IAMT-435: server_dir and gateway_dir naming ONE directory is refused,
// not tolerated. Both roles append to events.jsonl in their own
// directory (Dirs.ServerEvents and Dirs.GatewayEvents) in two different
// formats, so in a shared directory whichever role writes second
// corrupts the other's audit journal. The platform defaults can never
// collide (the server directory is per-user since 1.4, the gateway's is
// machine-wide); only explicit config keys can name one directory for
// both — and Load refuses them instead of letting the journals interleave.
func TestIAMT435_LoadRefusesOneDirectoryForTheGatewayAndTheMachine(t *testing.T) {
	read := func(body string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(body), nil }
	}

	_, err := Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/shared.json"},
		read(`{"server_dir":"/srv/iamtunnel","gateway_dir":"/srv/iamtunnel"}`))
	if err == nil {
		t.Fatal("Load accepted server_dir == gateway_dir — the machine and the gateway role would append their two different events.jsonl journals into one file (IAMT-435)")
	}
	if !strings.Contains(err.Error(), "events.jsonl") {
		t.Errorf("the refusal must name the collision it refuses: %v", err)
	}

	s, err := Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/split.json"},
		read(`{"server_dir":"/srv/machine","gateway_dir":"/srv/gateway"}`))
	if err != nil {
		t.Fatalf("distinct role directories must stay accepted: %v", err)
	}
	if s.ServerDir != "/srv/machine" || s.GatewayDir != "/srv/gateway" {
		t.Fatalf("role directories = %q / %q, want the config values verbatim", s.ServerDir, s.GatewayDir)
	}

	// A role directory that never resolved is an allowed-missing "" (the
	// gateway's $HOME-less systemd run, IAMT-310), not a collision — even
	// when both are missing: nothing is shared because neither role has a
	// directory. validate directly: Load cannot produce this pair on linux
	// (its gateway default is a fixed absolute path).
	s = Defaults()
	s.ClientDir, s.ServerDir, s.GatewayDir = "/c", "", ""
	if err := validate(s, true, false, true); err != nil {
		t.Fatalf("two unresolved directories are an allowed-missing pair, not a collision: %v", err)
	}
}
