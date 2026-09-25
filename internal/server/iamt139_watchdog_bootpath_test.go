package server

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// TestIAMT139_DefaultSpawnWatchdogIsWinkeysSpawnWatchdog guards the production
// default installed by setDefaults. In particular, it must not be a closure
// which captures its own max-wait or journal values and ignores the arguments
// supplied by door.open.
//
// This deliberately does not replace cfg.SpawnWatchdog: on Windows calling the
// real factory would create a child process. Function identity proves the
// structural invariant instead: the production path calls winkeys.SpawnWatchdog
// directly, so the values calculated once in door.go are the values passed on.
func TestIAMT139_DefaultSpawnWatchdogIsWinkeysSpawnWatchdog(t *testing.T) {
	cfg := &Config{
		GatewayAddr:        "127.0.0.1:1",
		GatewayFingerprint: "SHA256:00",
		MachineID:          "machine-test",
		MachineKey:         mustSigner(t),
		KeyFile:            filepath.Join(t.TempDir(), "key"),
		TargetAddr:         "127.0.0.1:22",
		DoorwatchExe:       "iamtunnel.exe",
		MaxDoorIdle:        time.Minute,
		MaxDoorHard:        30 * time.Minute,
		WatchdogJournal:    filepath.Join(t.TempDir(), "watchdog.jsonl"),
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}

	got := reflect.ValueOf(cfg.SpawnWatchdog).Pointer()
	want := reflect.ValueOf(winkeys.SpawnWatchdog).Pointer()
	if got != want {
		t.Fatalf("default cfg.SpawnWatchdog is not winkeys.SpawnWatchdog (got %x, want %x); a wrapping closure would reintroduce a second source of truth for watchdog lifetime or journal", got, want)
	}
}
