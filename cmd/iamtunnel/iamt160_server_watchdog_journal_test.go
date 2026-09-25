package main

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/server"
)

// TestIAMT160_ServerStartSetsWatchdogJournal pins the production seam: the
// watchdog receives the machine's own events.jsonl, derived from exactly the
// data directory server start was given. Building the config only reads its
// enrolment material; it must not create the journal.
//
// The assertion is platform-neutral — one assignment in serverStartConfig —
// but the fixture that lets serverStartConfig reach that assignment is not:
// "server start" resolves the door's key file before it returns the config,
// and that default differs by OS. Each subtest supplies the fixture of its
// own platform, the same way TestIAMT206_NoStateFilenameCollidesWithConfig
// and TestGate2_EnrolSuccessPath build their per-OS values, and both assert
// the same journal binding on every host the suite builds for.
func TestIAMT160_ServerStartSetsWatchdogJournal(t *testing.T) {
	t.Run("windows", func(t *testing.T) {
		// serverKeyFile's windows branch takes the door file from
		// %ProgramData% and builds it with filepath.Join, i.e. with the
		// HOST separator, and config.WindowsProgramData refuses a
		// %ProgramData% that is not an absolute WINDOWS path. Only a
		// Windows host mints such a value in t.TempDir(): on Linux
		// this fixture would be refused before the assertion, and a
		// hand-written `C:\…` would produce mixed separators — a path
		// production never builds on Windows. See iamt156 for the
		// key-file default itself, and the "linux" subtest below for
		// the same journal binding through the other branch.
		if runtime.GOOS != "windows" {
			t.Skipf("this subtest seeds the Windows door-file fixture (%%ProgramData%% must be an absolute Windows path, and the product joins it with the host separator), which only a Windows host can build inside t.TempDir(); on %s it would be refused or assert a mixed-separator path production never produces. The journal binding itself is asserted here by the \"linux\" subtest through the Linux/Darwin branch.", runtime.GOOS)
		}
		dataDir := t.TempDir()
		seedEnrolledMachine(t, dataDir)
		cfg, err := serverStartConfig("windows", map[string]string{
			"ProgramData": t.TempDir(),
		}, serverStartParams{
			dataDir:     dataDir,
			exe:         "unused",
			idleMinutes: 15,
			maxHours:    8,
		})
		assertWatchdogJournal(t, dataDir, cfg, err)
	})

	t.Run("linux", func(t *testing.T) {
		// Linux and Darwin share one serverKeyFile branch (IAMT-248):
		// the door file is <osUser-home>/.ssh/authorized_keys, and the
		// home comes from the gateway-bound OS user recorded at enrol
		// time through the userLookupFn seam (a fixed observation
		// here, so the test binary never reads /etc/passwd). The home
		// directory itself lives in a t.TempDir() and is never
		// created or written to — the config only carries the path.
		dataDir := t.TempDir()
		seedEnrolledMachineWithOSUser(t, dataDir, "svc-ssh")

		saved := userLookupFn
		t.Cleanup(func() { userLookupFn = saved })
		home := t.TempDir()
		userLookupFn = func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: "1000", Gid: "1000", HomeDir: home}, nil
		}

		cfg, err := serverStartConfig("linux", map[string]string{}, serverStartParams{
			dataDir:     dataDir,
			exe:         "unused",
			idleMinutes: 15,
			maxHours:    8,
		})
		assertWatchdogJournal(t, dataDir, cfg, err)
	})
}

// seedEnrolledMachineWithOSUser is seedEnrolledMachine for the Linux/Darwin
// fixture: the enrolment record also carries the OS user the gateway bound
// at enrol time. Without it serverKeyFile refuses on those platforms ("cannot
// resolve the default door key file on linux without an osUser") and
// serverStartConfig never reaches the journal assignment this test is about.
func seedEnrolledMachineWithOSUser(t *testing.T, dir, osUser string) {
	t.Helper()
	seedEnrolledMachine(t, dir)
	if err := atomicWriteJSON(gatewayRecordPath(dir), gatewayRecord{
		Host:        "127.0.0.1",
		Port:        1,
		Fingerprint: fpr43,
		MachineID:   "testmachine",
		OSUser:      osUser,
	}); err != nil {
		t.Fatalf("seed enrolment record with os-user %q: %v", osUser, err)
	}
}

// assertWatchdogJournal is the single assertion both platform subtests make,
// so neither branch can drift into a weaker check than the other.
func assertWatchdogJournal(t *testing.T, dataDir string, cfg server.Config, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("serverStartConfig: %v", err)
	}
	want := filepath.Join(dataDir, "events.jsonl")
	if cfg.WatchdogJournal != want {
		t.Fatalf("serverStartConfig(...).WatchdogJournal = %q, want %q — the watchdog must retain a machine-local cleanup audit trail", cfg.WatchdogJournal, want)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("building the server config touched watchdog journal %s (stat err=%v); it must write nothing", want, err)
	}
}
