// helper_watchdog_parent_linux is the linux-side stand-in for the
// server role in the doorwatch integration test (the Windows
// version lives in testdata/helper_watchdog_parent/main.go and
// uses NewDoor; on Linux NewDoor refuses because LockPath is
// required by validateOptionsPlatform, so this binary uses
// NewDoorWithOptions with explicit LockPath/OwnerUID/OwnerGID).
//
// It mimics a server role: installs a door line, writes a
// control file with the door-id, then sleeps until killed. The
// test kills it with SIGKILL (no graceful exit); the spawned
// doorwatch subprocess must then clean up the line.
//
// Why a separate binary: the test wants to kill a different
// process than the one running the test. Killing the test
// process to trigger the watcher is not possible — the watcher
// would also die. Spawning a real subprocess with its own PID
// is the only way to exercise "parent dies, watcher cleans up".
//
// Args: <keyfile> <lock-path> <owner-uid> <owner-gid>
//
// Writes (next to keyfile): <keyfile>.parent.pid — the helper's
// own PID, as plain text. The test waits for this file to appear
// before continuing.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: helper_watchdog_parent_linux <keyfile> <lock-path> <owner-uid> <owner-gid>")
		os.Exit(2)
	}
	keyFile, err := filepath.Abs(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "abs:", err)
		os.Exit(2)
	}
	lockPath := os.Args[2]
	ownerUID, uidErr := strconv.Atoi(os.Args[3])
	if uidErr != nil {
		fmt.Fprintln(os.Stderr, "owner-uid:", uidErr)
		os.Exit(2)
	}
	ownerGID, gidErr := strconv.Atoi(os.Args[4])
	if gidErr != nil {
		fmt.Fprintln(os.Stderr, "owner-gid:", gidErr)
		os.Exit(2)
	}

	d, err := winkeys.NewDoorWithOptions(keyFile, nil, winkeys.DoorOptions{
		LockPath: lockPath,
		OwnerUID: ownerUID,
		OwnerGID: ownerGID,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "door:", err)
		os.Exit(2)
	}
	if _, err := d.EnsureDir(); err != nil {
		fmt.Fprintln(os.Stderr, "ensure dir:", err)
		os.Exit(2)
	}

	id := makeID()
	if err := d.Install(id, winkeys.TestKey); err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		os.Exit(2)
	}

	// Write the pid file first; the test waits on this.
	pidPath := keyFile + ".parent.pid"
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "pid file:", err)
		os.Exit(2)
	}

	// Sleep forever. The test will SIGKILL this process; the
	// watcher then removes our line.
	for {
		time.Sleep(1 * time.Second)
	}
}

// makeID returns a 32-hex id (matching SPEC §6.3 table row 0).
func makeID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a deterministic string — the test will
		// still fail later because it won't see its line.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}
