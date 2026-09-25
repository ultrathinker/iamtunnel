// helper_door_cycler drives a real winkeys.Door against a shared
// key file from its own OS process, independent of any other
// process doing the same thing at the same time. Used by
// doors_windows_lock_test.go's cross-process race test to prove
// that the file lock, not luck, keeps concurrent installs/removes
// from corrupting the key file.
//
// Args: <keyfile> <doorID> <iterations>
//
// Runs Install(doorID)+Remove(doorID) exactly `iterations` times.
// Install only collapses the SAME doorID line (see doors.go:
// PROTOCOL §5.1 "atomically replace the file" means door.open adds one
// line and only deletes the line for that exact doorID). When the
// helper is invoked with two different doorIDs in parallel, each
// process's Install leaves the OTHER process's line alone; each
// process's Remove drops only its own doorID. A process that always
// ends its own cycle on Remove therefore leaves no line of its own
// behind — regardless of how its cycles interleaved with another
// process's, PROVIDED the cross-process lock genuinely serialises
// the two. The test spawns two of these concurrently with different
// doorIDs and checks that the file ends with zero iamtunnel lines
// and every foreign line untouched, byte-for-byte — the
// cross-process twin of TestConcurrentInstallAndRemove in
// doors_test.go.
//
// Every Install/Remove call already does its own read-back proof
// (see doors.go); a race that loses an update surfaces here as a
// non-zero exit.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: helper_door_cycler <keyfile> <doorID> <iterations>")
		os.Exit(2)
	}
	keyFile := os.Args[1]
	doorID := os.Args[2]
	n, err := strconv.Atoi(os.Args[3])
	if err != nil || n < 1 {
		fmt.Fprintln(os.Stderr, "bad iteration count:", os.Args[3])
		os.Exit(2)
	}

	d, err := winkeys.NewDoor(keyFile, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "door:", err)
		os.Exit(2)
	}

	for i := 0; i < n; i++ {
		if err := d.Install(doorID, winkeys.TestKey); err != nil {
			fmt.Fprintln(os.Stderr, "install", i, ":", err)
			os.Exit(2)
		}
		if err := d.Remove(doorID); err != nil {
			fmt.Fprintln(os.Stderr, "remove", i, ":", err)
			os.Exit(2)
		}
	}
}
