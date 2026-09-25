// wd is the test-side doorwatch binary. It is what a production
// iamtunnel doorwatch binary would look like in shape: parse the
// argv, call RunWatchdog, exit.
//
// RunWatchdog blocks until the parent PID dies, removes the
// door line, and returns. The doorwatch_test.go test kills the
// parent (helper_watchdog_parent) and verifies that this binary
// cleans up.
//
// Arguments follow the contract documented in PROTOCOL §5.2 and
// in internal/winkeys.ParseWatchdogArgs:
//
//	wd server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>
//
// <max-wait-ms> is the safety cap on how long this process is
// willing to wait for the parent before exiting. It comes from the
// spawner's MaxDoorHard + slack (IAMT-130: the previous hard-coded
// 5-minute cap could expire while the door was still legally open).
//
// <journal-path> is the optional audit log this binary writes its
// layer-3 cleanup event into. Empty means "no journal" — the
// cleanup event is dropped.

package main

import (
	"fmt"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func main() {
	if len(os.Args) < 8 {
		fmt.Fprintln(os.Stderr, "usage: wd server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>")
		os.Exit(2)
	}
	// ParseWatchdogArgs expects args[1]="server", args[2]="doorwatch".
	pid, doorID, keyFile, journalPath, maxWait, err := winkeys.ParseWatchdogArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchdog args:", err)
		os.Exit(2)
	}
	var sink winkeys.Sink
	if journalPath != "" {
		s, ferr := winkeys.NewFileSink(journalPath)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "watchdog journal:", ferr)
			os.Exit(2)
		}
		sink = s
	}
	if err := winkeys.RunWatchdog(pid, doorID, keyFile, sink, maxWait, "", 0, 0); err != nil {
		fmt.Fprintln(os.Stderr, "watchdog run:", err)
		os.Exit(1)
	}
}
