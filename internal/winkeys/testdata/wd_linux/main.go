// wd_linux is the linux-side doorwatch binary — the watchdog
// child that internal/winkeys.SpawnWatchdog launches and that
// internal/winkeys.RunWatchdog drives. It is to wd_linux.go what
// testdata/wd/main.go is to the Windows side: parse argv, call
// RunWatchdog, exit.
//
// RunWatchdog blocks until the parent PID dies (via pidfd poll,
// not signal-handler latency) and removes the door line via the
// same NewDoorWithOptions path the server uses — with the
// LockPath/OwnerUID/OwnerGID the parent passed through, so the
// unix validateOptionsPlatform gate (linux/darwin) is satisfied.
// The argv parser is the shared Unix one (ParseWatchdogArgsUnix,
// doorwatch_unix.go) because macOS takes the same tail (IAMT-263);
// this helper stays linux-tagged because only a Linux test binary
// can spawn it in this repo's CI.
//
// Arguments (8 positional after the subcommand verb, IAMT-247):
//
//	wd_linux server doorwatch <door-id> <parent-pid> <keyfile>
//	          <max-wait-ms> <journal-path>
//	          <lock-path> <owner-uid> <owner-gid>

package main

import (
	"fmt"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func main() {
	if len(os.Args) < 11 {
		fmt.Fprintln(os.Stderr, "usage: wd_linux server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path> <lock-path> <owner-uid> <owner-gid>")
		os.Exit(2)
	}
	pid, doorID, keyFile, journalPath, lockPath, ownerUID, ownerGID, maxWait, err := winkeys.ParseWatchdogArgsUnix(os.Args)
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
	if err := winkeys.RunWatchdog(pid, doorID, keyFile, sink, maxWait, lockPath, ownerUID, ownerGID); err != nil {
		fmt.Fprintln(os.Stderr, "watchdog run:", err)
		os.Exit(1)
	}
}
