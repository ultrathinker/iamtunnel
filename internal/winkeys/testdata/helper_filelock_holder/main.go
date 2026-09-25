// helper_filelock_holder acquires the winkeys cross-process file
// lock on a given key file and holds it until told to release, or
// until killed. Used by doors_windows_lock_test.go to prove the
// lock excludes a second, real OS process — not just a second
// goroutine in the same process.
//
// Args: <keyfile> <pidfile> [releasefile]
//
// Writes <pidfile> with its own PID as soon as the lock is held;
// the test waits on this file before proceeding.
//
// If releasefile is given: polls for that path to appear, then
// calls Release(), writes <pidfile>.released, and exits 0. This is
// the "graceful release" path.
//
// If releasefile is omitted: sleeps forever, still holding the
// lock. The test kills this process with "taskkill /f" to prove
// the lock is released by the OS on a hard kill, not by any
// cooperative shutdown code in this binary.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: helper_filelock_holder <keyfile> <pidfile> [releasefile]")
		os.Exit(2)
	}
	keyFile := os.Args[1]
	pidFile := os.Args[2]
	releaseFile := ""
	if len(os.Args) >= 4 {
		releaseFile = os.Args[3]
	}

	lock, err := winkeys.AcquireFileLock(keyFile + ".lock")
	if err != nil {
		fmt.Fprintln(os.Stderr, "acquire:", err)
		os.Exit(2)
	}

	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "pidfile:", err)
		os.Exit(2)
	}

	if releaseFile == "" {
		for {
			time.Sleep(1 * time.Second)
		}
	}

	for {
		if _, err := os.Stat(releaseFile); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := lock.Release(); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(2)
	}
	if err := os.WriteFile(pidFile+".released", []byte("ok"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "released marker:", err)
		os.Exit(2)
	}
}
