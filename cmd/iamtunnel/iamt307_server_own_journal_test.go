package main

// iamt307_server_own_journal_test.go: live scenario (enrol -> systemd
// install -> two interactive sessions -> one exec session -> graceful
// server stop -> manual server start -> two kill -9) found that
// /var/lib/iamtunnel-machine/events.jsonl held EXACTLY two lines the
// whole run, both {"Op":"close",...} written by the watchdog child after
// a kill -9. A graceful Stop, which SPEC §3.2 says the SERVER itself
// removes its own door line for, wrote nothing there at all - and
// RUNBOOK §1.7/§6 and THREATS.md both document {"Op":"open"|"close"|
// "sweep",...} in this exact file as the machine's own local audit
// trail, not a watchdog-only one ("Op:"close" in .../events.jsonl" is
// RUNBOOK's own worked example for a plain Stop).
//
// Root cause: cmd/iamtunnel's serverStartConfig built server.Config with
// WatchdogJournal set (threaded to the doorwatch child's argv) but never
// set Config.Sink - the server's OWN door open/close/sweep calls
// (internal/server, already independently tested against Config.Sink -
// see internal/server/door_test.go's doorActionSink) went to the default
// no-op sink and never reached the file at all.
//
// This test proves the wiring without needing a reachable gateway or a
// real door open: internal/server.Run's very first action on every
// connect attempt, before it ever dials (sweepBeforeConnect in
// internal/server/run.go), is an unconditional SweepStale through the
// same Config.Sink - winkeys.Door.SweepStale emits exactly one
// {"Op":"sweep",...} action every time, successful or not. A gateway
// nothing listens on (the same "unreachable on purpose" fixture
// gate4_server_pair_test.go's seedEnrolledMachine already uses) is
// therefore enough to observe the server's own Sink wiring end to end.
//
// Canary: revert cmd/iamtunnel/server.go's scfg.Sink assignment (leave
// server.Config.Sink at its zero value) and re-run - the sweep line never
// lands and this test fails at its own deadline, on its own message: "the
// server's own door sweep never reached the machine's local journal".

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func TestIAMT307_ServerStartWritesOwnDoorSweepToMachineJournal(t *testing.T) {
	dir := t.TempDir()
	var args []string
	if runtime.GOOS == "windows" {
		seedEnrolledMachine(t, dir)
		// R4 F-04: seed the anchor the enrol would have laid down, so
		// the start reaches the door sweep this canary wires.
		seedEnrolmentAnchor(t, testsupport.PlatformDataEnvAt(t, dir), dir)
		args = []string{"server", "start", "--data-dir", dir}
	} else {
		// Linux/Darwin: serverKeyFile refuses before the sink is ever
		// built unless the enrolment record carries an OS user (see
		// iamt160's own fixture for the same reason) - and unless
		// --key-file also names a path this test process can actually
		// create a directory under. userLookupFn is faked with this
		// process's own uid/gid so the door layer's owner check (which
		// requireServerElevation's injected isElevated=true does not
		// bypass) does not need real root.
		//
		// Except under root itself (a root container, R2 24.09.2026):
		// there the process's own pair is 0:0 — exactly the UNSET
		// sentinel validateOptionsPlatform refuses at NewDoorWithOptions,
		// before the sweep ever runs, with the refusal vanishing into the
		// no-op Logger. Root running the server for a RESOLVED non-root
		// owner is a supported configuration (fchownIfRoot, IAMT-269) and
		// the strict-mode owner check accepts root-owned fixtures, so the
		// fake claims a non-root pair instead of tripping the sentinel:
		// the sweep — and with it the wiring this canary proves — stays
		// reachable under root.
		seedEnrolledMachineWithOSUser(t, dir, "svc-ssh")
		saved := userLookupFn
		t.Cleanup(func() { userLookupFn = saved })
		home := t.TempDir()
		uid, gid := os.Getuid(), os.Getgid()
		if uid == 0 && gid == 0 {
			uid, gid = 1000, 1000
		}
		userLookupFn = func(name string) (*user.User, error) {
			return &user.User{Username: name, Uid: strconv.Itoa(uid), Gid: strconv.Itoa(gid), HomeDir: home}, nil
		}
		args = []string{"server", "start", "--data-dir", dir, "--key-file", filepath.Join(t.TempDir(), "authorized_keys")}
	}

	var out, errs bytes.Buffer
	s := &streams{
		in:              strings.NewReader(""),
		out:             &out,
		errs:            &errs,
		env:             testsupport.PlatformDataEnvAt(t, dir),
		checkSSHD:       func(string) error { return nil },
		checkSSHDConfig: func(string) error { return nil },
		isElevated:      func() (bool, error) { return true, nil },
	}

	done := make(chan int, 1)
	go func() { done <- run(args, s) }()
	t.Cleanup(func() {
		_, contacted, _ := sendControl(dir, "stop")
		if contacted {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	})

	journalPath := filepath.Join(dir, "events.jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case code := <-done:
			t.Fatalf("server start exited early (code=%d) before ever reaching sweepBeforeConnect; stdout=%q stderr=%q", code, out.String(), errs.String())
		default:
		}
		if raw, err := os.ReadFile(journalPath); err == nil && strings.Contains(string(raw), `"Op":"sweep"`) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("IAMT-307 canary: the server's own door sweep never reached the machine's local journal %s within the deadline "+
		"(server.Config.Sink was never wired to the same file as WatchdogJournal); stderr=%q", journalPath, errs.String())
}

// TestIAMT307_WatchdogAuditErrorReporterAppendsSiblingLog pins F-307-3's
// fix (round 7, review round15): the server role's own OnError
// (a few lines above scfg.Sink's construction) reaches this process's
// stderr, but a watchdog subprocess has no stderr anyone reads in
// production — SpawnWatchdog routes it to /dev/null specifically so the
// watchdog keeps running once the parent whose stderr that was is
// already gone (SPEC §6.3), which is exactly the moment this journal
// matters most. watchdogAuditErrorReporter is the seam both
// cmdServerDoorwatchUnix and cmdServerDoorwatchOther now pass as
// JournalOptions.OnError instead of leaving it nil: a channel that is
// still reachable regardless of whether the parent process, or this
// process's own stderr, exist at all — a plain file living next to the
// journal itself.
//
// Canary: revert either cmdServerDoorwatchUnix or cmdServerDoorwatchOther
// back to winkeys.NewFileSink(journalPath) (a nil OnError) and this test
// still passes (it calls the seam directly), but a real failed watchdog
// write goes silent again — see TestIAMT307_WatchdogJournalErrorReaches
// SiblingLogPastLockContention below for the wiring-level canary.
func TestIAMT307_WatchdogAuditErrorReporterAppendsSiblingLog(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "events.jsonl")
	report := watchdogAuditErrorReporter(journalPath)

	report(errors.New("first failure"))
	report(errors.New("second failure"))

	errPath := journalPath + ".watchdog.err"
	raw, err := os.ReadFile(errPath)
	if err != nil {
		t.Fatalf("read watchdog audit error log %s: %v", errPath, err)
	}
	text := string(raw)
	if !strings.Contains(text, "first failure") || !strings.Contains(text, "second failure") {
		t.Fatalf("watchdog audit error log %s is missing an expected failure line; got:\n%s", errPath, text)
	}
	if got := strings.Count(text, "\n"); got != 2 {
		t.Fatalf("expected exactly two appended lines in %s (one per report call), got %d; content:\n%s", errPath, got, text)
	}
}

// TestIAMT307_WatchdogJournalErrorReachesSiblingLogPastLockContention
// wires watchdogAuditErrorReporter into a real winkeys.NewJournalSink
// the way both doorwatch entry points do, and forces the same rotation-
// lock contention TestJournalSink_OnErrorFiresOnLockContention (internal/
// winkeys/file_sink_test.go) forces from inside that package, to prove
// the wiring end to end: a real OnDoor failure in the watchdog's own
// sink construction reaches <journal>.watchdog.err, not this test
// process's stderr (which a real watchdog never has anyone reading).
//
// Canary: pass a nil OnError instead of watchdogAuditErrorReporter(...)
// here (i.e. revert either doorwatch entry point to winkeys.NewFileSink)
// and this test fails at its own deadline: "...watchdog.err was never
// written to within the deadline".
func TestIAMT307_WatchdogJournalErrorReachesSiblingLogPastLockContention(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "events.jsonl")

	sink, err := winkeys.NewJournalSink(journalPath, winkeys.JournalOptions{
		OnError: watchdogAuditErrorReporter(journalPath),
	})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(interface{ Close() error }).Close()

	held, err := winkeys.AcquireFileLock(journalPath + ".rotate.lock")
	if err != nil {
		t.Fatalf("acquire rotation lock directly: %v", err)
	}
	defer held.Release()

	go sink.OnDoor(winkeys.Action{Op: "close", DoorID: "blocked-by-test", At: time.Now()})

	errPath := journalPath + ".watchdog.err"
	// winkeys' own OnDoor retries ordinary lock contention across a 30s
	// budget (journalLockWait, unexported — see file_sink.go) before
	// giving up and reporting; this deadline gives that its own room
	// plus margin, the same way the internal package's own test of the
	// identical contention does.
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if raw, rerr := os.ReadFile(errPath); rerr == nil && len(raw) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("IAMT-307 canary: %s was never written to within the deadline — a watchdog-side journal write failure did not reach its sibling error log", errPath)
}
