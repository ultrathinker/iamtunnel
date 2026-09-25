package client

// R1-CX F-17: every change of the saved connections - save, select,
// rename, forget - read connection.json, changed the list in memory and
// put a whole new file in its place. The replace is atomic, so the file
// was never half-written; but nothing held the file between the read and
// the write, and of two writers that read the same list, the one that
// wrote second wiped out the other's change without a word: the Client
// tab saving one gateway while "client forget" drops another, or a
// "client use" whose choice of the current gateway silently vanished.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// r1cxF17Conn is a gateway at host with a well-formed pinned key.
func r1cxF17Conn(host string) config.ConnString {
	return config.ConnString{Host: host, Port: 2222, Person: "alice", Fingerprint: "SHA256:" + strings.Repeat("A", 43)}
}

// r1cxF17Store is a client directory with two gateways saved;
// two.example, saved last, is the current one.
func r1cxF17Store(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, host := range []string{"one.example", "two.example"} {
		if _, err := SaveConnectionNamed(dir, r1cxF17Conn(host), "", false); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// r1cxF17PauseFirst stops the first change that reaches the point
// between its read and its write until release is closed; every later
// change passes straight through.
func r1cxF17PauseFirst(t *testing.T) (paused <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	p := make(chan struct{})
	r := make(chan struct{})
	var once sync.Once
	midTransaction = func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(p)
			<-r
		}
	}
	t.Cleanup(func() { midTransaction = nil })
	return p, r
}

// r1cxF17Wait takes one result, or fails the test after a while.
func r1cxF17Wait(t *testing.T, what string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not finish in 10s", what)
	}
}

// r1cxF17Race runs first, stops it between its read and its write, runs
// second while it is stopped and gives second a moment to finish before
// the first one is let go. Before the fix, second finished in that
// moment, and first then wrote the list it had read before second's
// change.
func r1cxF17Race(t *testing.T, dir string, first, second func() error) {
	t.Helper()
	paused, release := r1cxF17PauseFirst(t)
	firstDone := make(chan error, 1)
	go func() { firstDone <- first() }()
	select {
	case <-paused:
	case <-time.After(10 * time.Second):
		t.Fatal("the first change never reached its write")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second() }()
	var early chan error
	select {
	case err := <-secondDone:
		early = make(chan error, 1)
		early <- err
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	r1cxF17Wait(t, "the first change", firstDone)
	if early != nil {
		secondDone = early
	}
	r1cxF17Wait(t, "the second change", secondDone)
}

func r1cxF17Load(t *testing.T, dir string) Connections {
	t.Helper()
	set, err := LoadConnections(dir)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestR1CX_F17_AGatewaySavedWhileAnotherChangeIsInFlightIsNotLost(t *testing.T) {
	cases := []struct {
		name   string
		change func(dir string) error
		// kept is the first change's own effect, which must be there too.
		kept func(set Connections) string
	}{
		{"save", func(dir string) error {
			_, err := SaveConnectionNamed(dir, r1cxF17Conn("three.example"), "", false)
			return err
		}, func(set Connections) string {
			if _, ok := set.Find("three.example"); !ok {
				return "the gateway the first change saved is gone"
			}
			return ""
		}},
		{"select", func(dir string) error {
			_, err := SelectConnection(dir, "one.example")
			return err
		}, nil},
		{"rename", func(dir string) error {
			_, err := RenameConnection(dir, "one.example", "Work")
			return err
		}, func(set Connections) string {
			if _, ok := set.Find("Work"); !ok {
				return "the rename the first change made is gone"
			}
			return ""
		}},
		{"forget the current one", func(dir string) error {
			_, err := ForgetConnection(dir)
			return err
		}, func(set Connections) string {
			if _, ok := set.Find("two.example"); ok {
				return "the gateway the first change forgot is back"
			}
			return ""
		}},
		{"forget by name", func(dir string) error {
			_, err := ForgetGateway(dir, "one.example")
			return err
		}, func(set Connections) string {
			if _, ok := set.Find("one.example"); ok {
				return "the gateway the first change forgot is back"
			}
			return ""
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := r1cxF17Store(t)
			r1cxF17Race(t, dir, func() error { return c.change(dir) }, func() error {
				_, err := SaveConnectionNamed(dir, r1cxF17Conn("late.example"), "", false)
				return err
			})
			set := r1cxF17Load(t, dir)
			if _, ok := set.Find("late.example"); !ok {
				t.Fatalf("a gateway saved while a %q was in flight is gone: the %s wrote back the list it had read before it (saved now: %s)", c.name, c.name, strings.Join(set.names(), ", "))
			}
			if c.kept != nil {
				if msg := c.kept(set); msg != "" {
					t.Fatalf("%s (saved now: %s)", msg, strings.Join(set.names(), ", "))
				}
			}
		})
	}
}

// The other half of the owner-facing case: not a gateway but the choice
// of the current one disappears.
func TestR1CX_F17_AChoiceOfTheCurrentGatewayMadeWhileASaveIsInFlightIsNotLost(t *testing.T) {
	dir := r1cxF17Store(t)
	r1cxF17Race(t, dir, func() error {
		_, err := SaveConnectionNamed(dir, r1cxF17Conn("three.example"), "", false)
		return err
	}, func() error {
		_, err := SelectConnection(dir, "one.example")
		return err
	})
	set := r1cxF17Load(t, dir)
	if !strings.EqualFold(set.Current, "one.example") {
		t.Fatalf("the current gateway chosen while a save was in flight is %q, want one.example: the save wrote back the pointer it had read before the choice", set.Current)
	}
	if _, ok := set.Find("three.example"); !ok {
		t.Fatalf("the gateway the save made is gone (saved now: %s)", strings.Join(set.names(), ", "))
	}
}

// The finding's own case is two PROCESSES - the window and a CLI
// command - so the lock must be the operating system's, not a mutex of
// one program. The helper below is this test binary run again: it saves
// child.example and stops between its read and its write until its
// standard input closes.
func TestR1CX_F17_TwoProcessesDoNotLoseEachOthersChange(t *testing.T) {
	dir := r1cxF17Store(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestR1CX_F17_HelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "IAMT_R1CX_F17_DIR="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var childErr strings.Builder
	cmd.Stderr = &childErr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	lines := bufio.NewScanner(stdout)
	pausedLine := make(chan bool, 1)
	go func() {
		for lines.Scan() {
			if lines.Text() == "r1cx-f17: paused" {
				pausedLine <- true
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
		close(pausedLine)
	}()
	select {
	case ok := <-pausedLine:
		if !ok {
			t.Fatalf("the helper process ended before its read: %s", childErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the helper process never reached its write")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := SaveConnectionNamed(dir, r1cxF17Conn("late.example"), "", false)
		secondDone <- err
	}()
	var early chan error
	select {
	case err := <-secondDone:
		early = make(chan error, 1)
		early <- err
	case <-time.After(300 * time.Millisecond):
	}
	_ = stdin.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("the helper process failed: %v: %s", err, childErr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the helper process did not finish")
	}
	if early != nil {
		secondDone = early
	}
	r1cxF17Wait(t, "this process's change", secondDone)

	set := r1cxF17Load(t, dir)
	for _, want := range []string{"child.example", "late.example"} {
		if _, ok := set.Find(want); !ok {
			t.Fatalf("%s is gone after two processes changed the saved connections at once (saved now: %s)", want, strings.Join(set.names(), ", "))
		}
	}
}

// TestR1CX_F17_HelperProcess is the second process of the test above;
// run on its own, without IAMT_R1CX_F17_DIR, it does nothing.
func TestR1CX_F17_HelperProcess(t *testing.T) {
	dir := os.Getenv("IAMT_R1CX_F17_DIR")
	if dir == "" {
		return
	}
	midTransaction = func() {
		fmt.Println("r1cx-f17: paused")
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	if _, err := SaveConnectionNamed(dir, r1cxF17Conn("child.example"), "", false); err != nil {
		t.Fatal(err)
	}
}

// A holder that never lets go - a stuck or suspended process - costs a
// change a bounded wait and a refusal in words, not a window that hangs.
func TestR1CX_F17_AChangeGivesUpInWordsOnAStuckHolder(t *testing.T) {
	dir := r1cxF17Store(t)
	unlock, err := lockStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	done := make(chan error, 1)
	go func() {
		_, err := SelectConnection(dir, "one.example")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "has not finished") {
			t.Fatalf("a change while another holds the store = %v, want the refusal that names the wait", err)
		}
	case <-time.After(storeLockWait + 10*time.Second):
		t.Fatalf("a change is still waiting for a holder that never lets go, %v past its own bound", 10*time.Second)
	}
	if set := r1cxF17Load(t, dir); !strings.EqualFold(set.Current, "two.example") {
		t.Fatalf("the refused change moved the current gateway to %q anyway", set.Current)
	}
}

// The lock file is a long-lived file of the client directory like any
// other: an entry planted at its name is refused, never followed - a
// lock taken on a planted target would exclude nobody, and a privileged
// command aimed at somebody's directory must not open through it.
func TestR1CX_F17_APlantAtTheLockNameIsRefusedNotFollowed(t *testing.T) {
	rows := []struct {
		kind  string
		plant func(t *testing.T, at string) (sentinelPath string, sentinel []byte)
	}{
		{"symlink", func(t *testing.T, at string) (string, []byte) { return testsupport.PlantSymlinkAt(t, at) }},
		{"file", func(t *testing.T, at string) (string, []byte) {
			target := at + ".sentinel"
			sentinel := testsupport.WriteSentinelFile(t, target)
			testsupport.PlantHardLinkAt(t, at, target)
			return target, sentinel
		}},
		{"directory", func(t *testing.T, at string) (string, []byte) {
			testsupport.PlantDirectoryAt(t, at)
			return "", nil
		}},
	}
	for _, r := range rows {
		t.Run(r.kind, func(t *testing.T) {
			// The list as a version from before the lock left it: saved,
			// and no lock file next to it yet.
			saved, err := os.ReadFile(ConnectionPath(r1cxF17Store(t)))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(ConnectionPath(dir), saved, 0o600); err != nil {
				t.Fatal(err)
			}
			at := filepath.Join(dir, storeLockFile)
			sentinelPath, sentinel := r.plant(t, at)
			err = testsupport.RunBounded(t, 10*time.Second, "a save with a "+r.kind+" planted at the lock's name", func() error {
				_, err := SaveConnectionNamed(dir, r1cxF17Conn("late.example"), "", false)
				if err == nil {
					return fmt.Errorf("the save went through a %s planted at %s", r.kind, at)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, sentinelPath, sentinel)
			}
			testsupport.AssertKindStillThere(t, at, r.kind)
			if _, ok := r1cxF17Load(t, dir).Find("late.example"); ok {
				t.Fatal("the refused save was written anyway")
			}
		})
	}
}
