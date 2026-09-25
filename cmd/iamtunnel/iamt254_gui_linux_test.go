//go:build linux && !nogui

package main

// iamt254_gui_linux_test.go — IAMT-254, the seam tests for the two
// Linux window actions: Connect's terminal launch and the pkexec
// relaunch behind "Restart as administrator" (IAMT-295, round 3: the
// ready line means the elevated WINDOW is up — the frame's
// OnWindowReady —, this copy's own stdout/stderr are moved to /dev/null
// before the line goes out, and the wait is bounded at five minutes,
// whose expiry is an ERROR that kills the process group. Round 4: the
// window must have SUBMITTED that first frame, and a redirect that did
// not fully succeed sends no line at all — an interrupted dup2 is
// retried, a refused one is an error. Round 5: the rule became total —
// every failure on the way (an unsavable pipe, a half-done redirect, a
// failed marker write) leaves the handover unconfirmed; exactly one
// code path writes the marker).
//
// Every point where a process would actually start — or where the
// kernel would be asked for a dup — is one of the gui_linux.go seams
// (linuxLookPath / linuxCommand / linuxStartDetached / linuxStartChild
// / linuxWaitChild / linuxKillGroup / linuxStat, and for the elevated
// handover linuxIsElevated / linuxStdoutIsTTY / linuxDup / linuxDup2 /
// linuxOpenDevNull / linuxNewFile); each test swaps the ones it needs
// for recording fakes and restores them by defer or t.Cleanup. No test
// launches a terminal, pkexec or any other external program — with one
// deliberate exception: *exec.ExitError cannot be fabricated (its
// ProcessState is built by the runtime), so the pkexecOutcome tests
// raise real ones with `sh -c "exit <code>"`. That is an exit-status
// fixture, neither a terminal nor pkexec, and it is the only honest way
// to pin the 126/127 wording.
//
// This file deliberately does not import internal/ui: the one test that
// reaches the window launcher itself (iamt295_readywindow_linux_test.go,
// through the linuxUIRun seam) must, and ui pulls gioui.org/app, which
// a GOOS=linux CGO_ENABLED=0 cross type-check cannot even load.
//
// Run on the Linux host: go test -count=1 ./cmd/iamtunnel/

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// seamSwap replaces one seam for the duration of a test.
func seamSwap[T any](t *testing.T, seam *T, fake T) {
	t.Helper()
	orig := *seam
	*seam = fake
	t.Cleanup(func() { *seam = orig })
}

// recordingStart remembers every child the action tried to launch.
type recordingStart struct {
	cmds []*exec.Cmd
	err  error // returned to the action when non-nil
}

func (r *recordingStart) start(cmd *exec.Cmd) error {
	if r.err != nil {
		return r.err
	}
	r.cmds = append(r.cmds, cmd)
	return nil
}

// exitErrorOf raises a real *exec.ExitError with the given status. See
// the file comment: sh -c "exit N" is an exit-status fixture.
func exitErrorOf(t *testing.T, code int) *exec.ExitError {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("fixture sh -c \"exit %d\" did not yield an ExitError: %v", code, err)
	}
	return ee
}

// fakeLookPath resolves exactly the names in found.
func fakeLookPath(found map[string]bool) func(string) (string, error) {
	return func(name string) (string, error) {
		if found[name] {
			return filepath.Join("/usr/bin", name), nil
		}
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
}

// fakeStatFor stats exactly the paths in exists (as plain files);
// everything else is ENOENT. The FileInfo is borrowed from a real file
// — findPkexec only asks IsDir of it — so no type is fabricated here.
func fakeStatFor(t *testing.T, exists map[string]bool) func(string) (os.FileInfo, error) {
	t.Helper()
	probe := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	borrowed, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	return func(path string) (os.FileInfo, error) {
		if exists[path] {
			return borrowed, nil
		}
		return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
}

// guiClientConnectLinuxArgv is the one-paragraph summary of the Connect
// action in test form: the first installed emulator wins, the child
// command travels as argv elements behind that emulator's separator —
// exe, "client", "connect", machine — in a session of its own.
//
// Canary: hard-code one separator (say "--") for every emulator, or
// build the command with sh -c "iamtunnel client connect "+machine.
// This test goes red: on the per-terminal separator expectations, and
// on the argv-equality assertion the moment the machine name is
// concatenated into a string.
func TestIAMT254_ClientConnectArgv(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cases := []struct {
		name     string
		found    map[string]bool
		wantTerm string
		wantSep  string
	}{
		{"x-terminal-emulator wins when everything is installed", map[string]bool{
			"x-terminal-emulator": true, "gnome-terminal": true, "konsole": true,
			"xfce4-terminal": true, "xterm": true,
		}, "x-terminal-emulator", "-e"},
		{"gnome-terminal alone", map[string]bool{"gnome-terminal": true}, "gnome-terminal", "--"},
		{"konsole alone", map[string]bool{"konsole": true}, "konsole", "-e"},
		{"xfce4-terminal alone", map[string]bool{"xfce4-terminal": true}, "xfce4-terminal", "-x"},
		{"xterm alone", map[string]bool{"xterm": true}, "xterm", "-e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seamSwap(t, &linuxLookPath, fakeLookPath(tc.found))
			rec := &recordingStart{}
			seamSwap(t, &linuxStartDetached, rec.start)

			msg, err := guiClientConnectLinux("testmachine")
			if err != nil {
				t.Fatalf("guiClientConnectLinux: %v", err)
			}
			if msg != "Opened a terminal on testmachine." {
				t.Fatalf("message %q — must match the Windows wording the frame already shows", msg)
			}
			if len(rec.cmds) != 1 {
				t.Fatalf("started %d children, want 1", len(rec.cmds))
			}
			cmd := rec.cmds[0]
			wantArgs := []string{tc.wantTerm}
			if tc.wantSep != "" {
				wantArgs = append(wantArgs, tc.wantSep)
			}
			wantArgs = append(wantArgs, exe, "client", "connect", "testmachine")
			if strings.Join(cmd.Args, "|") != strings.Join(wantArgs, "|") {
				t.Fatalf("argv = %v, want %v — the machine name must be one argv element behind %q", cmd.Args, wantArgs, tc.wantSep)
			}
			if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
				t.Fatal("terminal not started in its own session — it would die with the window's terminal (SIGHUP)")
			}
		})
	}
}

// TestIAMT254_ClientConnectRefusals pins the two refusal paths: a
// machine name that fails config.ValidName is refused before anything
// is launched, and a machine with no terminal at all is refused with
// the command that still works.
//
// Canary: drop the ValidName pre-check (rely on the emulator to error),
// or shorten the no-terminal message to not name the CLI command. This
// test goes red on the corresponding case.
func TestIAMT254_ClientConnectRefusals(t *testing.T) {
	seamSwap(t, &linuxLookPath, fakeLookPath(nil))
	rec := &recordingStart{}
	seamSwap(t, &linuxStartDetached, rec.start)

	if _, err := guiClientConnectLinux("bad name!"); err == nil {
		t.Fatal("invalid machine name not refused")
	} else if !strings.Contains(err.Error(), "machine") {
		t.Fatalf("refusal does not name the field: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Fatalf("invalid name launched %d children — the check must come first", len(rec.cmds))
	}

	_, err := guiClientConnectLinux("testmachine")
	if err == nil {
		t.Fatal("no terminal installed, yet Connect claimed success")
	}
	for _, want := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm", "iamtunnel client connect"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("no-terminal refusal must name %q: %v", want, err)
		}
	}
	if len(rec.cmds) != 0 {
		t.Fatalf("no-terminal path launched %d children", len(rec.cmds))
	}
}

// TestIAMT254_ClientConnectStartFailure surfaces a launch failure as
// the action's error, worded like its Windows sibling ("could not open
// a terminal").
func TestIAMT254_ClientConnectStartFailure(t *testing.T) {
	seamSwap(t, &linuxLookPath, fakeLookPath(map[string]bool{"xterm": true}))
	seamSwap(t, &linuxStartDetached, (&recordingStart{err: errors.New("fork failed")}).start)

	if _, err := guiClientConnectLinux("testmachine"); err == nil || !strings.Contains(err.Error(), "could not open a terminal") {
		t.Fatalf("start failure not worded as a terminal failure: %v", err)
	}
}

// TestIAMT254_RestartAsAdminPkexec pins the relaunch end to end, on the
// faked seams: the argv (this binary, original arguments, nothing
// rebuilt, behind the FIXED /usr/bin/pkexec — never the caller's PATH,
// R1-CX F-25), its own session, the watched stdout, and every outcome
// the handover can produce — ready line confirms, 126/127 refused,
// another code failed, a silent clean exit NOT a handover, tool absent
// refused.
//
// Canary: drop the 126/127 branch in pkexecOutcome (polkit internals
// would reach the banner), rebuild the arguments instead of passing
// os.Args[1:] through, drop Setsid, read a plain exit as a confirmed
// handover again, or resolve pkexec through LookPath once more. This
// test goes red on the corresponding subtest.
func TestIAMT254_RestartAsAdminPkexec(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	savedArgs := append([]string(nil), os.Args[1:]...)

	t.Run("argv preserves the original arguments, session of its own", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		rec := &recordingStart{}
		// The child confirms the handover the moment it is started: the
		// ready line travels through the watcher the action installed
		// as Stdout, while the wait goroutine stays parked until
		// cleanup — the action must come back nil on the ready path
		// alone, without needing pkexec to exit.
		release := make(chan struct{})
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { <-release; return nil })
		t.Cleanup(func() { close(release) })
		seamSwap(t, &linuxStartChild, func(cmd *exec.Cmd) error {
			if serr := rec.start(cmd); serr != nil {
				return serr
			}
			cmd.Stdout.Write([]byte(elevatedReadyLine + "\n"))
			return nil
		})

		if err := guiRestartAsAdminLinux(); err != nil {
			t.Fatalf("the elevated copy confirmed the handover, yet an error came back: %v", err)
		}
		if len(rec.cmds) != 1 {
			t.Fatalf("started %d children, want 1", len(rec.cmds))
		}
		cmd := rec.cmds[0]
		if _, ok := cmd.Stdout.(*readyWatcher); !ok {
			t.Fatalf("pkexec stdout is not watched for the ready line (got %T) — the confirmation would be lost", cmd.Stdout)
		}
		want := append([]string{"/usr/bin/pkexec", exe}, savedArgs...)
		if strings.Join(cmd.Args, "|") != strings.Join(want, "|") {
			t.Fatalf("argv = %v, want %v — the elevated copy must receive the original arguments verbatim", cmd.Args, want)
		}
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
			t.Fatal("pkexec not started in its own session — the elevated copy would die with the original terminal (SIGHUP)")
		}
	})

	t.Run("dialog dismissed (126) is a refusal, not polkit internals", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		seamSwap(t, &linuxStartChild, (&recordingStart{}).start)
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { return exitErrorOf(t, 126) })

		err := guiRestartAsAdminLinux()
		if err == nil || !strings.Contains(err.Error(), "permission was not granted") {
			t.Fatalf("dismissed dialog must read as a declined grant, got: %v", err)
		}
	})

	t.Run("authentication failed (127) reads the same", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		seamSwap(t, &linuxStartChild, (&recordingStart{}).start)
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { return exitErrorOf(t, 127) })

		if err := guiRestartAsAdminLinux(); err == nil || !strings.Contains(err.Error(), "permission was not granted") {
			t.Fatalf("failed authentication must read as a declined grant, got: %v", err)
		}
	})

	t.Run("other pkexec failure surfaces in its own words", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		seamSwap(t, &linuxStartChild, (&recordingStart{}).start)
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { return exitErrorOf(t, 3) })

		err := guiRestartAsAdminLinux()
		if err == nil || !strings.Contains(err.Error(), "exit status 3") {
			t.Fatalf("unexpected pkexec failure must keep its own words, got: %v", err)
		}
	})

	t.Run("a silent clean exit is not a confirmed handover", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		rec := &recordingStart{}
		seamSwap(t, &linuxStartChild, rec.start)
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { return nil })

		if err := guiRestartAsAdminLinux(); err == nil || !strings.Contains(err.Error(), "without confirming the restart") {
			t.Fatalf("clean exit with no ready line must keep the window open, got: %v", err)
		}
		if len(rec.cmds) != 1 {
			t.Fatalf("started %d children, want 1", len(rec.cmds))
		}
	})

	t.Run("the ready line beats a simultaneous clean exit", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		rec := &recordingStart{}
		seamSwap(t, &linuxStartChild, rec.start)
		seamSwap(t, &linuxWaitChild, func(cmd *exec.Cmd) error {
			cmd.Stdout.Write([]byte(elevatedReadyLine + "\n"))
			return nil
		})

		if err := guiRestartAsAdminLinux(); err != nil {
			t.Fatalf("a confirmed handover must win even when pkexec also exits, got: %v", err)
		}
	})

	t.Run("pkexec absent is a refusal naming the fix", func(t *testing.T) {
		seamSwap(t, &linuxStat, fakeStatFor(t, nil))
		rec := &recordingStart{}
		seamSwap(t, &linuxStartChild, rec.start)

		err := guiRestartAsAdminLinux()
		if err == nil || !strings.Contains(err.Error(), "pkexec is not installed") {
			t.Fatalf("absent pkexec must be refused with the root-shell fix, got: %v", err)
		}
		if len(rec.cmds) != 0 {
			t.Fatalf("absent pkexec launched %d children", len(rec.cmds))
		}
	})

	t.Run("pkexec is launched from the fixed system paths, not the caller's PATH", func(t *testing.T) {
		// R1-CX F-25: the invoking user shapes their own PATH, and pkexec
		// is about to carry this binary past root's door — resolving it
		// through that PATH lets anyone who can plant a file decide what
		// actually runs. Here the PATH refuses EVERY name (pkexec
		// included); the relaunch must still go ahead from the fixed
		// system path — neither a refusal nor anything taken from PATH.
		seamSwap(t, &linuxLookPath, fakeLookPath(nil))
		seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
		rec := &recordingStart{}
		release := make(chan struct{})
		seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { <-release; return nil })
		t.Cleanup(func() { close(release) })
		seamSwap(t, &linuxStartChild, func(cmd *exec.Cmd) error {
			if serr := rec.start(cmd); serr != nil {
				return serr
			}
			cmd.Stdout.Write([]byte(elevatedReadyLine + "\n"))
			return nil
		})

		if err := guiRestartAsAdminLinux(); err != nil {
			t.Fatalf("the PATH named no pkexec at all, yet the relaunch did not go ahead from the fixed system path either: %v", err)
		}
		if len(rec.cmds) != 1 {
			t.Fatalf("started %d children, want 1", len(rec.cmds))
		}
		if got := rec.cmds[0].Args[0]; got != "/usr/bin/pkexec" {
			t.Fatalf("pkexec launched as %q, want the fixed system path /usr/bin/pkexec", got)
		}
	})
}

// TestIAMT295_LivingPkexecIsNotSuccess is THE canary for IAMT-295. A
// pkexec that is still alive, with no ready line, means the polkit
// dialog is (still) open — it can sit there for minutes and still be
// cancelled, so it must never read as success. The pre-fix code gave up
// at a 3-second deadline, returned nil, and the caller closed the
// window while the dialog was still up. The parked wait below
// deliberately outlives that old deadline (3.5 s — the one slow test in
// this file, still well inside the current five-minute bound): if the
// deadline-as-success guess ever comes back, this test goes red at
// about the 3-second mark.
//
// Canary: restore the old
// `case <-time.After(pkexecRelaunchWait): return nil` branch. This test
// goes red with:
//
//	pkexec was still alive with no ready line, yet the action finished
//	(<nil>) after ~3s — a living pkexec must never read as success (the
//	3-second-deadline guess is back)
func TestIAMT295_LivingPkexecIsNotSuccess(t *testing.T) {
	seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
	rec := &recordingStart{}
	seamSwap(t, &linuxStartChild, rec.start)
	refused := exitErrorOf(t, 126)
	release := make(chan struct{})
	seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { <-release; return refused })
	// One owner for the close: the body's "dialog dismissed" step and
	// the cleanup share this OnceFunc, so the release channel closes
	// exactly once on every path (a body close plus a cleanup close
	// panicked the cleanup and killed the whole package run).
	closeRelease := sync.OnceFunc(func() { close(release) })
	t.Cleanup(closeRelease)

	res := make(chan error, 1)
	started := time.Now()
	go func() { res <- guiRestartAsAdminLinux() }()

	// The dialog stays open well past the old 3-second deadline: the
	// action must not return anything — neither success nor an error —
	// while pkexec is alive and has not spoken.
	select {
	case err := <-res:
		t.Fatalf("pkexec was still alive with no ready line, yet the action finished (%v) after %s — a living pkexec must never read as success (the 3-second-deadline guess is back)", err, time.Since(started).Round(100*time.Millisecond))
	case <-time.After(3500 * time.Millisecond):
		// Still nothing: the window is up, the dialog is still open,
		// nothing has been decided. Exactly right.
	}

	closeRelease() // the dialog is finally dismissed
	if err := <-res; err == nil || !strings.Contains(err.Error(), "permission was not granted") {
		t.Fatalf("dismissed dialog must read as a declined grant, got: %v", err)
	}
	if len(rec.cmds) != 1 {
		t.Fatalf("started %d children, want 1", len(rec.cmds))
	}
}

// TestIAMT295_PkexecTimeoutIsAnError pins the bounded wait (round 3,
// the hung-pkexec finding): a pkexec that never exits and never prints
// the ready line must be abandoned as an ERROR — never success — and
// its process group killed, so the frame gets its restarting flag back
// and the person can simply try again.
//
// Canary: treat the timer's expiry as success (restore the old
// `case <-time.After(...): return nil` reading, in any form). This test
// goes red with:
//
//	a pkexec that never answered read as success after ~40ms — a
//	timed-out wait must be an error that kills the process group (the
//	deadline-as-success guess is back)
func TestIAMT295_PkexecTimeoutIsAnError(t *testing.T) {
	seamSwap(t, &linuxStat, fakeStatFor(t, map[string]bool{"/usr/bin/pkexec": true}))
	seamSwap(t, &linuxStartChild, (&recordingStart{}).start)
	refused := exitErrorOf(t, 126)
	release := make(chan struct{})
	seamSwap(t, &linuxWaitChild, func(*exec.Cmd) error { <-release; return refused })
	// The same single-owner close discipline as the canary above: the
	// parked Wait is let go exactly once, from here or from cleanup.
	closeRelease := sync.OnceFunc(func() { close(release) })
	t.Cleanup(closeRelease)
	seamSwap(t, &pkexecConfirmTimeout, 40*time.Millisecond)
	killed := false
	seamSwap(t, &linuxKillGroup, func(*exec.Cmd) error { killed = true; return nil })

	started := time.Now()
	err := guiRestartAsAdminLinux()

	if err == nil {
		t.Fatalf("a pkexec that never answered read as success after %s — a timed-out wait must be an error that kills the process group (the deadline-as-success guess is back)", time.Since(started).Round(10*time.Millisecond))
	}
	if !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("the timeout must be worded as an abandoned attempt, got: %v", err)
	}
	if !killed {
		t.Fatal("the timed-out wait returned without killing the hung pkexec process group")
	}
	closeRelease() // the parked Wait lands in the buffered done; nothing leaks
}

// TestIAMT295_ReadyWatcherLineReassembly pins the watcher itself: the
// ready line is recognized wherever it lands in the stream — split
// across writes, carried with \r\n — everything is forwarded verbatim
// into the buffer, near-miss lines confirm nothing, and no number of
// repeated markers — twice in one Write, across Writes, or drained
// after the pkexec Wait returned — may close the channel twice
// (sync.Once; a double close panics the test on the spot).
//
// Canary: require the marker to arrive in one whole Write (drop the
// line reassembly), or match a prefix instead of the whole line. This
// test goes red on the split-write case.
func TestIAMT295_ReadyWatcherLineReassembly(t *testing.T) {
	w := newReadyWatcher()
	w.Write([]byte("pkexec: some noise\niamtunnel: elevat"))
	select {
	case <-w.ready:
		t.Fatal("ready fired on a partial line")
	default:
	}
	w.Write([]byte("ed session ready\nmore output\n"))
	select {
	case <-w.ready:
	default:
		t.Fatal("ready line split across two writes was not recognized")
	}
	if got := w.buf.String(); got != "pkexec: some noise\niamtunnel: elevated session ready\nmore output\n" {
		t.Fatalf("watcher did not forward every byte verbatim: %q", got)
	}
	// A ready line with a trailing \r is still the marker, and NO number
	// of further markers — across writes, twice in ONE write, or drained
	// after the pkexec Wait has already returned (the exec copier may
	// still be emptying the pipe) — may close the channel twice: any
	// double close panics right here.
	w.Write([]byte(elevatedReadyLine + "\r\n"))
	w.Write([]byte(elevatedReadyLine + "\n" + elevatedReadyLine + "\n"))
	w.Write([]byte("later noise\n" + elevatedReadyLine + "\n"))
	<-w.ready // closed once, and stays closed

	near := newReadyWatcher()
	near.Write([]byte("iamtunnel: elevated session NOT ready\n"))
	select {
	case <-near.ready:
		t.Fatal("a near-miss line must not confirm the handover")
	default:
	}
}

// announceRecorder routes the elevated side of the handover into
// memory: the order the plumbing ran in ("dup", "devnull", "dup2",
// "newfile", "write", "close"), which dup2 pairs were issued, what the
// marker was and which fd it travelled on. Since round 5 there is no
// fallback channel left to record — the marker has exactly one path;
// anything written straight to the real os.Stdout is caught separately
// by captureStdout. armAnnounce installs the recorder; the caller still
// pins linuxIsElevated / linuxStdoutIsTTY per case.
type announceRecorder struct {
	order     []string
	dup2s     [][2]int
	marker    string
	markerFD  uintptr
	devnullFD int
}

// recBuf is the writer the production code builds over the saved fd.
type recBuf struct{ r *announceRecorder }

func (w *recBuf) Write(p []byte) (int, error) {
	w.r.order = append(w.r.order, "write")
	w.r.marker = string(p)
	return len(p), nil
}

func (w *recBuf) Close() error {
	w.r.order = append(w.r.order, "close")
	return nil
}

func armAnnounce(t *testing.T) *announceRecorder {
	t.Helper()
	r := &announceRecorder{}
	seamSwap(t, &linuxDup, func(int) (int, error) {
		r.order = append(r.order, "dup")
		return 7, nil // the fake saved fd
	})
	seamSwap(t, &linuxDup2, func(oldfd, newfd int) error {
		r.order = append(r.order, "dup2")
		r.dup2s = append(r.dup2s, [2]int{oldfd, newfd})
		return nil
	})
	seamSwap(t, &linuxOpenDevNull, func() (*os.File, error) {
		r.order = append(r.order, "devnull")
		f, err := os.CreateTemp(t.TempDir(), "devnull")
		if err != nil {
			return nil, err
		}
		r.devnullFD = int(f.Fd())
		return f, nil
	})
	seamSwap(t, &linuxNewFile, func(fd uintptr, _ string) io.Writer {
		r.order = append(r.order, "newfile")
		r.markerFD = fd
		return &recBuf{r}
	})
	return r
}

func (r *announceRecorder) announcedAnywhere() bool {
	return r.marker != ""
}

// capturedStdout is os.Stdout swapped for a pipe for the duration of a
// test: anything the code under test writes "directly to stdout" — the
// old dup-failure fallback did exactly that — lands in the pipe instead
// of the test's own output, where drain() can catch it.
type capturedStdout struct {
	r *os.File
	w *os.File
}

func captureStdout(t *testing.T) *capturedStdout {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = orig
		r.Close()
		w.Close()
	})
	return &capturedStdout{r: r, w: w}
}

// drain returns whatever was written to the captured stdout — a
// deadline read, so a silent stdout returns "" without blocking.
func (c *capturedStdout) drain() string {
	if err := c.r.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, _ := c.r.Read(buf)
	return string(buf[:n])
}

// TestIAMT295_AnnounceElevatedSession pins the elevated copy's GATES:
// the line can only go out when the session is root AND stdout is not a
// terminal — a piped stdout (the pkexec relaunch) speaks, a person at a
// root shell and a non-root session say nothing. Round 5: an unsavable
// pipe speaks on NO channel — the old dup-failure fallback that
// announced on the still-piped stdout is exactly the
// confirmed-then-killed handover this file exists to prevent.
//
// Canary: drop the tty check (the line would be noise at a root shell),
// the elevation check (every GUI start would claim a handover it did
// not do), or restore the dup-failure fallback write. This test goes
// red on the corresponding case.
func TestIAMT295_AnnounceElevatedSession(t *testing.T) {
	cases := []struct {
		name     string
		elevated bool
		elevErr  error
		tty      bool
		silent   bool
	}{
		{"root with piped stdout announces", true, nil, false, false},
		{"root at a terminal says nothing", true, nil, true, true},
		{"not root says nothing", false, nil, false, true},
		{"failed elevation check says nothing", true, errors.New("boom"), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seamSwap(t, &linuxIsElevated, func() (bool, error) { return tc.elevated, tc.elevErr })
			seamSwap(t, &linuxStdoutIsTTY, func() bool { return tc.tty })
			r := armAnnounce(t)

			announceElevatedSession()

			if tc.silent && r.announcedAnywhere() {
				t.Fatalf("a silent gate announced anyway (marker %q)", r.marker)
			}
			if !tc.silent && r.marker != elevatedReadyLine+"\n" {
				t.Fatalf("announce wrote %q on the saved pipe, want %q", r.marker, elevatedReadyLine+"\n")
			}
		})
	}

	t.Run("an unsavable pipe announces nowhere", func(t *testing.T) {
		seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
		seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
		r := armAnnounce(t)
		seamSwap(t, &linuxDup, func(int) (int, error) { return -1, syscall.EMFILE })
		stdout := captureStdout(t)

		announceElevatedSession()

		if r.announcedAnywhere() {
			t.Fatalf("the ready line went out although the pipe could not be saved (marker %q) — fd 1 and fd 2 still end in the pipe whose only reader the original closes the instant it reads the marker; the confirmed window dies of EPIPE/SIGPIPE on its very next write", r.marker)
		}
		if leaked := stdout.drain(); leaked != "" {
			t.Fatalf("the still-piped stdout carried %q while the pipe could not be saved — a marker on the old channel confirms a handover this window's next write can kill", leaked)
		}
		if len(r.dup2s) != 0 {
			t.Fatalf("nothing was saved, so nothing may be moved aside (dup2 %v)", r.dup2s)
		}
	})
}

// TestIAMT295_StdioIsVoidedBeforeTheReadyLine pins the fd protocol the
// marker rides on (round 3, the EPIPE finding): the pipe is saved with
// a dup FIRST, then this copy's own stdout AND stderr move to /dev/null,
// then — and only then — the marker is written on the SAVED fd, which is
// closed. The original ends itself the moment it has read the line and
// takes the pipe's only reader with it; anything the elevated GUI prints
// afterwards must already point at the void, or the next write to fd 1
// (SIGPIPE) or fd 2 (EPIPE) kills the very window the line announced.
//
// Canary: write the marker before (or without) the redirect, or skip
// the redirect entirely. This test goes red with:
//
//	handover plumbing order = [dup,newfile,devnull,write,dup2,dup2,close]
//	(or any order whose dup2s are not both before "write") — the ready
//	line went out while this copy's stdout/stderr still pointed at the
//	pipe: once the original exits, the elevated GUI dies of EPIPE/SIGPIPE
//	on its next write
func TestIAMT295_StdioIsVoidedBeforeTheReadyLine(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
	r := armAnnounce(t)

	announceElevatedSession()

	want := "dup,newfile,devnull,dup2,dup2,write,close"
	if got := strings.Join(r.order, ","); got != want {
		t.Fatalf("handover plumbing order = [%s], want [%s] — the ready line went out while this copy's stdout/stderr still pointed at the pipe: once the original exits, the elevated GUI dies of EPIPE/SIGPIPE on its next write", got, want)
	}
	wantPairs := [][2]int{
		{r.devnullFD, int(os.Stdout.Fd())},
		{r.devnullFD, int(os.Stderr.Fd())},
	}
	if !reflect.DeepEqual(r.dup2s, wantPairs) {
		t.Fatalf("dup2 pairs = %v, want %v — exactly this copy's fd 1 and fd 2 move to the void", r.dup2s, wantPairs)
	}
	if r.marker != elevatedReadyLine+"\n" {
		t.Fatalf("marker = %q, want %q", r.marker, elevatedReadyLine+"\n")
	}
	if r.markerFD != 7 {
		t.Fatalf("marker travelled on fd %d, want the SAVED dup (7) — the marker must not depend on what fd 1 becomes", r.markerFD)
	}
}

// TestIAMT295_FailedDup2SendsNoMarker pins the round-4 rule the dropped
// dup2 error broke: a redirect that did not fully succeed means the
// marker is NEVER sent and the saved fd is closed. A half-voided copy
// (fd 1 moved, fd 2 still the parent's pipe) that announced itself would
// hand the original a confirmed handover whose window its very next
// write — a panic report lands straight on fd 2 — can kill.
//
// Canary: ignore the second dup2's error and announce anyway (the
// round-3 shape). This test goes red with:
//
//	the ready line went out on a half-voided stdio (dup2 to stderr
//	failed: ebadf) — the original confirms the handover and ends itself,
//	and this window's next write to fd 2 dies of EPIPE
func TestIAMT295_FailedDup2SendsNoMarker(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
	r := armAnnounce(t)
	calls := 0
	seamSwap(t, &linuxDup2, func(oldfd, newfd int) error {
		calls++
		r.order = append(r.order, "dup2")
		r.dup2s = append(r.dup2s, [2]int{oldfd, newfd})
		if calls == 2 { // stdout voided, stderr refused
			return syscall.EBADF
		}
		return nil
	})

	announceElevatedSession()

	if r.announcedAnywhere() {
		t.Fatalf("the ready line went out on a half-voided stdio (dup2 to stderr failed: %v) — the original confirms the handover and ends itself, and this window's next write to fd 2 dies of EPIPE", syscall.EBADF)
	}
	if len(r.dup2s) != 2 {
		t.Fatalf("the redirect must attempt both fds before giving up, dup2 attempts = %d (%v)", len(r.dup2s), r.dup2s)
	}
	if len(r.order) == 0 || r.order[len(r.order)-1] != "close" {
		t.Fatalf("a refused redirect must close the saved fd and say nothing, order = %v", r.order)
	}
}

// TestIAMT295_EINTRIsRetriedNotFatal pins the retry: one EINTR from
// dup2 is the kernel saying "interrupted before it happened" — the
// redirect retries and the handover goes out. A dropped or fatal EINTR
// would leave a perfectly good window unannounced and the original
// waiting until pkexec exits or the timeout fires.
//
// Canary: treat EINTR as an ordinary dup2 failure (no retry, no
// announce). This test goes red with:
//
//	an EINTR from dup2 killed the handover (marker "") — a
//	signal-interrupted dup2 did not happen; it must be retried, not read
//	as a failed redirect
func TestIAMT295_EINTRIsRetriedNotFatal(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
	r := armAnnounce(t)
	calls := 0
	seamSwap(t, &linuxDup2, func(oldfd, newfd int) error {
		calls++
		r.order = append(r.order, "dup2")
		r.dup2s = append(r.dup2s, [2]int{oldfd, newfd})
		if calls == 1 { // the very first dup2 is interrupted
			return syscall.EINTR
		}
		return nil
	})

	announceElevatedSession()

	// stdout: one interrupted attempt + the retry; stderr: one clean call.
	if calls != 3 {
		t.Fatalf("dup2 ran %d time(s), want 3 — the interrupted call must be retried, and both fds must still be voided", calls)
	}
	if r.marker != elevatedReadyLine+"\n" {
		t.Fatalf("an EINTR from dup2 killed the handover (marker %q) — a signal-interrupted dup2 did not happen; it must be retried, not read as a failed redirect", r.marker)
	}
}

// failingBuf is the saved pipe's writer the day the write itself fails:
// no bytes go anywhere, the error goes back to the caller.
type failingBuf struct{ r *announceRecorder }

func (w *failingBuf) Write(p []byte) (int, error) {
	w.r.order = append(w.r.order, "write")
	return 0, errors.New("ebadf")
}

func (w *failingBuf) Close() error {
	w.r.order = append(w.r.order, "close")
	return nil
}

// TestIAMT295_FailedMarkerWriteIsNotAHandover pins the last unconfirmed
// path (round 5): a marker write that fails reads as a handover that
// never happened — the saved fd is given back, and no attempt is made
// on any other channel. A fallback here would be the dup-failure bug
// again in miniature: the original would end itself on a confirmation
// whose very write failed, while this copy still holds an end of the
// pipe it closes.
//
// Canary: on write failure fall back to writing the marker on the
// still-piped stdout (or retry the handover some other way). This test
// goes red with:
//
//	the failed marker write was retried on the still-piped stdout
//	("iamtunnel: elevated session ready\n") — an unconfirmed handover
//	stays unconfirmed: no retry, no fallback, the original keeps its
//	window
func TestIAMT295_FailedMarkerWriteIsNotAHandover(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
	r := armAnnounce(t)
	seamSwap(t, &linuxNewFile, func(fd uintptr, _ string) io.Writer {
		r.order = append(r.order, "newfile")
		r.markerFD = fd
		return &failingBuf{r}
	})
	stdout := captureStdout(t)

	announceElevatedSession()

	if r.marker != "" {
		t.Fatalf("a failed marker write must not count as a handover (marker %q) — the original ends itself on a confirmation whose very write failed", r.marker)
	}
	if n := strings.Count(strings.Join(r.order, ","), "write"); n != 1 {
		t.Fatalf("a failed marker write was followed by %d more write(s) (order %v) — an unconfirmed handover stays unconfirmed: no retry, no fallback to the old channel", n-1, r.order)
	}
	if len(r.order) == 0 || r.order[len(r.order)-1] != "close" {
		t.Fatalf("the saved fd must be given back on the failing path too, order = %v", r.order)
	}
	if leaked := stdout.drain(); leaked != "" {
		t.Fatalf("the failed marker write was retried on the still-piped stdout (%q) — an unconfirmed handover stays unconfirmed: no retry, no fallback, the original keeps its window", leaked)
	}
}

// TestIAMT254_PkexecOutcomeWording pins the decision table in isolation
// (pkexecOutcome), so a future edit cannot quietly widen 126/127 into
// "show polkit internals" or read a silent clean exit as a confirmed
// handover.
//
// Canary: change the 126/127 pair to just 127, or make the nil case
// return nil again. This test goes red on the corresponding case.
func TestIAMT254_PkexecOutcomeWording(t *testing.T) {
	err := pkexecOutcome(nil, "")
	if err == nil || !strings.Contains(err.Error(), "without confirming the restart") {
		t.Fatalf("a silent clean exit is not a confirmed handover — the window must stay, got: %v", err)
	}
	for _, code := range []int{126, 127} {
		err := pkexecOutcome(exitErrorOf(t, code), "")
		if err == nil || !strings.Contains(err.Error(), "permission was not granted") {
			t.Fatalf("pkexec exit %d must read as a declined grant, got: %v", code, err)
		}
	}
	err = pkexecOutcome(errors.New("polkit agent vanished"), "")
	if err == nil || err.Error() != "polkit agent vanished" {
		t.Fatalf("raw error must survive untouched when there is no output, got: %v", err)
	}
	err = pkexecOutcome(exitErrorOf(t, 3), "  a door check failed\n")
	if err == nil || err.Error() != "a door check failed" {
		t.Fatalf("captured output must become the message verbatim, got: %v", err)
	}
}

// Compile-time guard that the action implementations still satisfy
// ui.Actions' shapes (a drift would surface on the Linux build only —
// pin it here too).
var (
	_ func(string) (string, error) = guiClientConnectLinux
	_ func() error                 = guiRestartAsAdminLinux
)
