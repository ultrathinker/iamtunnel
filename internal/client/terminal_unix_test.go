//go:build linux || darwin

package client

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeTermAPI records the calls openUnixTerminal made and the
// snapshots it handed back, and lets a test pick what the underlying
// ioctl would do (snapshot the canonical "cooked" Linux/macOS values,
// fail, or return nil winsize). Tests for the signal path use it to
// verify that restore() was called and the exit seam was triggered.
//
// sizePerFd lets a test assign different winsizes to the in and out
// fds, which the size fallback in unixTerminal.size() uses to
// distinguish "stdout is a tty" from "stdout is a file, stdin is the
// tty" — exactly the `client connect M > session.log` case.
type fakeTermAPI struct {
	mu sync.Mutex

	// current is what getTermios returns. Tests preload this before
	// openUnixTerminal; the production opener reads it once.
	current termiosSnapshot
	// setCalls is the sequence of snapshots passed to setTermios.
	setCalls []termiosSnapshot
	// winsize is the default per-fd response when sizePerFd is empty.
	winsize terminalSize
	// winsizeOK controls whether getWinSize reports the size as known.
	winsizeOK bool
	// sizePerFd maps fd -> (size, ok). When non-empty, it overrides
	// the default winsize/winsizeOK for those fds.
	sizePerFd map[uintptr]fakeSize
	// setErr makes the next setTermios call fail with this error.
	setErr error
}

// fakeSize carries both the size and the ok flag so a test can
// express "this fd is not a tty" with ok=false.
type fakeSize struct {
	size terminalSize
	ok   bool
}

func (f *fakeTermAPI) getTermios(uintptr) (termiosSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current, nil
}

func (f *fakeTermAPI) setTermios(_ uintptr, s termiosSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.setCalls = append(f.setCalls, s)
	f.current = s
	return nil
}

func (f *fakeTermAPI) getWinSize(fd uintptr) (terminalSize, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if entry, ok := f.sizePerFd[fd]; ok {
		return entry.size, entry.ok
	}
	return f.winsize, f.winsizeOK
}

// lastSet returns the most recent setTermios snapshot. It panics if no
// snapshot was set, which is the right shape for an assertion: the
// test wants a specific call, not "any call".
func (f *fakeTermAPI) lastSet(t *testing.T) termiosSnapshot {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.setCalls) == 0 {
		t.Fatal("no setTermios call was made")
	}
	return f.setCalls[len(f.setCalls)-1]
}

// callCount returns how many times setTermios was called.
func (f *fakeTermAPI) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.setCalls)
}

// canonicalCooked is the termios shape a "just after `stty sane`"
// cooked-mode terminal has on this OS: ECHO|ICANON|ISIG|IEXTEN set in
// lflag; ICRNL in iflag; OPOST in oflag; CS8|PARENB in cflag. The bits
// come from x/sys/unix by name, so the fake models the real kernel
// values (IAMT-244: hand-typed numbers let a wrong ICANON pass).
func canonicalCooked() termiosSnapshot {
	return termiosSnapshot{
		iflag:  unix.ICRNL,
		oflag:  unix.OPOST,
		cflag:  unix.CS8 | unix.PARENB,
		lflag:  unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN,
		ispeed: 0,
		ospeed: 0,
	}
}

// fakeSubscribe holds the channel it would signal on. The fake
// never actually subscribes to OS signals, so the test can drive it
// from a goroutine it owns. stopCount counts the number of times
// signal.Stop was called so tests can assert "stop happened exactly
// once".
type fakeSubscribe struct {
	mu        sync.Mutex
	gotCh     chan<- os.Signal // installed channel (if non-nil)
	signals   []os.Signal      // signals it was asked to subscribe to
	stopCount int
}

func (f *fakeSubscribe) subscribe(c chan<- os.Signal, sig ...os.Signal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotCh = c
	f.signals = append([]os.Signal(nil), sig...)
}

func (f *fakeSubscribe) stop(c chan<- os.Signal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gotCh == c {
		f.gotCh = nil
	}
	f.stopCount++
}

// withSignalSeam swaps the package-level signal/fatal seams for the
// duration of one test, restoring them on t.Cleanup. Every test that
// drives openUnixTerminal uses this so an accidental production
// signal.Notify / os.Exit cannot leak across tests.
func withSignalSeam(t *testing.T, sub signalSubscriber, stop signalStopper, exit func(int)) {
	t.Helper()
	prevSub, prevStop, prevExit := signalSubscribe, signalStop, fatalExit
	signalSubscribe = sub
	signalStop = stop
	fatalExit = exit
	t.Cleanup(func() {
		signalSubscribe = prevSub
		signalStop = prevStop
		fatalExit = prevExit
	})
}

// TestUnixTerminalRawModeAndExactRestore proves the two essential
// console facts without ever touching the owner's real tty: raw input
// is installed on a fake console, then the original bit patterns are
// restored exactly rather than replaced by guessed defaults. It is
// the Unix analogue of TestWindowsTerminalRawModeAndExactRestore.
func TestUnixTerminalRawModeAndExactRestore(t *testing.T) {
	api := &fakeTermAPI{current: canonicalCooked()}
	withSignalSeam(t, nil, nil, func(int) { t.Fatal("fatalExit called in unit test") })
	const in, out uintptr = 11, 12
	terminal, err := openUnixTerminal(in, out, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}

	wantRaw := makeRaw(canonicalCooked())
	if got := api.lastSet(t); got != wantRaw {
		t.Fatalf("input raw mode = %+v, want %+v", got, wantRaw)
	}
	// raw.lflag must have ECHO|ICANON|ISIG|IEXTEN all cleared.
	cleared := wantRaw.lflag & lflagClearRaw
	if cleared != 0 {
		t.Errorf("raw lflag still has lflagClearRaw bits set: %#x", cleared)
	}
	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := api.lastSet(t); got != canonicalCooked() {
		t.Fatalf("restored snapshot = %+v, want original %+v", got, canonicalCooked())
	}
	if api.callCount() != 2 {
		t.Errorf("setTermios called %d times, want 2 (raw install + restore)", api.callCount())
	}
}

// TestUnixTerminalNonTtyReturnsInert proves that a stdin which cannot
// answer a termios ioctl (e.g. a pipe, a CI harness) is handled by
// returning inertTerminal without error — that path is how
// "client connect" still works through `echo input | iamtunnel client
// connect MACHINE`.
func TestUnixTerminalNonTtyReturnsInert(t *testing.T) {
	api := &errAPI{getErr: errors.New("not a tty")}
	withSignalSeam(t, nil, nil, nil)
	terminal, err := openUnixTerminal(1, 2, api)
	if err != nil {
		t.Fatalf("openUnixTerminal on non-tty: %v", err)
	}
	if _, ok := terminal.(inertTerminal); !ok {
		t.Fatalf("terminal type = %T, want inertTerminal", terminal)
	}
	if api.setCount != 0 {
		t.Errorf("setTermios called on a non-tty path; want 0 calls")
	}
}

// TestUnixTerminalRestoreIsIdempotent: the closeOnceTerminal under the
// hood protects against double-restore. Two restore() calls must
// perform exactly one setTermios that puts back the original snapshot
// — the second call must not re-apply anything.
func TestUnixTerminalRestoreIsIdempotent(t *testing.T) {
	api := &fakeTermAPI{current: canonicalCooked()}
	withSignalSeam(t, nil, nil, nil)
	const in uintptr = 11
	terminal, err := openUnixTerminal(in, 12, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}
	// setCount after open: 1 (raw install).
	if got := api.callCount(); got != 1 {
		t.Fatalf("after open, setCount = %d, want 1", got)
	}
	if err := terminal.restore(); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if err := terminal.restore(); err != nil {
		t.Fatalf("second restore: %v", err)
	}
	// raw install + one restore; the second restore is a no-op.
	if got := api.callCount(); got != 2 {
		t.Fatalf("after two restores, setCount = %d, want 2 (raw install + 1 restore)", got)
	}
	if got := api.lastSet(t); got != canonicalCooked() {
		t.Fatalf("final snapshot = %+v, want original %+v", got, canonicalCooked())
	}
}

// TestUnixTerminalRawInstallFailureRestoresNothing: when setTermios
// fails AFTER the snapshot was taken, the openUnixTerminal returns an
// error and NO partial change remains. There is nothing to clean up
// because the kernel still has the original termios — the failed
// call did not touch it. The test pins down that the openUnixTerminal
// does NOT install a signal handler in this failure path either
// (signal.Notify would be process-global and noisy).
func TestUnixTerminalRawInstallFailureRestoresNothing(t *testing.T) {
	api := &fakeTermAPI{
		current: canonicalCooked(),
		setErr:  errors.New("ENOTTY"),
	}
	sub := &fakeSubscribe{}
	withSignalSeam(t, sub.subscribe, sub.stop, func(int) { t.Fatal("fatalExit called") })
	terminal, err := openUnixTerminal(11, 12, api)
	if err == nil {
		t.Fatal("openUnixTerminal with failing setTermios succeeded; want an error")
	}
	if terminal != nil {
		t.Errorf("terminal = %+v, want nil on failed open", terminal)
	}
	if sub.gotCh != nil {
		t.Error("signal handler was installed despite setTermios failure")
	}
}

// TestUnixTerminalSizeFromAPI: getWinSize is wired through the fake.
// A 0×0 winsize (the kernel observed nothing) is reported as "no
// size" — same contract as terminal_windows.go's windowsTerminal.size:
// the resize monitor sticks with the configured defaults.
func TestUnixTerminalSizeFromAPI(t *testing.T) {
	for _, tc := range []struct {
		name string
		size terminalSize
		ok   bool
		want bool
	}{
		{"known size", terminalSize{cols: 80, rows: 24}, true, true},
		{"unknown (0x0)", terminalSize{}, false, false},
		// "present but zero" is what the kernel returns for a TTY
		// opened after detach: TIOCGWINSZ succeeds with rows=cols=0.
		// The contract is the same as Windows — ok=false means
		// resize.go uses the configured default sizes.
		{"present but zero", terminalSize{}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeTermAPI{
				current:   canonicalCooked(),
				winsize:   tc.size,
				winsizeOK: tc.ok,
			}
			withSignalSeam(t, nil, nil, nil)
			terminal, err := openUnixTerminal(11, 12, api)
			if err != nil {
				t.Fatalf("openUnixTerminal: %v", err)
			}
			gotSize, gotOK := terminal.size()
			if gotOK != tc.want {
				t.Errorf("size ok = %v, want %v", gotOK, tc.want)
			}
			if tc.want && (gotSize.cols != tc.size.cols || gotSize.rows != tc.size.rows) {
				t.Errorf("size = %+v, want %+v", gotSize, tc.size)
			}
		})
	}
}

// TestUnixTerminalSizeFallsBackToStdin is the canary for fix #3
// (size polling falls back to stdin when stdout is not a tty). The
// case it pins down: `client connect M > session.log` — stdin is a
// tty (so raw mode is on), stdout is a file (so TIOCGWINSZ on it
// fails). The size the user sees must come from stdin, not the
// default 80x24.
//
// Two fds: 21 (the fake stdin) and 22 (the fake stdout). sizePerFd
// makes 22 look like a regular file (ok=false) and 21 look like the
// user's terminal. size() must consult 22 first, see the failure,
// fall back to 21, and report the tty's size.
func TestUnixTerminalSizeFallsBackToStdin(t *testing.T) {
	api := &fakeTermAPI{
		current: canonicalCooked(),
		sizePerFd: map[uintptr]fakeSize{
			22: {ok: false}, // stdout is not a tty
			21: {size: terminalSize{cols: 132, rows: 43}, ok: true},
		},
	}
	withSignalSeam(t, nil, nil, nil)
	const in, out uintptr = 21, 22
	terminal, err := openUnixTerminal(in, out, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}
	gotSize, gotOK := terminal.size()
	if !gotOK {
		t.Fatalf("size ok = false, want true (fallback should have succeeded)")
	}
	if gotSize.cols != 132 || gotSize.rows != 43 {
		t.Errorf("size = %+v, want {132 43} (stdin's winsize)", gotSize)
	}
}

// TestUnixTerminalSizeNoFdAvailable: when both stdout and stdin
// report no size (both non-tty), size() returns false. resize.go
// treats false as "use the configured default 80x24".
func TestUnixTerminalSizeNoFdAvailable(t *testing.T) {
	api := &fakeTermAPI{
		current: canonicalCooked(),
		sizePerFd: map[uintptr]fakeSize{
			22: {ok: false},
			21: {ok: false},
		},
	}
	withSignalSeam(t, nil, nil, nil)
	terminal, err := openUnixTerminal(21, 22, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}
	if gotSize, gotOK := terminal.size(); gotOK {
		t.Errorf("size ok = true, want false (both fds non-tty); got %+v", gotSize)
	}
}

// TestUnixTerminalSignalRestoresThenExits is the canary for the
// signal seam. The fake subscriber receives a synthetic SIGTERM; the
// goroutine must restore the terminal AND call the exit seam with
// 128+15=143. A production path that forgets to install the seam
// would touch the real signal table and crash the test.
func TestUnixTerminalSignalRestoresThenExits(t *testing.T) {
	api := &fakeTermAPI{current: canonicalCooked()}
	sub := &fakeSubscribe{}
	var (
		exitMu sync.Mutex
		exit   int
	)
	withSignalSeam(t, sub.subscribe, sub.stop, func(code int) {
		exitMu.Lock()
		exit = code
		exitMu.Unlock()
	})
	const in uintptr = 11
	terminal, err := openUnixTerminal(in, 12, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}
	ut := terminal.(*unixTerminal)

	// Drive the signal: the fake has captured the channel.
	sub.mu.Lock()
	ch := sub.gotCh
	sub.mu.Unlock()
	if ch == nil {
		t.Fatal("signal subscriber never installed a channel")
	}
	ch <- sigTerm
	// Wait deterministically for the goroutine to exit. Without
	// this, the assertions below race against the goroutine's
	// late work (cleanup.restore, stopAndClose) and trip -race.
	waitExited(t, ut)

	exitMu.Lock()
	gotExit := exit
	exitMu.Unlock()
	if gotExit != 128+sigTermNum {
		t.Errorf("exit code = %d, want %d", gotExit, 128+sigTermNum)
	}

	// restore was called as part of the signal path. The cleanup is
	// idempotent, so the setTermios call count is exactly 2 after
	// the signal: raw install + restore (from signal). A later
	// restore() call from the test is a no-op.
	if got := api.callCount(); got != 2 {
		t.Errorf("setTermios called %d times after signal, want 2", got)
	}
	if got := api.lastSet(t); got != canonicalCooked() {
		t.Errorf("final snapshot after signal = %+v, want original %+v", got, canonicalCooked())
	}

	// Verify signal.Stop was called exactly once. The signal-driven
	// branch calls stopAndClose which calls stop on the channel.
	sub.mu.Lock()
	gotStops := sub.stopCount
	sub.mu.Unlock()
	if gotStops != 1 {
		t.Errorf("signal.Stop called %d times after a real signal, want exactly 1", gotStops)
	}

	// Idempotency survives a signal: calling restore() now is a
	// no-op because closeOnceTerminal already fired.
	_ = terminal.restore()
	if got := api.callCount(); got != 2 {
		t.Errorf("post-signal restore() bumped setCount to %d, want 2 (idempotent)", got)
	}
}

// TestUnixTerminalRestoreStopsSignalHandler is the canary for fix #3
// (signal subscription owned by the terminal token). The point:
// a normal `Connect` ends with `restore()`, which now must
//
//  1. idempotently put back the termios snapshot;
//  2. call signal.Stop exactly once;
//  3. close the done channel so the goroutine wakes.
//
// A late signal arriving after restore() must NOT trigger the
// exit seam: the session is already over and the cleanup has
// already fired.
func TestUnixTerminalRestoreStopsSignalHandler(t *testing.T) {
	api := &fakeTermAPI{current: canonicalCooked()}
	sub := &fakeSubscribe{}
	var (
		exitMu sync.Mutex
		exit   int
	)
	withSignalSeam(t, sub.subscribe, sub.stop, func(code int) {
		exitMu.Lock()
		exit = code
		exitMu.Unlock()
	})
	const in uintptr = 11
	terminal, err := openUnixTerminal(in, 12, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}
	ut := terminal.(*unixTerminal)

	// Sanity: subscription is live and no stops have happened yet.
	sub.mu.Lock()
	stopBefore := sub.stopCount
	gotCh := sub.gotCh
	sub.mu.Unlock()
	if stopBefore != 0 {
		t.Fatalf("signal.Stop already called %d times before restore(); want 0", stopBefore)
	}
	if gotCh == nil {
		t.Fatal("signal subscriber never installed a channel")
	}

	// restore() is the clean-path exit: it must stop the
	// subscription and put the termios back.
	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Wait deterministically for the goroutine to exit. Otherwise
	// the next assertions race the goroutine's doneCh branch,
	// which is exactly what the canary for fix #2 tests against.
	waitExited(t, ut)

	sub.mu.Lock()
	stopAfterRestore := sub.stopCount
	chAfterRestore := sub.gotCh
	sub.mu.Unlock()
	if stopAfterRestore != 1 {
		t.Errorf("signal.Stop called %d times after restore(); want exactly 1", stopAfterRestore)
	}
	if chAfterRestore != nil {
		t.Error("signal subscriber still holds the channel after restore(); the goroutine would deliver to a closed subscription")
	}

	// A second restore() is idempotent — it must NOT call stop again.
	if err := terminal.restore(); err != nil {
		t.Fatalf("second restore: %v", err)
	}
	waitExited(t, ut) // already closed; returns immediately.

	sub.mu.Lock()
	stopAfterSecond := sub.stopCount
	sub.mu.Unlock()
	if stopAfterSecond != 1 {
		t.Errorf("signal.Stop called %d times after a second restore(); want still 1 (idempotent)", stopAfterSecond)
	}

	// Late signal: the fake still has the channel reference saved
	// from before restore, but sending on it now must NOT cause exit
	// to be called. The goroutine has already exited, so any signal
	// we deliver after this is dropped on the floor.
	select {
	case gotCh <- sigTerm:
	default:
	}
	exitMu.Lock()
	gotExit := exit
	exitMu.Unlock()
	if gotExit != 0 {
		t.Errorf("late signal after restore() called exit with %d; want 0 (session already ended)", gotExit)
	}
}

// TestOpenTerminalTtyStdinWriterWithoutFd is the canary for fix #4:
// raw mode is enabled based on tty stdin alone. A `client connect
// MACHINE > session.log` keeps stdin as a tty but redirects stdout
// to a regular file (writer without Fd), and the user expects
// Ctrl+C to be forwarded to the remote rather than killing the
// client.
//
// We can't easily mock *os.File in this package, so we drive
// openTerminal through a small fake fdReader whose Fd() pretends to
// be a tty and a writer with no Fd() method — exactly the shape of
// a redirected `> file.log`. The test asserts the production path
// went raw (setTermios called once with the cleared lflag bits)
// and that restore() restores them.
func TestOpenTerminalTtyStdinWriterWithoutFd(t *testing.T) {
	api := &fakeTermAPI{current: canonicalCooked()}
	withSignalSeam(t, nil, nil, func(int) { t.Fatal("fatalExit called in unit test") })
	stdin := &fakeFdReader{fd: 11}
	stdout := noFdWriter{}

	// Swap in the fake API so openTerminal sees our recorder rather
	// than the real ioctl. Restore on cleanup so the swap never
	// leaks to the next test.
	swapUnixTermAPI(api)
	t.Cleanup(func() { swapUnixTermAPI(xSysTermiosAPI{}) })

	terminal, err := openTerminal(stdin, stdout)
	if err != nil {
		t.Fatalf("openTerminal: %v", err)
	}
	if _, ok := terminal.(inertTerminal); ok {
		t.Fatal("openTerminal returned inertTerminal for tty-stdin + non-fd-writer; want raw-mode terminal")
	}
	if got := api.callCount(); got != 1 {
		t.Fatalf("after open, setCount = %d, want 1 (raw install)", got)
	}
	raw := api.lastSet(t)
	if cleared := raw.lflag & lflagClearRaw; cleared != 0 {
		t.Errorf("raw lflag still has lflagClearRaw bits set: %#x", cleared)
	}
	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := api.lastSet(t); got != canonicalCooked() {
		t.Errorf("restored snapshot = %+v, want original %+v", got, canonicalCooked())
	}
}

// TestOpenTerminalNonTtyStdinReturnsInert pins down the other half
// of fix #4: when stdin is NOT a tty (e.g. `echo foo | iamtunnel
// client connect M`), openTerminal returns inertTerminal regardless
// of whether stdout is a tty or a pipe. The user's intent here is
// the non-interactive mode, and Ctrl+C simply isn't possible.
func TestOpenTerminalNonTtyStdinReturnsInert(t *testing.T) {
	withSignalSeam(t, nil, nil, nil)
	stdin := noFdReader{}
	stdout := noFdWriter{}
	terminal, err := openTerminal(stdin, stdout)
	if err != nil {
		t.Fatalf("openTerminal: %v", err)
	}
	if _, ok := terminal.(inertTerminal); !ok {
		t.Fatalf("terminal type = %T, want inertTerminal (non-tty stdin)", terminal)
	}
}

// waitExited blocks until the signal-handling goroutine returns.
// Tests that drive openUnixTerminal call this right after the
// event they want to observe (a signal, a restore) so subsequent
// assertions do not race the goroutine under -race. exitedCh is
// closed in a `defer` inside the goroutine, so it is closed on
// every exit path (signal, doneCh, or signal-on-closed-channel).
func waitExited(t *testing.T, ut *unixTerminal) {
	t.Helper()
	if ut.exitedCh == nil {
		t.Fatal("exitedCh is nil; the goroutine was never started")
	}
	select {
	case <-ut.exitedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("signal-handling goroutine did not exit within 2s")
	}
}

// sigTerm is the os.Signal value the canary drives into the
// goroutine. We use unix.SIGTERM directly because signal.Notify in
// production delivers syscall.Signal values, and the production code's
// signalNumber type-switch matches syscall.Signal first. The constant
// is the same 15 on both Linux and Darwin.
var sigTerm = unix.SIGTERM

// sigTermNum is the integer the production signalNumber(sig) extracts
// from sigTerm. We assert exit == 128+sigTermNum below.
const sigTermNum = 15

// errAPI is a unixTermAPI whose getTermios always fails. Used by the
// non-tty path test.
type errAPI struct {
	getErr   error
	setCount int
}

func (f *errAPI) getTermios(uintptr) (termiosSnapshot, error) {
	return termiosSnapshot{}, f.getErr
}
func (f *errAPI) setTermios(uintptr, termiosSnapshot) error {
	f.setCount++
	return nil
}
func (f *errAPI) getWinSize(uintptr) (terminalSize, bool) { return terminalSize{}, false }

// fakeFdReader is an io.Reader whose Fd() returns a fixed integer.
// It exists so tests can drive openTerminal without spinning up an
// actual tty. The production xSysTermiosAPI sees the fd value but
// goes through the fakeTermAPI seam in the test, so the underlying
// ioctls never run.
type fakeFdReader struct {
	fd  uintptr
	buf []byte
}

func (r *fakeFdReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		return 0, errors.New("EOF")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *fakeFdReader) Fd() uintptr { return r.fd }

// noFdReader is an io.Reader with no Fd() method — exactly what
// strings.Reader, bytes.Reader, and an os.Pipe give you.
type noFdReader struct{}

func (noFdReader) Read(p []byte) (int, error) { return 0, errors.New("EOF") }

// noFdWriter is an io.Writer with no Fd() method.
type noFdWriter struct{}

func (noFdWriter) Write(p []byte) (int, error) { return len(p), nil }

// swapUnixTermAPI installs a fake API into the package-level seam
// so openTerminal's production call path picks it up. Tests pair it
// with a t.Cleanup that calls swapUnixTermAPI(xSysTermiosAPI{}) to
// restore the default. Production never calls this.
func swapUnixTermAPI(fake unixTermAPI) {
	unixTermAPIForTest = fake
}
