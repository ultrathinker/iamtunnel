//go:build linux || darwin

// Package client on Linux and macOS: terminal mode and size.
//
// SIGWINCH is not required — internal/client/resize.go polls size()
// every 100 ms. We do, however, have to recover the terminal cleanly
// when the controlling shell sends us SIGTERM (process manager),
// SIGHUP (terminal closed) or, as a rare external case, SIGINT (e.g.
// the parent of a pipeline killed us). In raw mode Ctrl+C is forwarded
// as a byte to the remote, so SIGINT does NOT arrive from the user —
// it can only arrive from outside our process, which means the right
// thing after restoring is to terminate, not return to a session that
// is already broken.
package client

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// unixTermAPI is the tiny termios-shaped surface used by openUnixTerminal.
// It is package-local for the same reason consoleAPI is on Windows:
// the production opener cannot be told to skip the snapshot/restore
// discipline, but tests need a fake to assert against.
type unixTermAPI interface {
	getTermios(fd uintptr) (termiosSnapshot, error)
	setTermios(fd uintptr, st termiosSnapshot) error
	getWinSize(fd uintptr) (terminalSize, bool)
}

// termiosSnapshot is the minimal slice of unix.Termios we read and
// write. The implementation is built field-by-field so it does not
// need to depend on the platform's exact struct layout (Linux uses
// uint32 for the flag fields, Darwin uses uint64) — the snapshot
// keeps the wider type so the Darwin values are preserved exactly,
// and the Linux values fit without a cast.
//
// Ispeed and Ospeed are Darwin-only (Linux does not have them on
// Termios; cfsetispeed/cfsetospeed live in the syscall interface
// there). On Darwin they are part of the payload of TIOCSETA: a
// raw-mode call that does not preserve them changes the line
// discipline's baud rate on the way out. We carry both fields in
// the snapshot and copy them on every setTermios so a raw + restore
// pair round-trips a non-zero baud rate byte-for-byte.
type termiosSnapshot struct {
	iflag  uint64
	oflag  uint64
	cflag  uint64
	lflag  uint64
	cc     [20]uint8 // Linux NCCS=19, Darwin NCCS=20; 20 covers both.
	ispeed uint64    // Darwin only; zero on Linux.
	ospeed uint64    // Darwin only; zero on Linux.
}

// xSysTermiosAPI is the production unixTermiosAPI. The constants it
// references live in terminal_ioctl_linux.go and
// terminal_ioctl_darwin.go behind per-OS build tags, so the same Go
// file compiles for both without dragging in x/sys/unix's
// conditional sources here.
type xSysTermiosAPI struct{}

func (xSysTermiosAPI) getTermios(fd uintptr) (termiosSnapshot, error) {
	return ioctlGetTermios(int(fd))
}

func (xSysTermiosAPI) setTermios(fd uintptr, s termiosSnapshot) error {
	return ioctlSetTermios(int(fd), s.iflag, s.oflag, s.cflag, s.lflag, s.ispeed, s.ospeed, s.cc)
}

func (xSysTermiosAPI) getWinSize(fd uintptr) (terminalSize, bool) {
	w, err := ioctlGetWinsize(int(fd))
	if err != nil || w == nil {
		return terminalSize{}, false
	}
	return terminalSize{cols: uint32(w.Col), rows: uint32(w.Row)}, true
}

// openTerminal is the production entry point. The decision to enter
// raw mode is based on stdin alone — `client connect MACHINE >
// session.log` keeps stdin as a tty but redirects stdout to a file,
// and the user expects Ctrl+C to be forwarded as 0x03 to the remote
// rather than killing the client. Size, however, is read from stdout
// if it is a tty (so resizes track the visible terminal) and from
// stdin otherwise; the lookup falls back at the kernel level, not
// here, because the right way to detect "this fd is a tty" is
// TIOCGWINSZ on the fd itself.
func openTerminal(in io.Reader, out io.Writer) (localTerminal, error) {
	input, inputOK := in.(fdReader)
	if !inputOK {
		// stdin is the only thing that has to be a tty for raw mode
		// to make sense: without it, the user has no terminal to
		// send Ctrl+C from, and a piped stdin (CI, script) is
		// deliberately inert.
		return inertTerminal{}, nil
	}
	var sizeFD uintptr
	if output, outputOK := out.(fdWriter); outputOK {
		sizeFD = output.Fd()
	} else {
		sizeFD = input.Fd()
	}
	return openUnixTerminal(input.Fd(), sizeFD, apiForOpen())
}

// apiForOpen returns the production xSysTermiosAPI in normal use,
// and the test seam value when one has been installed by
// swapUnixTermAPI. The variable is package-private: production
// callers cannot tamper with it.
func apiForOpen() unixTermAPI {
	if a := unixTermAPIForTest; a != nil {
		return a
	}
	return xSysTermiosAPI{}
}

// unixTermAPIForTest is the test seam over the production api.
// swapUnixTermAPI installs a fake here for the duration of a test
// and restores the default on t.Cleanup. nil means "use the real
// xSysTermiosAPI", which is the production path.
var unixTermAPIForTest unixTermAPI = xSysTermiosAPI{}

// openUnixTerminal takes snapshots before changing either fd, puts the
// input side into raw mode, and arranges for the snapshot to be put
// back on every return path. The api parameter is the test seam —
// production passes xSysTermiosAPI{}, tests pass a recorder that
// inspects the snapshot/restore calls. The signal-related seams are
// the package-level signalSubscribe and fatalExit functions, which
// tests override before driving openUnixTerminal.
//
// `in` is the fd we install raw mode on (and the one we save/restore
// termios for). `out` is the fd we prefer for size polling — if it
// is not a tty at the time of the query (e.g. the user redirected
// stdout to a file) unixTerminal.size falls back to in.
func openUnixTerminal(in, out uintptr, api unixTermAPI) (localTerminal, error) {
	saved, err := api.getTermios(in)
	if err != nil {
		// Redirected stdin (a pipe, a CI harness) is a supported
		// non-interactive mode of "client connect"; refuse to change a
		// terminal we cannot read.
		return inertTerminal{}, nil
	}

	raw := makeRaw(saved)
	if err := api.setTermios(in, raw); err != nil {
		return nil, fmt.Errorf("set raw terminal mode: %w", err)
	}

	cleanup := &closeOnceTerminal{fn: func() error {
		return api.setTermios(in, saved)
	}}

	t := &unixTerminal{
		cleanup: cleanup,
		inFd:    in,
		outFd:   out,
		api:     api,
	}
	t.startSignalHandler(cleanup)
	return t, nil
}

// makeRaw applies the cfmakeraw-equivalent transformation to s: the
// canonical set of input, output, local and control flags is cleared,
// CS8 is set, and the read-timing CCs are VMIN=1 VTIME=0 so read(2)
// returns as soon as a single byte arrives.
//
// The set/clear masks are platform constants
// (terminal_ioctl_linux.go, terminal_ioctl_darwin.go) because Linux
// and Darwin disagree on a few bit positions even though the names
// match.
func makeRaw(s termiosSnapshot) termiosSnapshot {
	s.iflag &^= iflagClearRaw
	s.oflag &^= oflagClearRaw
	s.lflag &^= lflagClearRaw
	s.cflag &^= cflagClearRaw
	s.cflag |= cflagSetRaw
	// VMIN=1, VTIME=0 means "block until at least one byte is ready,
	// return as soon as it is" — the discipline x/term.MakeRaw applies.
	if ccVMin < len(s.cc) {
		s.cc[ccVMin] = 1
	}
	if ccVTime < len(s.cc) {
		s.cc[ccVTime] = 0
	}
	return s
}

// unixTerminal is the package-private terminal token returned by
// openUnixTerminal. The cleanup closure holds the snapshot, not the
// terminal itself, so a successful setup cannot lose the original mode.
//
// The signal-handling goroutine and its done channel are owned by
// THIS struct. restore() claims the cleanup and signals the
// goroutine via a single sync.Once ("stopAndClose"), so a session
// that ends cleanly leaves no stale signal table entry behind. A
// late signal that arrives after restore() observes a closed done
// channel AND a stopped subscription, so the goroutine simply
// returns — it does not re-fire cleanup, and the exit decision
// has already been claimed by restore.
//
// exitedCh is closed when the goroutine returns. Tests that drive
// restore() then drive the goroutine rely on this channel to wait
// deterministically (instead of polling or sleeping) so the suite
// stays race-free under -race.
type unixTerminal struct {
	cleanup *closeOnceTerminal
	inFd    uintptr
	outFd   uintptr
	api     unixTermAPI

	// stopAndClose fires exactly once. It calls signal.Stop on
	// sigCh and closes doneCh. Whichever path triggers it
	// (restore() on the clean exit, or the signal goroutine on
	// the real-signal branch) wins; the other path is a no-op.
	stopOnce sync.Once

	// exitDecision is shared between restore() and the signal
	// goroutine. The first caller claims it; whoever loses the
	// race observes a no-op Do and must not trigger an exit. The
	// shared state is exactly two booleans (one local to each
	// caller) — sync.Once is the synchronization, the local
	// variables are the values.
	exitDecision sync.Once
	exitWanted   bool // set by the goroutine if it claimed exitDecision

	sigCh    chan os.Signal
	doneCh   chan struct{}
	exitedCh chan struct{} // closed when the goroutine returns
}

// restore returns the termios to the snapshot we took on open and,
// idempotently, stops the signal subscription and wakes the
// goroutine. Subsequent calls are no-ops; the second restore() in a
// Connect that already closed its terminal is the standard path.
func (t *unixTerminal) restore() error {
	err := t.cleanup.restore()
	// Claim the exit decision FIRST so the goroutine, if it is
	// about to read a signal from sigCh, sees "exit wanted" as
	// false when it tries to claim. If the goroutine has already
	// claimed exitDecision (real signal arrived first), this Do
	// is a no-op — that path will go on to exit the process, and
	// our caller's exit value never matters.
	t.exitDecision.Do(func() { /* restore claimed the decision */ })
	t.stopAndClose()
	return err
}

// stopAndClose is the single owner of the signal-subscription
// cleanup. It calls signal.Stop on sigCh (so the runtime stops
// relaying signals to our channel) and closes doneCh (so the
// goroutine wakes via the doneCh branch of its select). Calling it
// any number of times is safe: only the first call does work.
func (t *unixTerminal) stopAndClose() {
	t.stopOnce.Do(func() {
		stop := signalStop
		if stop != nil && t.sigCh != nil {
			stop(t.sigCh)
		}
		if t.doneCh != nil {
			close(t.doneCh)
		}
	})
}

func (t *unixTerminal) size() (terminalSize, bool) {
	if t.api == nil {
		return terminalSize{}, false
	}
	// Prefer stdout (so the user sees resizes match the visible
	// terminal). If stdout's TIOCGWINSZ fails or returns 0×0 (the
	// fd is a regular file or pipe), fall back to stdin — that is
	// where the tty lives in `client connect M > session.log`.
	if size, ok := t.api.getWinSize(t.outFd); ok && (size.cols != 0 && size.rows != 0) {
		return size, true
	}
	if t.outFd != t.inFd {
		if size, ok := t.api.getWinSize(t.inFd); ok && (size.cols != 0 && size.rows != 0) {
			return size, true
		}
	}
	return terminalSize{}, false
}

// startSignalHandler wires SIGINT/SIGTERM/SIGHUP to cleanup + exit.
// The goroutine races between a real signal and the done channel
// that restore() closes; whichever fires first terminates the
// goroutine. A signal arriving after restore() is observed as a
// no-op (the subscription is gone and the goroutine has either
// exited or is about to).
//
// Two synchronizations are captured locally before the goroutine
// starts so a test's t.Cleanup can swap the package-level seams
// without racing the goroutine:
//
//   - sub:  who delivers signals;
//   - exit: who terminates the process.
//
// signalStop is read inside stopAndClose (the goroutine does NOT
// touch it), so it does not need to be captured here. The same
// reasoning applies to unixTermAPIForTest: nothing on the
// goroutine reads it.
func (t *unixTerminal) startSignalHandler(cleanup *closeOnceTerminal) {
	sub := signalSubscribe
	if sub == nil {
		// No subscriber wanted (a test that does not want a
		// goroutine at all). We still need doneCh because
		// restore() will close it through stopAndClose. The
		// goroutine is not started; restore() is the only path
		// to closing doneCh, and stopOnce keeps the close
		// idempotent.
		t.doneCh = make(chan struct{})
		t.exitedCh = make(chan struct{})
		close(t.exitedCh)
		return
	}
	exit := fatalExit
	if exit == nil {
		exit = func(int) {}
	}
	t.sigCh = make(chan os.Signal, 1)
	t.doneCh = make(chan struct{})
	t.exitedCh = make(chan struct{})
	sub(t.sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		// exitedCh must be closed on EVERY exit path so tests
		// that wait on it do not deadlock under -race.
		defer close(t.exitedCh)
		select {
		case sig, ok := <-t.sigCh:
			if !ok {
				return
			}
			// Try to claim the exit decision. If restore()
			// got here first, this Do is a no-op and
			// exitWanted stays false — we must NOT call
			// exit() in that case.
			t.exitDecision.Do(func() { t.exitWanted = true })
			if !t.exitWanted {
				return
			}
			_ = cleanup.restore()
			t.stopAndClose()
			exit(128 + signalNumber(sig))
		case <-t.doneCh:
			// restore() already did the cleanup and removed
			// the subscription. Nothing left to do.
		}
	}()
}

// fdReader / fdWriter are duplicated in terminal_windows.go and here
// on purpose: build-tagged files do not share types across the
// windows / !windows boundary, and the interfaces are tiny.
type fdReader interface {
	io.Reader
	Fd() uintptr
}

type fdWriter interface {
	io.Writer
	Fd() uintptr
}

// signalNumber extracts the canonical exit-code contribution of a
// signal — the value a shell would write as "$?". The syscall.Signal
// case is what signal.Notify delivers in production.
func signalNumber(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return int(s)
	}
	return 0
}

// signalSubscribe is the seam over signal.Notify. Production assigns
// signal.Notify at package init; tests assign a fake that delivers
// signals from a channel they control. nil disables signal handling
// entirely (used by tests that want a fake terminal but no goroutine
// at all).
var signalSubscribe signalSubscriber = func(c chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(c, sig...)
}

// signalStop is the seam over signal.Stop. As with signalSubscribe,
// tests can replace it; nil means "do nothing", which is fine for the
// fake subscribers used by unit tests.
var signalStop signalStopper = func(c chan<- os.Signal) {
	signal.Stop(c)
}

// fatalExit is the seam over os.Exit. Production wraps os.Exit;
// tests record the code instead. The function MUST terminate the
// process — tests inject a t.Fatal so an accidental production path
// is caught loudly.
var fatalExit = func(code int) { os.Exit(code) }

// signalSubscriber is the type of the production/ fake signal.Notify
// replacement. The varargs stay as-is: signal.Notify's signature is
// what the rest of this file expects.
type signalSubscriber func(c chan<- os.Signal, sig ...os.Signal)

// signalStopper is the type of the production/ fake signal.Stop
// replacement.
type signalStopper func(c chan<- os.Signal)
