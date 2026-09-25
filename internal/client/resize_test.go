package client

import (
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

type fakeResizableTerminal struct {
	mu      sync.Mutex
	current terminalSize
}

func (t *fakeResizableTerminal) restore() error { return nil }
func (t *fakeResizableTerminal) size() (terminalSize, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.current, true
}
func (t *fakeResizableTerminal) set(size terminalSize) {
	t.mu.Lock()
	t.current = size
	t.mu.Unlock()
}

func receiveResize(t *testing.T, got <-chan sshx.WindowChange, want sshx.WindowChange) {
	t.Helper()
	select {
	case actual := <-got:
		if actual != want {
			t.Fatalf("window-change = %+v, want %+v", actual, want)
		}
	case <-time.After(3 * resizePollInterval):
		t.Fatalf("did not send window-change %+v", want)
	}
}

func requireNoResize(t *testing.T, got <-chan sshx.WindowChange) {
	t.Helper()
	select {
	case actual := <-got:
		t.Fatalf("unexpected window-change %+v", actual)
	case <-time.After(2 * resizePollInterval):
	}
}

// TestWatchWindowChangesExactlyOnce exercises the client-side invariant
// independent of timing in an SSH server: unchanged size is silent, and every
// distinct observed value is forwarded exactly once, including a return and a
// one-axis resize.
func TestWatchWindowChangesExactlyOnce(t *testing.T) {
	terminal := &fakeResizableTerminal{current: terminalSize{cols: 80, rows: 24}}
	done := make(chan struct{})
	got := make(chan sshx.WindowChange, 8)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		watchWindowChanges(done, terminal, terminalSize{cols: 80, rows: 24}, func(change sshx.WindowChange) error {
			got <- change
			return nil
		})
	}()

	requireNoResize(t, got)
	terminal.set(terminalSize{cols: 120, rows: 35})
	receiveResize(t, got, sshx.WindowChange{Columns: 120, Rows: 35})
	requireNoResize(t, got)

	terminal.set(terminalSize{cols: 80, rows: 24})
	receiveResize(t, got, sshx.WindowChange{Columns: 80, Rows: 24})
	terminal.set(terminalSize{cols: 81, rows: 24})
	receiveResize(t, got, sshx.WindowChange{Columns: 81, Rows: 24})

	close(done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("resize monitor did not stop")
	}
	terminal.set(terminalSize{cols: 99, rows: 50})
	requireNoResize(t, got)
}
