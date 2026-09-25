package client

import (
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

const resizePollInterval = 100 * time.Millisecond

// watchWindowChanges polls only while a granted channel is alive. It compares
// against the last observed size, so every distinct resize creates exactly one
// request and a return to an earlier size creates one new request of its own.
func watchWindowChanges(done <-chan struct{}, terminal localTerminal, initial terminalSize, send func(sshx.WindowChange) error) {
	last := initial
	ticker := time.NewTicker(resizePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			next, ok := terminal.size()
			if !ok || next == last {
				continue
			}
			if err := send(sshx.WindowChange{Columns: next.cols, Rows: next.rows}); err != nil {
				return
			}
			last = next
		}
	}
}
