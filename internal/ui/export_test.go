package ui

import (
	"sync/atomic"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// This file is compiled only into the test binary of package ui.
// Test audit hooks and counters live here in export_test.go, NOT in
// product types like sessionView.

var (
	testSessionLockedReads  int64
	testSessionLockedWrites int64
)

// EnableSessionAudit installs audit counters that track critical section entries in the Session tab.
func EnableSessionAudit(f *Frame) {
	f.sessionUI.mu.Lock()
	defer f.sessionUI.mu.Unlock()
	f.sessionUI.auditHook = func(isWrite bool) {
		if isWrite {
			atomic.AddInt64(&testSessionLockedWrites, 1)
		} else {
			atomic.AddInt64(&testSessionLockedReads, 1)
		}
	}
}

// SessionAuditCounts returns the recorded counts of locked reads and writes.
func SessionAuditCounts() (reads, writes int64) {
	return atomic.LoadInt64(&testSessionLockedReads), atomic.LoadInt64(&testSessionLockedWrites)
}

// ResetSessionAuditCounts zeroes the audit counters.
func ResetSessionAuditCounts() {
	atomic.StoreInt64(&testSessionLockedReads, 0)
	atomic.StoreInt64(&testSessionLockedWrites, 0)
}

// SetSessionRenderHook installs a callback invoked for every terminal line rendered by layoutSessionTerminal.
func SetSessionRenderHook(f *Frame, hook func(index int, numHistory int, line record.Line)) {
	f.sessionUI.mu.Lock()
	defer f.sessionUI.mu.Unlock()
	f.sessionUI.renderHook = hook
}

// SetSessionInterleaveHook installs a callback invoked immediately after HistoryTotal is read in layoutSessionTerminal.
func SetSessionInterleaveHook(f *Frame, hook func()) {
	f.sessionUI.mu.Lock()
	defer f.sessionUI.mu.Unlock()
	f.sessionUI.interleaveHook = hook
}
