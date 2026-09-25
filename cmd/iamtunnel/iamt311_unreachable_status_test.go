//go:build !nogui

package main

// iamt311_unreachable_status_test.go — IAMT-311: unreachableStatusText is
// pollServerStatus's own wording for a "status" attempt that ended in an
// error rather than an answer. A denied read must echo
// requireServerElevation's own sentence for the identical missing right
// on the identical command (server.go), so an owner reads the same words
// whether they asked from a terminal or from this window; any other
// error must keep its own words, never a borrowed rights sentence that
// would misdescribe it.

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestIAMT311_UnreachableStatusTextDeniedMatchesCLIWording pins the
// rights-denied case against requireServerElevation's own phrase.
//
// Canary: word the denied case differently from requireServerElevation
// (server.go). This test goes red on the corresponding substring.
func TestIAMT311_UnreachableStatusTextDeniedMatchesCLIWording(t *testing.T) {
	err := deniedErrf("%s: %v", "/var/lib/iamtunnel-machine/control.json", errors.New("permission denied"))
	got := unreachableStatusText(err)

	if !strings.HasPrefix(got, "unknown") {
		t.Fatalf("unreachableStatusText for a denied read = %q, want it to start with \"unknown\" — this is a fact that could not be learned, not a negative one", got)
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(got, "administrator privileges are required") {
			t.Fatalf("unreachableStatusText on Windows = %q, want the same wording requireServerElevation uses for the identical missing right", got)
		}
	} else {
		if !strings.Contains(got, "root privileges are required") || !strings.Contains(got, "sudo iamtunnel server status") {
			t.Fatalf("unreachableStatusText on %s = %q, want the same \"root privileges are required ... sudo iamtunnel server status\" wording requireServerElevation uses", runtime.GOOS, got)
		}
	}
}

// TestIAMT311_UnreachableStatusTextOtherErrorKeepsItsOwnWords pins the
// non-denial case: the fact is still unknown, but the message must not
// claim a missing right it did not observe.
//
// Canary: always return the missing-rights wording regardless of the
// error's own class. This test goes red on the borrowed-wording check.
func TestIAMT311_UnreachableStatusTextOtherErrorKeepsItsOwnWords(t *testing.T) {
	err := envErrf("control.json: %v", errors.New("unexpected EOF"))
	got := unreachableStatusText(err)

	if !strings.HasPrefix(got, "unknown") {
		t.Fatalf("unreachableStatusText = %q, want it to start with \"unknown\"", got)
	}
	if !strings.Contains(got, "unexpected EOF") {
		t.Fatalf("unreachableStatusText for a non-denial error = %q, want it to carry the original error", got)
	}
	if strings.Contains(got, "root privileges") || strings.Contains(got, "administrator privileges") {
		t.Fatalf("unreachableStatusText borrowed the missing-rights wording for a non-denial error it did not observe: %q", got)
	}
}
