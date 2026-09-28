//go:build !nogui

package main

// iamt311_unreachable_status_test.go — IAMT-311: unreachableStatusText is
// pollServerStatus's own wording for a "status" attempt that ended in an
// error rather than an answer. A denied read must name the missing right
// and the window's own way to get it -- the "Restart as administrator"
// button -- never a console to close or a command to type (1.51); any
// other error must keep its own words, never a borrowed rights sentence
// that would misdescribe it.

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestIAMT311_UnreachableStatusTextDeniedMatchesCLIWording pins the
// rights-denied case: the missing right, and the window's button.
//
// Canary: send the owner to a console again. This test goes red on the
// console check.
func TestIAMT311_UnreachableStatusTextDeniedMatchesCLIWording(t *testing.T) {
	err := deniedErrf("%s: %v", "/var/lib/iamtunnel-machine/control.json", errors.New("permission denied"))
	got := unreachableStatusText(err)

	if !strings.HasPrefix(got, "unknown") {
		t.Fatalf("unreachableStatusText for a denied read = %q, want it to start with \"unknown\" — this is a fact that could not be learned, not a negative one", got)
	}
	right := "root privileges are required"
	if runtime.GOOS == "windows" {
		right = "administrator privileges are required"
	}
	if !strings.Contains(got, right) || !strings.Contains(got, `press "Restart as administrator"`) {
		t.Fatalf("unreachableStatusText on %s = %q, want %q and the window's \"Restart as administrator\" button", runtime.GOOS, got, right)
	}
	for _, console := range []string{"console", "terminal", "sudo ", "iamtunnel server status"} {
		if strings.Contains(got, console) {
			t.Fatalf("unreachableStatusText = %q sends the owner to a console (%q); the window has its own button", got, console)
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
