package main

import (
	"strings"
	"testing"
)

// The canary for IAMT-403.
//
// The whole task exists so that the external classifier's key does not
// leak along the way. A command-line argument contradicts that outright:
// it stays in the shell's history file and, while the command runs, is
// visible in the process list of every other account on the machine.
//
// That is why "--key -" reads the key from standard input. The canary
// guards exactly this: that "-" does not travel to the gateway as a
// literal key.
func TestCanary_IAMT403_RiskKeyDashReadsStandardInput(t *testing.T) {
	const secret = "apikey_canary_not_a_real_key"
	s := &streams{in: strings.NewReader(secret + "\n")}

	got, err := riskKeyArgument(s, "-")
	if err != nil {
		t.Fatalf("test setup failed: riskKeyArgument returned an error: %v", err)
	}
	if got == "-" {
		t.Fatalf("CANARY IAMT-403: \"--key -\" would travel to the gateway as the literal key \"-\" instead of " +
			"the contents of standard input — the way of not leaving the key in command history does not work")
	}
	if got != secret {
		t.Errorf("CANARY IAMT-403: read %q from standard input but %q was fed in", got, secret)
	}

	// A trailing newline from the clipboard or a heredoc must not become
	// part of the key: the gateway tries the key with a real request,
	// and one extra byte turns a valid key into a refusal.
	s = &streams{in: strings.NewReader("  " + secret + "  \r\n")}
	if got, err := riskKeyArgument(s, "-"); err != nil || got != secret {
		t.Errorf("CANARY IAMT-403: surrounding whitespace not trimmed: got=%q err=%v", got, err)
	}

	// An ordinary argument passes as is — "-" must not break the old path.
	if got, err := riskKeyArgument(&streams{in: strings.NewReader("")}, secret); err != nil || got != secret {
		t.Errorf("CANARY IAMT-403: the ordinary --key is corrupted: got=%q err=%v", got, err)
	}

	// Empty input is a refusal, not an attempt to set an empty key.
	if _, err := riskKeyArgument(&streams{in: strings.NewReader("\n")}, "-"); err == nil {
		t.Errorf("CANARY IAMT-403: empty standard input accepted — the gateway would have received an empty key")
	}
}
