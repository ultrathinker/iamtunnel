package auth

import (
	"strings"
	"testing"
)

func TestParseUsernameForms(t *testing.T) {
	for _, tc := range []struct {
		in      string
		person  string
		machine string
	}{
		{"alice", "alice", ""},
		{"alice:win01", "alice", "win01"},
		{"a.b-c_d0", "a.b-c_d0", ""},
		{"a:z9", "a", "z9"},
		{strings.Repeat("a", 32), strings.Repeat("a", 32), ""},
	} {
		got, err := ParseUsername(tc.in)
		if err != nil {
			t.Errorf("ParseUsername(%q): %v", tc.in, err)
			continue
		}
		if got.Person != tc.person || got.Machine != tc.machine {
			t.Errorf("ParseUsername(%q) = %+v, want person=%q machine=%q", tc.in, got, tc.person, tc.machine)
		}
	}
}

func TestParseUsernameRejectsBad(t *testing.T) {
	long := strings.Repeat("a", 33)
	for _, in := range []string{
		"",                               // empty
		"alice:",                         // empty machine part
		":win01",                         // empty person part
		"a:b:c",                          // more than one colon
		"a:b:c:d",                        // ditto
		"Alice",                          // uppercase
		"ali ce",                         // space
		"\u0430\u043b\u0438\u0441\u0430", // non-ASCII (ambiguous Unicode is refused by the name class)
		"ali\u0441e",                     // Cyrillic U+0441 inside - exactly the spoofing case
		"ali\tce",                        // control character
		"ali\nce",                        // control character
		"ali\x00ce",                      // NUL
		".alice",                         // must start with [a-z0-9]
		"-alice",                         // ditto
		long,                             // 33 chars, over the 32 limit
		"alice:" + long,                  // machine part over the limit
	} {
		if got, err := ParseUsername(in); err == nil {
			t.Errorf("ParseUsername(%q) = %+v, want error", in, got)
		}
	}
}

func TestMachineUsernameRoundTrip(t *testing.T) {
	u, err := MachineUsername("win01")
	if err != nil {
		t.Fatalf("MachineUsername: %v", err)
	}
	if u != "machine:win01" {
		t.Fatalf("MachineUsername = %q", u)
	}
	id, err := ParseMachineUsername(u)
	if err != nil || id != "win01" {
		t.Fatalf("ParseMachineUsername(%q) = %q, %v", u, id, err)
	}
	for _, bad := range []string{"alice", "machine:", "machine:A", "machine:a:b", "machine:win01:extra", "machine"} {
		if _, err := ParseMachineUsername(bad); err == nil {
			t.Errorf("ParseMachineUsername(%q): no error", bad)
		}
	}
}
