//go:build !windows

package main

import (
	"os"
	"testing"
)

// sudoInvoker is the whole of what the drop trusts from the environment:
// a malformed or root invoker is "no drop", never a guess.
func TestIAMT504_SudoInvokerReadsOnlyAPlainAccount(t *testing.T) {
	cases := []struct {
		env      map[string]string
		uid, gid int
		ok       bool
	}{
		{map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}, 1000, 1000, true},
		{map[string]string{"SUDO_UID": "501", "SUDO_GID": "20"}, 501, 20, true},
		{map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}, 0, 0, false},
		{map[string]string{"SUDO_UID": "1000"}, 0, 0, false},
		{map[string]string{"SUDO_UID": "x", "SUDO_GID": "1000"}, 0, 0, false},
		{map[string]string{"SUDO_UID": "-5", "SUDO_GID": "1000"}, 0, 0, false},
		{map[string]string{}, 0, 0, false},
	}
	for _, c := range cases {
		uid, gid, ok := sudoInvoker(c.env)
		if ok != c.ok || (ok && (uid != c.uid || gid != c.gid)) {
			t.Errorf("sudoInvoker(%v) = %d, %d, %v; want %d, %d, %v", c.env, uid, gid, ok, c.uid, c.gid, c.ok)
		}
	}
}

// Not root, nothing to give up: the real drop must answer "not this case"
// without touching the process -- which is also why the test run can call
// it at all.
func TestIAMT504_TheRealDropDoesNothingWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: this test pins the non-root answer, and calling the real drop as root would drop the test process itself")
	}
	dir := t.TempDir()
	dropped, err := dropToInvokerOS(map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1000"}, dir)
	if dropped || err != nil {
		t.Fatalf("dropToInvokerOS as uid %d = %v, %v; want false, nil", os.Geteuid(), dropped, err)
	}
}
