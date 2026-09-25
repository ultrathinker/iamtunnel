package main

// IAMT-445b: on Linux and macOS server install writes a unit (a LaunchDaemon
// on macOS) that starts the running binary as root at every boot, and it
// checked nobody's ability to change that binary. Whoever can change the
// file - or rename a directory on the way to it and put their own in its
// place - is root from the next boot on. The check itself is a pure function
// of what stat says, so it is pinned here on every platform the tests run
// on; statExeOwner, its Linux/macOS source, is the platform's own os.Stat.

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// iamt445bTree is a file system as stat sees it: path -> owner and bits.
type iamt445bTree map[string]exeOwnerStat

func (t iamt445bTree) stat(p string) (exeOwnerStat, error) {
	st, ok := t[p]
	if !ok {
		return exeOwnerStat{}, fs.ErrNotExist
	}
	return st, nil
}

func iamt445bAsIs(p string) (string, error) { return p, nil }

func iamt445bRootTree() iamt445bTree {
	return iamt445bTree{
		"/":                           {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr":                        {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local":                  {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local/bin":              {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local/bin/iamtunnel":    {uid: 0, gid: 0, mode: 0o755},
		"/home":                       {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/home/alice":                 {uid: 1000, gid: 1000, mode: fs.ModeDir | 0o750},
		"/home/alice/tools":           {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/home/alice/tools/iamtunnel": {uid: 0, gid: 0, mode: 0o755},
		"/opt":                        {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/opt/iamtunnel":              {uid: 0, gid: 1000, mode: fs.ModeDir | 0o775},
		"/opt/iamtunnel/iamtunnel":    {uid: 0, gid: 0, mode: 0o755},
		"/srv":                        {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/srv/iamtunnel":              {uid: 0, gid: 0, mode: 0o757},
		"/wheel":                      {uid: 0, gid: 0, mode: fs.ModeDir | 0o775},
		"/wheel/iamtunnel":            {uid: 0, gid: 0, mode: 0o775},
	}
}

func TestIAMT445b_AProgramOnlyRootCanChangeIsAccepted(t *testing.T) {
	tree := iamt445bRootTree()
	for _, bin := range []string{"/usr/local/bin/iamtunnel", "/wheel/iamtunnel"} {
		who, err := unixExeWriters(bin, tree.stat, iamt445bAsIs)
		if err != nil || len(who) != 0 {
			t.Errorf("%s: writers=%v err=%v, want none: root owns every step and only root's group may write", bin, who, err)
		}
	}
}

func TestIAMT445b_AProgramSomeoneElseCanChangeIsNamed(t *testing.T) {
	tree := iamt445bRootTree()
	tree["/usr/local/bin/iamtunnel"] = exeOwnerStat{uid: 1000, gid: 1000, mode: 0o755}
	for _, tc := range []struct {
		bin, want string
	}{
		{"/usr/local/bin/iamtunnel", "/usr/local/bin/iamtunnel"}, // the file is someone's
		{"/home/alice/tools/iamtunnel", "/home/alice"},           // a directory above it is someone's
		{"/opt/iamtunnel/iamtunnel", "/opt/iamtunnel"},           // its directory is a group's
		{"/srv/iamtunnel", "/srv/iamtunnel"},                     // everybody may write the file
	} {
		who, err := unixExeWriters(tc.bin, tree.stat, iamt445bAsIs)
		if err != nil {
			t.Fatalf("%s: %v", tc.bin, err)
		}
		found := false
		for _, w := range who {
			if strings.HasPrefix(w, tc.want+" (") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: writers=%v, want %s among them", tc.bin, who, tc.want)
		}
	}
}

func TestIAMT445b_ALinkIsFollowedToWhereTheProgramReallyIs(t *testing.T) {
	tree := iamt445bRootTree()
	resolve := func(p string) (string, error) {
		if p == "/usr/local/bin/iamtunnel" {
			return "/home/alice/tools/iamtunnel", nil
		}
		return p, nil
	}
	who, err := unixExeWriters("/usr/local/bin/iamtunnel", tree.stat, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(who) == 0 || !strings.Contains(strings.Join(who, ";"), "/home/alice (") {
		t.Fatalf("writers=%v: a link to a program under someone's home must name that home", who)
	}
}

func TestIAMT445b_AnUncheckablePathIsAnError(t *testing.T) {
	tree := iamt445bRootTree()
	if _, err := unixExeWriters("/nowhere/iamtunnel", tree.stat, iamt445bAsIs); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err=%v, want the stat failure itself: an unchecked program must not pass as a safe one", err)
	}
}

// The refusal itself: named, with the fix, and a user error (exit 2) like
// its Windows counterpart - the operator put the program in the wrong
// place, nothing in the environment failed.
func TestIAMT445b_ServerInstallRefusesAProgramSomeoneElseCanChange(t *testing.T) {
	writers := func(string) ([]string, error) { return []string{"/opt/tools (owned by uid 1000)"}, nil }
	err := refuseChangeableServiceExe("server install", "/opt/tools/iamtunnel", writers)
	if err == nil {
		t.Fatal("server install accepted a program someone other than root can change")
	}
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitUser {
		t.Errorf("refusal %v is not a user error (exit %d): the operator's choice of place, not the environment", err, exitUser)
	}
	for _, want := range []string{"/opt/tools/iamtunnel", "/opt/tools (owned by uid 1000)", "as root", "sudo install -o root -m 0755"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if err := refuseChangeableServiceExe("server install", "/usr/local/bin/iamtunnel", func(string) ([]string, error) { return nil, nil }); err != nil {
		t.Errorf("a program only root can change was refused: %v", err)
	}
	if err := refuseChangeableServiceExe("server install", "/x", func(string) ([]string, error) { return nil, fs.ErrPermission }); err == nil {
		t.Error("a program whose owners could not be checked was accepted")
	}
}
