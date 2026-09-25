package main

// R1 supplementary round, found while fixing R1-CX F-18: the Windows window refuses to
// hand a file another account can change to UAC (refuseElevatingTamperableExe,
// IAMT-445), and server install on Linux and macOS refuses a unit binary
// anyone but root can change (IAMT-445b). The window's own "Restart as
// administrator" on Linux (pkexec) and macOS (the administrator prompt)
// asked nobody anything: whoever could change the file, or rename a
// directory on the way to it, was answering the password prompt for the
// person who pressed the button - and got root for it.
//
// The window files need cgo and are built only on their own platforms, so
// the wiring is pinned by reading them, and the check itself - a pure
// function of what stat says - on every platform the tests run on.

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestR1X_TheUnixWindowAsksWhoCanChangeTheProgramBeforeRestartingItAsRoot(t *testing.T) {
	for _, c := range []struct{ file, elevates string }{
		{"gui_linux.go", `linuxCommand(pkexec`},
		{"gui_darwin.go", "macos.RelaunchAsAdmin(exe)"},
	} {
		body, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(body)
		elevate := strings.Index(src, c.elevates)
		if elevate < 0 {
			t.Fatalf("%s no longer restarts the program through %q - this test has to follow it there", c.file, c.elevates)
		}
		check := strings.Index(src, "refuseElevatingChangeableExe(exe)")
		if check < 0 || check > elevate {
			t.Errorf("%s restarts the program as root (%s) without first asking who else can change it", c.file, c.elevates)
		}
	}

	// R2 (R1-CX F-25): which pkexec runs is pinned in the source too —
	// it must come from findPkexec's FIXED system paths, never from the
	// invoking user's PATH (the behavior half lives on the seams in
	// iamt254_gui_linux_test.go).
	src, err := os.ReadFile("gui_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `[]string{"/usr/bin/pkexec", "/bin/pkexec"}`) {
		t.Errorf("gui_linux.go no longer resolves pkexec from the fixed system paths /usr/bin/pkexec and /bin/pkexec")
	}
}

// r1xTree is a file system as stat sees it, for a person with uid 1000
// and primary group 1000.
func r1xTree() iamt445bTree {
	return iamt445bTree{
		"/":                               {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr":                            {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local":                      {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local/bin":                  {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/usr/local/bin/iamtunnel":        {uid: 0, gid: 0, mode: 0o755},
		"/home":                           {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/home/alice":                     {uid: 1000, gid: 1000, mode: fs.ModeDir | 0o750},
		"/home/alice/Downloads":           {uid: 1000, gid: 1000, mode: fs.ModeDir | 0o775},
		"/home/alice/Downloads/iamtunnel": {uid: 1000, gid: 1000, mode: 0o775},
		"/tmp":                            {uid: 0, gid: 0, mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"/tmp/go-build1":                  {uid: 1000, gid: 1000, mode: fs.ModeDir | 0o700},
		"/tmp/go-build1/iamtunnel":        {uid: 1000, gid: 1000, mode: 0o755},
		"/tmp/bob":                        {uid: 1001, gid: 1001, mode: fs.ModeDir | 0o755},
		"/tmp/bob/iamtunnel":              {uid: 1000, gid: 1000, mode: 0o755},
		"/Applications":                   {uid: 0, gid: 80, mode: fs.ModeDir | 0o775},
		"/Applications/iamtunnel":         {uid: 1000, gid: 80, mode: 0o755},
		"/opt":                            {uid: 0, gid: 0, mode: fs.ModeDir | 0o755},
		"/opt/shared":                     {uid: 0, gid: 2000, mode: fs.ModeDir | 0o775},
		"/opt/shared/iamtunnel":           {uid: 0, gid: 0, mode: 0o755},
		"/srv":                            {uid: 0, gid: 0, mode: fs.ModeDir | 0o777},
		"/srv/iamtunnel":                  {uid: 1000, gid: 1000, mode: 0o755},
		"/home/bob":                       {uid: 1001, gid: 1001, mode: fs.ModeDir | 0o755},
		"/home/bob/iamtunnel":             {uid: 1001, gid: 1001, mode: 0o755},
	}
}

func r1xAlice() exeElevator {
	// root's group, alice's own, and the macOS admin group: members of
	// the last can become root with their own password anyway.
	return exeElevator{uid: 1000, gids: map[uint32]bool{0: true, 1000: true, 80: true}}
}

func TestR1X_AProgramOnlyThePersonAndAdministratorsCanChangeMayBeRestartedAsRoot(t *testing.T) {
	tree := r1xTree()
	for _, exe := range []string{
		"/usr/local/bin/iamtunnel",        // root's
		"/home/alice/Downloads/iamtunnel", // the person's own, group-writable by the person's own group
		"/tmp/go-build1/iamtunnel",        // under the sticky /tmp, in a directory of the person's own
		"/Applications/iamtunnel",         // macOS: root:admin 0775, as the system ships it
	} {
		who, err := elevationExeWriters(exe, r1xAlice(), tree.stat, iamt445bAsIs)
		if err != nil || len(who) != 0 {
			t.Errorf("%s: writers=%v err=%v, want none", exe, who, err)
		}
	}
}

func TestR1X_AProgramSomeoneElseCanChangeIsNotRestartedAsRoot(t *testing.T) {
	tree := r1xTree()
	for _, tc := range []struct{ exe, want string }{
		{"/home/bob/iamtunnel", "/home/bob/iamtunnel"}, // another person's file
		{"/tmp/bob/iamtunnel", "/tmp/bob"},             // the person's file in a directory another person owns
		{"/opt/shared/iamtunnel", "/opt/shared"},       // a directory a group of other people may write
		{"/srv/iamtunnel", "/srv"},                     // a directory everybody may write, without the sticky bit
	} {
		who, err := elevationExeWriters(tc.exe, r1xAlice(), tree.stat, iamt445bAsIs)
		if err != nil {
			t.Fatalf("%s: %v", tc.exe, err)
		}
		found := false
		for _, w := range who {
			if strings.HasPrefix(w, tc.want+" (") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: writers=%v, want %s named", tc.exe, who, tc.want)
		}
	}
	// A path that cannot be looked at is an error, never a pass.
	if _, err := elevationExeWriters("/nowhere/iamtunnel", r1xAlice(), tree.stat, iamt445bAsIs); err == nil {
		t.Error("a path stat cannot see was passed")
	}
}
