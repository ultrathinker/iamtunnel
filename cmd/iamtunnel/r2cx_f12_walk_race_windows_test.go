package main

// R2-CX F-12: the hardening walks - the gateway's data directory and the
// machine's - classified each child through filepath.WalkDir (its type as
// the directory listing reported it) and then set its DACL by name,
// SetNamedSecurityInfo resolving the name afresh. Between the two the name
// could come to mean something else: a hard link to a file outside the
// directory (which needs no privilege at all), or a directory link whose
// listing the walk then went on into. The lockdown - owner included, since
// R2-CX F-07/F-13 - then fell on the other object.
//
// The swap happens in the window itself, through the walks' own seams, as
// the owner of a pre-made directory could do it in a race.

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// r2cxF12Walks are the two hardening walks, each with its window seam.
var r2cxF12Walks = []struct {
	name   string
	window *func(string)
	walk   func(dir string) error
}{
	{"machine", &serverTreeBeforeApply, func(dir string) error { return hardenServerDir(dir, false) }},
	{"gateway", &gatewayTreeBeforeApply, func(dir string) error { return hardenGatewayDataTree(dir, false, nil) }},
}

// r2cxF12Untouched fails the test if the lockdown reached path.
func r2cxF12Untouched(t *testing.T, walk, path string) {
	t.Helper()
	protected, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatalf("the %s walk locked %s, outside the directory it was locking: the name was checked as one object and locked as another", walk, path)
	}
}

func TestR2CX_F12_AFileSwappedBetweenItsCheckAndItsLockIsNotTheOneLocked(t *testing.T) {
	for _, w := range r2cxF12Walks {
		t.Run(w.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			child := filepath.Join(dir, "state.json")
			if err := os.WriteFile(child, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(t.TempDir(), "sentinel.dat")
			testsupport.WriteSentinelFile(t, sentinel)

			// In the window, the name is made to mean the sentinel: the
			// file is removed and a hard link to the sentinel takes its
			// name. A walk that holds the child open cannot be raced this
			// way - the remove is refused - and that is a pass, not an
			// error.
			*w.window = func(p string) {
				if p != child {
					return
				}
				if err := os.Remove(child); err != nil {
					return
				}
				if err := os.Link(sentinel, child); err != nil {
					t.Errorf("plant the hard link: %v", err)
				}
			}
			t.Cleanup(func() { *w.window = nil })

			_ = w.walk(dir)
			r2cxF12Untouched(t, w.name, sentinel)
		})
	}
}

func TestR2CX_F12_ADirectorySwappedBetweenItsCheckAndItsLockIsNotWalkedInto(t *testing.T) {
	for _, w := range r2cxF12Walks {
		t.Run(w.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			sub := filepath.Join(dir, "recordings")
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "sentinel.dat")
			testsupport.WriteSentinelFile(t, sentinel)

			*w.window = func(p string) {
				if p != sub {
					return
				}
				if err := os.Remove(sub); err != nil {
					return
				}
				if err := os.Symlink(outside, sub); err != nil {
					t.Skipf("this host does not grant symlink creation, so the directory row cannot be planted here (%v)", err)
				}
			}
			t.Cleanup(func() { *w.window = nil })

			_ = w.walk(dir)
			r2cxF12Untouched(t, w.name, sentinel)
		})
	}
}

// Install writes into the data directory by name after locking it: until
// it releases the lock, nothing on the path may be renamed away and
// replaced.
func TestR2CX_F12_TheLockedDirectoryStaysPinnedUntilReleased(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	dir := filepath.Join(parent, "gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := lockGatewayDataTree(dir, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".moved"); err == nil {
		release()
		t.Fatal("the locked data directory was renamed away while install still held it")
	}
	if err := os.Rename(parent, parent+".moved"); err == nil {
		release()
		t.Fatal("the directory above the locked data directory was renamed away while install still held it")
	}
	release()
	if err := os.Rename(dir, dir+".moved"); err != nil {
		t.Fatalf("the data directory is still pinned after release: %v", err)
	}
}

// A file with two names is not an object of this directory alone: the
// other name may be outside it.
func TestR2CX_F12_AFileWithTwoNamesIsLeftAloneAndReported(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(t.TempDir(), "sentinel.dat")
	testsupport.WriteSentinelFile(t, sentinel)
	linked := filepath.Join(dir, "state.json")
	if err := os.Link(sentinel, linked); err != nil {
		t.Fatal(err)
	}
	var report strings.Builder
	if err := hardenGatewayDataTree(dir, false, &report); err != nil {
		t.Fatal(err)
	}
	r2cxF12Untouched(t, "gateway", sentinel)
	if !strings.Contains(report.String(), linked) {
		t.Errorf("the file left alone was not reported: %q", report.String())
	}
}

// The directory to lock is the directory, not a link to one: whoever owns
// the link could point it elsewhere after the lock.
func TestR2CX_F12_ARootThatIsALinkIsRefused(t *testing.T) {
	target := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "gateway")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this host does not grant symlink creation, so a linked root cannot be planted here (%v)", err)
	}
	if err := hardenGatewayDataTree(link, false, nil); err == nil {
		t.Fatal("a data directory that is a link was locked")
	}
	r2cxF12Untouched(t, "gateway", target)
}

// r2cxJunction makes link a junction to target: what any account can
// make, no privilege needed.
func r2cxJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J could not make a junction here: %v: %s", err, out)
	}
}

// A link above the data directory is refused as well: install writes into
// the directory by name while it holds it, and the pin holds the directory
// and every real folder above it, not a link - whoever may repoint one
// sends the host key and the bootstrap token wherever it points by then.
func TestR2CX_F12_ADataDirectoryReachedThroughALinkIsRefused(t *testing.T) {
	real := t.TempDir()
	target := filepath.Join(real, "gateway")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "iamtunnel")
	r2cxJunction(t, link, real)
	release, err := lockGatewayDataTree(filepath.Join(link, "gateway"), false, nil)
	if err == nil {
		release()
		t.Fatal("a data directory reached through a junction was locked and pinned: the junction, not the pin, decides where install's writes go next")
	}
	var lp *winkeys.LinkedPathRefusalError
	if !errors.As(err, &lp) {
		t.Fatalf("refused, but not as a linked path: %v", err)
	}
	r2cxF12Untouched(t, "gateway", target)
}

// The refusal is the operator's to act on - another path - so install
// exits denied, as for a foreign owner, not with an environment error.
func TestR2CX_F12_ALinkedDataDirectoryRefusesInstallAsDenied(t *testing.T) {
	real := t.TempDir()
	if err := os.Mkdir(filepath.Join(real, "gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "iamtunnel")
	r2cxJunction(t, link, real)
	setup := windowsServiceSetup{
		hardenExeDir: func(string, string, bool, io.Writer) error { return nil },
		hardenDir:    lockGatewayDataTree,
	}
	release, err := hardenGatewayDirs(setup, gatewayServiceSpec{}, real, filepath.Join(link, "gateway"), false, nil)
	if err == nil {
		release()
	}
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitDenied {
		t.Fatalf("install's answer to a linked data directory = %v, want the denied class (exit %d)", err, exitDenied)
	}
}

// An 8.3 short name is the same folder under another name, not a link.
func TestR2CX_F12_AShortNameOnTheWayIsNotALink(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "a-long-folder-name")
	dir := filepath.Join(parent, "gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	long, err := windows.UTF16PtrFromString(parent)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Skipf("no short name to try here: %v", err)
	}
	short := windows.UTF16ToString(buf[:n])
	if strings.EqualFold(short, parent) {
		t.Skip("8.3 names are off on this volume")
	}
	if err := hardenGatewayDataTree(filepath.Join(short, "gateway"), false, nil); err != nil {
		t.Fatalf("the data directory given by its short name %s was refused: %v", short, err)
	}
}
