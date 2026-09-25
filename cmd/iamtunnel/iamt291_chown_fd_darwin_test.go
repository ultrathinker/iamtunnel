//go:build darwin

package main

// iamt291_chown_fd_darwin_test.go — canary tests for the second layer
// of IAMT-291 (fd-based chownDirByFD, round 2).
//
// Each test catches one specific regression found in review rounds
// 5/6:
//
//   - TestIAMT291_ChownsRootDirectory       — the root of the tree is
//     fchown'ed (round 1 chown'ed only the entries);
//   - TestIAMT291_FifoRefusedWithoutHanging — a FIFO in the tree gives
//     a refusal in finite time, not an eternal hang in Openat;
//   - TestIAMT291_SymlinksRefused           — a symlink at the root and
//     inside the tree is rejected, no chown happens through the
//     symlink's target, and the refusal names the symlink (on a real
//     Mac darwin answers open(O_NOFOLLOW|O_DIRECTORY) on a symlink
//     with ENOTDIR, not ELOOP — a "not a directory" refusal tells the
//     operator nothing);
//   - TestIAMT291_DeepTreeRefusedBeforeFdExhaustion — a tree deeper
//     than maxChownDepth gives a named refusal BEFORE the next level is
//     opened (every level keeps its parent directory open; without the
//     limit a few hundred nested directories exhaust the ~256 soft fd
//     limit and bring install down with EMFILE);
//   - TestIAMT291_HardLinkedFileRefused — a regular file with Nlink > 1
//     (a hard link to an inode outside the tree) is rejected via Fstat
//     on the opened fd, and that inode never reaches Fchown;
//   - TestIAMT291_FailedFchownDoesNotLeakFds — a failed fchown on a
//     nested directory does not leak fds: the *os.File wrapper with the
//     deferred Close must exist before the first failure point (review
//     round 7; on darwin the leak shows up as new entries in /dev/fd).
//
// The tests run as an ordinary unprivileged user (the way the Mac
// runner drives them): the chown target is the process's own uid/gid
// (Geteuid/Getegid), and Fchown itself is substituted through the
// chownFDFn seam with a recording fake — the test never changes real
// file ownership. Calling chownTreeNoFollow directly bypasses
// guardProductionLaunchd legitimately: the guard sits on the
// darwinLaunchd closures, not on the bypass.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// chownFDCall records one chownFDFn invocation: the dev/ino the fd
// named at call time plus the requested owner. dev/ino are resolved
// inside the fake via unix.Fstat, so assertions pin exact inodes — a
// chown of a symlink's target, of a replaced file, or of some other
// directory cannot masquerade as the asserted one.
type chownFDCall struct {
	// dev is widened to int64: Stat_t.Dev's type on darwin is
	// platform-defined (int32 here), and widening at the recording
	// site keeps the assertions portable.
	dev int64
	ino uint64
	uid int
	gid int
}

// recordChownSeam swaps chownFDFn for a recording fake for the
// duration of the test. The fake Fstats each fd at call time (before
// anything is closed) and appends a chownFDCall; the real ownership of
// any file is left untouched. Returns a snapshot function.
func recordChownSeam(t *testing.T) func() []chownFDCall {
	t.Helper()

	var mu sync.Mutex
	var calls []chownFDCall
	prod := chownFDFn
	chownFDFn = func(fd int, uid, gid int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		mu.Lock()
		calls = append(calls, chownFDCall{dev: int64(st.Dev), ino: st.Ino, uid: uid, gid: gid})
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { chownFDFn = prod })

	return func() []chownFDCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]chownFDCall(nil), calls...)
	}
}

// lstatIno returns the dev/ino of path itself (never through a
// symlink), so assertions address inodes rather than names. unix.Lstat
// is used instead of os.Lstat on purpose: os.FileInfo.Sys() on darwin
// carries a *syscall.Stat_t, while the production walk — whose chown
// seam records what the assertions compare against — speaks
// unix.Stat_t (Dev int32, Ino uint64). dev is widened to int64 to
// match chownFDCall.
func lstatIno(t *testing.T, path string) (int64, uint64) {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	return int64(st.Dev), st.Ino
}

// assertChowned fails when no recorded call names exactly the dev/ino
// with the requested owner. why becomes the canary prefix.
func assertChowned(t *testing.T, calls []chownFDCall, dev int64, ino uint64, uid, gid int, why string) {
	t.Helper()

	for _, c := range calls {
		if c.dev == dev && c.ino == ino && c.uid == uid && c.gid == gid {
			return
		}
	}
	t.Fatalf("%s: dev=%d ino=%d (uid=%d gid=%d) not among %+v", why, dev, ino, uid, gid, calls)
}

// TestIAMT291_ChownsRootDirectory pins the round-two defect: the root
// of the tree must be fchown'ed itself, before its entries are walked.
// The canary fires when the root Fchown (top of chownDirByFD) is
// removed — exactly the shape review round5 found, where only entries
// were chowned and the first-install data dir stayed root:root 0700.
func TestIAMT291_ChownsRootDirectory(t *testing.T) {
	root := t.TempDir()
	hostkey := filepath.Join(root, "hostkey")
	if err := os.WriteFile(hostkey, []byte("key material"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	snapshot := recordChownSeam(t)

	if err := chownTreeNoFollow(root, unix.Geteuid(), unix.Getegid()); err != nil {
		t.Fatalf("chownTreeNoFollow(%s): %v", root, err)
	}

	calls := snapshot()
	rootDev, rootIno := lstatIno(t, root)
	assertChowned(t, calls, rootDev, rootIno, unix.Geteuid(), unix.Getegid(),
		"IAMT-291 canary: the root directory itself was never fchown'ed — chownDirByFD must chown its own fd before walking entries",
	)

	// The inner file must still be chowned: fixing the root must not
	// regress the round-one behaviour on entries.
	fileDev, fileIno := lstatIno(t, hostkey)
	assertChowned(t, calls, fileDev, fileIno, unix.Geteuid(), unix.Getegid(),
		"IAMT-291 canary: the regular file inside the tree was not fchown'ed — entries must keep being chowned after the root fix",
	)
}

// TestIAMT291_FifoRefusedWithoutHanging pins the round-two defect: a
// FIFO inside the data dir must produce an error quickly instead of
// parking the install in Openat (a blocking O_RDONLY open of a FIFO
// waits for a writer forever). The walk runs in a goroutine under a
// deadline; a timeout is a hard failure naming the hang.
func TestIAMT291_FifoRefusedWithoutHanging(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "stray_fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	snapshot := recordChownSeam(t)

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() {
		done <- result{err: chownTreeNoFollow(root, unix.Geteuid(), unix.Getegid())}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("IAMT-291 canary: chownTreeNoFollow accepted a FIFO inside the tree (%s) — special files must be refused", fifo)
		}
		if !strings.Contains(r.err.Error(), "stray_fifo") {
			t.Fatalf("IAMT-291 canary: refusal of the FIFO does not name it: %v", r.err)
		}
		fifoDev, fifoIno := lstatIno(t, fifo)
		for _, c := range snapshot() {
			if c.dev == fifoDev && c.ino == fifoIno {
				t.Fatalf("IAMT-291 canary: the FIFO was chown'ed (dev %d ino %d) instead of refused", fifoDev, fifoIno)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("IAMT-291 canary: chownTreeNoFollow blocked on a FIFO (%s) for over 10s — entries must be classified with fstatat before any open; a blocking open of a FIFO waits for a writer and hangs the install", fifo)
	}
}

// TestIAMT291_SymlinksRefused keeps the round-one guarantee through the
// rewrite: a symlink at the root and a symlink inside the tree are both
// refused, and the chown never lands on the link's target.
func TestIAMT291_SymlinksRefused(t *testing.T) {
	uid, gid := unix.Geteuid(), unix.Getegid()

	t.Run("at the root", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		root := filepath.Join(t.TempDir(), "data_link")
		if err := os.Symlink(target, root); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		snapshot := recordChownSeam(t)

		err := chownTreeNoFollow(root, uid, gid)
		if err == nil {
			t.Fatal("IAMT-291 canary: a symlinked data dir was accepted — the root must be opened O_NOFOLLOW and refused")
		}
		// darwin answers open(O_NOFOLLOW|O_DIRECTORY) on a symlink
		// with ENOTDIR, so the refusal must name the symlink
		// explicitly — "not a directory" tells the operator nothing.
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("IAMT-291 canary: refusal of a symlinked root does not name the symlink (got %q)", err)
		}
		if !strings.Contains(err.Error(), "data_link") {
			t.Fatalf("IAMT-291 canary: refusal of a symlinked root does not name its path: %v", err)
		}
		tgtDev, tgtIno := lstatIno(t, target)
		for _, c := range snapshot() {
			if c.dev == tgtDev && c.ino == tgtIno {
				t.Fatalf("IAMT-291 canary: the symlink target (dev %d ino %d) was chown'ed — it was followed instead of refused", tgtDev, tgtIno)
			}
		}
	})

	t.Run("inside the tree", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "hostkey"), []byte("key material"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		target := filepath.Join(t.TempDir(), "outside_target")
		if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(root, "data_link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		snapshot := recordChownSeam(t)

		err := chownTreeNoFollow(root, uid, gid)
		if err == nil {
			t.Fatal("IAMT-291 canary: a symlink inside the tree was accepted — it must be refused")
		}
		if !strings.Contains(err.Error(), "data_link") {
			t.Fatalf("IAMT-291 canary: refusal of the symlink does not name it: %v", err)
		}
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("IAMT-291 canary: refusal of the symlink does not say it is a symlink: %v", err)
		}
		tgtDev, tgtIno := lstatIno(t, target)
		for _, c := range snapshot() {
			if c.dev == tgtDev && c.ino == tgtIno {
				t.Fatalf("IAMT-291 canary: the symlink target (dev %d ino %d) was chown'ed — it was followed instead of refused", tgtDev, tgtIno)
			}
		}
	})
}

// TestIAMT291_DeepTreeRefusedBeforeFdExhaustion pins the depth limit:
// the walk must stop with a named refusal BEFORE opening level
// maxChownDepth+1 — every open level holds its parent directory, so an
// unbounded walk drains the soft fd limit (~256 on darwin) on a tree
// of a few hundred nested directories. Level maxChownDepth itself is
// still chowned (off-by-one canary); nothing past it is.
func TestIAMT291_DeepTreeRefusedBeforeFdExhaustion(t *testing.T) {
	uid, gid := unix.Geteuid(), unix.Getegid()
	root := t.TempDir()
	// levelPath returns the path of the directory at the given level
	// (the root itself is level 1): root/d1/.../d(n-1).
	levelPath := func(n int) string {
		p := root
		for i := 1; i <= n-1; i++ {
			p = filepath.Join(p, fmt.Sprintf("d%d", i))
		}
		return p
	}
	for lvl := 2; lvl <= maxChownDepth+2; lvl++ {
		if err := os.Mkdir(levelPath(lvl), 0o755); err != nil {
			t.Fatalf("Mkdir %s: %v", levelPath(lvl), err)
		}
	}

	snapshot := recordChownSeam(t)

	err := chownTreeNoFollow(root, uid, gid)
	if err == nil {
		t.Fatalf("IAMT-291 canary: a tree %d levels deep was accepted without refusal — the walk must stop with a named error before fd exhaustion", maxChownDepth+2)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("deeper than %d", maxChownDepth)) {
		t.Fatalf("IAMT-291 canary: the depth refusal does not name the limit (%d): %v", maxChownDepth, err)
	}

	calls := snapshot()
	atLimitDev, atLimitIno := lstatIno(t, levelPath(maxChownDepth))
	assertChowned(t, calls, atLimitDev, atLimitIno, uid, gid,
		fmt.Sprintf("IAMT-291 canary: the directory at the limit itself (level %d) was not fchown'ed — the depth check is off by one", maxChownDepth))
	pastDev, pastIno := lstatIno(t, levelPath(maxChownDepth+1))
	for _, c := range calls {
		if c.dev == pastDev && c.ino == pastIno {
			t.Fatalf("IAMT-291 canary: the level past the depth limit (level %d) was opened and fchown'ed (dev %d ino %d) — the limit must be checked before opening the next level", maxChownDepth+1, pastDev, pastIno)
		}
	}
}

// TestIAMT291_HardLinkedFileRefused pins the Nlink guard: a regular
// file inside the tree with more than one hard link may share its
// inode with a file outside the tree, and fchown by fd would change
// that outside file's owner. The refusal must come from the Fstat of
// the opened, identity-checked fd, and the shared inode must never
// reach the chown seam.
func TestIAMT291_HardLinkedFileRefused(t *testing.T) {
	uid, gid := unix.Geteuid(), unix.Getegid()
	outside := filepath.Join(t.TempDir(), "outside_target")
	if err := os.WriteFile(outside, []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	root := t.TempDir()
	linked := filepath.Join(root, "linked_file")
	if err := os.Link(outside, linked); err != nil {
		t.Skipf("hard links are not available for this user/filesystem: %v", err)
	}

	snapshot := recordChownSeam(t)

	err := chownTreeNoFollow(root, uid, gid)
	if err == nil {
		t.Fatalf("IAMT-291 canary: a hard-linked regular file (%s) was accepted — chowning it would change the owner of the inode outside the tree", linked)
	}
	if !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("IAMT-291 canary: the hard-link refusal does not mention hard links: %v", err)
	}
	if !strings.Contains(err.Error(), "linked_file") {
		t.Fatalf("IAMT-291 canary: the hard-link refusal does not name the file: %v", err)
	}
	// The link and the outside file are the same inode: if any recorded
	// call names it, fchown reached outside the tree.
	dev, ino := lstatIno(t, linked)
	for _, c := range snapshot() {
		if c.dev == dev && c.ino == ino {
			t.Fatalf("IAMT-291 canary: the shared inode (dev %d ino %d) behind the hard link was passed to Fchown — Nlink must be checked after Fstat on the opened fd and the file refused", dev, ino)
		}
	}
}

// TestIAMT291_FailedFchownDoesNotLeakFds pins the ownership order in
// chownDirByFD: the *os.File wrap with its deferred Close must exist
// before the first thing that can fail. A failing fchown on a nested
// directory used to return before the wrap existed and leaked that
// level's fd — the caller's defer only ever covered the caller's own.
// On darwin the leak is visible as new entries in /dev/fd.
func TestIAMT291_FailedFchownDoesNotLeakFds(t *testing.T) {
	uid, gid := unix.Geteuid(), unix.Getegid()
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "inner.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Both counts are taken the same way, so the listing fd each
	// ReadDir opens for itself cancels out; only a real leak shifts
	// the difference.
	countFDs := func() int {
		t.Helper()
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Fatalf("ReadDir /dev/fd: %v", err)
		}
		return len(entries)
	}

	// The seam succeeds for the tree root (the walk must reach the
	// nested directory) and fails for every other directory: the
	// failure under test fires inside chownDirByFD's own frame, at its
	// fchown, right where the round-five leak used to happen.
	seamErr := errors.New("IAMT-291 seam: fchown refused")
	rootDev, rootIno := lstatIno(t, root)
	prod := chownFDFn
	t.Cleanup(func() { chownFDFn = prod })
	chownFDFn = func(fd int, uid, gid int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR && (int64(st.Dev) != rootDev || st.Ino != rootIno) {
			return seamErr
		}
		return nil
	}

	before := countFDs()
	err := chownTreeNoFollow(root, uid, gid)
	after := countFDs()

	// The failure must be the arranged one — otherwise the leak
	// comparison below proves nothing.
	if err == nil || !strings.Contains(err.Error(), "fchown refused") || !strings.Contains(err.Error(), "sub") {
		t.Fatalf("IAMT-291 canary: the walk did not fail on the nested directory's fchown as arranged (err: %v) — the fd-leak check would be vacuous", err)
	}
	if leaked := after - before; leaked > 0 {
		t.Fatalf("IAMT-291 canary: leaked %d fd(s) on a failing fchown of a nested directory (open fds before: %d, after: %d) — chownDirByFD must wrap the fd in *os.File with a deferred Close BEFORE the fchown, so every failure path closes it", leaked, before, after)
	}
}
