package events

// iamt332_ownership_test.go — IAMT-332 round two: events.jsonl is among
// the files a root-run maintenance command can CREATE ("gateway pair"
// over a gateway whose journal was never written yet, or after a log
// rotation went missing). A fresh file carries the creating process's
// account, so without adoption at the creation site the unprivileged
// service would find its own journal owned by root and could never
// append another event.
//
// The real step is a chown on POSIX: no test may chown for real, and
// only root could. The test records the request through the
// adoptOwnership seam instead; nothing touches real ownership and no
// privilege is needed, on any platform.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLogAdoptsTheDataDirOwnerWhenItCreatesTheFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, DefaultLogFileName)

	orig := adoptOwnership
	var adopted []string
	adoptOwnership = func(f *os.File, replacedPath string) error {
		adopted = append(adopted, f.Name())
		if replacedPath != "" {
			t.Errorf("the log creation asked to adopt the owner of %q, want the empty replacement — a created file takes the data directory's owner, not anybody's replaced file", replacedPath)
		}
		return nil
	}
	t.Cleanup(func() { adoptOwnership = orig })

	l, err := OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	defer func() { _ = l.Close() }()

	if len(adopted) == 0 {
		t.Fatal("OpenLog never asked for the created log's ownership to be adopted — a root run that creates events.jsonl would leave it owned by root and the service could never append another event (IAMT-332 round 2)")
	}
	if len(adopted) != 1 || adopted[0] != logPath {
		t.Errorf("OpenLog asked for adoption about %v, want exactly once for %q", adopted, logPath)
	}

	// A second OpenLog over the now-existing file must still adopt: the
	// common case finds the same owner and pays nothing (the fast path),
	// but a pre-fix root-owned file gets healed by the same step instead
	// of staying unreadable forever.
	l2, err := OpenLog(logPath)
	if err != nil {
		t.Fatalf("second OpenLog: %v", err)
	}
	defer func() { _ = l2.Close() }()

	if len(adopted) != 2 {
		t.Errorf("reopening an existing log asked for adoption %d times (%v), want exactly once more — every open that may have created the file adopts its owner, which is also what heals a pre-fix root-owned log", len(adopted), adopted)
	}
}

// Round three: events.jsonl is a LONG-LIVED file reused across restarts,
// so its open cannot be O_EXCL-unconditionally — but a symlink planted at
// its real name must be refused, not opened through. The pre-round-three
// open followed the link: the ownership adoption then Fchowned whatever
// the directory's owner had pointed it at, and the torn-tail repair
// appended a byte to it.
func TestOpenLogRefusesASymlinkAtTheLogFilesName(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, DefaultLogFileName)

	target := filepath.Join(t.TempDir(), "victim")
	const canary = "the file a planted symlink points at"
	if err := os.WriteFile(target, []byte(canary), 0o600); err != nil {
		t.Fatalf("write the symlink target: %v", err)
	}
	if err := os.Symlink(target, logPath); err != nil {
		t.Skipf("this platform refuses the symlink the scenario needs (usually an unprivileged Windows): %v", err)
	}

	orig := adoptOwnership
	var adopted []string
	adoptOwnership = func(f *os.File, replacedPath string) error {
		adopted = append(adopted, f.Name())
		return nil
	}
	t.Cleanup(func() { adoptOwnership = orig })

	l, err := OpenLog(logPath)
	if err == nil {
		_ = l.Close()
		t.Fatal("OpenLog opened a symlink planted at the log file's name — the service account can point a root-run command's descriptor (its ownership adoption, its torn-tail append) at any file on the system; a symlink at a gateway data file's name must be refused (IAMT-332 round 3)")
	}
	if len(adopted) != 0 {
		t.Errorf("the refused open still asked for ownership adoption (%v) — nothing at the end of a planted symlink may be touched", adopted)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("re-read the symlink target: %v", err)
	}
	if string(got) != canary {
		t.Errorf("the symlink target changed (%q) — neither the torn-tail repair nor the open may write behind a planted link", got)
	}
	if st, err := os.Lstat(logPath); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the planted symlink did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", err, st)
	}
}
