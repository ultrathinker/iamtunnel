package winkeys

// moduleroot_test.go — where the package's own source directory and the
// module root come from, for every test in this package that builds or scans
// something by path.
//
// IAMT-305 round 3: those paths used to come from os.Getwd(), and one test in
// this package changes the process working directory on purpose
// (TestIntegrationDoorOnRealSyscalls_CanaryDoorID chdirs into an unrelated
// temp dir so an Fchmodat(AT_FDCWD) bug would surface as a chmod of the wrong
// path). Test order inside a package follows file order, `doors_unix_test.go`
// runs before `doorwatch_linux_test.go`, and the chdir test's cleanup left the
// process in "/". Every later `go build` therefore ran with cmd.Dir = "/" and
// the full package run failed with
//
//	go: go.mod file not found in current directory or any parent directory
//	package github.com/ultrathinker/iamtunnel/cmd/iamtunnel is not in std (/usr/local/go/src/...)
//
// while the -run-filtered run, which skips the chdir test, stayed green. Both
// sides are fixed: that test now uses t.Chdir (which restores the previous
// directory), and these helpers never ask the working directory in the first
// place — the compiler records the path of this file, and the module root is
// the nearest directory above it that holds go.mod.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// winkeysDir returns this package's own source directory — what the tests
// that scan package source (acceptance_test.go's AST and archive passes) and
// the ones that build ./testdata helpers need.
func winkeysDir(t *testing.T) string {
	t.Helper()
	return filepath.Dir(winkeysSourceFile(t))
}

// winkeysRepoRoot returns the module root: the nearest ancestor of this
// package's directory that holds a go.mod. Builds of module-relative packages
// (github.com/ultrathinker/iamtunnel/cmd/iamtunnel) need it as cmd.Dir.
func winkeysRepoRoot(t *testing.T) string {
	t.Helper()
	dir := winkeysDir(t)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod in any directory above %s: the module root cannot be derived from this file's path (a -trimpath build makes it relative), and guessing it from the working directory is exactly the bug IAMT-305 round 3 fixed", winkeysDir(t))
		}
		dir = parent
	}
}

// winkeysSourceFile is this file's path as the compiler recorded it. A
// relative path means the binary was built with -trimpath: fail loudly rather
// than let a build helper guess a directory.
func winkeysSourceFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(file) {
		t.Fatalf("runtime.Caller returned %q for this test file: not an absolute path, so the module root cannot be located without the working directory", file)
	}
	return file
}

// TestModuleRootIgnoresTheWorkingDirectory is the canary for the defect the two
// helpers above exist for, and it is the reason they are asked for on every
// platform rather than only where a build happens: it takes both answers, moves
// the process working directory somewhere unrelated, and requires the same
// answers again. os.Getwd()-based versions of these helpers cannot pass it —
// after the chdir they answer with the temp directory (or "/"), which is
// exactly how the full package run ended up building from outside the module.
func TestModuleRootIgnoresTheWorkingDirectory(t *testing.T) {
	root := winkeysRepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("winkeysRepoRoot returned %s, which holds no go.mod: %v", root, err)
	}
	dir := winkeysDir(t)
	if _, err := os.Stat(filepath.Join(dir, "doors.go")); err != nil {
		t.Fatalf("winkeysDir returned %s, which is not this package's source directory: %v", dir, err)
	}
	if !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		t.Fatalf("winkeysDir (%s) is not below winkeysRepoRoot (%s)", dir, root)
	}

	t.Chdir(t.TempDir())
	if again := winkeysRepoRoot(t); again != root {
		t.Fatalf("after chdir, winkeysRepoRoot returned %s, want %s — the module root must not be read from the working directory (IAMT-305 round 3: a chdir in this package made every later `go build` run outside the module)", again, root)
	}
	if again := winkeysDir(t); again != dir {
		t.Fatalf("after chdir, winkeysDir returned %s, want %s", again, dir)
	}
}
