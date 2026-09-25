package winkeys

// buildhelpers_test.go — the one place this package's tests compile anything.
//
// IAMT-305: the build helpers used to live next to the tests that needed them
// (buildLinux in the linux file, build in the windows one) and each took the
// package path and the working directory as arguments. That split is how
// every ./testdata/... build broke at once when the module root replaced the
// package directory as cmd.Dir: `./testdata/helper_watchdog_parent` resolved
// to <repo>/testdata, which does not exist, and the failure reached the test
// as a one-line "build parent: exit status 1" — the combined output, which
// says `stat <repo>/testdata/...: directory not found`, was lost in the
// message.
//
// So: one helper, one convention. Every package is named by its MODULE PATH
// (github.com/ultrathinker/iamtunnel/internal/winkeys/testdata/wd_linux) and every build runs in the
// module root — never in a path computed from "where the calling file is" or
// from os.Getwd(). The failure carries the combined output and the directory
// the build ran in, so a reader never has to reproduce it to learn why.

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// buildPackage compiles the module package pkg into dst and returns dst.
// It fails the test — with go's own output — if the build does not succeed.
func buildPackage(t *testing.T, dst, pkg string) string {
	t.Helper()
	root := winkeysRepoRoot(t)
	cmd := exec.Command("go", "build", "-o", dst, pkg)
	cmd.Dir = root
	cmd.Env = testsupport.IamtunnelBuildEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = "<go build printed nothing>"
		}
		t.Fatalf("go build %s (in %s): %v\n%s", pkg, root, err, text)
	}
	return dst
}
