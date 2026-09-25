//go:build linux || windows

package winkeys

// buildiamtunnel_test.go — the two build helpers only the linux and windows
// tests use. They are tagged because on darwin nothing builds a helper binary
// (the darwin half of the watchdog is exercised through the queue seam, not
// through a spawned process), and an untagged helper nothing calls is exactly
// the U1000 finding staticcheck reports.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// buildIamtunnel compiles the real CLI binary into dst and returns dst.
//
// It goes through testsupport.BuildIamtunnel rather than buildPackage because
// that helper (IAMT-302) knows which builds need cgo on this host and reports
// "cannot build a cgo package here" as ErrNoCgo — a skip, not a failure. Its
// own module-root lookup walks up from the working directory, which is this
// package's directory for every test (the one test that moves it restores it
// through t.Chdir), so it lands on the same root buildPackage uses.
func buildIamtunnel(t *testing.T, dst string) string {
	t.Helper()
	if err := testsupport.BuildIamtunnel(dst); err != nil {
		if errors.Is(err, testsupport.ErrNoCgo) {
			t.Skip("building iamtunnel binary requires cgo on Linux/macOS (no C toolchain or CGO_ENABLED=0)")
		}
		t.Fatalf("build real iamtunnel: %v", err)
	}
	return dst
}

// testdataPackage names a helper under internal/winkeys/testdata by its module
// path, so callers never spell out a path relative to a directory.
func testdataPackage(name string) string {
	return fmt.Sprintf("github.com/ultrathinker/iamtunnel/internal/winkeys/testdata/%s", name)
}
