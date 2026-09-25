package scripts

// check_rawfileio_test.go — gate 16 (IAMT-332) in go test form, so that
// the protection lives not only in scripts/gates.ps1|sh but in every
// `go test ./...` as well. The checker itself is scripts/check_rawfileio.go
// with the //go:build ignore build tag (the go run seam, same as
// check_errdict and the other checkers), so the test invokes it as a
// subprocess:
//
//   - -selftest runs the engine's built-in probes: harmless code with no
//     findings, a writer through p+".tmp" -- caught, the CreateTemp
//     pattern -- clean, os and ioutil import aliases -- caught, a live
//     allowlist entry not stale, a stale one -- caught. The negative
//     control and the stale entry live here, inside the checker, so
//     that they travel together with the detector;
//   - a real run over the repository root: not a single finding outside
//     the allowlist, not a single stale entry. This is the anti-rot
//     test: somebody's new os.WriteFile bypassing internal/datafile
//     turns red right here, without waiting for a full gate run.

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot is anchored at THIS file's location, not at the working
// directory: the scan must see exactly this checkout, wherever the test
// binary happens to run.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	return filepath.Dir(filepath.Dir(thisFile)) // scripts/ -> repo root
}

func runChecker(t *testing.T, args ...string) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not in PATH: %v", err)
	}
	out, err := exec.Command(goTool, append([]string{"run", "check_rawfileio.go", "rawfileio_types.go"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("go run check_rawfileio.go %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestCheckRawfileioSelftest(t *testing.T) {
	runChecker(t, "-selftest")
}

func TestCheckRawfileioRepoClean(t *testing.T) {
	runChecker(t, "-root", repoRoot(t))
}
