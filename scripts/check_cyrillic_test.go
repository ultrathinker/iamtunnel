package scripts

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func cyrillicRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

func runCyrillicChecker(t *testing.T, args ...string) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is not in PATH: %v", err)
	}
	out, err := exec.Command(goTool, append([]string{"run", "check_cyrillic.go"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("go run check_cyrillic.go %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestCheckCyrillicSelftest(t *testing.T) {
	runCyrillicChecker(t, "-selftest")
}

func TestCheckCyrillicRepoClean(t *testing.T) {
	runCyrillicChecker(t, "-root", cyrillicRepoRoot(t))
}
