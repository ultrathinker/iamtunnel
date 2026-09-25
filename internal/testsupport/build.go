package testsupport

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNoCgo is returned when building a package requires cgo (such as cmd/iamtunnel on Linux/macOS)
// but the environment has CGO_ENABLED=0 or no C toolchain is available.
var ErrNoCgo = errors.New("cgo toolchain unavailable for cgo-dependent package")

// buildCacheEnv pins, at process start, the module and build caches this
// machine's real HOME resolves to. A test that isolates HOME (the e2e
// fixture's isolateEnv, PlatformDataEnvAt) runs the builds of this
// package with a HOME inside its own TempDir — and a plain `go build`
// resolves GOPATH, and with it the module cache, from the CURRENT HOME.
// The cache then materialised inside the test's TempDir, read-only the
// way go keeps it, and the TempDir cleanup died on
// "unlinkat .../go/pkg/mod/...: permission denied" (TestIAMT337 on the
// macOS gate, 24.09.2026). With the caches pinned the build reads the
// same caches every other `go` invocation in the gate uses — and writes
// only what any ordinary build writes to them — so the test's TempDir
// stays clean and no module tree is re-downloaded into it on every run.
//
// An explicitly set GOMODCACHE/GOCACHE wins: the snapshot only fills in
// what the environment left to go's defaults. The snapshot is taken in
// init, before any test can t.Setenv HOME.
var buildCacheEnv []string

func init() {
	if _, set := os.LookupEnv("GOMODCACHE"); !set {
		base := ""
		if gp := os.Getenv("GOPATH"); gp != "" && filepath.SplitList(gp)[0] != "" {
			base = filepath.SplitList(gp)[0]
		}
		if base == "" {
			if home, err := os.UserHomeDir(); err == nil && home != "" {
				base = filepath.Join(home, "go")
			}
		}
		if base != "" {
			buildCacheEnv = append(buildCacheEnv, "GOMODCACHE="+filepath.Join(base, "pkg", "mod"))
		}
	}
	if _, set := os.LookupEnv("GOCACHE"); !set {
		if dir, err := os.UserCacheDir(); err == nil && dir != "" {
			buildCacheEnv = append(buildCacheEnv, "GOCACHE="+filepath.Join(dir, "go-build"))
		}
	}
}

// IamtunnelBuildEnv returns the environment for building the iamtunnel binary in subprocess tests.
//
// Platform distinction (IAMT-252, IAMT-302):
//   - On Linux and macOS: cmd/iamtunnel imports internal/ui which brings in Gio GUI (talking to
//     X11/Wayland on Linux, and Cocoa/OpenGL on macOS). These require cgo, so subprocess builds
//     must inherit the parent process's CGO_ENABLED (do not force CGO_ENABLED=0).
//   - On Windows: Gio does not require cgo (uses Win32/Direct3D directly). The release binary policy
//     (SPEC §4.1, Gate 6) explicitly asserts CGO_ENABLED=0 in Windows build info. Subprocess tests
//     on Windows preserve today's behavior exactly by appending CGO_ENABLED=0.
//
// The build caches ride on buildCacheEnv (after os.Environ(), so the pin
// wins any inherited duplicate): a build from inside a test with an
// isolated HOME must not seed a module cache into the test's TempDir.
func IamtunnelBuildEnv() []string {
	env := append(os.Environ(), buildCacheEnv...)
	if runtime.GOOS == "windows" {
		env = append(env, "CGO_ENABLED=0")
	}
	return env
}

// HasCCompiler reports whether a C compiler is available in PATH.
func HasCCompiler() bool {
	if cc := os.Getenv("CC"); cc != "" {
		_, err := exec.LookPath(cc)
		return err == nil
	}
	if _, err := exec.LookPath("gcc"); err == nil {
		return true
	}
	if _, err := exec.LookPath("clang"); err == nil {
		return true
	}
	return false
}

// FindRepoRoot locates the repository root directory by walking up from the current working directory.
func FindRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// BuildIamtunnel builds "github.com/ultrathinker/iamtunnel/cmd/iamtunnel" into the specified dst path.
// If building fails because cgo is required on Linux/macOS but unavailable (e.g. CGO_ENABLED=0
// or no C toolchain), it returns an error wrapping ErrNoCgo so that callers can call t.Skip.
func BuildIamtunnel(dst string) error {
	return BuildPackage(dst, "github.com/ultrathinker/iamtunnel/cmd/iamtunnel")
}

// BuildPackage builds the specified Go package to dst using IamtunnelBuildEnv().
// If the package requires cgo (on Linux/Darwin) and cgo is unavailable or the build fails
// with cgo-related toolchain/constraint errors, an error wrapping ErrNoCgo is returned.
func BuildPackage(dst, pkg string) error {
	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && packageRequiresCgo(pkg) {
		if os.Getenv("CGO_ENABLED") == "0" {
			return fmt.Errorf("%w: CGO_ENABLED=0 in environment", ErrNoCgo)
		}
		if !HasCCompiler() {
			return fmt.Errorf("%w: no C compiler (gcc/clang) found in PATH", ErrNoCgo)
		}
	}

	cmd := exec.Command("go", "build", "-o", dst, pkg)
	if root := FindRepoRoot(); root != "" {
		cmd.Dir = root
	}
	cmd.Env = IamtunnelBuildEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && packageRequiresCgo(pkg) && isCgoBuildFailure(outStr) {
			return fmt.Errorf("%w: %v\n%s", ErrNoCgo, err, strings.TrimSpace(outStr))
		}
		return fmt.Errorf("go build %s: %v\n%s", pkg, err, strings.TrimSpace(outStr))
	}
	return nil
}

func packageRequiresCgo(pkg string) bool {
	return pkg == "github.com/ultrathinker/iamtunnel/cmd/iamtunnel" || strings.HasPrefix(pkg, "github.com/ultrathinker/iamtunnel/internal/ui")
}

func isCgoBuildFailure(out string) bool {
	patterns := []string{
		"build constraints exclude all Go files",
		"gioui.org/internal/vk",
		"gioui.org/internal/gl",
		"cgo: C compiler",
		"undefined: Functions",
		`exec: "gcc": executable file not found`,
		`exec: "clang": executable file not found`,
		"X11/Xlib.h",
		"cannot find -lX11",
		"cannot find -lGL",
		"vulkan/vulkan.h",
		"wayland-client.h",
		"xkbcommon/xkbcommon.h",
	}
	for _, p := range patterns {
		if strings.Contains(out, p) {
			return true
		}
	}
	return false
}
