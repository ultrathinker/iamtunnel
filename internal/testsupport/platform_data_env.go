// Package testsupport contains helpers used only by tests in this module.
package testsupport

import "testing"

// PlatformDataEnv returns a complete, isolated role-data environment. Every
// directory is rooted in the calling test's temporary directory, so the same
// test setup is safe on Windows and Unix hosts.
func PlatformDataEnv(t *testing.T) map[string]string {
	t.Helper()
	return PlatformDataEnvAt(t, t.TempDir())
}

// PlatformDataEnvAt is PlatformDataEnv for a caller that deliberately shares
// role state across several invocations in one test.
func PlatformDataEnvAt(t *testing.T, root string) map[string]string {
	t.Helper()
	return map[string]string{
		"LOCALAPPDATA":  root,
		"ProgramData":   root,
		"HOME":          root,
		"XDG_DATA_HOME": root,
		// Since 1.4 `enrol` reports the OS account this process runs as
		// (the one fact only the machine knows, SPEC §3.4), and on
		// Windows it reads that from the environment. A test env
		// without these would make every enrol test fail on "cannot
		// tell which Windows account this is" — a true sentence about
		// the fixture, not about anything under test. Fixed values, not
		// the host's: a test must not depend on who is logged in.
		"USERNAME":     "testuser",
		"USERDOMAIN":   "TESTMACHINE",
		"COMPUTERNAME": "TESTMACHINE",
	}
}

// ApplyPlatformDataEnv installs the isolated environment for a test that
// exercises code reading process environment directly.
func ApplyPlatformDataEnv(t *testing.T, root string) {
	t.Helper()
	for key, value := range PlatformDataEnvAt(t, root) {
		t.Setenv(key, value)
	}
}
