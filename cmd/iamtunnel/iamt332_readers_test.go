package main

// iamt332_readers_test.go — IAMT-332 round five. The cmd/iamtunnel readers
// of gateway and machine data files — the host-key loaders behind every
// command, the machine-key loaders, the bootstrap-token read behind
// "gateway install"/"--rebootstrap" — read by final pathname. Round five
// routes them through state.ReadDataFile, whose open refuses any
// non-regular entry at the name before the first byte is read.
//
// This table plants a DIRECTORY at each name: the portable non-regular
// entry. (The FIFO — the entry that actually wedges open(2) — is proven
// against the same seam in the state, events and gateway packages, which
// run on POSIX; this package's tests must run on Windows too, where a
// planted directory is refused by the Lstat leg's IsRegular check.) Before
// the fix each reader answered a planted directory with the OS's own
// read error ("access is denied"), not the actionable refusal, so the
// wording assertion below is what goes red.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIAMT332Round5CmdReadersRefuseANonRegularEntryAtTheName plants a
// directory at each data file's name in turn and requires each reader to
// refuse it promptly with the actionable refusal, leaving the name as it
// found it.
func TestIAMT332Round5CmdReadersRefuseANonRegularEntryAtTheName(t *testing.T) {
	for _, tt := range []struct {
		name string
		// call plants the directory and returns its path plus the
		// production read to run against it.
		call func(t *testing.T) (string, func() error)
	}{
		{
			name: "loadOrGenerateSigner's read of the gateway host key",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "hostkey")
				plantDir(t, path)
				return path, func() error { _, err := loadOrGenerateSigner(path); return err }
			},
		},
		{
			name: "loadSignerStrict's read of the machine key",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "machine.key")
				plantDir(t, path)
				return path, func() error { _, err := loadSignerStrict(path); return err }
			},
		},
		{
			name: "loadOrGenerateMachineSigner's read of the machine key",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "machine.key")
				plantDir(t, path)
				return path, func() error { _, err := loadOrGenerateMachineSigner(path); return err }
			},
		},
		{
			name: "ensureBootstrapToken's read of the bootstrap token",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, bootstrapFileName)
				plantDir(t, path)
				return path, func() error {
					token, err := ensureBootstrapToken(dir)
					if err == nil {
						t.Logf("ensureBootstrapToken handed out a token %q despite the planted entry", token)
					}
					return err
				}
			},
		},
		{
			name: "loadGatewayRecord's read of the machine enrolment record",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, gatewayRecordName)
				plantDir(t, path)
				return path, func() error { _, err := loadGatewayRecord(dir); return err }
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, call := tt.call(t)
			err := call()
			if err == nil {
				t.Fatalf("%s read through a non-regular entry planted at %s — a data file's name must be refused when it is not a regular file (IAMT-332 round 5)", tt.name, path)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do, not the raw OS read error", tt.name, path, err)
			}
			if st, serr := os.Lstat(path); serr != nil || !st.IsDir() {
				t.Errorf("the planted entry did not survive the refused read (Lstat: %v, %#v) — the refusal must leave the name as it found it, never replace it", serr, st)
			}
		})
	}
}

// plantDir replaces name (removing any file already there) with a
// directory — a non-regular entry any platform can plant without
// privilege.
func plantDir(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear the name before planting: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("plant the directory: %v", err)
	}
}
