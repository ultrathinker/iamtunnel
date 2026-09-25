package main

import (
	"fmt"
	"os"
	"testing"
)

// TestMain removes ProgramData from this test binary's own process
// environment before any test runs (IAMT-156). "server start" takes its
// door key file, %ProgramData%\ssh\administrators_authorized_keys, from
// the environment it was started with and refuses when ProgramData is
// not an absolute path (serverKeyFile has no C:\ProgramData fallback).
// In-process runs get a t.TempDir() ProgramData from driveFull; a real
// iamtunnel subprocess inherits this process's environment instead, so
// without the scrub a test that forgot --key-file would sweep, lock and
// re-ACL the real sshd file of the machine running the suite. With it
// such a test fails closed. Windows environment names are
// case-insensitive, so one Unsetenv also removes PROGRAMDATA.
func TestMain(m *testing.M) {
	if err := os.Unsetenv("ProgramData"); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: cannot remove ProgramData from the test environment: %v\n", err)
		os.Exit(2)
	}
	if v, ok := os.LookupEnv("ProgramData"); ok {
		fmt.Fprintf(os.Stderr, "TestMain: ProgramData=%q is still set; refusing to run tests that could reach the real sshd key file\n", v)
		os.Exit(2)
	}
	os.Exit(m.Run())
}
