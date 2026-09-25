package main

// IAMT-504 (IAMT-333 P2.8): a client verb run under sudo against the
// invoker's own data directory gives root up and carries on as the
// invoker, instead of refusing. The drop itself needs root and cannot run
// in a test; what is pinned here is the decision around it -- the drop is
// asked for exactly when the P1.6 refusal would fire, a drop that happened
// lets the command through and says so, and a drop that did not happen or
// failed leaves the refusal standing.

import (
	"errors"
	"strings"
	"testing"
)

func stubDrop(t *testing.T, dropped bool, err error) *[]string {
	t.Helper()
	var asked []string
	saved := dropToInvoker
	dropToInvoker = func(env map[string]string, dir string) (bool, error) {
		asked = append(asked, dir)
		return dropped, err
	}
	t.Cleanup(func() { dropToInvoker = saved })
	return &asked
}

func TestIAMT504_ADropLetsTheCommandThroughAndSaysSo(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)
	asked := stubDrop(t, true, nil)

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d: the drop made the directory the command's own; stderr:\n%s", code, exitOK, errs)
	}
	if len(*asked) != 1 || (*asked)[0] != dir {
		t.Fatalf("drop asked for %v, want exactly [%s]", *asked, dir)
	}
	if !strings.Contains(errs, "without root") {
		t.Fatalf("the command gave root up without saying so; stderr:\n%s", errs)
	}
}

func TestIAMT504_NoDropKeepsTheRefusal(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)
	stubDrop(t, false, nil)

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitDenied {
		t.Fatalf("exit code = %d, want %d (the P1.6 refusal); stderr:\n%s", code, exitDenied, errs)
	}
	if !strings.Contains(errs, "--accept-foreign-data-dir") {
		t.Fatalf("the refusal lost its override hint; stderr:\n%s", errs)
	}
}

func TestIAMT504_AFailedDropRefuses(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)
	stubDrop(t, false, errors.New("setuid 1000: operation not permitted"))

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitDenied {
		t.Fatalf("exit code = %d, want %d: a half-done drop must not go on writing; stderr:\n%s", code, exitDenied, errs)
	}
	if !strings.Contains(errs, "could not give up root") {
		t.Fatalf("the refusal does not say the drop failed; stderr:\n%s", errs)
	}
}

func TestIAMT504_TheOwnDirectoryNeverAsksForADrop(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, "", nil)
	asked := stubDrop(t, true, nil)

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, errs)
	}
	if len(*asked) != 0 {
		t.Fatalf("a directory the command already owns asked for a drop: %v", *asked)
	}
}
