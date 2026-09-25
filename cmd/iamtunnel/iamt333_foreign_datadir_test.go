package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// IAMT-333 (P1.6): an elevated command must refuse to write into a data
// directory somebody else owns, BEFORE the first write (IAMT-315's lesson:
// a refusal that fires after the key exists leaves a live secret behind).
// A missing directory is not a refusal (first run is legitimate), the
// override flag --accept-foreign-data-dir is opt-in and named in the
// refusal, a probe the command cannot answer refuses too (fail closed,
// the same rule the datafile contract learned in IAMT-332 round 10), and
// the check must be reachable from the window's actions (gui_actions.go),
// not only from the CLI verbs — that wiring test lives in the gui-tagged
// sibling file (iamt333_foreign_datadir_gui_test.go), because
// gui_actions.go does not compile under the nogui builds the gates vet
// (IAMT-470's rule: a test that needs the window is tagged !nogui).
//
// The platform probe (dataDirOwnerForeign) is a package seam: no test can
// chown a directory to another account portably, so the tests substitute
// it the same way the service seams are substituted; one test pins the
// real probe's behaviour on this host (the process's own directory — and
// a directory that does not exist — must pass). The no-streams elevation
// seam (foreignDirElevation) is substituted in the gui-tagged sibling.

const iamt333ForeignReason = "owned by uid 1000, and this command is running as root — " +
	"a directory somebody else owns can aim this command's writes at files of their choosing"

// driveElevated runs the CLI with an explicit elevation verdict; driveFull
// always claims elevated, which is right for server verbs but hides exactly
// the branch this card adds for client verbs — elevated is the only state
// in which the foreign-owner check speaks at all.
func driveElevated(t *testing.T, elevated bool, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	merged := testsupport.PlatformDataEnv(t)
	for k, v := range env {
		merged[k] = v
	}
	var out, errs bytes.Buffer
	s := &streams{
		in:          strings.NewReader(""),
		interactive: false,
		out:         &out,
		errs:        &errs,
		env:         merged,
		isElevated:  func() (bool, error) { return elevated, nil },
	}
	code := run(args, s)
	return out.String(), errs.String(), code
}

// stubOwnerProbe replaces the platform owner probe with a fixed verdict
// for one path: dir is the foreign directory (reason non-empty — "this
// directory exists and somebody else owns it"), every other path comes
// back clean the way a real probe answers for the process's own and for
// missing directories. err non-nil means the probe itself failed and is
// answered for every path.
func stubOwnerProbe(t *testing.T, dir, reason string, err error) {
	t.Helper()
	saved := dataDirOwnerForeign
	dataDirOwnerForeign = func(asked string) (string, error) {
		if err != nil {
			return "", err
		}
		if asked == dir {
			return reason, nil
		}
		return "", nil
	}
	t.Cleanup(func() { dataDirOwnerForeign = saved })
}

func iamt333SeedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "client-data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The sample connection string must parse or none of the tests below mean
// anything: the refusal is checked to fire after the grammar passes but
// before the first write.
func TestIAMT333_ConnectStrSampleParses(t *testing.T) {
	cs, err := config.ParseConnString(connStr)
	if err != nil {
		t.Fatalf("the sample connection string must parse: %v", err)
	}
	if cs.Host != "127.0.0.1" {
		t.Fatalf("sample parsed to the wrong host %q", cs.Host)
	}
}

func TestIAMT333_ElevatedRefusesForeignClientDataDir(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitDenied {
		t.Fatalf("exit code = %d, want %d (denied); stderr:\n%s", code, exitDenied, errs)
	}
	for _, want := range []string{dir, "uid 1000", "--accept-foreign-data-dir"} {
		if !strings.Contains(errs, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, errs)
		}
	}
	// The whole point of the ordering: the refusal comes BEFORE the first
	// write, so the foreign directory is left exactly as it was found —
	// no key, no connection.json, nothing.
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the refusal must come before the first write, but the directory now holds %v", names)
	}
}

func TestIAMT333_AcceptFlagLetsVerifiedDirThrough(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)

	out, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir, "--accept-foreign-data-dir")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitOK, errs)
	}
	if strings.Contains(errs, "accept-foreign") {
		t.Fatalf("the flag must let the command through without a refusal, stderr:\n%s", errs)
	}
	if !strings.Contains(out, "saved the connection") {
		t.Fatalf("the ordinary success narrative must be intact, stdout:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "connection.json")); err != nil {
		t.Fatalf("the verified directory must receive the write: %v", err)
	}
}

func TestIAMT333_NotElevatedNeverRefuses(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)

	out, errs, code := driveElevated(t, false, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("a non-elevated process is not who this check is for; exit = %d, stderr:\n%s", code, errs)
	}
	if !strings.Contains(out, "saved the connection") {
		t.Fatalf("the ordinary path must keep working untouched, stdout:\n%s", out)
	}
}

func TestIAMT333_MissingDataDirIsNotRefused(t *testing.T) {
	// The stub knows one EXISTING foreign directory; the command runs
	// against a path that does not exist, which a real probe answers
	// with "" — a first run is legitimate, not a refusal.
	stubOwnerProbe(t, iamt333SeedDir(t), iamt333ForeignReason, nil)
	dir := filepath.Join(t.TempDir(), "not-created-yet")

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("a missing directory is a legitimate first run, exit = %d (stderr: %s)", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "connection.json")); err != nil {
		t.Fatalf("the first run must create its directory and save: %v", err)
	}
}

func TestIAMT333_ProbeFailureFailsClosed(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, "", os.ErrPermission)

	_, errs, code := driveElevated(t, true, map[string]string{},
		"client", "connect-string", connStr, "--data-dir", dir)
	if code != exitDenied {
		t.Fatalf("a probe the command cannot answer is a refusal, not a pass; exit = %d, stderr:\n%s", code, errs)
	}
	if !strings.Contains(errs, "cannot verify the owner") || !strings.Contains(errs, "--accept-foreign-data-dir") {
		t.Errorf("the fail-closed refusal must name the probe failure and the escape flag:\n%s", errs)
	}
}

func TestIAMT333_AdminVerbRefusesBeforeDialing(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)

	_, errs, code := driveElevated(t, true, map[string]string{"IAMTUNNEL_DATA_DIR": dir},
		"admin", "people", "list")
	if code != exitDenied {
		t.Fatalf("exit code = %d, want %d; stderr:\n%s", code, exitDenied, errs)
	}
	if !strings.Contains(errs, dir) || !strings.Contains(errs, "--accept-foreign-data-dir") {
		t.Errorf("the admin refusal must name the directory and the escape flag:\n%s", errs)
	}
	// No dial happened: the failure is the refusal, not a connection error.
	if strings.Contains(errs, "could not reach") {
		t.Errorf("the refusal must come before the gateway dial:\n%s", errs)
	}
}

// The real probe, on this host: the process's own directory (and a
// directory that does not exist yet) both pass — the substitution above
// proves the refusal wiring, this one proves the platform check does not
// refuse what it must not.
func TestIAMT333_RealProbePassesOwnAndMissingDirs(t *testing.T) {
	dir := iamt333SeedDir(t)
	reason, err := dataDirOwnerForeign(dir)
	if err != nil {
		t.Fatalf("the real probe must read its own test directory: %v", err)
	}
	if reason != "" {
		t.Fatalf("the real probe must not call the process's own directory foreign, got %q", reason)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	reason, err = dataDirOwnerForeign(missing)
	if err != nil {
		t.Fatalf("a missing directory is not a probe failure: %v", err)
	}
	if reason != "" {
		t.Fatalf("a missing directory must pass, got %q", reason)
	}
}
