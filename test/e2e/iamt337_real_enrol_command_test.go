package e2e

// iamt337_real_enrol_command_test.go — the client's `enrol` body meets
// the gateway that actually has to accept it.
//
// Every other test of the enrol wire builds its own body. doEnrol and
// its cousins in this package take `machine` and `osUser` as arguments
// and send whatever the test says; the gateway's own tests do the same
// from the other side. So both halves were free to drift, and they did:
// 1.3 made the gateway REQUIRE an OS account while `iamtunnel enrol`
// went on sending an empty one, and registration was broken end to end
// for the whole release. Nothing went red, because the one test that
// watched the client's body — cmd/iamtunnel's — watched it against a
// fake gateway that was still content with it.
//
// The gap was structural, not an oversight: no test in the tree put the
// REAL client body in front of the REAL gateway. This one does. It is
// deliberately thin — it asserts that the registration happens at all —
// because everything it could assert beyond that is already covered,
// and what was missing was not detail but contact.

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestIAMT337_TheRealEnrolCommandRegistersAgainstTheRealGateway builds
// the product binary, mints an invitation through the real admin wire,
// and runs `iamtunnel enrol <code>` as a person would. A green run means
// the two halves of the enrol body agree; a red one means they have
// drifted again, which is the only thing this test is for.
//
// Canary: drop the OSUser field from enrolMachine's Exec body (the exact
// 1.3 defect) and this goes red on the command's own exit status, with
// the gateway's refusal quoted.
func TestIAMT337_TheRealEnrolCommandRegistersAgainstTheRealGateway(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("the product binary is not built for %s", runtime.GOOS)
	}
	// On unix `iamtunnel enrol` demands root — it sets up the machine's
	// server data directory and its sshd door, which an unprivileged
	// process may not write ("root privileges are required — run it with
	// sudo", exitDenied). The gate runs the suite unprivileged and must
	// not elevate, so the honest answer is a skip that says so; the
	// command path this test drives is exercised for real by the runs
	// that do go as root — the container gate (and any sudo run)
	// (MAC, 24.09.2026). Windows has no unix-root gate and keeps running.
	if euid := os.Geteuid(); euid != -1 && euid != 0 {
		t.Skipf("iamtunnel enrol requires root on unix (\"root privileges are required — run it with sudo\") — the gate runs unprivileged and must not elevate; covered by the root container run (euid=%d)", euid)
	}
	f := newFixture(t, nil)

	const regName = "office-pc"

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	code, _, err := root.MachinesInvite(regName)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(t.TempDir(), "iamtunnel"+exeSuffix())
	if err := testsupport.BuildIamtunnel(exe); err != nil {
		t.Fatalf("build the product binary: %v", err)
	}

	cmd := exec.Command(exe, "enrol", code, "--data-dir", dir)
	cmd.Env = enrolCommandEnv(t, dir)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		// R4 F-04 gave the enrol one more, LOCAL step: after the gateway
		// has accepted the registration, the client writes its enrolment
		// anchor and refuses to report success when the folders above the
		// anchor tree carry a foreign ACE — whoever can rename an ancestor
		// can move the anchor aside (cmd/iamtunnel/machine_anchor_windows.go).
		// On machines whose temp roots are sandboxed that way, that refusal
		// fires on every run of this test, and it is not the drift this
		// test hunts: both markers below are printed only by the LAST step
		// of enrol, reached strictly after conn.Exec has already succeeded
		// — a body/gateway disagreement dies earlier, as "gateway refused
		// registration", and never reaches the anchor. So when the markers
		// are there, the wire agreement this test exists for HAS held, the
		// client had already written everything it writes before the anchor,
		// and every assertion below stays meaningful. Tolerate exactly this
		// refusal, never any other shape of failure; the anchor mechanics
		// themselves are covered in-process by cmd/iamtunnel's F-04 tests.
		outText := string(out)
		anchorRefusal := strings.Contains(outText, "could not write the enrolment anchor") &&
			strings.Contains(outText, "can be changed by")
		if !anchorRefusal {
			t.Fatalf("`iamtunnel enrol` refused the invitation the gateway had just minted — the client's body and the gateway's expectations have drifted apart: %v\n%s", runErr, out)
		}
		t.Logf("the F-04 anchor ancestor check refused the sandboxed folders above the temp data dir AFTER the gateway had accepted the registration — an environment property, not the wire; the assertions below still hold: %v\n%s", runErr, out)
	}

	// The gateway holds the registration under the administrator's name.
	st, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	m, ok := st.MachineByID(regName)
	if !ok {
		t.Fatalf("machine %q is not in state after a successful enrol; state has %d machine(s)", regName, len(st.Machines))
	}
	if m.State != "enrolled" {
		t.Errorf("machine.State = %q, want %q", m.State, "enrolled")
	}
	// And it carries the account the CLIENT reported, which is the half
	// of the body that was missing.
	if m.RequestedOSUser == "" {
		t.Error("the machine record carries no requestedOsUser — the client reported no account, which is exactly the shape that was broken")
	}
	if m.OSUserStatus != state.OSUserStatusPending {
		t.Errorf("machine.OSUserStatus = %q, want %q — a reported account is a claim until the gateway's own login proves it", m.OSUserStatus, state.OSUserStatusPending)
	}

	// The machine wrote its side down too, or the next `server start`
	// would have nothing to go on.
	if _, err := os.Stat(filepath.Join(dir, "enrolment.json")); err != nil {
		t.Errorf("the client did not record the enrolment locally: %v", err)
	}
}

// enrolCommandEnv is the environment the child binary runs with: the
// isolated data roots every test uses, plus whatever else the process
// genuinely needs from the host. It deliberately does NOT inherit the
// host's own account names — the fixture's fixed USERNAME/USERDOMAIN
// decide what the machine reports, so the test says the same thing on
// every developer's box and in CI.
func enrolCommandEnv(t *testing.T, dir string) []string {
	t.Helper()
	env := os.Environ()
	var kept []string
	for _, kv := range env {
		k := kv[:strings.IndexByte(kv+"=", '=')]
		switch k {
		case "LOCALAPPDATA", "ProgramData", "HOME", "XDG_DATA_HOME",
			"USERNAME", "USERDOMAIN", "COMPUTERNAME", "SUDO_USER":
			continue
		}
		kept = append(kept, kv)
	}
	for k, v := range testsupport.PlatformDataEnvAt(t, dir) {
		kept = append(kept, k+"="+v)
	}
	if runtime.GOOS != "windows" {
		// On Unix the reported account must exist locally: the client
		// checks it before writing machine.key, and a made-up name
		// would fail for a reason that has nothing to do with the wire.
		// $SUDO_USER is what currentOSUser prefers, and it is the only
		// value here that has to be real.
		u, err := user.Current()
		if err != nil {
			t.Fatalf("who is this test running as: %v", err)
		}
		kept = append(kept, "SUDO_USER="+u.Username)
	}
	return kept
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
