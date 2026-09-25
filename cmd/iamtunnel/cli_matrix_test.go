package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFile creates a file with content inside a temp dir and returns
// its path; used where a command validates existence before executing.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// wantUserError asserts exit 2 and a message naming the problem.
func wantUserError(t *testing.T, want string, args ...string) {
	t.Helper()
	_, errs, code := drive(t, args...)
	if code != 2 {
		t.Errorf("%v: exit code = %d, want 2", args, code)
	}
	if !strings.Contains(errs, want) {
		t.Errorf("%v: stderr lacks %q, got:\n%s", args, want, errs)
	}
}

// The `server doorwatch` argv layout differs by host, and these three
// helpers are the single place the tests derive it from: five positional
// fields on Windows (<door-id> <parent-pid> <keyfile> <max-wait-ms>
// <journal-path>, the pre-IAMT-247 shape) and eight on Linux and macOS,
// where IAMT-247 and IAMT-263 appended the DoorOptions tail
// (<lock-path> <owner-uid> <owner-gid>). The two parsers in the product
// are two functions for the same reason (cmdServerDoorwatch's comment).
//
// IAMT-287 fixed the doorwatch matrix in TestServerSurfaceMatrix with a
// subtest-local closure; IAMT-297 found TestArgumentParsingErrors in
// main_test.go still spelling the five-field shape out by hand, so the
// closure moved up here and both tests now ask the same three questions.
func doorwatchUnixLayout() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// doorwatchFields returns a well-formed positional field vector for this
// host's layout.
func doorwatchFields() []string {
	fields := []string{"door1", "4321", "keyfile", "1000", "journal"}
	if doorwatchUnixLayout() {
		fields = append(fields, "door.lock", "1000", "1000")
	}
	return fields
}

// doorwatchArgs returns the full argv for `server doorwatch` with the field
// at brokenField (0-based, -1 = none) replaced by broken — so a test can
// break exactly one field and let the validation under test be the thing
// that answers.
func doorwatchArgs(brokenField int, broken string) []string {
	fields := doorwatchFields()
	if brokenField >= 0 {
		fields[brokenField] = broken
	}
	return append([]string{"server", "doorwatch"}, fields...)
}

// doorwatchArityHint is the count the arity check names on this host.
func doorwatchArityHint() string {
	if doorwatchUnixLayout() {
		return "exactly 8"
	}
	return "exactly 5"
}

// wantAccepted asserts the parser accepted the call: whatever happens
// next, it is not a user error about the arguments. The client commands
// really execute now (IAMT-64), so "accepted" no longer means "reached
// the stub" - it means the argument layer let the call through.
func wantAccepted(t *testing.T, args ...string) {
	t.Helper()
	_, errs, code := drive(t, args...)
	if code == 2 {
		t.Errorf("%v: rejected as a user error: %s", args, errs)
	}
}

// TestClientSurfaceMatrix covers gate 2 for the client commands: the
// valid call, a missing required argument, an extra argument and an
// invalid value.
func TestClientSurfaceMatrix(t *testing.T) {
	t.Run("connect-string", func(t *testing.T) {
		// --replace because the harness already seeded a different
		// string: refusing to overwrite it silently is the correct
		// behaviour, and it is asserted in the client package tests.
		wantAccepted(t, "client", "connect-string", connStr, "--replace")
		wantUserError(t, "exactly one", "client", "connect-string")
		wantUserError(t, "exactly one", "client", "connect-string", connStr, connStr)
		wantUserError(t, `must start with "iamtunnel://"`, "client", "connect-string", "https://gw:2222/alice#"+fpr43)
		wantUserError(t, "not a valid name", "client", "connect-string", "iamtunnel://gw:2222/Alice#"+fpr43)
		wantUserError(t, "43 base64 characters", "client", "connect-string", "iamtunnel://gw:2222/alice#deadbeef")
	})
	t.Run("machines", func(t *testing.T) {
		// The valid call needs a saved connection string, so it runs in a
		// directory shared with the call that saves one.
		dir := t.TempDir()
		if _, errs, code := driveInDir(t, dir, "client", "connect-string", connStr); code != 0 {
			t.Fatalf("seed connection string: code=%d errs=%s", code, errs)
		}
		if _, errs, code := driveInDir(t, dir, "client", "machines"); code == 2 {
			t.Errorf("client machines with a saved string: rejected as a user error: %s", errs)
		}
		// machines takes no arguments, so the "missing/invalid" slots of
		// the matrix collapse into the extra-argument rejection.
		wantUserError(t, "unexpected argument", "client", "machines", "win01")
	})
	t.Run("connect", func(t *testing.T) {
		dir := t.TempDir()
		if _, errs, code := driveInDir(t, dir, "client", "connect-string", connStr); code != 0 {
			t.Fatalf("seed connection string: code=%d errs=%s", code, errs)
		}
		if _, errs, code := driveInDir(t, dir, "client", "connect", "win01"); code == 2 {
			t.Errorf("client connect with a saved string: rejected as a user error: %s", errs)
		}
		wantUserError(t, "exactly one", "client", "connect")
		wantUserError(t, "unexpected argument", "client", "connect", "win01", "win02")
		wantUserError(t, "not a valid name", "client", "connect", "WIN01")
		wantUserError(t, "not a valid name", "client", "connect", strings.Repeat("m", 33))
	})
	// "client exec" is the only way an exec-only grant can be used at
	// all, and "--" before the command is mandatory (no flags are
	// parsed past it) rather than an ordinary fixed-arity positional,
	// so this subtest asks the matrix's four questions plus the "--"
	// one specifically.
	t.Run("exec", func(t *testing.T) {
		dir := t.TempDir()
		if _, errs, code := driveInDir(t, dir, "client", "connect-string", connStr); code != 0 {
			t.Fatalf("seed connection string: code=%d errs=%s", code, errs)
		}
		if _, errs, code := driveInDir(t, dir, "client", "exec", "win01", "--", "cmd", "/c", "echo", "hi"); code == 2 {
			t.Errorf("client exec with a saved string: rejected as a user error: %s", errs)
		}
		wantUserError(t, `missing "--"`, "client", "exec", "win01")
		wantUserError(t, `missing "--"`, "client", "exec", "win01", "echo", "hi")
		wantUserError(t, "missing <machine>", "client", "exec", "--")
		wantUserError(t, "missing <command>", "client", "exec", "win01", "--")
		wantUserError(t, "not a valid name", "client", "exec", "WIN01", "--", "echo")
		wantUserError(t, "not a valid name", "client", "exec", strings.Repeat("m", 33), "--", "echo")
	})
}

// TestServerSurfaceMatrix covers gate 2 for the server role. Every
// invocation here runs in a fresh, unenrolled temp environment: "start"
// really needs a saved machine identity (from "enrol") and gives the
// real env-class refusal, never the old stub; "stop"/"status" really
// look for a running control endpoint and, finding none, report "not
// running" with exit 0 (idempotent, not an error).
func TestServerSurfaceMatrix(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		wantUserError(t, "unexpected argument", "server", "start", "now")
		wantUserError(t, "1 to 10080", "server", "start", "--idle-minutes", "0")
		wantUserError(t, "1 to 10080", "server", "start", "--idle-minutes", "banana")
		wantUserError(t, "1 to 720", "server", "start", "--max-hours", "1000")
		for _, args := range [][]string{
			{"server", "start"},
			{"server", "start", "--idle-minutes", "15", "--max-hours", "4"},
		} {
			out, errs, code := drive(t, args...)
			if code != exitEnv || !strings.Contains(errs, "not registered") {
				t.Errorf("%v: code=%d out=%q errs=%q, want exitEnv naming \"not registered\"", args, code, out, errs)
			}
			if strings.Contains(errs, "not implemented") {
				t.Errorf("%v: still answers with the stub text", args)
			}
		}
	})
	t.Run("install and uninstall", func(t *testing.T) {
		// IAMT-249: both subcommands are parser leaves without positional
		// arguments; an extra argument is a user error, not an
		// "unknown command" (that path stayed with "server frob").
		wantUserError(t, "unexpected argument", "server", "install", "now")
		wantUserError(t, "unexpected argument", "server", "uninstall", "now")
	})
	t.Run("stop and status", func(t *testing.T) {
		wantUserError(t, "unexpected argument", "server", "stop", "now")
		wantUserError(t, "unexpected argument", "server", "status", "now")
		for _, sub := range []string{"stop", "status"} {
			out, errs, code := drive(t, "server", sub)
			if code != exitOK || !strings.Contains(out, "not running") {
				t.Errorf("server %s with nobody running: code=%d out=%q errs=%q", sub, code, out, errs)
			}
		}
	})
	t.Run("doorwatch", func(t *testing.T) {
		// IAMT-130 grew the argument list from three to five:
		// <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>.
		// IAMT-247 (Linux) and IAMT-263 (macOS) appended the DoorOptions
		// tail — <lock-path> <owner-uid> <owner-gid> — so the Unix layout
		// is eight positional fields while Windows keeps five; the two
		// parsers are two functions precisely because the layouts differ
		// (cmdServerDoorwatch's own comment says so). Every case below is
		// the original one restated against the layout this host actually
		// has, and none of them was weakened.
		//
		// IAMT-287 is why this subtest is layout-aware at all: the cases
		// were written for five fields and run on every host, so on Linux
		// and macOS every one of them died at the arity check ("want
		// exactly 8") before reaching the validation it is about — five
		// separate scenarios had quietly become one, and the three
		// Unix-only fields had no arity-correct coverage at all.
		arityHint := doorwatchArityHint()

		// Too few fields: the arity check names this layout's count.
		wantUserError(t, arityHint, "server", "doorwatch", "door1")
		wantUserError(t, arityHint, "server", "doorwatch", "door1", "4321")
		// One field too many: "unexpected argument" needs a well-formed
		// call first, because a short one would fail at the arity check
		// and prove nothing about the extra-argument path.
		wantUserError(t, "unexpected argument", append(doorwatchArgs(-1, ""), "extra")...)
		// Each field that has its own rejection, one at a time.
		wantUserError(t, "not a valid name", doorwatchArgs(0, "DOOR!")...)
		wantUserError(t, "not by hand", doorwatchArgs(1, "zero")...)
		wantUserError(t, "keyfile path must not be empty", doorwatchArgs(2, "   ")...)
		wantUserError(t, "max-wait-ms", doorwatchArgs(3, "zero")...)
		// The three fields only the Unix layout has (IAMT-247/263).
		if doorwatchUnixLayout() {
			wantUserError(t, "lock-path must not be empty", doorwatchArgs(5, "   ")...)
			wantUserError(t, "owner-uid", doorwatchArgs(6, "abc")...)
			wantUserError(t, "owner-gid", doorwatchArgs(7, "abc")...)
		}
	})
}

// TestGatewaySurfaceMatrix covers gate 2 for the local gateway role.
// "gateway run" is never invoked here with a valid port: unlike every
// other command, a successful "run" blocks serving until stopped, and
// driving it through drive() in a unit test would hang forever. Its real
// serving behaviour is proven separately by TestGatewayRunServesReal
// (gateway_run_test.go), which drives the underlying gatewayServe
// function with its own stop channel instead of the CLI's blocking call.
func TestGatewaySurfaceMatrix(t *testing.T) {
	t.Run("install run", func(t *testing.T) {
		wantUserError(t, "unexpected argument", "gateway", "install", "now")
		wantUserError(t, "1024 to 65535", "gateway", "run", "--port", "80", "--public-host", "gw.example.test")
		wantUserError(t, "1024 to 65535", "gateway", "install", "--port", "70000", "--public-host", "gw.example.test")
		wantUserError(t, "1024 to 65535", "gateway", "run", "--port", "ssh", "--public-host", "gw.example.test")

		// IAMT-258/259: with the Windows and macOS halves of install the
		// service seams are now three — substitute all of them; which one
		// is called depends on the host OS.
		_ = withFakeSystemd(t)
		_ = withFakeGatewayService(t)
		_ = withFakeLaunchd(t)
		out, errs, code := drive(t, "gateway", "install", "--public-host", "gw.example.test")
		if strings.Contains(errs, "not implemented") {
			t.Errorf("gateway install: still answers with the stub text: %s", errs)
		}
		switch runtime.GOOS {
		case "linux":
			if code != exitOK || !strings.Contains(out, "host key") {
				t.Errorf("gateway install on linux: code=%d out=%q errs=%q, want exitOK reporting the local setup", code, out, errs)
			}
		case "windows":
			if code != exitOK || !strings.Contains(out, "host key") || !strings.Contains(out, "the firewall was not touched") {
				t.Errorf("gateway install on windows: code=%d out=%q errs=%q, want exitOK with the local setup and the firewall hint (SPEC §3.5.1)", code, out, errs)
			}
		case "darwin":
			if code != exitOK || !strings.Contains(out, "host key") || !strings.Contains(out, "the firewall was not touched") {
				t.Errorf("gateway install on darwin: code=%d out=%q errs=%q, want exitOK with the local setup and the firewall hint (SPEC §3.5.1)", code, out, errs)
			}
		default:
			if code != exitEnv || !strings.Contains(errs, "supports Linux, Windows and macOS") {
				t.Errorf("gateway install on %s: code=%d errs=%q, want exitEnv naming all three supported OSes", runtime.GOOS, code, errs)
			}
			if !strings.Contains(out, "host key") {
				t.Errorf("gateway install: stdout should still report the local setup that did happen, got:\n%s", out)
			}
		}
	})
	t.Run("status backup", func(t *testing.T) {
		wantUserError(t, "unexpected argument", "gateway", "status", "now")
		out, errs, code := drive(t, "gateway", "status")
		if code != exitOK || !strings.Contains(out, "no gateway is installed") {
			t.Errorf("gateway status (fresh dir): code=%d out=%q errs=%q", code, out, errs)
		}
		_, errs, code = drive(t, "gateway", "backup", "--out", filepath.Join(t.TempDir(), "b.tar.gz"))
		if code != exitEnv || !strings.Contains(errs, "no gateway state found") {
			t.Errorf("gateway backup (fresh dir): code=%d errs=%q", code, errs)
		}
	})
	t.Run("restore", func(t *testing.T) {
		_, errs, code := drive(t, "gateway", "restore", writeFile(t, "b.tar.gz", "x"), "--yes")
		if code != exitEnv || !strings.Contains(errs, "not a valid gzip file") {
			t.Errorf("restore garbage tarball: code=%d errs=%q", code, errs)
		}
		wantUserError(t, "exactly one", "gateway", "restore")
		wantUserError(t, "unexpected argument", "gateway", "restore", "a", "b", "--yes")
		// A missing restore source is an environment problem, not a
		// syntax problem: different class, same code family.
		_, errs, code = drive(t, "gateway", "restore", filepath.Join(t.TempDir(), "nope.tar.gz"), "--yes")
		if code != 3 || !strings.Contains(errs, "does not exist") {
			t.Errorf("restore missing file: code=%d errs=%q, want 3 with not-exist text", code, errs)
		}
	})
	t.Run("rotate-hostkey", func(t *testing.T) {
		out, errs, code := drive(t, "gateway", "rotate-hostkey", "--yes")
		if code != exitOK || !strings.Contains(out, "rotated the gateway host key") {
			t.Errorf("gateway rotate-hostkey: code=%d out=%q errs=%q", code, out, errs)
		}
		wantUserError(t, "unexpected argument", "gateway", "rotate-hostkey", "now", "--yes")
	})
}

// TestEnrolShotSelftestMatrix covers gate 2 for the remaining §7.2
// commands.
func TestEnrolShotSelftestMatrix(t *testing.T) {
	t.Run("enrol", func(t *testing.T) {
		wantUserError(t, "exactly one", "enrol")
		wantUserError(t, "unexpected argument", "enrol", enrolCode, "extra")
		wantUserError(t, `must start with "iamtunnel-enrol://"`, "enrol", connStr)
		wantUserError(t, "wrong shape", "enrol", "iamtunnel-enrol://gw:2222#"+fpr43+":xx")
		// Valid shape, unreachable gateway (127.0.0.1:1 in enrolCode):
		// the real dial fails fast with a network-class error.
		out, errs, code := drive(t, "enrol", enrolCode)
		if code != exitEnv || !strings.Contains(errs, "could not reach the gateway") {
			t.Errorf("enrol with an unreachable gateway: code=%d out=%q errs=%q", code, out, errs)
		}
	})
	t.Run("shot", func(t *testing.T) {
		// The argument grammar is unchanged; the rendering itself is
		// proven platform-side in shot_test.go (windows) and
		// shot_other_test.go (!windows).
		wantUserError(t, "exactly one", "shot")
		wantUserError(t, "unexpected argument", "shot", "client", "server")
		wantUserError(t, "not one of", "shot", "lobby")
	})
	t.Run("selftest", func(t *testing.T) {
		out, errs, code := drive(t, "selftest")
		if code != exitOK {
			t.Errorf("selftest: code=%d, want 0; out=%q errs=%q", code, out, errs)
		}
		if !strings.Contains(out, "loopback networking") {
			t.Errorf("selftest: missing the real networking check, got:\n%s", out)
		}
		wantUserError(t, "unexpected argument", "selftest", "now")
	})
}

// TestAdminEveryVerbParses walks the whole §3.3 table generated from the
// adminVerbs registry itself: every verb must parse and reach the real
// dispatch with a well-formed sample call. Since none of these runs has
// a saved client connection string, every one is uniformly refused by
// internal/client's own "no connection string saved yet" — proof the
// call reached runAdminExec's real switch rather than a missing case
// (which panics) or the old stub.
func TestAdminEveryVerbParses(t *testing.T) {
	pub := pubKeyLine(t)
	sample := map[string]map[string][]string{
		"people": {
			"add":               {"bob", "--key", pub},
			"rename":            {"bob", "robert", "--yes"},
			"remove":            {"bob", "--yes"},
			"list":              {},
			"keys":              {"add", "bob", pub},
			"connection-string": {"bob"},
		},
		"machines": {
			"enrol-code": {"win01"},
			"list":       {},
			"rename":     {"win01", "win-box"},
			"remove":     {"win01", "--yes"},
			"rekey":      {"win01", "--confirm-fingerprint", fpr43, "--yes"},
			"verify":     {"win01"},
			"set-user":   {"win01", `CONTOSO\svc-ssh`, "--yes"},
		},
		"grants": {
			"grant":    {"bob", "win01", "2027-01-31T18:00:00Z"},
			"extend":   {"bob", "win01", "2027-02-28T18:00:00Z", "--yes"},
			"set-caps": {"bob", "win01", "exec", "--yes"},
			"revoke":   {"bob", "win01", "--yes"},
			"list":     {},
		},
		"sessions": {
			"active":  {},
			"history": {},
			"kill":    {"sess-0001-abcd", "--yes"},
			// IAMT-338 added this verb to the admin CLI and never gave the
			// matrix its sample argument, so the walk stopped at "missing
			// required argument" instead of reaching the identity check it
			// is here to make.
			"tail": {"sess-0001-abcd"},
		},
		"recordings": {
			"list":  {},
			"fetch": {"sess-0001-abcd", "--out", "rec"},
		},
		"gateway": {
			"status":         {},
			"fingerprint":    {},
			"backup":         {},
			"rotate-hostkey": {"--yes"},
		},
		"goal": {
			"set":     {"alice", "win01", "--goal", "keep the service online"},
			"current": {"alice", "win01"},
			"history": {"alice", "win01"},
		},
		"risk": {
			"check": {"echo safe"},
			"key":   {"--key", "new-key-for-matrix"},
			// A well-formed id, so this verb reaches the same missing-identity
			// refusal every other verb here is sampled for (IAMT-394): with no
			// argument it would stop one step earlier, on the argument count,
			// and prove nothing about the wire path.
			"approve": {"apr-0123456789abcdef"},
			"deny":    {"apr-0123456789abcdef"},
			"pending": {},
		},
	}
	for group, verbs := range adminGroups {
		for _, verb := range verbs {
			args := sample[group][verb]
			for _, extra := range [][]string{nil, {"--json"}} {
				full := append(append([]string{"admin", group, verb}, args...), extra...)
				out, errs, code := drive(t, full...)
				if strings.Contains(out, "not implemented") || strings.Contains(errs, "not implemented") {
					t.Errorf("%v: still answers with the stub text", full)
				}
				if code != exitUser || !strings.Contains(errs, "no connection string saved yet") {
					t.Errorf("%v: code=%d errs=%q, want exitUser naming the missing client identity", full, code, errs)
				}
			}
		}
	}
}

// TestAdminVerbErrors samples the missing / extra / invalid-value slots
// of the matrix across all groups.
func TestAdminVerbErrors(t *testing.T) {
	pub := pubKeyLine(t)
	cases := []struct {
		want string
		args []string
	}{
		// people
		{"exactly one", []string{"admin", "people", "add"}},
		{"unexpected argument", []string{"admin", "people", "add", "bob", "extra"}},
		{"not a valid name", []string{"admin", "people", "add", "Bob"}},
		{`must be "user" or "admin"`, []string{"admin", "people", "add", "bob", "--role", "root"}},
		{"--key <pubkey> is required", []string{"admin", "people", "add", "bob"}},
		{"unknown verb", []string{"admin", "people", "promote", "bob"}},
		{`want "add <name> <pubkey>"`, []string{"admin", "people", "keys"}},
		{`want "add <name> <pubkey>"`, []string{"admin", "people", "keys", "drop", "bob"}},
		{"exactly two more arguments", []string{"admin", "people", "keys", "add", "bob"}},
		{"not a valid name", []string{"admin", "people", "keys", "add", "BOB", pub}},
		{"does not parse as an OpenSSH public key", []string{"admin", "people", "keys", "add", "bob", "garbage"}},
		{"43 base64 characters", []string{"admin", "people", "keys", "remove", "bob", "deadbeef"}},
		{"exactly one", []string{"admin", "people", "connection-string"}},
		// machines
		{"exactly one", []string{"admin", "machines", "enrol-code"}},
		{"DOMAIN\\name or MACHINE\\name", []string{"admin", "machines", "enrol-code", "win01", "--os-user", "no space allowed here"}},
		{"exactly one", []string{"admin", "machines", "verify"}},
		{"not a valid name", []string{"admin", "machines", "remove", "WIN01", "--yes"}},
		{"exactly 2", []string{"admin", "machines", "set-user", "win01"}},
		{"DOMAIN\\name or MACHINE\\name", []string{"admin", "machines", "set-user", "win01", "no space here"}},
		{"--confirm-fingerprint <fp> is required", []string{"admin", "machines", "rekey", "win01", "--yes"}},
		{"43 base64 characters", []string{"admin", "machines", "rekey", "win01", "--confirm-fingerprint", "zz", "--yes"}},
		// grants
		{"exactly 3", []string{"admin", "grants", "grant", "bob", "win01"}},
		{"unexpected argument", []string{"admin", "grants", "grant", "bob", "win01", "2027-01-31T18:00:00Z", "extra"}},
		{"not a valid name", []string{"admin", "grants", "grant", "BOB", "win01", "2027-01-31T18:00:00Z"}},
		{"ISO-8601", []string{"admin", "grants", "grant", "bob", "win01", "tomorrow"}},
		{"ISO-8601", []string{"admin", "grants", "grant", "bob", "win01", "2027-01-31T18:00:00"}},
		{"exactly 2", []string{"admin", "grants", "revoke", "bob"}},
		// sessions
		{"exactly one", []string{"admin", "sessions", "kill"}},
		{"wrong shape", []string{"admin", "sessions", "kill", "x", "--yes"}},
		// recordings (--yes belongs only to destructive verbs)
		{"exactly one", []string{"admin", "recordings", "fetch"}},
		{"unknown flag", []string{"admin", "recordings", "fetch", "sess-0001-abcd", "--yes"}},
		{"wrong shape", []string{"admin", "recordings", "fetch", "short"}},
		// unknown group / flags-first
		{"unknown group", []string{"admin", "widgets", "list"}},
		{"flags come after the verb", []string{"admin", "--json", "people", "list"}},
		// claim
		{"exactly one", []string{"admin", "claim"}},
		{"takes no URI scheme", []string{"admin", "claim", "iamtunnel://gw:2222#" + fpr43 + ":token1234", "--key", pub}},
		{"43 base64 characters", []string{"admin", "claim", "gw:2222#zz:token1234", "--key", pub}},
		{"does not parse as an OpenSSH public key", []string{"admin", "claim", claimRef, "--key", "nope"}},
		{"--key", []string{"admin", "claim", claimRef}},
	}
	for _, tc := range cases {
		wantUserError(t, tc.want, tc.args...)
	}
}
