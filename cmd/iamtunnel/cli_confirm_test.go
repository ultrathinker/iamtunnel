package main

import (
	"strings"
	"testing"
)

// destructiveCase is one destructive command plus what it really does
// once --yes lets it through (IAMT-73: there is no shared stub outcome
// any more — each command's real result differs).
type destructiveCase struct {
	args     []string
	wantCode int
	wantIn   string
}

// destructiveCases lists one full invocation per destructive verb of the
// §3.3 table plus the local gateway pair, so the uniform confirmation
// gate is proven for every dangerous command, not a sample. The
// "after --yes" outcome is real: every admin verb dials with no saved
// client identity (env is a fresh temp dir) and is uniformly refused by
// internal/client's own "no connection string saved yet"; the two local
// gateway commands differ because they touch only the local disk.
func destructiveCases(t *testing.T) []destructiveCase {
	t.Helper()
	tarball := writeFile(t, "b.tar.gz", "x") // not a valid gzip on purpose
	const noConn = "no connection string saved yet"
	return []destructiveCase{
		{[]string{"admin", "people", "remove", "bob", "--yes"}, exitUser, noConn},
		{[]string{"admin", "people", "keys", "remove", "bob", fpr43, "--yes"}, exitUser, noConn},
		{[]string{"admin", "machines", "remove", "win01", "--yes"}, exitUser, noConn},
		{[]string{"admin", "machines", "rekey", "win01", "--confirm-fingerprint", fpr43, "--yes"}, exitUser, noConn},
		{[]string{"admin", "machines", "set-user", "win01", `CONTOSO\svc-ssh`, "--yes"}, exitUser, noConn},
		{[]string{"admin", "grants", "revoke", "bob", "win01", "--yes"}, exitUser, noConn},
		{[]string{"admin", "sessions", "kill", "sess-0001-abcd", "--yes"}, exitUser, noConn},
		{[]string{"admin", "gateway", "rotate-hostkey", "--yes"}, exitUser, noConn},
		{[]string{"gateway", "restore", tarball, "--yes"}, exitEnv, "not a valid gzip file"},
		{[]string{"gateway", "rotate-hostkey", "--yes"}, exitOK, "rotated the gateway host key"},
	}
}

// TestDestructiveCommandsRefuseWithoutYes: every dangerous command, in a
// non-interactive stream and without --yes, refuses with the consequence
// sentence and the --yes instruction — uniformly. The same invocation
// with --yes passes the gate and really executes (never the old "not
// implemented yet" stub).
func TestDestructiveCommandsRefuseWithoutYes(t *testing.T) {
	for _, tc := range destructiveCases(t) {
		noYes := stripYes(tc.args)
		_, errs, code := drive(t, noYes...)
		if code != exitUser {
			t.Errorf("%v: exit code = %d, want %d", noYes, code, exitUser)
		}
		if !strings.Contains(errs, "refusing to act without confirmation") || !strings.Contains(errs, "--yes") {
			t.Errorf("%v: refusal lacks the uniform text, got:\n%s", noYes, errs)
		}

		out, errs2, code2 := drive(t, tc.args...)
		if code2 != tc.wantCode {
			t.Errorf("%v: exit code = %d, want %d (out=%q errs=%q)", tc.args, code2, tc.wantCode, out, errs2)
		}
		if !strings.Contains(out, tc.wantIn) && !strings.Contains(errs2, tc.wantIn) {
			t.Errorf("%v: output lacks %q, out=%q errs=%q", tc.args, tc.wantIn, out, errs2)
		}
		if strings.Contains(out, "not implemented") || strings.Contains(errs2, "not implemented") {
			t.Errorf("%v: still answers with the stub text", tc.args)
		}
	}
}

// stripYes removes every --yes from an invocation.
func stripYes(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != "--yes" {
			out = append(out, a)
		}
	}
	return out
}

// TestDestructiveInteractiveConfirm: on an interactive terminal the gate
// asks, a typed "yes" proceeds (reaching the real dispatch, refused only
// for lack of a saved client identity in this fresh environment),
// anything else cancels.
func TestDestructiveInteractiveConfirm(t *testing.T) {
	base := []string{"admin", "people", "remove", "bob"}

	_, errs, code := driveIn(t, "yes\n", true, base...)
	if code != exitUser || !strings.Contains(errs, "no connection string saved yet") {
		t.Errorf("typed yes: code=%d errs=%q, want the real dispatch outcome", code, errs)
	}
	if !strings.Contains(errs, `Type "yes" to confirm`) {
		t.Errorf("typed yes: the question was not asked, got:\n%s", errs)
	}

	_, errs, code = driveIn(t, "no\n", true, base...)
	if code != exitUser || !strings.Contains(errs, "cancelled") {
		t.Errorf("typed no: code=%d errs=%q, want cancelled", code, errs)
	}

	_, errs, code = driveIn(t, "YES\n", true, base...)
	if code != exitUser || !strings.Contains(errs, "no connection string saved yet") {
		t.Errorf("typed YES: code=%d errs=%q, want case-insensitive accept", code, errs)
	}

	// EOF instead of an answer cancels too.
	_, errs, code = driveIn(t, "", true, base...)
	if code != exitUser || !strings.Contains(errs, "no answer read") {
		t.Errorf("EOF: code=%d errs=%q, want cancel on EOF", code, errs)
	}
}

// TestAdminClaimIsNotDestructive: the bootstrap claim needs no --yes —
// it grants the token holder, it removes nothing. Its real dial (SPEC
// §3.3 bootstrap-login, 127.0.0.1:1 in claimRef) fails fast with a
// network-class error, never the confirmation gate and never the stub.
func TestAdminClaimIsNotDestructive(t *testing.T) {
	pub := pubKeyLine(t)
	_, errs, code := drive(t, "admin", "claim", claimRef, "--key", pub)
	if code != exitEnv {
		t.Errorf("claim without --yes: code=%d errs=%q, want exitEnv (no confirmation gate, real dial failure)", code, errs)
	}
	if strings.Contains(errs, "refusing to act without confirmation") {
		t.Errorf("claim should never go through the confirmation gate, got:\n%s", errs)
	}
	if strings.Contains(errs, "not implemented") {
		t.Errorf("claim still answers with the stub text: %s", errs)
	}
}
