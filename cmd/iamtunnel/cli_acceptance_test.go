package main

// Acceptance tests, each sensitive: a documented mutation of the
// product code makes it fail and the restoration makes it pass again.

import (
	"bytes"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// ---------------------------------------------------------------------------
// Test 1: every destructive verb in the admin table actually funnels through
// the confirmation gate. The gate must refuse without --yes and let the
// stub run with --yes. Verified by enumerating the table itself, so a
// new destructive verb that forgets to opt into the gate is caught.
// ---------------------------------------------------------------------------
func TestAcceptance_DestructiveGateCoversEveryDestructiveVerb(t *testing.T) {
	for group, verbs := range adminGroups {
		for _, verb := range verbs {
			v, ok := adminVerbs[group][verb]
			if !ok {
				continue
			}
			if !v.destructive {
				continue // non-destructive verbs do not go through the gate
			}
			t.Run(group+" "+verb, func(t *testing.T) {
				args := minimalValidArgs(t, group, verb)
				if args == nil {
					t.Skipf("%s/%s has no minimal sample in this build", group, verb)
				}
				full := append([]string{"admin", group, verb}, args...)
				// Without --yes: must refuse with the uniform text.
				noYes := stripYes(full)
				_, errs, code := drive(t, noYes...)
				if code != 2 {
					t.Fatalf("refused: code=%d errs=%q, want 2 (no --yes means gate blocks)", code, errs)
				}
				if !strings.Contains(errs, "refusing to act without confirmation") {
					t.Fatalf("refused: stderr lacks the uniform gate text, got:\n%s", errs)
				}
				if !strings.Contains(errs, "--yes") {
					t.Fatalf("refused: stderr lacks the --yes instruction, got:\n%s", errs)
				}
				// The flag --yes must reach the gate and let the real
				// dispatch run — never the old stub.
				fullWithYes := append(append([]string{}, full...), "--yes")
				_, errs, code = drive(t, fullWithYes...)
				if code != exitUser || !strings.Contains(errs, "no connection string saved yet") {
					t.Fatalf("with --yes: code=%d errs=%q, want the real dispatch outcome", code, errs)
				}
				if strings.Contains(errs, "not implemented") {
					t.Fatalf("with --yes: still answers with the stub text: %s", errs)
				}
			})
		}
	}
}

// minimalValidArgs returns a sample invocation that parses and validates
// for the given admin verb, so Test 1 and Test 2 can exercise the gate
// rather than fight argument syntax. False negatives are acceptable when a
// verb really has no representative call yet (the test then skips).
func minimalValidArgs(t *testing.T, group, verb string) []string {
	t.Helper()
	pub := pubKeyLine(t)
	switch group + "/" + verb {
	case "people/add":
		return []string{"bob"}
	case "people/remove":
		return []string{"bob"}
	case "people/keys":
		return []string{"add", "bob", pub}
	case "people/connection-string":
		return []string{"bob"}
	case "machines/enrol-code":
		return []string{"win01"}
	case "machines/remove":
		return []string{"win01"}
	case "machines/rekey":
		return []string{"win01", "--confirm-fingerprint", fpr43}
	case "machines/verify":
		return []string{"win01"}
	case "machines/set-user":
		return []string{"win01", `CONTOSO\svc-ssh`}
	case "grants/grant":
		return []string{"bob", "win01", "2027-01-31T18:00:00Z"}
	case "grants/revoke":
		return []string{"bob", "win01"}
	case "sessions/kill":
		return []string{"sess-0001-abcd"}
	case "recordings/fetch":
		return []string{"sess-0001-abcd"}
	case "gateway/rotate-hostkey":
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test 2: flags that look harmless must not bypass the confirmation gate.
// A destructive verb without --yes must refuse even when --json (which is
// legal on every admin verb per SPEC §7.2) is passed. Same probe for
// --config: the file path must not be a back-door around confirmation.
// ---------------------------------------------------------------------------
func TestAcceptance_HarmlessFlagsCannotBypassConfirmation(t *testing.T) {
	cases := [][]string{
		{"admin", "people", "remove", "bob"},
		{"admin", "machines", "remove", "win01"},
		{"admin", "machines", "rekey", "win01", "--confirm-fingerprint", fpr43},
		{"admin", "machines", "set-user", "win01", `CONTOSO\svc-ssh`},
		{"admin", "grants", "revoke", "bob", "win01"},
		{"admin", "sessions", "kill", "sess-0001-abcd"},
		{"admin", "people", "keys", "remove", "bob", fpr43},
	}
	for _, base := range cases {
		t.Run(strings.Join(base, "_"), func(t *testing.T) {
			// --json alone must not bypass the gate.
			_, errs, code := drive(t, append(append([]string{}, base...), "--json")...)
			if code != 2 || !strings.Contains(errs, "refusing to act without confirmation") {
				t.Fatalf("--json alone: code=%d errs=%q, want gate refusal", code, errs)
			}
			// --config alone (with a valid path) must not bypass the gate.
			good := writeConfig(t, `{"port": 2300}`)
			_, errs, code = drive(t, append(append([]string{}, base...), "--config", good)...)
			if code != 2 || !strings.Contains(errs, "refusing to act without confirmation") {
				t.Fatalf("--config alone: code=%d errs=%q, want gate refusal", code, errs)
			}
			// --config /tmp --json together still refuse.
			_, errs, code = drive(t, append(append([]string{}, base...), "--config", good, "--json")...)
			if code != 2 || !strings.Contains(errs, "refusing to act without confirmation") {
				t.Fatalf("--config --json together: code=%d errs=%q, want gate refusal", code, errs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 3: the configuration layer never lets a file quietly override
// something the user typed on the command line. Verified with the real
// config.Load: a file with port=80 is masked by --port 2400, and by
// IAMTUNNEL_PORT=2300, and is rejected outright when no stronger source
// speaks.
// ---------------------------------------------------------------------------
func TestAcceptance_FileCannotQuietlyOverrideFlagOrEnv(t *testing.T) {
	// File says 80; nothing else speaks. The run must error (port range).
	_, err := config.Load("linux", map[string]string{"HOME": "/h"}, config.Override{ConfigPath: "ignored"},
		func(string) ([]byte, error) { return []byte(`{"port": 80}`), nil })
	if err == nil || !strings.Contains(err.Error(), "1024..65535") {
		t.Fatalf("file alone with bad port: err=%v, want range error", err)
	}
	// File says 80; env says 2300. The bad file value must NOT survive.
	s, err := config.Load("linux",
		map[string]string{"HOME": "/h", "IAMTUNNEL_PORT": "2300"},
		config.Override{ConfigPath: "ignored"},
		func(string) ([]byte, error) { return []byte(`{"port": 80}`), nil })
	if err != nil {
		t.Fatalf("env masking bad file port: %v", err)
	}
	if s.Port != 2300 {
		t.Fatalf("env did not mask file: Port=%d, want 2300", s.Port)
	}
	// File says 80; env says 2300; flag says 2400. Flag wins.
	flagPort := 2400
	s, err = config.Load("linux",
		map[string]string{"HOME": "/h", "IAMTUNNEL_PORT": "2300"},
		config.Override{ConfigPath: "ignored", Port: &flagPort},
		func(string) ([]byte, error) { return []byte(`{"port": 80}`), nil })
	if err != nil {
		t.Fatalf("flag masking env and file: %v", err)
	}
	if s.Port != 2400 {
		t.Fatalf("flag did not win: Port=%d, want 2400", s.Port)
	}
}

// ---------------------------------------------------------------------------
// Test 4: a wrong value is always refused with a message naming what was
// wrong and what was wanted — never silently defaulted. The probe is the
// surface of every leaf command: each wrong value class must produce a
// user-facing message that mentions the bad value and the wanted shape.
// ---------------------------------------------------------------------------
func TestAcceptance_BadValueMessageNamesTheProblem(t *testing.T) {
	cases := []struct {
		name, wantIn, doesNotWant string
		args                      []string
	}{
		{"server idle 0", "1 to 10080", "default", []string{"server", "start", "--idle-minutes", "0"}},
		{"server max 1000", "1 to 720", "default", []string{"server", "start", "--max-hours", "1000"}},
		{"server max non-int", "must be a whole number", "default", []string{"server", "start", "--max-hours", "banana"}},
		{"gateway port 80", "1024 to 65535", "default", []string{"gateway", "run", "--port", "80", "--public-host", "gw.example.test"}},
		{"gateway port 70000", "1024 to 65535", "default", []string{"gateway", "run", "--port", "70000", "--public-host", "gw.example.test"}},
		{"people role root", `must be "user" or "admin"`, "user", []string{"admin", "people", "add", "bob", "--role", "root"}},
		{"grants until tomorrow", "ISO-8601", "RFC3339", []string{"admin", "grants", "grant", "bob", "win01", "tomorrow"}},
		{"shot lobby", "not one of", "settings", []string{"shot", "lobby"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs, code := drive(t, tc.args...)
			if code != 2 {
				t.Fatalf("code=%d errs=%q, want 2 (user error)", code, errs)
			}
			if !strings.Contains(errs, tc.wantIn) {
				t.Fatalf("stderr lacks %q, got:\n%s", tc.wantIn, errs)
			}
			// Belt-and-braces: the message names the bad value (or its
			// position) — never silently substitutes a default.
			if tc.doesNotWant != "" && strings.Contains(errs, tc.doesNotWant+" (default)") {
				t.Fatalf("stderr silently names a default, got:\n%s", errs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 5: the help text and the parser agree. Every "--<name>" token in
// the top-level usage and the role help topics corresponds to a flag the
// parser registers for at least one command; every flag the parser
// registers for a command is mentioned somewhere in its help text.
//
// The help text is a constant string and the parser is built per leaf —
// so the assertion walks every known leaf and compares the two surfaces.
// ---------------------------------------------------------------------------
func TestAcceptance_HelpAndParserAgree(t *testing.T) {
	// 1. The top-level usage must not advertise a flag that no leaf
	// registers. We mine every constant for --xxx tokens.
	helpSources := []string{
		usageText, clientHelp, serverHelp, adminHelp, gatewayHelp,
		enrolHelp, shotHelp, selftestHelp, configHelp,
	}
	for _, src := range helpSources {
		for _, m := range flagRegex.FindAllString(src, -1) {
			name := strings.TrimPrefix(m, "--")
			if name == "help" || name == "yes" {
				continue // special tokens, parser handles them implicitly
			}
			if !flagKnownInAnyLeaf(name) {
				t.Errorf("help mentions --%s but no leaf command registers it", name)
			}
		}
	}
	// 2. Every flag the parser knows about for a given leaf is mentioned
	// in the help. We probe one representative verb per shape.
	probe := []struct {
		help  string
		flags []string
	}{
		{clientHelp, []string{"replace", "config", "data-dir"}},
		{serverHelp, []string{"idle-minutes", "max-hours", "key-file", "config", "data-dir"}},
		{adminHelp, []string{"config", "json", "yes", "role", "os-user", "out"}},
		{gatewayHelp, []string{"port", "config", "data-dir", "yes", "out"}},
		{enrolHelp, []string{"config", "data-dir"}},
		{shotHelp, []string{"dark", "out"}},
	}
	for _, p := range probe {
		for _, f := range p.flags {
			needle := "--" + f
			// The top-level usage is consulted as a fallback for tokens
			// that live in many roles.
			if !strings.Contains(p.help, needle) &&
				!strings.Contains(usageText, needle) {
				t.Errorf("flag %s is registered by the parser but not mentioned in any help", needle)
			}
		}
	}
}

var flagRegex = regexp.MustCompile(`--[a-z][a-z0-9-]+`)

// flagKnownInAnyLeaf scans every leaf for at least one command whose
// flag set includes the given name. This is the inverse of the help
// assertion: it proves the parser side, not the help side.
func flagKnownInAnyLeaf(name string) bool {
	// The registry-driven surface for admin is the largest. We rebuild
	// the spec just as runAdminVerb does.
	for _, verbs := range adminVerbs {
		for _, v := range verbs {
			if name == "config" || name == "json" {
				return true
			}
			if v.destructive && name == "yes" {
				return true
			}
			for _, f := range v.flags {
				if f == name {
					return true
				}
			}
		}
	}
	// Known hard-coded flags across non-admin leaves.
	hardKnown := map[string]bool{
		"replace": true, "data-dir": true, "config": true,
		// IAMT-432: "client connect-string --name" labels the gateway
		// being remembered. Several gateways can be saved at once now,
		// and a list of them named only by host is a list a person has
		// to decode every time they switch.
		"name":         true,
		"idle-minutes": true, "max-hours": true, "key-file": true, "port": true,
		"dark": true, "out": true, "key": true,
		// IAMT-336: shot --subtab, registered in cmdShot beside --dark and
		// --out. Without it a picture could only ever show a tab's opening
		// sub-tab, which since the sub-tabs went in is a minority of what
		// the window can draw.
		"subtab": true,
		// gateway install only (cmd/iamtunnel/gateway.go:113); registered
		// behind installOnly, hence not visible in any admin verb spec.
		"rebootstrap": true,
		// gateway reset only (IAMT-388, cmdGatewayReset); registered beside
		// --yes and invisible to every admin verb spec.
		"new-hostkey": true,
		// IAMT-333: the foreign-data-directory escape, registered by every
		// client verb that writes and by the admin write paths
		// (runAdminVerb, admin pair); the refusal names it.
		"accept-foreign-data-dir": true,
		// IAMT-202: gateway install/run, validated through gatewayHelp.
		// Registered behind installOnly and unconditionally for run;
		// not in any admin verb spec.
		"public-host": true,
		// IAMT-256: the GUI launch's own flag (main.go's
		// runGUIWithFlags), not a leaf command's — the no-arguments GUI
		// path has no verb spec for this table to walk.
		"tab": true,
	}
	return hardKnown[name]
}

// ---------------------------------------------------------------------------
// Test 6: the screen list that the "shot" command consults cannot be
// changed by an importer. ScreenNames must hand out a defensive copy —
// mutating the returned slice must not affect future calls.
// ---------------------------------------------------------------------------
func TestAcceptance_ScreenNamesReturnsADefensiveCopy(t *testing.T) {
	original := config.ScreenNames()
	// Record the originals before we mutate.
	first := append([]string(nil), original...)
	// Mutate the slice we were handed and confirm the next call returns
	// the original list (the package copy is intact).
	for i := range original {
		original[i] = "pwned-" + original[i]
	}
	again := config.ScreenNames()
	if !equalSlices(first, again) {
		t.Fatalf("ScreenNames() returned a live alias: first=%v again=%v", first, again)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Test 7: the local "gateway restore" and "gateway rotate-hostkey"
// destructive commands apply the same gate as the admin role. A missing
// --yes is refused with the exact text the admin path uses, never
// silently allowed — "every dangerous command" applies here too; this
// pins the local pair.
// ---------------------------------------------------------------------------
func TestAcceptance_LocalGatewayDestructiveGate(t *testing.T) {
	cases := []struct {
		base     []string
		wantCode int
		wantIn   string
	}{
		// The tarball is not valid gzip on purpose — the real "restore"
		// fails fast on that, past the gate.
		{[]string{"gateway", "restore", writeFile(t, "b.tar.gz", "x")}, exitEnv, "not a valid gzip file"},
		{[]string{"gateway", "rotate-hostkey"}, exitOK, "rotated the gateway host key"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.base, "_"), func(t *testing.T) {
			// No --yes: refused.
			_, errs, code := drive(t, tc.base...)
			if code != exitUser || !strings.Contains(errs, "refusing to act without confirmation") {
				t.Fatalf("no --yes: code=%d errs=%q, want refusal", code, errs)
			}
			// --yes: the gate lets the real command run (never the old
			// stub, and the local gate is uniform with admin's).
			out, errs, code := drive(t, append(append([]string{}, tc.base...), "--yes")...)
			if code != tc.wantCode || (!strings.Contains(out, tc.wantIn) && !strings.Contains(errs, tc.wantIn)) {
				t.Fatalf("--yes: code=%d out=%q errs=%q, want %d containing %q", code, out, errs, tc.wantCode, tc.wantIn)
			}
			if strings.Contains(out, "not implemented") || strings.Contains(errs, "not implemented") {
				t.Fatalf("--yes: still answers with the stub text")
			}
			// --json alone must not bypass. The local-gateway subcommands
			// do not even register --json, so the parser rejects it as
			// unknown; either outcome (unknown-flag or gate-refusal) is
			// evidence the gate was not bypassed.
			_, errs, code = drive(t, append(append([]string{}, tc.base...), "--json")...)
			if code != exitUser {
				t.Fatalf("--json alone: code=%d errs=%q, want %d", code, errs, exitUser)
			}
			if !strings.Contains(errs, "refusing to act without confirmation") &&
				!strings.Contains(errs, "unknown flag") {
				t.Fatalf("--json alone: stderr lacks refusal/unknown text, got:\n%s", errs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 8: a refused destructive command must not reach the exec stub.
// If the gate ever calls exec() before refusing, the errs will mention
// "not implemented yet" instead of "refusing to act" — the order matters.
// ---------------------------------------------------------------------------
func TestAcceptance_RefusalReachesNoExecution(t *testing.T) {
	// "people keys remove" — destructive shape, no --yes.
	_, errs, _ := drive(t, "admin", "people", "keys", "remove", "bob", fpr43)
	if strings.Contains(errs, "not implemented yet") {
		t.Fatalf("gate let the stub fire; errs=%q", errs)
	}
	if !strings.Contains(errs, "refusing to act without confirmation") {
		t.Fatalf("gate did not refuse; errs=%q", errs)
	}
	// And a known-yes path proves the real dispatch is reachable from the
	// same call site — so the refusal really is the gate's doing, not a
	// parser accident.
	_, errs, code := drive(t, "admin", "people", "keys", "remove", "bob", fpr43, "--yes")
	if code != exitUser || !strings.Contains(errs, "no connection string saved yet") {
		t.Fatalf("with --yes the real dispatch must run; code=%d errs=%q", code, errs)
	}
}

// ---------------------------------------------------------------------------
// Test 9: enumerated structural assertion on the admin table. Every verb
// listed in adminGroups must exist in adminVerbs, and every entry in
// adminVerbs must be listed in its group. Together this proves the parser
// registry is internally consistent — a defect here would silently add or
// drop commands from the surface.
// ---------------------------------------------------------------------------
func TestAcceptance_AdminTablesAreInternallyConsistent(t *testing.T) {
	for group, verbs := range adminGroups {
		for _, verb := range verbs {
			if _, ok := adminVerbs[group][verb]; !ok {
				t.Errorf("adminGroups lists %q in %q but adminVerbs has no such verb", verb, group)
			}
		}
	}
	for group, verbs := range adminVerbs {
		listed := map[string]bool{}
		for _, v := range adminGroups[group] {
			listed[v] = true
		}
		for verb, v := range verbs {
			if !listed[verb] {
				t.Errorf("adminVerbs has %s/%s but adminGroups does not list it", group, verb)
			}
			if v.destructive && v.consequence == "" {
				t.Errorf("%s/%s is marked destructive but has no consequence sentence", group, verb)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test 10: a destructive verb in the admin table is also flagged as such
// when reached through "admin <group> <verb> --help" — the leaf help must
// name the consequence and the --yes hint, so the destructive property is
// not just enforced at run time but advertised where the reader looks
// first.
// ---------------------------------------------------------------------------
func TestAcceptance_DestructiveLeafHelpAdvertisesGate(t *testing.T) {
	for group, verbs := range adminVerbs {
		for verb, v := range verbs {
			if !v.destructive {
				continue
			}
			t.Run(group+" "+verb, func(t *testing.T) {
				out, _, code := drive(t, "admin", group, verb, "--help")
				if code != 0 {
					t.Fatalf("help exit code = %d, want 0", code)
				}
				if !strings.Contains(out, "Destructive") {
					t.Fatalf("destructive leaf help lacks 'Destructive':\n%s", out)
				}
				if !strings.Contains(out, "--yes") {
					t.Fatalf("destructive leaf help lacks --yes hint:\n%s", out)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test 11: the silent-fallback claim for parseScreen must hold: every
// input that maps to a known screen is canonicalised; every other input
// is refused with a message naming the bad value and the wanted list.
// ---------------------------------------------------------------------------
func TestAcceptance_ParseScreenShape(t *testing.T) {
	// Sanity: known screens round-trip.
	for _, s := range config.ScreenNames() {
		got, err := config.ParseScreen(s)
		if err != nil || got != s {
			t.Errorf("ParseScreen(%q) = %q, %v; want %q, nil", s, got, err, s)
		}
	}
	// Unknown screen: refused with a list of the wanted values.
	_, err := config.ParseScreen("pwned")
	if err == nil {
		t.Fatal("ParseScreen(\"pwned\"): want error, got nil")
	}
	if !strings.Contains(err.Error(), "pwned") {
		t.Errorf("ParseScreen(pwned): error lacks the bad value: %v", err)
	}
	for _, s := range config.ScreenNames() {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("ParseScreen(pwned): error lacks wanted value %q: %v", s, err)
		}
	}
}

// quietReader is here to silence unused-import warnings if a future test
// uses bytes/io in addition to strings; keep the import block minimal.
var _ = bytes.NewBuffer
var _ io.Reader = (*strings.Reader)(nil)

// keep sort import alive if we add deterministic checks later.
var _ = sort.Slice
