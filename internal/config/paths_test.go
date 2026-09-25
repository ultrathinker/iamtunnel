package config

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// §4.1  Invariant: DirsFor always returns absolute paths or an error.
//
// This test is a full cross-product of:
//   - platforms:  "windows", "linux" (plus the unknown → unix fallthrough)
//   - env combos: every combination of present/absent for the platform's
//     relevant variables (LOCALAPPDATA, USERPROFILE for Windows;
//     XDG_DATA_HOME, HOME for Linux)
//   - roles:      "client", "server", "enrol", "gateway" (via RoleDir)
//
// The assertion: for every cell the result is either an error, or ALL
// four directory paths plus every RoleDir are absolute. "Absolute" is
// checked with isAbsWin / isAbsUnix (the same helpers the product code
// uses) so the test verifies the invariant on both platforms regardless
// of the machine it runs on.
// ---------------------------------------------------------------------------

func TestDirsFor_AbsoluteOrError_Exhaustive(t *testing.T) {
	type envCase struct {
		name string
		env  map[string]string
	}

	// Windows combinations: LOCALAPPDATA × USERPROFILE present/absent.
	winCombos := []envCase{
		{"both set", map[string]string{
			"LOCALAPPDATA": `C:\Users\u\AppData\Local`,
			"USERPROFILE":  `C:\Users\u`,
			"ProgramData":  `C:\ProgramData`,
		}},
		{"LOCALAPPDATA only", map[string]string{
			"LOCALAPPDATA": `C:\Users\u\AppData\Local`,
			"ProgramData":  `C:\ProgramData`,
		}},
		{"USERPROFILE only", map[string]string{
			"USERPROFILE": `C:\Users\u`,
			"ProgramData": `C:\ProgramData`,
		}},
		{"neither", map[string]string{
			"ProgramData": `C:\ProgramData`,
		}},
		{"all empty", map[string]string{}},
		{"nil env", nil},
	}

	// Linux combinations: XDG_DATA_HOME × HOME present/absent.
	linuxCombos := []envCase{
		{"both set", map[string]string{
			"XDG_DATA_HOME": "/xdg/data",
			"HOME":          "/home/u",
		}},
		{"XDG_DATA_HOME only", map[string]string{
			"XDG_DATA_HOME": "/xdg/data",
		}},
		{"HOME only", map[string]string{
			"HOME": "/home/u",
		}},
		{"neither", map[string]string{}},
		{"nil env", nil},
	}

	roles := []string{"client", "server", "enrol", "gateway"}

	for _, goos := range []string{"windows"} {
		for _, ec := range winCombos {
			t.Run(goos+"/"+ec.name, func(t *testing.T) {
				d, err := DirsFor(goos, ec.env)
				if err != nil {
					// Error is acceptable — the invariant holds.
					return
				}
				// Success: every path must be absolute (Windows style).
				for label, p := range map[string]string{
					"Client":     d.Client,
					"Server":     d.Server,
					"Gateway":    d.Gateway,
					"ConfigFile": d.ConfigFile,
				} {
					if !isAbsWin(p) {
						t.Errorf("%s = %q is not an absolute Windows path", label, p)
					}
				}
				for _, role := range roles {
					rd := d.RoleDir(role)
					if rd != "" && !isAbsWin(rd) {
						t.Errorf("RoleDir(%q) = %q is not an absolute Windows path", role, rd)
					}
				}
			})
		}
	}

	for _, goos := range []string{"linux", "darwin", ""} {
		for _, ec := range linuxCombos {
			t.Run(goos+"/"+ec.name, func(t *testing.T) {
				// IAMT-310: the Gateway path is fixed and absolute on
				// Linux/darwin and needs no environment variable at all,
				// so DirsFor never fails outright here. The PER-USER
				// paths may be deferred instead, and since 1.4 there are
				// two of them — Client and Server — each with its own
				// RoleDirE error. Each field is checked on its own:
				// absolute, or empty with RoleDirE reporting why.
				d, err := DirsFor(goos, ec.env)
				if err != nil {
					t.Fatalf("DirsFor(%s, %s) unexpected top-level error (the gateway path needs no $HOME): %v", goos, ec.name, err)
				}
				for _, perUser := range []struct {
					role string
					path string
				}{
					{"client", d.Client},
					{"server", d.Server},
				} {
					if perUser.path == "" {
						if _, cerr := d.RoleDirE(perUser.role); cerr == nil {
							t.Errorf("%s is empty but RoleDirE(%q) reports no error", perUser.role, perUser.role)
						}
					} else if !isAbsUnix(perUser.path) {
						t.Errorf("%s = %q is not an absolute Unix path", perUser.role, perUser.path)
					}
				}
				for label, p := range map[string]string{
					"Gateway":    d.Gateway,
					"ConfigFile": d.ConfigFile,
				} {
					if !isAbsUnix(p) {
						t.Errorf("%s = %q is not an absolute Unix path", label, p)
					}
				}
				for _, role := range roles {
					rd, rerr := d.RoleDirE(role)
					if rerr != nil {
						continue
					}
					if rd != "" && !isAbsUnix(rd) {
						t.Errorf("RoleDir(%q) = %q is not an absolute Unix path", role, rd)
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// §4.2  Empty LOCALAPPDATA + USERPROFILE → clear error naming the variables.
// Same for XDG_DATA_HOME + HOME on Linux.
// ---------------------------------------------------------------------------

func TestDirsFor_EmptyEnvError_Windows(t *testing.T) {
	_, err := DirsFor("windows", map[string]string{})
	if err == nil {
		t.Fatal("DirsFor(windows, {}) must return an error when both LOCALAPPDATA and USERPROFILE are empty")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("error type %T is not *config.Error", err)
	}
	if ce.Class != ClassEnv {
		t.Errorf("error class = %d, want ClassEnv (%d)", ce.Class, ClassEnv)
	}
	msg := err.Error()
	if !strings.Contains(msg, "LOCALAPPDATA") || !strings.Contains(msg, "USERPROFILE") {
		t.Errorf("error message must name %%LOCALAPPDATA%% and %%USERPROFILE%%: %s", msg)
	}
}

// TestDirsFor_ProgramDataMustBeAbsolute is the IAMT-159 canary. Restoring
// the C:\ProgramData fallback makes its exact refusal assertion fail.
func TestDirsFor_ProgramDataMustBeAbsolute(t *testing.T) {
	for _, programData := range []string{"", "ProgramData", `relative\programdata`} {
		d, err := DirsFor("windows", map[string]string{
			"LOCALAPPDATA": `C:\Users\alice\AppData\Local`,
			"ProgramData":  programData,
		})
		if err != nil {
			t.Fatalf("DirsFor(windows, ProgramData=%q): %v", programData, err)
		}
		// Since 1.4 the role this guards is the GATEWAY: the server
		// directory moved under %LOCALAPPDATA%, so that two people on
		// one machine hold two registrations, and no longer reads
		// %ProgramData% at all.
		if _, err := d.RoleDirE("gateway"); err == nil {
			t.Fatalf("RoleDirE(gateway, ProgramData=%q) succeeded; want refusal for empty or relative ProgramData", programData)
		}
		if rd, rerr := d.RoleDirE("server"); rerr != nil || rd == "" {
			t.Fatalf("RoleDirE(server, ProgramData=%q) = %q, %v; the server directory does not read %%ProgramData%% any more", programData, rd, rerr)
		}
	}
}

// TestDirsFor_EmptyEnvError_Linux is the IAMT-310 canary for Linux: Server
// and Gateway are fixed absolute paths that need no environment variable at
// all, so DirsFor itself must succeed even with XDG_DATA_HOME and HOME both
// empty — only RoleDirE("client") may refuse, since only the client role
// actually needs one of those two variables.
func TestDirsFor_EmptyEnvError_Linux(t *testing.T) {
	d, err := DirsFor("linux", map[string]string{})
	if err != nil {
		t.Fatalf("DirsFor(linux, {}) must succeed — Server/Gateway need no $HOME: %v", err)
	}
	if rd, _ := d.RoleDirE("gateway"); rd == "" {
		t.Error("RoleDirE(\"gateway\") must resolve without $HOME/$XDG_DATA_HOME")
	}
	// The per-user roles are the ones that may refuse, and since 1.4
	// there are two of them. They refuse SEPARATELY from the gateway,
	// which is what the deferred errors exist for: a systemd gateway is
	// never given $HOME and must not be turned away over it.
	if _, serr := d.RoleDirE("server"); serr == nil {
		t.Error("RoleDirE(\"server\") must refuse without $HOME/$XDG_DATA_HOME — the server directory is per-user since 1.4")
	}
	_, err = d.RoleDirE("client")
	if err == nil {
		t.Fatal("RoleDirE(\"client\") must return an error when both XDG_DATA_HOME and HOME are empty")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("error type %T is not *config.Error", err)
	}
	if ce.Class != ClassEnv {
		t.Errorf("error class = %d, want ClassEnv (%d)", ce.Class, ClassEnv)
	}
	msg := err.Error()
	if !strings.Contains(msg, "XDG_DATA_HOME") {
		t.Errorf("error message lacks $XDG_DATA_HOME: %s", msg)
	}
	if !strings.Contains(msg, "HOME") {
		t.Errorf("error message lacks $HOME: %s", msg)
	}
}

func TestDirsFor_EmptyEnvError_NilEnv(t *testing.T) {
	// nil env must behave identically to an empty map. Windows still fails
	// outright (Client is Windows' only default and there is no fixed
	// machine-dir split there — see IAMT-159's ProgramData handling
	// instead). Linux/darwin resolve Server/Gateway regardless (IAMT-310)
	// and only refuse RoleDirE("client").
	_, err := DirsFor("windows", nil)
	if err == nil {
		t.Fatal("DirsFor(windows, nil) must return an error")
	}
	d, err := DirsFor("linux", nil)
	if err != nil {
		t.Fatalf("DirsFor(linux, nil) must succeed — Server/Gateway need no $HOME: %v", err)
	}
	if _, cerr := d.RoleDirE("client"); cerr == nil {
		t.Fatal("RoleDirE(\"client\") must return an error for a nil env")
	}
}

// ---------------------------------------------------------------------------
// §4.4  Normal behavior unchanged — same paths as before the fix.
// ---------------------------------------------------------------------------

func TestDirsFor_NormalWindows_Unchanged(t *testing.T) {
	d, err := DirsFor("windows", map[string]string{
		"LOCALAPPDATA": `C:\Users\alice\AppData\Local`,
		"ProgramData":  `C:\ProgramData`,
	})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	want := Dirs{
		Client:     `C:\Users\alice\AppData\Local\iamtunnel`,
		Server:     `C:\Users\alice\AppData\Local\iamtunnel\server`,
		Gateway:    `C:\ProgramData\iamtunnel\gateway`,
		ConfigFile: `C:\ProgramData\iamtunnel\gateway.json`,
	}
	if d != want {
		t.Errorf("DirsFor(windows, normal env) =\n  %+v\nwant\n  %+v", d, want)
	}
}

func TestDirsFor_NormalLinux_Unchanged(t *testing.T) {
	d, err := DirsFor("linux", map[string]string{"HOME": "/home/alice"})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	want := Dirs{
		Client:     "/home/alice/.local/share/iamtunnel",
		Server:     "/home/alice/.local/share/iamtunnel/server",
		Gateway:    "/var/lib/iamtunnel",
		ConfigFile: "/etc/iamtunnel/gateway.json",
	}
	if d != want {
		t.Errorf("DirsFor(linux, normal env) =\n  %+v\nwant\n  %+v", d, want)
	}
}

func TestDirsFor_NormalDarwin_Unchanged(t *testing.T) {
	d, err := DirsFor("darwin", map[string]string{"HOME": "/Users/alice"})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	// IAMT-257: the gateway paths are the §3.5.1 macOS layout since the
	// Windows/macOS gateway work. The server directory joined the client
	// under the person's own Library in 1.4 — a registration belongs to
	// one person on one machine.
	want := Dirs{
		Client:     "/Users/alice/Library/Application Support/iamtunnel",
		Server:     "/Users/alice/Library/Application Support/iamtunnel/server",
		Gateway:    "/Library/Application Support/iamtunnel/gateway",
		ConfigFile: "/Library/Application Support/iamtunnel/gateway.json",
	}
	if d != want {
		t.Errorf("DirsFor(darwin, normal env) =\n  %+v\nwant\n  %+v", d, want)
	}
}

// TestDirsFor_DarwinGatewaySpec351 is the IAMT-257 canary: SPEC §3.5.1
// puts the macOS gateway data dir and its config file in the SYSTEM
// scope /Library/Application Support/iamtunnel — the Unix /var/lib and
// /etc defaults this branch used before are wrong for a LaunchDaemon
// that must run regardless of any user session.
//
// Canary: revert the darwin branch of DirsFor to the old paths (Gateway
// /var/lib/iamtunnel, ConfigFile /etc/iamtunnel/gateway.json) — turns
// the exact assertion below red: "IAMT-257: darwin Gateway ... must be
// the SPEC §3.5.1 macOS path".
func TestDirsFor_DarwinGatewaySpec351(t *testing.T) {
	d, err := DirsFor("darwin", map[string]string{"HOME": "/Users/alice"})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if d.Gateway != "/Library/Application Support/iamtunnel/gateway" {
		t.Errorf("IAMT-257: darwin Gateway = %q, must be the SPEC §3.5.1 macOS path /Library/Application Support/iamtunnel/gateway", d.Gateway)
	}
	if d.ConfigFile != "/Library/Application Support/iamtunnel/gateway.json" {
		t.Errorf("IAMT-257: darwin ConfigFile = %q, must be the SPEC §3.5.1 macOS path /Library/Application Support/iamtunnel/gateway.json", d.ConfigFile)
	}
	// The server role left the machine-wide directory in 1.4 and now sits
	// beside the client, under the person's own Library: a registration
	// belongs to one person on one machine.
	if d.Server != "/Users/alice/Library/Application Support/iamtunnel/server" {
		t.Errorf("darwin Server = %q, want the per-user path", d.Server)
	}
	if rd, _ := d.RoleDirE("gateway"); rd != d.Gateway {
		t.Errorf("IAMT-257: RoleDirE(\"gateway\") = %q, want the same §3.5.1 path DirsFor returned (%q)", rd, d.Gateway)
	}
}

// TestDirsFor_DarwinIgnoresXDG is the canary: macOS does not honour
// XDG_DATA_HOME — Library/Application Support is fixed by the platform.
// Setting it on darwin must NOT pull the client's data directory into
// the Linux layout.
func TestDirsFor_DarwinIgnoresXDG(t *testing.T) {
	d, err := DirsFor("darwin", map[string]string{
		"HOME":          "/Users/alice",
		"XDG_DATA_HOME": "/xdg/should-be-ignored",
	})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if got := d.Client; got != "/Users/alice/Library/Application Support/iamtunnel" {
		t.Errorf("darwin Client with XDG_DATA_HOME set = %q, want the macOS layout", got)
	}
}

// TestDirsFor_DarwinEmptyHomeRefuses is the IAMT-310 canary: a macOS
// LaunchDaemon running the server or gateway role is never given $HOME
// (launchd hands system daemons nothing but PATH), and neither role's data
// directory lives under $HOME — so DirsFor itself must still succeed with
// $HOME empty or relative, resolving Server and Gateway normally. Only
// RoleDirE("client") may refuse, with a message that names the variable
// the user actually has to set.
//
// Canary: revert DirsFor to an unconditional refusal on a bad $HOME —
// turns "DirsFor(darwin, HOME=...) must succeed" below red (the real
// symptom was: `sudo iamtunnel server install` worked, but the
// restarted launchd daemon died with "cannot determine the client
// data directory: $HOME is empty", even though the server role never
// reads the client directory at all).
func TestDirsFor_DarwinEmptyHomeRefuses(t *testing.T) {
	for _, home := range []string{"", "relative/home"} {
		d, err := DirsFor("darwin", map[string]string{"HOME": home})
		if err != nil {
			t.Fatalf("DirsFor(darwin, HOME=%q) must succeed — the gateway needs no $HOME: %v", home, err)
		}
		// Since 1.4 the server directory is per-user, so it refuses here
		// exactly as the client does — and, crucially, without taking
		// the gateway down with it, which is what this test is for.
		if _, rerr := d.RoleDirE("server"); rerr == nil {
			t.Errorf("RoleDirE(\"server\") must refuse without $HOME (HOME=%q)", home)
		}
		if rd, rerr := d.RoleDirE("gateway"); rerr != nil || rd == "" {
			t.Errorf("RoleDirE(\"gateway\") must resolve without $HOME (HOME=%q): dir=%q err=%v", home, rd, rerr)
		}
		_, err = d.RoleDirE("client")
		if err == nil {
			t.Fatalf("RoleDirE(\"client\") with HOME=%q succeeded; want refusal", home)
		}
		var ce *Error
		if !errors.As(err, &ce) {
			t.Fatalf("error type %T is not *config.Error", err)
		}
		if ce.Class != ClassEnv {
			t.Errorf("error class = %d, want ClassEnv (%d)", ce.Class, ClassEnv)
		}
		msg := err.Error()
		if !strings.Contains(msg, "$HOME") {
			t.Errorf("error message must name $HOME: %s", msg)
		}
		if !strings.Contains(msg, "Library/Application Support/iamtunnel") {
			t.Errorf("error message must show what the bad path would have been: %s", msg)
		}
	}
}

// TestDirsFor_DarwinNilEnvRefuses: a darwin DirsFor with a nil/empty env
// still resolves Server/Gateway (IAMT-310); only RoleDirE("client") cannot
// resolve the Library/Application Support path.
func TestDirsFor_DarwinNilEnvRefuses(t *testing.T) {
	for _, env := range []map[string]string{nil, {}} {
		d, err := DirsFor("darwin", env)
		if err != nil {
			t.Fatalf("DirsFor(darwin, %v) must succeed — Server/Gateway need no $HOME: %v", env, err)
		}
		if _, cerr := d.RoleDirE("client"); cerr == nil {
			t.Fatalf("RoleDirE(\"client\") with env=%v succeeded; want refusal", env)
		}
	}
}

func TestDirsFor_XDGOverride_Unchanged(t *testing.T) {
	d, err := DirsFor("linux", map[string]string{"XDG_DATA_HOME": "/xdg"})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if d.Client != "/xdg/iamtunnel" {
		t.Errorf("XDG_DATA_HOME override: Client = %q, want /xdg/iamtunnel", d.Client)
	}
}

func TestDirsFor_WindowsFallbackToUserprofile_Unchanged(t *testing.T) {
	d, err := DirsFor("windows", map[string]string{
		"USERPROFILE": `C:\Users\bob`,
		"ProgramData": `C:\ProgramData`,
	})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if d.Client != `C:\Users\bob\AppData\Local\iamtunnel` {
		t.Errorf("USERPROFILE fallback: Client = %q", d.Client)
	}
}

// ---------------------------------------------------------------------------
// isAbsWin / isAbsUnix unit tests — these helpers guard the invariant, so
// they need their own coverage.
// ---------------------------------------------------------------------------

func TestIsAbsWin(t *testing.T) {
	cases := []struct {
		p    string
		want bool
	}{
		{`C:\Users`, true},
		{`D:\`, true},
		{`\\server\share`, true},
		{`AppData\Local`, false},
		{`.\relative`, false},
		{"", false},
		{`c:\lower`, true},
	}
	for _, tc := range cases {
		if got := isAbsWin(tc.p); got != tc.want {
			t.Errorf("isAbsWin(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestIsAbsUnix(t *testing.T) {
	cases := []struct {
		p    string
		want bool
	}{
		{"/home/alice", true},
		{"/", true},
		{".local/share", false},
		{"relative", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isAbsUnix(tc.p); got != tc.want {
			t.Errorf("isAbsUnix(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}
