package main

// iamt259_launchd_test.go — IAMT-259 (SPEC §3.5.1): the macOS half of
// install/uninstall — the _iamtunnel service user through dscl
// (hidden, a free UID < 500, shell /usr/bin/false), the LaunchDaemon
// /Library/LaunchDaemons/com.iamtunnel.gateway.plist (0644, root:wheel,
// RunAtLoad, KeepAlive, ProgramArguments = the same "gateway run
// --data-dir --port --public-host"), output to /Library/Logs/iamtunnel/
// gateway.log, launchctl bootstrap/bootout. All of it through the
// darwinLaunchdSetup seam: no test binary ever touches dscl, launchctl
// or /Library (in the test binary the seam's production calls panic —
// gateway_launchd_darwin.go), exactly like the Linux half with
// systemdSetup (IAMT-177) and the Windows half with windowsServiceSetup
// (IAMT-258).
//
// The file is deliberately platform-neutral: the sequences, the parsing
// of dscl/launchctl output and the plist render are pure — checked on
// any host OS; the darwin branch's CLI path runs only on a darwin host
// (that is where it is selected by runtime.GOOS), which is marked with
// self-explaining skips.

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// launchdRecorder — a fake of the darwinLaunchdSetup seam: journals
// every call and returns the assigned results. Result fields are filled
// in by the test BEFORE the sequence runs; the journal fields are read
// afterwards.
type launchdRecorder struct {
	// call journals
	rootCalls        int
	makeLogDirCalls  []string
	lookupUserCalls  []string
	uidsTakenCalls   int
	createUserCalls  []darwinServiceUserSpec
	chownCalls       []string // "path:uid:gid"
	writePlistCalls  []string // "path:mode:uid:gid"
	plistExistsCalls []string
	removePlistCalls []string
	loadedCalls      []string
	bootoutCalls     []string
	bootstrapCalls   []string
	runningCalls     []string
	lastPlist        string
	// order — the end-to-end journal of the ORDER of steps (the
	// individual fields' journals do not show their mutual order).
	order []string

	// assigned results (nil = success/none)
	//
	// rootResult — the only result field that tests expecting a
	// successful install/uninstall MUST set explicitly: the zero value
	// means "not root", and both sequences refuse at the very first
	// step, before anything the test meant to check. The "root needed"
	// refusal is checked by exactly one test — InstallSequenceRequiresRoot.
	rootResult     bool
	rootErr        error
	logDirErr      error
	lookupUID      int
	lookupExists   bool
	lookupErr      error
	uidsTaken      map[int]bool
	uidsErr        error
	createUserErr  error
	chownErr       error
	writePlistErr  error
	plistExistsRes bool
	plistExistsErr error
	removePlistErr error
	loadedRes      bool
	loadedErr      error
	bootoutRes     bool
	bootoutErr     error
	bootstrapErr   error
	// runningNotRunning: false (zero value) means the freshly bootstrapped
	// job answers "running" — the sensible default for every pre-existing
	// test that never heard of IAMT-308's post-bootstrap liveness check.
	// Set true to make it answer "not running" instead (the exact live-Mac
	// symptom); runningErr overrides both when set.
	runningNotRunning bool
	runningErr        error
	// traversableCalls journals every parentTraversable call as
	// "dataDir:uid:gid".
	traversableCalls []string
	// traversableErr: nil (zero value) means the real account can reach
	// dataDir's parent — the sensible default for every test that is
	// not specifically exercising IAMT-308's refusal, since this fake
	// OS seam never spawns a real subprocess or consults a real
	// filesystem (production's probeAccountCanReach does — see its own
	// darwin-only tests for coverage of the full-ancestor-chain, ACL and
	// symlink behaviour F-308-3 is about); this fake only ever models
	// "the seam step ran and said yes" or "...said no, with this exact
	// text" — never partial-chain reasoning, which belongs to the real
	// implementation instead. Set to a concrete error to simulate the
	// real-Mac refusal.
	traversableErr error
	// ancestorsAreSafeCalls journals every ancestorsAreSafe call.
	ancestorsAreSafeCalls []string
	// ancestorsUnsafeErr: nil (zero value) means every ancestor of a
	// custom --data-dir is exclusively root-controlled — the sensible
	// default for every test that is not specifically exercising IAMT-308
	// round 10's refusal, since this fake never inspects a real
	// filesystem tree (production's darwinCustomDataDirAncestorsAreSafe
	// does — see its own darwin-only tests). Every CLI-level darwin test
	// installs into a --data-dir under t.TempDir(), which a non-root test
	// process can never make root-owned, so a non-nil default here would
	// break them all — the same "must not fire under a fake seam" lesson
	// round 6 already learned for parentTraversable.
	ancestorsUnsafeErr error
	// leafIsSafeCalls journals every leafIsSafe call, as
	// "dataDir:serviceUID".
	leafIsSafeCalls []string
	// leafUnsafeErr: nil (zero value) means dataDir itself is safe (not
	// a symlink, not carrying an ACL, exclusively controlled by root or
	// the resolved service account) — the sensible default for every
	// test that is not specifically exercising IAMT-308 round 11's
	// refusal (F-308-9), for the exact same reason ancestorsUnsafeErr
	// above defaults to nil: this fake never inspects a real filesystem
	// tree, and every CLI-level darwin test installs into a --data-dir
	// under t.TempDir(), which a non-root test process can never make
	// root-owned.
	leafUnsafeErr error
	// exeWriters — who, besides root, may replace the binary (IAMT-445b);
	// by default nobody, for the same reason as above: the fake never
	// looks into a real filesystem.
	exeWriters []string
}

func (r *launchdRecorder) setup() darwinLaunchdSetup {
	return darwinLaunchdSetup{
		currentUserIsRoot: func() (bool, error) {
			r.rootCalls++
			r.order = append(r.order, "root")
			return r.rootResult, r.rootErr
		},
		makeLogDir: func(path string) error {
			r.makeLogDirCalls = append(r.makeLogDirCalls, path)
			r.order = append(r.order, "makeLogDir")
			return r.logDirErr
		},
		lookupUser: func(name string) (int, bool, error) {
			r.lookupUserCalls = append(r.lookupUserCalls, name)
			r.order = append(r.order, "lookupUser")
			return r.lookupUID, r.lookupExists, r.lookupErr
		},
		systemUIDsTaken: func() (map[int]bool, error) {
			r.uidsTakenCalls++
			r.order = append(r.order, "uidsTaken")
			return r.uidsTaken, r.uidsErr
		},
		createUser: func(spec darwinServiceUserSpec) error {
			r.createUserCalls = append(r.createUserCalls, spec)
			r.order = append(r.order, "createUser")
			return r.createUserErr
		},
		chownDir: func(path string, uid, gid int) error {
			r.chownCalls = append(r.chownCalls, fmt.Sprintf("%s:%d:%d", path, uid, gid))
			r.order = append(r.order, "chownDir")
			return r.chownErr
		},
		writePlist: func(path string, content []byte, mode os.FileMode, uid, gid int) error {
			r.writePlistCalls = append(r.writePlistCalls, fmt.Sprintf("%s:%04o:%d:%d", path, mode, uid, gid))
			r.lastPlist = string(content)
			r.order = append(r.order, "writePlist")
			return r.writePlistErr
		},
		plistExists: func(path string) (bool, error) {
			r.plistExistsCalls = append(r.plistExistsCalls, path)
			r.order = append(r.order, "plistExists")
			return r.plistExistsRes, r.plistExistsErr
		},
		removePlist: func(path string) error {
			r.removePlistCalls = append(r.removePlistCalls, path)
			r.order = append(r.order, "removePlist")
			return r.removePlistErr
		},
		serviceLoaded: func(label string) (bool, error) {
			r.loadedCalls = append(r.loadedCalls, label)
			r.order = append(r.order, "loaded")
			return r.loadedRes, r.loadedErr
		},
		bootout: func(label string) (bool, error) {
			r.bootoutCalls = append(r.bootoutCalls, label)
			r.order = append(r.order, "bootout")
			return r.bootoutRes, r.bootoutErr
		},
		bootstrap: func(plistPath string) error {
			r.bootstrapCalls = append(r.bootstrapCalls, plistPath)
			r.order = append(r.order, "bootstrap")
			return r.bootstrapErr
		},
		serviceRunning: func(label string) (bool, error) {
			r.runningCalls = append(r.runningCalls, label)
			if r.runningErr != nil {
				return false, r.runningErr
			}
			return !r.runningNotRunning, nil
		},
		parentTraversable: func(dataDir string, uid, gid int) error {
			r.traversableCalls = append(r.traversableCalls, fmt.Sprintf("%s:%d:%d", dataDir, uid, gid))
			r.order = append(r.order, "parentTraversable")
			return r.traversableErr
		},
		ancestorsAreSafe: func(dataDir string) error {
			r.ancestorsAreSafeCalls = append(r.ancestorsAreSafeCalls, dataDir)
			r.order = append(r.order, "ancestorsAreSafe")
			return r.ancestorsUnsafeErr
		},
		leafIsSafe: func(dataDir string, serviceUID int) error {
			r.leafIsSafeCalls = append(r.leafIsSafeCalls, fmt.Sprintf("%s:%d", dataDir, serviceUID))
			r.order = append(r.order, "leafIsSafe")
			return r.leafUnsafeErr
		},
		exeWriters: func(bin string) ([]string, error) {
			r.order = append(r.order, "exeWriters")
			return r.exeWriters, nil
		},
	}
}

// withFakeLaunchd substitutes the production darwinLaunchd seam with a
// recording fake and returns it. Restoration goes through t.Cleanup;
// the package's tests do not run in parallel, so the global
// substitution is safe. On non-darwin hosts the substitution is
// harmless: the seam is never reached, and calling the helper dampens
// the production seam's panic if a test drives the CLI path that on
// darwin must go through this seam.
func withFakeLaunchd(t *testing.T) *launchdRecorder {
	t.Helper()
	// rootResult: true — the helper serves the CLI tests that drive
	// install/uninstall and expect a successful outcome (on a darwin
	// host, where the branch is actually selected); the "root needed"
	// refusal is checked by a separate entry in
	// TestIAMT259_InstallSequenceRequiresRoot.
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true}
	prev := darwinLaunchd
	darwinLaunchd = rec.setup()
	t.Cleanup(func() { darwinLaunchd = prev })
	return rec
}

// TestIAMT259_PickFreeSystemUIDSkipsBusy — SPEC §3.5.1: a free UID
// < 500. The first unoccupied one in [200, 499] is picked; when the
// range is exhausted — "no one left to create", not a UID of 500+.
//
// Canary: search from 500 (the range of ordinary users) or return an
// occupied UID — the corresponding comparison turns red.
func TestIAMT259_PickFreeSystemUIDSkipsBusy(t *testing.T) {
	if uid, ok := pickFreeSystemUID(map[int]bool{}); !ok || uid != 200 {
		t.Fatalf("empty busy list: uid=%d ok=%v, wanted 200 (the bottom of the range)", uid, ok)
	}
	busy := map[int]bool{200: true, 201: true, 202: true}
	if uid, ok := pickFreeSystemUID(busy); !ok || uid != 203 {
		t.Fatalf("200–202 busy: uid=%d ok=%v, wanted 203 (the first free one)", uid, ok)
	}
	full := map[int]bool{}
	for uid := darwinSystemUIDMin; uid <= darwinSystemUIDMax; uid++ {
		full[uid] = true
	}
	if _, ok := pickFreeSystemUID(full); ok {
		t.Fatal("an exhausted range must return ok=false, not a UID outside < 500")
	}
}

// TestIAMT259_PlistRendersSpecKeys — the LaunchDaemon plist render
// carries exactly the keys SPEC §3.5.1 requires: Label
// com.iamtunnel.gateway, RunAtLoad, KeepAlive, UserName _iamtunnel,
// ProgramArguments = the binary + "gateway run --data-dir … --port …
// --public-host …", output to /Library/Logs/iamtunnel/gateway.log (both
// stdout and stderr). The document must be well-formed XML.
//
// Canary: drop any key (say, KeepAlive — the daemon would stop coming
// back after a crash) or assemble ProgramArguments without the binary —
// the check of the corresponding key/element turns red.
func TestIAMT259_PlistRendersSpecKeys(t *testing.T) {
	exe := "/usr/local/bin/iamtunnel"
	args := gatewayServiceArguments("/Library/Application Support/iamtunnel/gateway", 2222, "gw.example.test")
	plist, err := renderLaunchdPlist(exe, args)
	if err != nil {
		t.Fatalf("renderLaunchdPlist: %v", err)
	}

	for _, key := range []string{"Label", "RunAtLoad", "KeepAlive", "UserName", "ProgramArguments", "StandardOutPath", "StandardErrorPath"} {
		if !strings.Contains(plist, "<key>"+key+"</key>") {
			t.Errorf("the plist lacks the %s key (SPEC §3.5.1):\n%s", key, plist)
		}
	}
	if !strings.Contains(plist, "<string>com.iamtunnel.gateway</string>") {
		t.Errorf("Label must be com.iamtunnel.gateway:\n%s", plist)
	}
	if !strings.Contains(plist, "<string>_iamtunnel</string>") {
		t.Errorf("UserName must be _iamtunnel (SPEC §3.5.1):\n%s", plist)
	}
	if n := strings.Count(plist, "<true/>"); n != 2 {
		t.Errorf("RunAtLoad and KeepAlive must be <true/> (found %d):\n%s", n, plist)
	}
	if !strings.Contains(plist, "<string>/Library/Logs/iamtunnel/gateway.log</string>") {
		t.Errorf("the daemon's output must go to /Library/Logs/iamtunnel/gateway.log:\n%s", plist)
	}

	// ProgramArguments: the binary, then the same arguments as the
	// Windows service's (one command-line contract for both halves of
	// §3.5.1). plistStrings collects ALL string values in document
	// order: Label first, then UserName, then ProgramArguments, and
	// StandardOutPath and StandardErrorPath at the end.
	strs := plistStrings(t, plist)
	want := append([]string{darwinPlistLabel, darwinServiceUser, exe}, args...)
	want = append(want, darwinLogPath, darwinLogPath)
	if !reflect.DeepEqual(strs, want) {
		t.Fatalf("plist strings =\n  %q\nwanted:\n  %q", strs, want)
	}
}

// TestIAMT259_PlistEscapesXMLLikeSpec — "values in the plist are
// escaped as XML" (SPEC §3.5.1): the data directory and the public host
// land in the plist exactly as the operator gave them — with <, >, &,
// quotes — and the document must stay well-formed, and parsing must
// return the original strings.
//
// Canary: assemble the plist by concatenation without xml.EscapeText —
// both the parsing (not XML) and the original-string comparison turn
// red.
func TestIAMT259_PlistEscapesXMLLikeSpec(t *testing.T) {
	nasty := `/tmp/x<&>"y & z`
	plist, err := renderLaunchdPlist("/usr/local/bin/iamtunnel",
		gatewayServiceArguments(nasty, 2222, `host<"q">`))
	if err != nil {
		t.Fatalf("renderLaunchdPlist: %v", err)
	}
	if strings.Contains(plist, nasty) || strings.Contains(plist, `host<"q">`) {
		t.Fatalf("an unescaped value made it into the plist — that is no longer well-formed XML:\n%s", plist)
	}
	strs := plistStrings(t, plist) // the parsing doubles as proof of well-formedness
	foundDir, foundHost := false, false
	for _, s := range strs {
		if s == nasty {
			foundDir = true
		}
		if s == `host<"q">` {
			foundHost = true
		}
	}
	if !foundDir || !foundHost {
		t.Fatalf("after parsing the original values did not come back (dir=%v host=%v); strings: %q", foundDir, foundHost, strs)
	}
}

// plistStrings parses the plist as XML (at zero stakes: the document
// must be well-formed) and returns all string values.
func plistStrings(t *testing.T, plist string) []string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(plist))
	var strs []string
	inString := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the plist does not parse as XML: %v\n%s", err, plist)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			inString = el.Name.Local == "string"
		case xml.EndElement:
			// The flag must drop on a closing tag too: otherwise it
			// stays up until the next StartElement, and the whitespace
			// between </string> and the next tag lands in the result
			// as "yet another string value".
			if el.Name.Local == "string" {
				inString = false
			}
		case xml.CharData:
			if inString {
				strs = append(strs, string(el))
			}
		}
	}
	return strs
}

// TestIAMT259_DSCLCallsPinsShellHiddenAndHome — the set of dscl calls
// creating the service user repeats SPEC §3.5.1's words verbatim:
// UniqueID a free system one, PrimaryGroupID 20 (staff), UserShell
// /usr/bin/false, home /var/empty, IsHidden 1 ("hidden"). The launchctl
// targets are pinned: bootstrap system <plist>, bootout system/<label>.
//
// Canary: change the shell (say, /bin/bash — the user would be able to
// log in), forget IsHidden 1, or bootstrap outside the system domain —
// the comparison of the corresponding call turns red.
func TestIAMT259_DSCLCallsPinsShellHiddenAndHome(t *testing.T) {
	spec := darwinServiceUserSpec{
		Name: darwinServiceUser, UID: 201, GID: darwinServiceGID,
		Shell: darwinServiceShell, Gecos: darwinServiceGecos,
		Home: darwinServiceHome, Hidden: true,
	}
	want := [][]string{
		{".", "-create", "/Users/_iamtunnel", "UniqueID", "201"},
		{".", "-create", "/Users/_iamtunnel", "PrimaryGroupID", "20"},
		{".", "-create", "/Users/_iamtunnel", "UserShell", "/usr/bin/false"},
		{".", "-create", "/Users/_iamtunnel", "RealName", "iamtunnel gateway service"},
		{".", "-create", "/Users/_iamtunnel", "NFSHomeDirectory", "/var/empty"},
		{".", "-create", "/Users/_iamtunnel", "IsHidden", "1"},
	}
	if got := dsclCreateUserCalls(spec); !reflect.DeepEqual(got, want) {
		t.Fatalf("dsclCreateUserCalls =\n  %q\nwanted (shell /usr/bin/false and IsHidden 1 — SPEC §3.5.1):\n  %q", got, want)
	}
	spec.Hidden = false
	if got := dsclCreateUserCalls(spec); len(got) != 5 {
		t.Fatalf("without Hidden there must be no IsHidden call: %q", got)
	}

	if got := dsclUserReadArgs(darwinServiceUser); !reflect.DeepEqual(got, []string{".", "-read", "/Users/_iamtunnel", "UniqueID"}) {
		t.Errorf("dsclUserReadArgs = %q", got)
	}
	if got := dsclListUsersArgs(); !reflect.DeepEqual(got, []string{".", "-list", "/Users", "UniqueID"}) {
		t.Errorf("dsclListUsersArgs = %q", got)
	}
	if got := launchctlBootstrapArgs(darwinPlistPath); !reflect.DeepEqual(got, []string{"bootstrap", "system", darwinPlistPath}) {
		t.Errorf("launchctlBootstrapArgs = %q, wanted bootstrap system <plist> (SPEC §3.5.1)", got)
	}
	if got := launchctlBootoutArgs(darwinPlistLabel); !reflect.DeepEqual(got, []string{"bootout", "system/com.iamtunnel.gateway"}) {
		t.Errorf("launchctlBootoutArgs = %q, wanted bootout system/com.iamtunnel.gateway (SPEC §3.5.1)", got)
	}
	if got := launchctlPrintArgs(darwinPlistLabel); !reflect.DeepEqual(got, []string{"print", "system/com.iamtunnel.gateway"}) {
		t.Errorf("launchctlPrintArgs = %q", got)
	}
}

// TestIAMT259_ParsesDSCTAndLaunchctlOutput — parsing the tools' text
// answers: the UID from "dscl . -read", the busy UIDs from
// "dscl . -list", telling "no such user/daemon" (the norm on a first
// install) from a real error.
//
// Canary: credit any dscl error as "no user" — the real-error case
// turns red; fail to recognize "Could not find service" — the launchctl
// answer parsing turns red.
func TestIAMT259_ParsesDSCLAndLaunchctlOutput(t *testing.T) {
	if uid, ok := parseDSCLUniqueID("UniqueID: 201\n"); !ok || uid != 201 {
		t.Fatalf("parseDSCLUniqueID = (%d, %v), wanted (201, true)", uid, ok)
	}
	if _, ok := parseDSCLUniqueID("no such user\n"); ok {
		t.Fatal("output without UniqueID must yield ok=false")
	}

	got := parseDSCLUIDList("root 0\n_daemon 1\n_iamtunnel  201\n\n\u043c\u0443\u0441\u043e\u0440 \u0431\u0435\u0437 \u0447\u0438\u0441\u043b\u0430\n")
	want := map[int]bool{0: true, 1: true, 201: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDSCLUIDList = %v, wanted %v", got, want)
	}

	if !dsclSaysNoUser("<dscl_cmd> DS Error: -14036 (eDSRecordNotFound)") {
		t.Error("eDSRecordNotFound must count as \"no user\"")
	}
	if dsclSaysNoUser("operation denied by policy") {
		t.Error("a real dscl error does not count as \"no user\"")
	}
	if !launchctlSaysNotLoaded(`Could not find service "com.iamtunnel.gateway" in domain system`) {
		t.Error("\"Could not find service\" must count as \"no daemon\"")
	}
	if !launchctlSaysNotLoaded("No such process") {
		t.Error("\"No such process\" must count as \"no daemon\" (the print→bootout race)")
	}
	if launchctlSaysNotLoaded("Bootstrap failed: 5: Input/output error") {
		t.Error("a real launchctl error does not count as \"no daemon\"")
	}
}

// TestIAMT259_InstallSequenceFreshUser — the canary of the macOS
// install sequence: root → no user lookup → a free UID → creation →
// reachability → the log directory → chown of the data and log
// directories → the plist (0644, root:wheel) → launchctl bootstrap
// system, in that order. These are TWO calls, exactly as
// runGatewayInstall makes them (IAMT-308 round 8):
// preflightGatewayReachability resolves/creates the account and checks
// reachability BEFORE the secrets, setupLaunchdDaemon — after, with the
// uid already resolved.
//
// Canary: reorder the steps (say, create the user after the chown or
// bootstrap before writing the plist) or drop any step — the rec.order
// comparison turns red; write the plist with another owner/mode — the
// field in writePlistCalls turns red; call createUser inside
// setupLaunchdDaemon again (round 7's mistake — IAMT-177 saw it on a
// live Mac twice) — the len(rec.createUserCalls) != 1 turns red.
func TestIAMT259_InstallSequenceFreshUser(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true}
	uid, perr := preflightGatewayReachability(rec.setup(), "/Library/Application Support/iamtunnel/gateway")
	if perr != nil {
		t.Fatalf("preflightGatewayReachability: %v", perr)
	}
	err := setupLaunchdDaemon(rec.setup(), "/usr/local/bin/iamtunnel",
		gatewayServiceArguments("/Library/Application Support/iamtunnel/gateway", 2222, "gw.example.test"),
		"/Library/Application Support/iamtunnel/gateway", uid)
	if err != nil {
		t.Fatalf("setupLaunchdDaemon: %v", err)
	}
	wantOrder := []string{"root", "lookupUser", "uidsTaken", "createUser", "parentTraversable", "makeLogDir", "chownDir", "chownDir", "writePlist", "loaded", "bootstrap"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("install sequence = %v, wanted %v", rec.order, wantOrder)
	}
	if !reflect.DeepEqual(rec.makeLogDirCalls, []string{darwinLogDir}) {
		t.Errorf("the log directory is created at a path other than /Library/Logs/iamtunnel: %v", rec.makeLogDirCalls)
	}
	if len(rec.createUserCalls) != 1 {
		t.Fatalf("the service user must be created exactly once: %v", rec.createUserCalls)
	}
	spec := rec.createUserCalls[0]
	if spec.Name != "_iamtunnel" || spec.UID != darwinSystemUIDMin || spec.GID != 20 ||
		spec.Shell != "/usr/bin/false" || !spec.Hidden || spec.Home != "/var/empty" {
		t.Fatalf("the user spec contradicts SPEC §3.5.1: %+v", spec)
	}
	if !reflect.DeepEqual(rec.chownCalls, []string{
		"/Library/Application Support/iamtunnel/gateway:200:20",
		darwinLogDir + ":200:20",
	}) {
		t.Errorf("chown must hand the data and log directories to user 200:20: %v", rec.chownCalls)
	}
	if len(rec.writePlistCalls) != 1 || rec.writePlistCalls[0] != darwinPlistPath+":0644:0:0" {
		t.Errorf("the plist must land in %s with mode 0644 and owner root:wheel: %v", darwinPlistPath, rec.writePlistCalls)
	}
	if !strings.Contains(rec.lastPlist, "<string>_iamtunnel</string>") {
		t.Errorf("the written plist must name the _iamtunnel user:\n%s", rec.lastPlist)
	}
	if !reflect.DeepEqual(rec.bootstrapCalls, []string{darwinPlistPath}) {
		t.Errorf("bootstrap must be called with the plist path: %v", rec.bootstrapCalls)
	}
}

// TestIAMT308_InstallRefusesWhenBootstrappedJobIsNotRunning is the
// IAMT-308 canary: launchctl bootstrap succeeding is not evidence the
// daemon is up — a live Mac showed exactly this shape ("state = spawn
// scheduled, runs = 4, last exit code = 4") while `gateway install`
// itself had already returned exit 0. setupLaunchdDaemon must now poll
// serviceRunning after bootstrap and refuse (a named, non-nil error)
// when it never answers "running".
//
// Canary: drop the serviceRunning check after bootstrap in
// launchdBootstrapTail — this check turns red (err == nil, a refusal
// was wanted). The second canary (round 2, a real report from three
// machines): wrap this call in a retry loop AT THE launchdBootstrapTail
// LEVEL — the len(rec.runningCalls) == 1 check turns red: the seam must
// call launchctl print exactly once, and waiting/re-asking is the
// production implementation's business (waitForLiveness inside
// darwinLaunchd.serviceRunning), not the sequence's. Otherwise the
// platform-neutral test on the recording fake sees several steps where
// IAMT-258/259 pin exactly one — that is exactly how 20677ae broke
// TestIAMT258_..._started_but_never_reports_running on all three OSes.
func TestIAMT308_InstallRefusesWhenBootstrappedJobIsNotRunning(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, runningNotRunning: true}
	err := setupLaunchdDaemon(rec.setup(), "/usr/local/bin/iamtunnel",
		gatewayServiceArguments("/Library/Application Support/iamtunnel/gateway", 2222, "gw.example.test"),
		"/Library/Application Support/iamtunnel/gateway", 200)
	if err == nil {
		t.Fatal("setupLaunchdDaemon must refuse when launchctl never reports the job running after bootstrap")
	}
	if !strings.Contains(err.Error(), "bootstrapped") || !strings.Contains(err.Error(), "does not report it running") {
		t.Fatalf("refusal text must say the job was bootstrapped but is not running: %v", err)
	}
	if len(rec.runningCalls) != 1 {
		t.Fatalf("launchdBootstrapTail must call serviceRunning exactly once (waiting is the PRODUCT implementation's job, not the sequence's): got %d calls", len(rec.runningCalls))
	}
}

// TestIAMT312_RepeatInstallOnRunningJobSucceeds documents that macOS has
// no IAMT-312-shaped hole either: launchdBootstrapTail unconditionally
// bootouts a loaded job before bootstrapping it again, so a repeat
// install of an already-running LaunchDaemon succeeds by construction —
// there is no "already running" error launchctl bootstrap could return
// the way Windows' StartService does. This is the same scenario
// TestIAMT259_InstallSequenceReusesExistingUser already exercises
// (loadedRes: true); named separately per the round-3 request to cover
// "install when the service exists and is running" explicitly on all
// three OSes at the seam level.
func TestIAMT312_RepeatInstallOnRunningJobSucceeds(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, loadedRes: true}
	err := setupLaunchdDaemon(rec.setup(), "/usr/local/bin/iamtunnel",
		gatewayServiceArguments("/d", 2022, "127.0.0.1"), "/d", 215)
	if err != nil {
		t.Fatalf("setupLaunchdDaemon must succeed when the job is already loaded and running: %v", err)
	}
	if !reflect.DeepEqual(rec.bootoutCalls, []string{darwinPlistLabel}) {
		t.Fatalf("a running job must be stopped before the new plist is bootstrapped: bootout calls = %v", rec.bootoutCalls)
	}
	if !reflect.DeepEqual(rec.bootstrapCalls, []string{darwinPlistPath}) {
		t.Fatalf("the new plist must still be bootstrapped: bootstrap calls = %v", rec.bootstrapCalls)
	}
}

// TestIAMT259_InstallSequenceReusesExistingUser — a repeat install
// reuses the existing _iamtunnel (no duplicate is spawned and no UID
// rescan happens), and an already loaded daemon is restarted
// (bootout → bootstrap) so the new --port/--public-host take effect
// immediately, not after a reboot.
//
// Canary: with an existing user, call createUser or scan UIDs —
// len(rec.createUserCalls) and rec.order turn red; drop the restart of
// the loaded daemon — the order comparison turns red (bootout between
// writePlist and bootstrap).
func TestIAMT259_InstallSequenceReusesExistingUser(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, lookupUID: 215, lookupExists: true, loadedRes: true}
	uid, perr := preflightGatewayReachability(rec.setup(), "/d")
	if perr != nil {
		t.Fatalf("preflightGatewayReachability: %v", perr)
	}
	err := setupLaunchdDaemon(rec.setup(), "/usr/local/bin/iamtunnel",
		gatewayServiceArguments("/d", 2400, "gw.example.test"), "/d", uid)
	if err != nil {
		t.Fatalf("setupLaunchdDaemon: %v", err)
	}
	wantOrder := []string{"root", "lookupUser", "parentTraversable", "makeLogDir", "chownDir", "chownDir", "writePlist", "loaded", "bootout", "bootstrap"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("repeat install sequence = %v, wanted %v", rec.order, wantOrder)
	}
	if len(rec.createUserCalls) != 0 || rec.uidsTakenCalls != 0 {
		t.Fatalf("the existing user is reused: createUser=%v uidsTaken=%d", rec.createUserCalls, rec.uidsTakenCalls)
	}
	if !reflect.DeepEqual(rec.chownCalls, []string{"/d:215:20", darwinLogDir + ":215:20"}) {
		t.Errorf("chown must run under the existing user's UID: %v", rec.chownCalls)
	}
	if !reflect.DeepEqual(rec.bootoutCalls, []string{darwinPlistLabel}) {
		t.Errorf("bootout must be called with the daemon's label: %v", rec.bootoutCalls)
	}
}

// TestIAMT259_PreflightGatewayReachabilitySucceedsBeforeAnySecret is the
// IAMT-308 round 7 canary for review finding F-308-4: preflightGatewayReachability
// resolves the account and checks reachability using ONLY {root,
// lookupUser, [uidsTaken, createUser], parentTraversable} — it must
// never touch makeLogDir, chownDir, writePlist or bootstrap, because
// those come later in runGatewayInstall's flow, after secrets already
// exist; a preflight that quietly grew into a second full install would
// defeat the very point of calling it early.
//
// Canary: call an extra seam step inside preflightGatewayReachability
// (say, makeLogDir) — the rec.order comparison turns red.
func TestIAMT259_PreflightGatewayReachabilitySucceedsBeforeAnySecret(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true}
	uid, err := preflightGatewayReachability(rec.setup(), "/srv/gw")
	if err != nil {
		t.Fatalf("preflightGatewayReachability: %v", err)
	}
	if uid != darwinSystemUIDMin {
		t.Errorf("preflightGatewayReachability must return the freshly created account's uid: got %d, want %d", uid, darwinSystemUIDMin)
	}
	wantOrder := []string{"root", "lookupUser", "uidsTaken", "createUser", "parentTraversable"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("preflightGatewayReachability = %v, wanted %v (no makeLogDir/chownDir/writePlist/bootstrap before the refusal/success)", rec.order, wantOrder)
	}
}

// TestIAMT259_PreflightGatewayReachabilityRefusesByName mirrors
// TestIAMT259_SetupLaunchdDaemonRefusesWhenParentNotTraversable at the
// preflight's own level: the same parentTraversable refusal, reached
// WITHOUT ever calling makeLogDir/chownDir/writePlist/bootstrap, is what
// runGatewayInstall must see before it creates a single secret artifact
// (F-308-4).
func TestIAMT259_PreflightGatewayReachabilityRefusesByName(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, traversableErr: errors.New("stat /company-secrets: permission denied")}
	_, err := preflightGatewayReachability(rec.setup(), "/company-secrets/gw")
	if err == nil {
		t.Fatal("preflightGatewayReachability must refuse when parentTraversable answers a non-nil error (IAMT-308 round 7)")
	}
	if !strings.Contains(err.Error(), "cannot reach") || !strings.Contains(err.Error(), "chmod o+x") {
		t.Fatalf("refusal does not name the unreachable-parent problem with its chmod remedy: %v", err)
	}
	wantOrder := []string{"root", "lookupUser", "uidsTaken", "createUser", "parentTraversable"}
	if !reflect.DeepEqual(rec.order, wantOrder) {
		t.Fatalf("after parentTraversable refuses, the preflight may call nothing else: %v, wanted %v", rec.order, wantOrder)
	}
}

// TestIAMT259_CheckCustomDataDirAncestorsAreSafeRefusesByName is the
// round-10 seam-level canary for review finding F-308-8:
// checkCustomDataDirAncestorsAreSafe must surface the seam's refusal
// text verbatim (the real darwin implementation already names the exact
// offending path and the fix) and must name the exact dataDir it was
// asked about.
func TestIAMT259_CheckCustomDataDirAncestorsAreSafeRefusesByName(t *testing.T) {
	rec := &launchdRecorder{ancestorsUnsafeErr: errors.New("/company-secrets is not exclusively controlled by root (owner uid 501, mode 0755)")}
	err := checkCustomDataDirAncestorsAreSafe(rec.setup(), "/company-secrets/gw")
	if err == nil {
		t.Fatal("checkCustomDataDirAncestorsAreSafe must refuse when ancestorsAreSafe answers a non-nil error (IAMT-308 round 10)")
	}
	if !strings.Contains(err.Error(), "not exclusively controlled by root") {
		t.Fatalf("refusal does not carry the seam's own text: %v", err)
	}
	if !reflect.DeepEqual(rec.ancestorsAreSafeCalls, []string{"/company-secrets/gw"}) {
		t.Fatalf("ancestorsAreSafe must be handed the data directory: %v", rec.ancestorsAreSafeCalls)
	}
}

// TestIAMT259_CheckCustomDataDirAncestorsAreSafeSucceedsByDefault proves
// the fake seam's documented default: no real filesystem tree exists
// under a fake OS seam, so "assume every ancestor is safe" is the only
// meaningful default — the same convention parentTraversable's fake
// already follows, and the one every CLI-level darwin test installing
// into a --data-dir under t.TempDir() depends on not to break.
func TestIAMT259_CheckCustomDataDirAncestorsAreSafeSucceedsByDefault(t *testing.T) {
	rec := &launchdRecorder{}
	if err := checkCustomDataDirAncestorsAreSafe(rec.setup(), "/anything"); err != nil {
		t.Fatalf("checkCustomDataDirAncestorsAreSafe must succeed by default under a fake OS seam: %v", err)
	}
}

// TestIAMT259_PreflightGatewayReachabilityRefusesWhenProbeCannotRun is
// the round-8 canary for the review's third requirement: when the check
// itself could not run (the real darwin probe could not start, or "id
// -G" failed — errProbeCouldNotRun), the refusal text must say so
// distinctly and must NOT suggest the chmod remedy that fixes a genuine
// denial, since that remedy would not fix an unrunnable check. This is
// tested platform-neutrally through the fake seam: any OS can construct
// an errProbeCouldNotRun-wrapped error without touching a real probe.
//
// Canary: collapse the handling of errProbeCouldNotRun and an ordinary
// refusal into one text — the check for "chmod o+x" (which must not be
// there) or for "did not run" (which must be) turns red.
func TestIAMT259_PreflightGatewayReachabilityRefusesWhenProbeCannotRun(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, traversableErr: fmt.Errorf("%w: exec: \"test\": executable file not found in $PATH", errProbeCouldNotRun)}
	_, err := preflightGatewayReachability(rec.setup(), "/company-secrets/gw")
	if err == nil {
		t.Fatal("preflightGatewayReachability must refuse when the reachability check itself could not run — silently proceeding would reopen F-308-3")
	}
	if strings.Contains(err.Error(), "chmod o+x") {
		t.Fatalf("a chmod remedy is misleading when the check never ran at all: %v", err)
	}
	if !strings.Contains(err.Error(), "did not run") {
		t.Fatalf("refusal does not say the check itself could not run: %v", err)
	}
}

// TestIAMT259_PreflightGatewayReachabilityRequiresRoot — SPEC §3.5.1:
// install runs as root; without root nothing is done and the hint names
// sudo. The root-check lives in preflightGatewayReachability (IAMT-308 round
// 8): dscl needs root to even look up the account, so root must be
// confirmed before anything else runs — setupLaunchdDaemon itself no
// longer checks it at all, trusting the caller already did.
//
// Canary: drop the root check (or let non-root through) — both the
// rec.order comparison and the error-text comparison turn red.
func TestIAMT259_PreflightGatewayReachabilityRequiresRoot(t *testing.T) {
	rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: false}
	_, err := preflightGatewayReachability(rec.setup(), "/d")
	if err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("without root there must be a refusal with the sudo hint, got: %v", err)
	}
	if !reflect.DeepEqual(rec.order, []string{"root"}) {
		t.Fatalf("after the root refusal the seam must not be called: %v", rec.order)
	}
}

// TestIAMT259_PreflightGatewayReachabilityFailuresAreNamed covers the
// two account-resolution failures that moved out of setupLaunchdDaemon
// and into preflightGatewayReachability in round 8 (exhausting free
// system UIDs, and dscl refusing to create the account) — the
// setupLaunchdDaemon-side failures (log dir, chown, write plist,
// bootstrap) stay in TestIAMT259_InstallSequenceFailuresAreNamed below,
// since that is still where those steps run.
//
// Canary: collapse two steps into one or return a generic "install
// failed" without the step's name — the error-text comparison of the
// corresponding subtest turns red.
func TestIAMT259_PreflightGatewayReachabilityFailuresAreNamed(t *testing.T) {
	t.Run("no free UID", func(t *testing.T) {
		full := map[int]bool{}
		for uid := darwinSystemUIDMin; uid <= darwinSystemUIDMax; uid++ {
			full[uid] = true
		}
		rec := &launchdRecorder{uidsTaken: full, rootResult: true}
		_, err := preflightGatewayReachability(rec.setup(), "/d")
		if err == nil || !strings.Contains(err.Error(), "no free system UID") {
			t.Fatalf("UID exhaustion must name itself: %v", err)
		}
		if len(rec.createUserCalls) != 0 {
			t.Fatalf("with no free UID no user may be created: %v", rec.createUserCalls)
		}
	})
	t.Run("create user", func(t *testing.T) {
		rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, createUserErr: errors.New("eDSPermissionError")}
		_, err := preflightGatewayReachability(rec.setup(), "/d")
		if err == nil || !strings.Contains(err.Error(), "create the _iamtunnel service user") {
			t.Fatalf("the error does not name the user-creation step: %v", err)
		}
		if len(rec.traversableCalls) != 0 {
			t.Fatalf("after a user-creation failure reachability must not be checked: %v", rec.traversableCalls)
		}
	})
}

// TestIAMT259_InstallSequenceFailuresAreNamed — every setupLaunchdDaemon
// failure (after preflightGatewayReachability has already handed over a
// ready uid) is named by its step and stops the sequence.
//
// Canary: collapse two steps into one or return a generic "install
// failed" without the step's name — the error-text comparison of the
// corresponding subtest turns red.
func TestIAMT259_InstallSequenceFailuresAreNamed(t *testing.T) {
	t.Run("log dir", func(t *testing.T) {
		rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, logDirErr: errors.New("read-only file system")}
		err := setupLaunchdDaemon(rec.setup(), "/b", []string{"gateway", "run"}, "/d", 200)
		if err == nil || !strings.Contains(err.Error(), "create the log directory") {
			t.Fatalf("the error does not name the log-directory step: %v", err)
		}
		if len(rec.order) != 1 {
			t.Fatalf("after a log-directory failure there is no going on: %v", rec.order)
		}
	})
	t.Run("chown", func(t *testing.T) {
		rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, chownErr: errors.New("operation not permitted")}
		err := setupLaunchdDaemon(rec.setup(), "/b", []string{"gateway", "run"}, "/d", 200)
		if err == nil || !strings.Contains(err.Error(), "hand the data directory") {
			t.Fatalf("the error does not name the directory-handover step: %v", err)
		}
		if len(rec.writePlistCalls) != 0 {
			t.Fatalf("after a chown failure no plist may be written: %v", rec.writePlistCalls)
		}
	})
	t.Run("write plist", func(t *testing.T) {
		rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, writePlistErr: errors.New("disk full")}
		err := setupLaunchdDaemon(rec.setup(), "/b", []string{"gateway", "run"}, "/d", 200)
		if err == nil || !strings.Contains(err.Error(), "write the LaunchDaemon plist") {
			t.Fatalf("the error does not name the plist-write step: %v", err)
		}
		if len(rec.bootstrapCalls) != 0 {
			t.Fatalf("after a plist-write failure no bootstrap may run: %v", rec.bootstrapCalls)
		}
	})
	t.Run("bootstrap fails and the job never comes up", func(t *testing.T) {
		// IAMT-308 round 4: a bootstrap error alone is not enough to
		// refuse any more (a stale "already bootstrapped" EIO 5 is
		// tolerated when the job IS running — see the round-4 tests
		// below) — this case additionally sets runningNotRunning so the
		// fake matches what a GENUINE bootstrap failure looks like: the
		// job never came up either.
		rec := &launchdRecorder{uidsTaken: map[int]bool{}, rootResult: true, bootstrapErr: errors.New("Bootstrap failed: 5"), runningNotRunning: true}
		err := setupLaunchdDaemon(rec.setup(), "/b", []string{"gateway", "run"}, "/d", 200)
		if err == nil || !strings.Contains(err.Error(), "launchctl bootstrap system") {
			t.Fatalf("the error does not name the bootstrap step: %v", err)
		}
	})
}

// TestIAMT308_RepeatInstallToleratesStaleAlreadyBootstrappedError is the
// round-4 canary: on a real Mac, with the daemon already installed and
// running, a repeated `gateway install` hit "launchctl bootstrap ...:
// exit status 5: Bootstrap failed: 5: Input/output error" and refused
// (exit 3), even though the daemon was — and, after the refusal, was
// NOT — still up. Confirmed by hand: bootstrapping a label launchd still
// considers loaded gives exactly this error; it means "already
// bootstrapped", not a real I/O failure. setupLaunchdDaemon must not
// return this error at all when the running check right after it
// confirms the daemon IS actually up — the goal state is reached
// regardless of what bootstrap itself reported.
//
// Canary: return launchdBootstrapTail to refusing immediately on any
// bootstrap error (without checking serviceRunning) — the
// "setupLaunchdDaemon must succeed" below turns red.
func TestIAMT308_RepeatInstallToleratesStaleAlreadyBootstrappedError(t *testing.T) {
	rec := &launchdRecorder{
		uidsTaken:    map[int]bool{},
		rootResult:   true,
		loadedRes:    true,
		bootstrapErr: errors.New("exit status 5: Bootstrap failed: 5: Input/output error"),
		// runningNotRunning defaults to false: the daemon IS running,
		// same as it was before this repeated install — bootout tore
		// down the OLD instance and the goal state (a running daemon)
		// is reached even though bootstrap itself answered stale EIO 5.
	}
	err := setupLaunchdDaemon(rec.setup(), "/usr/local/bin/iamtunnel",
		gatewayServiceArguments("/d", 2022, "127.0.0.1"), "/d", 215)
	if err != nil {
		t.Fatalf("setupLaunchdDaemon must succeed when the daemon is running despite a stale \"already bootstrapped\" bootstrap error: %v", err)
	}
	if !reflect.DeepEqual(rec.bootoutCalls, []string{darwinPlistLabel}) {
		t.Fatalf("the previously loaded job must still be torn down before bootstrap: bootout calls = %v", rec.bootoutCalls)
	}
	if len(rec.bootstrapCalls) != 1 {
		t.Fatalf("bootstrap must still be attempted exactly once: got %d calls", len(rec.bootstrapCalls))
	}
	if len(rec.runningCalls) != 1 {
		t.Fatalf("the running check must still run exactly once, regardless of the stale bootstrap error: got %d calls", len(rec.runningCalls))
	}
}

// TestIAMT259_UninstallSequence — uninstall on macOS: root → no plist —
// "nothing to do" (idempotency) → unload the loaded daemon → remove the
// plist. The user and the data directory stay.
//
// Canary: make a missing plist an error — the "absent" subtest turns
// red; remove the plist before stopping the daemon — the order
// comparison turns red (bootout before removePlist).
func TestIAMT259_UninstallSequence(t *testing.T) {
	t.Run("absent is nothing to do", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true}
		removed, err := teardownLaunchdDaemon(rec.setup())
		if err != nil || removed {
			t.Fatalf("no plist: removed=%v err=%v, wanted (false, nil)", removed, err)
		}
		if !reflect.DeepEqual(rec.order, []string{"root", "plistExists"}) {
			t.Fatalf("nothing but the root check and the plist lookup may be called: %v", rec.order)
		}
	})
	t.Run("loaded daemon is booted out then plist removed", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: true}
		removed, err := teardownLaunchdDaemon(rec.setup())
		if err != nil || !removed {
			t.Fatalf("removed=%v err=%v, wanted (true, nil)", removed, err)
		}
		wantOrder := []string{"root", "plistExists", "loaded", "bootout", "removePlist"}
		if !reflect.DeepEqual(rec.order, wantOrder) {
			t.Fatalf("uninstall sequence = %v, wanted %v", rec.order, wantOrder)
		}
		if !reflect.DeepEqual(rec.bootoutCalls, []string{darwinPlistLabel}) {
			t.Errorf("bootout must be called with the com.iamtunnel.gateway label: %v", rec.bootoutCalls)
		}
		if !reflect.DeepEqual(rec.removePlistCalls, []string{darwinPlistPath}) {
			t.Errorf("the plist is removed from a path other than /Library/LaunchDaemons: %v", rec.removePlistCalls)
		}
	})
	t.Run("stopped daemon skips bootout", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: false}
		if removed, err := teardownLaunchdDaemon(rec.setup()); err != nil || !removed {
			t.Fatalf("removed=%v err=%v, wanted (true, nil)", removed, err)
		}
		if len(rec.bootoutCalls) != 0 {
			t.Fatalf("a stopped daemon needs no unloading: %v", rec.bootoutCalls)
		}
		if !reflect.DeepEqual(rec.order, []string{"root", "plistExists", "loaded", "removePlist"}) {
			t.Fatalf("sequence = %v", rec.order)
		}
	})
	t.Run("bootout failure stops before removePlist", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: true, bootoutErr: errors.New("Operation not permitted")}
		_, err := teardownLaunchdDaemon(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "launchctl bootout system/com.iamtunnel.gateway") {
			t.Fatalf("the error does not name the bootout step: %v", err)
		}
		if len(rec.removePlistCalls) != 0 {
			t.Fatalf("after a bootout failure the plist must not be removed: %v", rec.removePlistCalls)
		}
	})
	t.Run("removePlist failure is named", func(t *testing.T) {
		rec := &launchdRecorder{rootResult: true, plistExistsRes: true, loadedRes: true, removePlistErr: errors.New("permission denied")}
		_, err := teardownLaunchdDaemon(rec.setup())
		if err == nil || !strings.Contains(err.Error(), "remove the plist") {
			t.Fatalf("the error does not name the plist-removal step: %v", err)
		}
		if len(rec.bootoutCalls) != 1 {
			t.Fatalf("the daemon must be stopped before the removal fails: %v", rec.bootoutCalls)
		}
	})
}

// TestIAMT259_InstallCLIReportsOnDarwin — the CLI level of the darwin
// install branch: IAMT-259 made the macOS half real (the LaunchDaemon of
// SPEC §3.5.1), so `gateway install` here must reach exitOK, write the
// plist through the seam, load the job and tell the operator what was
// installed. On other host OSes the CLI's darwin branch is not selected
// — the sequence is covered by the platform-neutral
// TestIAMT259_InstallSequenceFreshUser above.
//
// IAMT-286: exactly this reality five checks in iamt131/iamt180 still
// denied, expecting an "OS not supported" refusal on darwin. Here it is
// pinned at the CLI level — from the --public-host flag to bootstrap.
//
// Canary: make the darwin CLI branch refuse, forget bootstrap, or stop
// creating the local half — the exit code, bootstrapCalls and the
// state.json check turn red respectively (on a darwin host).
func TestIAMT259_InstallCLIReportsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-259: the CLI darwin branch is selected by runtime.GOOS and checked only on a darwin host; here %s — the launchd sequence is covered platform-neutrally (TestIAMT259_InstallSequenceFreshUser)", runtime.GOOS)
	}
	sd := withFakeSystemd(t)
	rec := withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("gateway install on macOS: code=%d out=%q errs=%q — the darwin half is implemented (IAMT-259), there is nothing to refuse here", code, out, errs)
	}

	// The plist landed where SPEC §3.5.1 puts it: 0644, root:wheel, and
	// the job is loaded from the same path.
	if len(rec.writePlistCalls) != 1 || !strings.HasPrefix(rec.writePlistCalls[0], darwinPlistPath+":0644:0:0") {
		t.Fatalf("install must write the plist %s (0644 root:wheel) through the seam: %v", darwinPlistPath, rec.writePlistCalls)
	}
	if !reflect.DeepEqual(rec.bootstrapCalls, []string{darwinPlistPath}) {
		t.Fatalf("install must load the job from %s: %v", darwinPlistPath, rec.bootstrapCalls)
	}

	// The local half runs BEFORE the service half on all platforms
	// (SPEC §3.5.1): state.json on disk, otherwise the admin claim has
	// nothing to work with.
	if _, err := os.Stat(filepath.Join(dir, state.StateFileName)); err != nil {
		t.Fatalf("install did not create %s: %v — the local half must run before the service half", filepath.Join(dir, state.StateFileName), err)
	}

	// The operator is told what was installed.
	if !strings.Contains(out, darwinPlistPath) || !strings.Contains(out, "LaunchDaemon") {
		t.Fatalf("install's output must name the LaunchDaemon and its path: %q", out)
	}

	// The foreign service half is untouched.
	if sd.unitContent != "" || len(sd.systemctlCalls) != 0 {
		t.Fatalf("the macOS path must not touch the systemd seam: unitWritten=%v systemctl=%v", sd.unitContent != "", sd.systemctlCalls)
	}
}

// TestIAMT259_UninstallCLIReportsOnDarwin — the CLI level of the darwin
// uninstall branch: no plist → exitOK and "nothing to do"; present →
// exitOK, "stopped and removed" and the line about the untouched data
// directory. On other host OSes the CLI's darwin branch is not selected
// — there the sequence is already covered by the platform-neutral tests
// above.
//
// Canary: make the darwin CLI branch refuse or lose the untouched-
// directory line — the exit-code and text comparisons turn red (on a
// darwin host).
func TestIAMT259_UninstallCLIReportsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-259: the CLI darwin branch is selected by runtime.GOOS and checked only on a darwin host; here %s — the launchd sequence is covered platform-neutrally (TestIAMT259_UninstallSequence)", runtime.GOOS)
	}
	rec := withFakeLaunchd(t)
	out, errs, code := drive(t, "gateway", "uninstall", "--data-dir", t.TempDir())
	if code != exitOK || !strings.Contains(out, "not installed; nothing to do") {
		t.Fatalf("uninstall without a plist: code=%d out=%q errs=%q, wanted exitOK and \"nothing to do\"", code, out, errs)
	}
	if !reflect.DeepEqual(rec.order, []string{"root", "plistExists"}) {
		t.Fatalf("nothing but the root check and the plist lookup may be called: %v", rec.order)
	}

	dir := t.TempDir()
	rec2 := &launchdRecorder{rootResult: true, plistExistsRes: true}
	prev := darwinLaunchd
	darwinLaunchd = rec2.setup()
	t.Cleanup(func() { darwinLaunchd = prev })
	out, errs, code = drive(t, "gateway", "uninstall", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "stopped and removed") {
		t.Fatalf("uninstall with a plist: code=%d out=%q errs=%q, wanted exitOK and \"stopped and removed\"", code, out, errs)
	}
	if !strings.Contains(out, dir+" was not touched") {
		t.Fatalf("the output must name the untouched data directory %s: out=%q", dir, out)
	}
	if !reflect.DeepEqual(rec2.order, []string{"root", "plistExists", "loaded", "removePlist"}) {
		t.Fatalf("uninstall sequence = %v", rec2.order)
	}
}

// TestIAMT259_FirewallHintIsApplicationFirewall — the macOS port hint
// about the Application Firewall (SPEC §3.5.1); pf is neither mentioned
// nor configured, and install itself never touches a firewall on any OS.
//
// Canary: change one character in darwinFirewallHint or swap
// socketfilterfw for pfctl — the comparison with the reference string
// turns red.
func TestIAMT259_FirewallHintIsApplicationFirewall(t *testing.T) {
	const want = `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "/usr/local/bin/iamtunnel" --unblockapp "/usr/local/bin/iamtunnel"`
	if got := darwinFirewallHint("/usr/local/bin/iamtunnel"); got != want {
		t.Errorf("darwinFirewallHint =\n  %s\nwanted (Application Firewall, SPEC §3.5.1):\n  %s", got, want)
	}
	if strings.Contains(strings.ToLower(darwinFirewallHint("/b")), "pfctl") {
		t.Error("pf is not touched — the hint must be about the Application Firewall")
	}
}
