package main

// iamt206_gateway_record_rename_test.go — IAMT-206.
//
// The bug: enrol wrote the gateway address into
// %ProgramData%\iamtunnel\gateway.json on Windows, and the strict settings
// parser read the same path as gateway.json → every "server start" /
// "server status" after a successful enrol rejected the JSON with
// `unknown field "host"`. The fix renames the enrol file to
// enrolment.json and adds a one-shot migration in loadConfig that moves
// a leftover legacy file at the default config path into enrolment.json
// before any settings read. An explicit --config / IAMTUNNEL_CONFIG that
// points at the same shape must still error out — the operator chose
// that path on purpose, and silently renaming it would erase the
// settings file they meant to write.
//
// These tests pin both halves of that contract end-to-end: a real
// loadConfig + a real filesystem, with the Windows-on-disk path
// simulated by writing into a t.TempDir()-rooted environment (no real
// %ProgramData% touched).
//
// Platform split (IAMT-270). The migration itself is platform-agnostic
// and every direct migrateLegacyGatewayRecord test below runs on every
// platform the suite builds for. The end-to-end half cannot: it must
// write the DEFAULT config path before driving the CLI, and that path is
// substitutable only on Windows, where config.DirsFor builds it from
// %ProgramData% (the env map this file supplies) — so
// <root>\iamtunnel\gateway.json lands inside the test's own t.TempDir().
// On Linux and Darwin config.DirsFor builds the same path from fixed
// system locations (/etc/iamtunnel/gateway.json and
// "/Library/Application Support/iamtunnel/gateway.json") and no
// environment variable, flag or seam roots them in a temporary
// directory: --config/IAMTUNNEL_CONFIG names the file explicitly, which
// by IAMT-206's own contract SKIPS the migration and therefore cannot
// stand in for the default path. Writing there would be the gate-11
// violation this file was itself fixed for (a leftover settings-shaped
// file at the real /etc/iamtunnel/gateway.json broke every later test in
// the package that read the default config path). Those three tests
// therefore wait for a Windows host through
// requireWindowsDefaultConfigPath; see its doc comment for the full
// reason.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// legacyRecordFixture is the gatewayRecord shape every IAMT-206
// fixture uses. It lives here, not in writeLegacyGatewayRecord, so the
// migration-direct tests can reuse the same fingerprint without each
// hand-rolling it.
var legacyRecordFixture = gatewayRecord{
	Host:        "127.0.0.1",
	Port:        1,
	Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	MachineID:   "desktop-i3fl2s5",
}

// writeJSON writes v to path atomically (atomicWriteJSON already
// exists); tiny wrapper to keep the test reads short.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := atomicWriteJSON(path, v); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeLegacyAt writes the legacy "enrol wrote its result here" record
// at the exact path the test wants. The fingerprint uses a
// syntactically valid SHA-256:43base64 form so any future stricter
// parse of the legacy shape does not silently grow new reasons to
// refuse this fixture.
func writeLegacyAt(t *testing.T, path string) gatewayRecord {
	t.Helper()
	writeJSON(t, path, legacyRecordFixture)
	return legacyRecordFixture
}

// seedProgramDataEnv wires ProgramData + LOCALAPPDATA + HOME +
// XDG_DATA_HOME at root so config.DirsFor on Windows resolves
// ConfigFile to <root>\iamtunnel\gateway.json (the path the live VM
// hits) while on Linux/Darwin the same root only feeds the CLIENT layout
// — the machine paths and ConfigFile stay on the fixed system locations
// described in the file header. The helper returns the resolved paths
// the test then uses to seed the legacy file under the right name and to
// assert the migration moved the bytes verbatim.
//
// Its callers MUST have passed requireWindowsDefaultConfigPath first:
// on any other host the returned configPath is a real system file that a
// test may neither write (gate 11) nor migrate.
type seedEnv struct {
	env           map[string]string
	configPath    string // ConfigFile (where the legacy file lived pre-fix)
	enrolmentPath string // <Server>/enrolment.json (where it must live post-fix)
	serverDir     string // Dirs.Server — same dir as enrolmentPath's parent
}

func seedProgramDataEnv(t *testing.T) seedEnv {
	t.Helper()
	root := t.TempDir()
	env := testsupport.PlatformDataEnvAt(t, root)
	dirs, err := config.DirsFor(runtime.GOOS, env)
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	return seedEnv{
		env:           env,
		configPath:    dirs.ConfigFile,
		enrolmentPath: filepath.Join(dirs.Server, gatewayRecordName),
		serverDir:     dirs.Server,
	}
}

// requireWindowsDefaultConfigPath keeps a test that must write the
// DEFAULT config file off every host where that file is not a temporary
// path. what names the assertion being skipped, so the skip text says
// which contract waits for a Windows host and not merely "not Windows".
//
// Why the host and not the target OS: loadConfig resolves the default
// path with runtime.GOOS (cmd/iamtunnel/main.go), so the platform it
// resolves is always the platform it runs on — there is no goos
// parameter to inject here, unlike serverStartConfig/serverKeyFile
// (IAMT-156), whose callers pass one. On Windows config.DirsFor takes
// the path from %ProgramData%, which testsupport.PlatformDataEnvAt
// points at a t.TempDir(); on Linux and Darwin it hardcodes
// /etc/iamtunnel/gateway.json and
// "/Library/Application Support/iamtunnel/gateway.json" from
// internal/config/paths.go with no environment variable, flag or seam to
// root them elsewhere. IAMTUNNEL_CONFIG/--config are not a substitute:
// naming the config path explicitly makes loadConfig skip the migration
// altogether (the IAMT-206 contract that TestIAMT206_ExplicitConfigPath_*
// pins), so the migration can only be driven end-to-end through the real
// default path. Writing that path on a Linux/Darwin host is the gate-11
// violation that broke this package: the settings-shaped fixture one of
// these tests leaves behind at the real /etc/iamtunnel/gateway.json made
// every later test that read the default config fail with
// `unknown field "host"`.
func requireWindowsDefaultConfigPath(t *testing.T, what string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	t.Skipf("this test %s, but it can only be driven through the DEFAULT config path, and on %s that path is a fixed system file (internal/config/paths.go) with no environment variable, flag or seam that roots it in a t.TempDir(); --config/IAMTUNNEL_CONFIG is not an option because an explicit path makes loadConfig skip the migration this test exists to prove. The migration logic stays covered on this host by the direct migrateLegacyGatewayRecord tests in this file.", what, runtime.GOOS)
}

// TestIAMT206_LegacyGatewayRecord_MigratesToEnrolmentJson is the
// canary's primary half. A leftover legacy file at the default config
// path must be moved to enrolment.json on the first loadConfig call,
// and the next loadConfig must succeed against the new path so
// "server status" no longer crashes with "unknown field host".
//
// Canary: remove the migrateLegacyGatewayRecord call from loadConfig
// (cmd/iamtunnel/main.go). The first loadConfig now reads the legacy
// file as settings and exits with exitEnv + "unknown field host" —
// this test goes red on the first loadConfig's exit-code assertion.
func TestIAMT206_LegacyGatewayRecord_MigratesToEnrolmentJson(t *testing.T) {
	requireWindowsDefaultConfigPath(t, "drives the migration end-to-end: a leftover legacy gateway.json at the DEFAULT config path must be renamed to enrolment.json by the first loadConfig, and the loadConfig after it must succeed against the new path")

	s := seedProgramDataEnv(t)
	rec := writeLegacyAt(t, s.configPath)

	// First loadConfig: this is the one that migrates. After
	// migration the config path is empty so the settings parser takes
	// the ErrNotExist→defaults branch and the command returns exitOK
	// ("the server is not running").
	out, errs, code := driveEnv(t, s.env, "server", "status")
	if code != exitOK {
		t.Fatalf("first loadConfig (migrates): code=%d (out=%q errs=%q), want %d — without the migration the strict parser would refuse the legacy record with \"unknown field host\" (exitEnv)",
			code, out, errs, exitOK)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("first loadConfig stdout=%q, want the \"not running\" line", out)
	}

	// File-system state after migration:
	if _, err := os.Stat(s.configPath); !os.IsNotExist(err) {
		t.Fatalf("IAMT-206 canary: legacy %s should be gone after migration; stat err=%v", s.configPath, err)
	}
	if _, err := os.Stat(s.enrolmentPath); err != nil {
		t.Fatalf("IAMT-206 canary: %s must exist after migration; stat err=%v", s.enrolmentPath, err)
	}
	got, err := loadGatewayRecord(s.serverDir)
	if err != nil {
		t.Fatalf("loadGatewayRecord after migration: %v", err)
	}
	if got != rec {
		t.Fatalf("enrolment.json content = %+v, want %+v (verbatim from legacy gateway.json)", got, rec)
	}

	// Second loadConfig: same outcome (no settings file, defaults
	// stand). This is the line that used to crash with "unknown
	// field host" before the fix.
	out, errs, code = driveEnv(t, s.env, "server", "status")
	if code != exitOK {
		t.Fatalf("second loadConfig: code=%d out=%q errs=%q, want %d", code, out, errs, exitOK)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("second loadConfig stdout=%q, want the \"not running\" line", out)
	}
}

// TestIAMT206_ExplicitConfigPath_StillRejectsLegacyShape is the
// canary's other half: an operator who explicitly names
// --config=<file-shaped-like-an-enrolment-record> must keep getting
// the strict parser's "unknown field host" error. The migration must
// not silently rename a file the operator asked for by name.
//
// Canary: change loadConfig's migration gate from
// `o.configPath == "" && envOv.ConfigPath == ""` to always-true. The
// legacy file the test set up under --config is renamed to
// enrolment.json or .enrolment-migrated, the strict parser never sees
// it, and exit code is exitOK — this test goes red on the first
// assertion.
func TestIAMT206_ExplicitConfigPath_StillRejectsLegacyShape(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skipf("IAMT-206 fix is verified through loadConfig; skip on %s", runtime.GOOS)
	}

	// Put the "operator's settings file" outside any role-data root:
	// --config is an absolute path, and loadConfig must read it
	// verbatim. The file content is a real, valid enrolment record
	// (host+port+fingerprint+machineId), so under the migration this
	// would normally trigger a rename — except --config is explicit,
	// so it must NOT.
	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "operator-named-config.json")
	writeLegacyAt(t, confPath)

	// Drive with --config=<the legacy-shaped file>; loadConfig must
	// NOT migrate it. The settings parser then trips on "unknown
	// field host", which is exitEnv per the documented class for an
	// unparsable settings file.
	out, errs, code := driveEnv(t, testsupport.PlatformDataEnv(t),
		"server", "status", "--config", confPath)

	if code != exitEnv {
		t.Fatalf("server status with --config=<legacy-shaped>: code=%d (out=%q errs=%q), want %d",
			code, out, errs, exitEnv)
	}
	if !strings.Contains(errs, `unknown field "host"`) {
		t.Fatalf("explicit legacy-shaped --config must surface the strict parser's unknown-field error; errs=%q", errs)
	}

	// File at the explicit path must be byte-for-byte what the test
	// set up: migration must NOT have moved it.
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read explicit config after run: %v", err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("explicit config after run is no longer JSON: %v\n%s", err, data)
	}
	if _, ok := probe["machineId"]; !ok {
		t.Fatalf("explicit --config file lost its content (machineId missing); got %s", data)
	}
}

// TestIAMT206_ExplicitConfigPath_NewEnrolmentNameStillRefused is the
// same canary as above but with the freshly-named enrolment file the
// new binary would write. Even an operator who points --config at the
// new enrolment.json must get the strict parser's error, because the
// explicit-path branch is exactly the one we promised to keep strict.
//
// Canary: same as above — relaxing the migration gate to also fire
// when an explicit path is named would rename the operator's file and
// silently drop their settings, and THIS test goes red on the
// errs assertion below.
func TestIAMT206_ExplicitConfigPath_NewEnrolmentNameStillRefused(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skipf("IAMT-206 fix is verified through loadConfig; skip on %s", runtime.GOOS)
	}

	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "config.json")
	rec := gatewayRecord{Host: "127.0.0.1", Port: 1, Fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", MachineID: "x"}
	writeJSON(t, confPath, rec)

	out, errs, code := driveEnv(t, testsupport.PlatformDataEnv(t),
		"server", "status", "--config", confPath)
	if code != exitEnv {
		t.Fatalf("server status with --config=<enrolment-shaped>: code=%d (out=%q errs=%q), want %d",
			code, out, errs, exitEnv)
	}
	if !strings.Contains(errs, `unknown field "host"`) {
		t.Fatalf("explicit enrolment-shaped --config must surface the strict parser's unknown-field error; errs=%q", errs)
	}
}

// TestIAMT206_LegacyAndNewBothExist_RenamesToBackup is the third
// canary. When the default path holds a legacy gateway.json AND the
// new enrolment.json already exists (a fresh enrol on a newer binary
// followed by a stale enrol on an older one, or vice versa), migration
// must NOT overwrite enrolment.json — that record came from the
// binary the user is running NOW and is the source of truth. The
// legacy file is renamed to gateway.json.enrolment-migrated so the
// operator can compare and delete by hand.
//
// Canary: change migrateLegacyGatewayRecord's "both exist" branch
// from os.Rename(legacy, legacy+".enrolment-migrated") to a direct
// rename to enrolmentPath. The existing enrolment.json is
// overwritten, the loadGatewayRecord check finds the LEGACY machine
// id under the new name, and this test goes red on the got != newRec
// assertion.
func TestIAMT206_LegacyAndNewBothExist_RenamesToBackup(t *testing.T) {
	requireWindowsDefaultConfigPath(t, "drives the both-files-present branch end-to-end: a legacy gateway.json at the DEFAULT config path must move aside to .enrolment-migrated instead of overwriting the fresh enrolment.json")

	s := seedProgramDataEnv(t)

	// The "legacy" file from an older enrol.
	writeLegacyAt(t, s.configPath)

	// A NEW enrolment.json written by a fresh enrol on the upgraded
	// binary — different machine id so we can tell them apart.
	newRec := gatewayRecord{Host: "10.0.0.1", Port: 2022, Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", MachineID: "fresh-machine"}
	writeJSON(t, s.enrolmentPath, newRec)

	out, errs, code := driveEnv(t, s.env, "server", "status")
	if code != exitOK {
		t.Fatalf("server status with legacy+new: code=%d out=%q errs=%q, want %d", code, out, errs, exitOK)
	}

	backup := s.configPath + ".enrolment-migrated"

	if _, err := os.Stat(s.configPath); !os.IsNotExist(err) {
		t.Fatalf("legacy %s should be gone; stat err=%v", s.configPath, err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("legacy should have been renamed to %s; stat err=%v", backup, err)
	}
	got, err := loadGatewayRecord(s.serverDir)
	if err != nil {
		t.Fatalf("loadGatewayRecord (after backup rename): %v", err)
	}
	if got != newRec {
		t.Fatalf("enrolment.json content = %+v, want %+v (the fresh record, NOT the legacy one)", got, newRec)
	}
	// Also assert the backup parses back to the legacy machine id:
	// the operator's job is to read both and pick one; this test
	// makes sure both still parse.
	backupData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var backupRec gatewayRecord
	if err := json.Unmarshal(backupData, &backupRec); err != nil {
		t.Fatalf("backup %s does not parse as gatewayRecord: %v", backup, err)
	}
	if backupRec.MachineID != legacyRecordFixture.MachineID {
		t.Fatalf("backup.MachineID = %q, want %q (the legacy id)", backupRec.MachineID, legacyRecordFixture.MachineID)
	}
}

// TestIAMT206_SettingsShapedFileAtConfigPath_NotMigrated is the
// canary's fourth half. A file with even ONE settings key must be
// left alone by migration: the strict parser is the only authority on
// real settings, and the operator may be in the middle of writing it.
//
// Canary: in looksLikeLegacyGatewayRecord, drop the loop that
// disqualifies a file with any settings key. A test config like
// {"host":"x","port":2022} would now match the legacy shape (host is
// in both lists), the file would be renamed out of the way, and
// THIS test goes red because the strict parser no longer fires.
func TestIAMT206_SettingsShapedFileAtConfigPath_NotMigrated(t *testing.T) {
	requireWindowsDefaultConfigPath(t, "pins that a settings-shaped file at the DEFAULT config path is left where it is by the migration and still refused by the strict settings parser")

	s := seedProgramDataEnv(t)

	// File with one legacy key (host) AND one settings key (port) —
	// disqualifying. Settings parser will surface it on next read.
	if err := os.MkdirAll(filepath.Dir(s.configPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(s.configPath, []byte(`{"host":"x","port":2222}`), 0o600); err != nil {
		t.Fatalf("write settings-shaped legacy file: %v", err)
	}

	// loadConfig runs migration, sees a settings-shaped file, leaves
	// it untouched. The settings parser then complains about the
	// remaining legacy key (host) — that is exitEnv, and the message
	// is the same one operators saw before the fix.
	out, errs, code := driveEnv(t, s.env, "server", "status")
	if code != exitEnv {
		t.Fatalf("settings-shaped file at config path: code=%d out=%q errs=%q, want %d", code, out, errs, exitEnv)
	}
	if !strings.Contains(errs, `unknown field "host"`) {
		t.Fatalf("settings-shaped file must still surface the strict parser's unknown-field error; errs=%q", errs)
	}
}

// TestIAMT206_NoStateFilenameCollidesWithConfig locks the invariant
// that no role state file name (the gateway record, machine.key,
// machine.id, state.json, …) coincides with ConfigFile.
//
// The check enumerates the per-role filenames the product code reads
// or writes today and asserts none of their base names equals
// ConfigFile's base name on either Windows or Linux. The lookup set
// includes gateway.json (ConfigFile), enrolment.json (NEW gateway
// record name), machine.key, machine.id, events.jsonl, state.json,
// hostkey, recordings/ — and the IAMT-206 backup path
// (gateway.json.enrolment-migrated), which is the file the migration
// produces when both the legacy and the new record exist. The backup
// name shares the base with ConfigFile by construction; that is fine
// (it is a one-shot side artefact, never the file a role reads), and
// the test asserts exactly that property so a future bug that puts a
// real state file under the same name lights up red.
//
// Canary: rename gatewayRecordName back to "gateway.json". This test
// goes red on the "enrolment.json must not collide with gateway.json"
// assertion — which is exactly the collision that triggered IAMT-206.
func TestIAMT206_NoStateFilenameCollidesWithConfig(t *testing.T) {
	cases := []struct {
		goos string
		env  map[string]string
	}{
		{"windows", map[string]string{
			"LOCALAPPDATA": `C:\Users\u\AppData\Local`,
			"ProgramData":  `C:\ProgramData`,
		}},
		{"linux", map[string]string{"HOME": "/home/u"}},
	}
	// Names a role actually opens or writes. The backup name is the
	// one exception the test tolerates (see doc comment above).
	realStateNames := []string{
		// client role (internal/config/paths.go)
		"key", "known_hosts", "machines.mine",
		// server role
		"machine.key", "machine.id", "events.jsonl",
		// gateway role
		"state.json", "events.jsonl", "hostkey", "recordings",
		// enrolment record (the IAMT-206 fix).
		gatewayRecordName,
	}

	for _, c := range cases {
		t.Run(c.goos, func(t *testing.T) {
			d, err := config.DirsFor(c.goos, c.env)
			if err != nil {
				t.Fatalf("DirsFor(%s): %v", c.goos, err)
			}
			configBase := filepath.Base(d.ConfigFile)
			for _, name := range realStateNames {
				if name == configBase {
					t.Errorf("IAMT-206 invariant: state file %q collides with ConfigFile base %q on %s — rename one and this test goes green",
						name, configBase, c.goos)
				}
			}
			// Backup name is allowed to share ConfigFile's base, but
			// it must carry the .enrolment-migrated suffix and live
			// in the same dir as ConfigFile — the migration puts it
			// there. Assert both so a future move-of-purpose fails
			// the test.
			if !strings.HasSuffix(legacyGatewayRecordName+".enrolment-migrated", ".enrolment-migrated") {
				t.Errorf("backup name suffix drift — migration writes %q.enrolment-migrated; this test pinned it", legacyGatewayRecordName)
			}
			if c.goos == "windows" {
				// Enrolment record dir (d.Server) and the parent of
				// the default config file (filepath.Dir(d.ConfigFile))
				// must coincide on Windows so the migration can
				// find a leftover legacy gateway.json at the
				// default path. Today both are
				// <ProgramData>\iamtunnel; this test catches a
				// future drift that re-routes one without the
				// other.
				//
				// The comparison needs a Windows host: filepath.Dir
				// splits on the HOST separator, so on Linux it finds
				// none in `C:\ProgramData\iamtunnel\gateway.json` and
				// answers "." — not the directory the assertion is
				// about. The Windows branch above (DirsFor("windows",
				// …)) itself is host-independent and already ran; only
				// this backslash-sensitive half waits for Windows.
				if runtime.GOOS != "windows" {
					t.Skipf("the windows layout assertions below compare paths that only a Windows host can split: filepath.Dir(%q) = %q here, while windows answers %q. The same DirsFor(windows, …) branches above ran on this %s host — only the separator-dependent comparison is deferred, not dropped.",
						d.ConfigFile, filepath.Dir(d.ConfigFile), `C:\ProgramData\iamtunnel`, runtime.GOOS)
				}
				// 1.4 dissolved the collision this file exists for,
				// rather than working around it: the server directory
				// moved under %LOCALAPPDATA% so that two people on one
				// machine hold two registrations, and the default
				// config file stayed under %ProgramData% with the
				// gateway. They are no longer the same directory, so
				// the enrolment record and a settings file can no
				// longer contend for one name at all.
				//
				// The rename to enrolment.json stays regardless: it is
				// what an existing machine's file is already called,
				// and the migration below still moves a legacy one.
				if d.Server == filepath.Dir(d.ConfigFile) {
					t.Errorf("the enrolment record dir and the default config dir are the same again (%s) — that shared directory is what let a legacy gateway.json be read as a settings file (IAMT-206)",
						d.Server)
				}
			}
		})
	}
}

// TestIAMT206_MigrationProducesParseableEnrolmentJson drives the
// migration directly through migrateLegacyGatewayRecord (no CLI
// shell) and asserts the resulting enrolment.json parses back into
// the same gatewayRecord and that no other side effects occurred.
// This is the per-step canary the migration must satisfy even if the
// surrounding loadConfig flow changes.
//
// Canary: in migrateLegacyGatewayRecord, change the "both exist"
// branch to rename into enrolmentPath instead of the backup path.
// This test fails on the second assertion because the test sets up an
// enrolment.json first and the rename-back would lose the seed.
func TestIAMT206_MigrationProducesParseableEnrolmentJson(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, legacyGatewayRecordName)
	enrolmentPath := filepath.Join(dir, gatewayRecordName)
	writeLegacyAt(t, legacyPath)
	newRec := gatewayRecord{Host: "h", Port: 2, Fingerprint: "f", MachineID: "fresh-machine"}
	writeJSON(t, enrolmentPath, newRec)

	if err := migrateLegacyGatewayRecord(legacyPath, enrolmentPath); err != nil {
		t.Fatalf("migrateLegacyGatewayRecord: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy %s should be gone after migrate; stat err=%v", legacyPath, err)
	}
	if _, err := os.Stat(legacyPath + ".enrolment-migrated"); err != nil {
		t.Fatalf("legacy should have been backed up to %s; stat err=%v", legacyPath+".enrolment-migrated", err)
	}
	got, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("loadGatewayRecord after migration with both-exist: %v", err)
	}
	if got != newRec {
		t.Fatalf("enrolment.json content after migration = %+v, want %+v (the fresh record, NOT the legacy one)", got, newRec)
	}
}

// TestIAMT206_MigrationHappyPath_NoExistingEnrolment is the
// complementary direct-migration test: no enrolment.json yet, the
// legacy file should move straight to enrolment.json with no backup.
//
// Canary: in migrateLegacyGatewayRecord, flip the "both exist"
// branch to be the always-taken path (rename to backup regardless).
// This test goes red on the backup-stat assertion because no backup
// should have been created.
func TestIAMT206_MigrationHappyPath_NoExistingEnrolment(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, legacyGatewayRecordName)
	enrolmentPath := filepath.Join(dir, gatewayRecordName)
	writeLegacyAt(t, legacyPath)

	if err := migrateLegacyGatewayRecord(legacyPath, enrolmentPath); err != nil {
		t.Fatalf("migrateLegacyGatewayRecord: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy %s should be gone after migrate; stat err=%v", legacyPath, err)
	}
	if _, err := os.Stat(legacyPath + ".enrolment-migrated"); !os.IsNotExist(err) {
		t.Fatalf("no backup file should be created when enrolment.json is absent; stat err=%v", err)
	}
	got, err := loadGatewayRecord(dir)
	if err != nil {
		t.Fatalf("loadGatewayRecord after migration: %v", err)
	}
	if got != legacyRecordFixture {
		t.Fatalf("enrolment.json content after migration = %+v, want %+v", got, legacyRecordFixture)
	}
}

// TestIAMT206_MigrationIsNoOpForSettingsFile pins the negative
// half of the migration: a settings file at the legacy path must
// come through unchanged. Combined with
// TestIAMT206_SettingsShapedFileAtConfigPath_NotMigrated above, this
// is the canary that a settings file is NEVER renamed by the
// migration.
//
// Canary: drop the legacyEnrolmentExtraKeys loop from
// looksLikeLegacyGatewayRecord. A file with any settings key (e.g.
// port) would now match the legacy shape and be renamed; this test
// goes red on the stat assertion.
func TestIAMT206_MigrationIsNoOpForSettingsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyGatewayRecordName)
	// A file that parses as JSON, has the legacy key host, and ALSO
	// has the settings key public_host: disqualifying.
	if err := os.WriteFile(path, []byte(`{"host":"x","public_host":"gw.example.test"}`), 0o600); err != nil {
		t.Fatalf("seed settings-shaped: %v", err)
	}
	enrolmentPath := filepath.Join(dir, gatewayRecordName)
	if err := migrateLegacyGatewayRecord(path, enrolmentPath); err != nil {
		t.Fatalf("migrateLegacyGatewayRecord: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("settings-shaped file must NOT be moved by migration; stat err=%v", err)
	}
	if _, err := os.Stat(enrolmentPath); !os.IsNotExist(err) {
		t.Fatalf("enrolment.json must not be created when the source file is not a legacy record; stat err=%v", err)
	}
}

// TestIAMT206_MigrationIsNoOpForGarbage guards against migration
// trying to "rescue" a file the operator corrupted on purpose: a file
// that is not JSON at all is left alone, the strict parser will
// report the parse error verbatim on the next loadConfig call.
//
// Canary: in looksLikeLegacyGatewayRecord, remove the json.Unmarshal
// guard. A file like "this is not json" would now look like an empty
// map (nil), pass the loop (no host/machineId, but also no
// disqualifying keys), and be renamed; this test goes red on the
// stat assertion.
func TestIAMT206_MigrationIsNoOpForGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyGatewayRecordName)
	if err := os.WriteFile(path, []byte("this is not json at all"), 0o600); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	enrolmentPath := filepath.Join(dir, gatewayRecordName)
	if err := migrateLegacyGatewayRecord(path, enrolmentPath); err != nil {
		t.Fatalf("migrateLegacyGatewayRecord: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("garbage file must NOT be moved by migration; stat err=%v", err)
	}
}

// TestIAMT206_LegacyShapeDetection pins the byte-level shape the
// migration recognises. The named key sets are the only ones
// looksLikeLegacyGatewayRecord uses today; the test goes red if any
// future change relaxes or tightens them silently, which is exactly
// the drift the canary exists to catch.
//
// Canary: add a key to legacyGatewayRecordKeys that the test does not
// include. LooksLikeLegacyGatewayRecord now recognises the new key as
// "legacy", and a file containing only that key would now be
// migrated — this test goes red on the missing-key assertion.
func TestIAMT206_LegacyShapeDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyGatewayRecordName)

	// All four required keys — must match.
	if !looksLikeLegacyGatewayRecord(mustJSON(t, map[string]any{"host": "x", "port": 1, "fingerprint": "f", "machineId": "m"})) {
		t.Errorf("looksLikeLegacyGatewayRecord: four-key legacy shape must match")
	}

	// Missing host.
	if looksLikeLegacyGatewayRecord(mustJSON(t, map[string]any{"port": 1, "fingerprint": "f", "machineId": "m"})) {
		t.Errorf("looksLikeLegacyGatewayRecord: missing host must NOT match")
	}
	// Missing machineId.
	if looksLikeLegacyGatewayRecord(mustJSON(t, map[string]any{"host": "x", "port": 1, "fingerprint": "f"})) {
		t.Errorf("looksLikeLegacyGatewayRecord: missing machineId must NOT match")
	}
	// Adds a settings key (port is a settings key, but it's also in
	// legacyGatewayRecordKeys — pick public_host which is settings-only).
	if looksLikeLegacyGatewayRecord(mustJSON(t, map[string]any{"host": "x", "port": 1, "fingerprint": "f", "machineId": "m", "public_host": "gw.example.test"})) {
		t.Errorf("looksLikeLegacyGatewayRecord: presence of public_host (settings key) must disqualify")
	}
	// Adds an unknown key.
	if looksLikeLegacyGatewayRecord(mustJSON(t, map[string]any{"host": "x", "port": 1, "fingerprint": "f", "machineId": "m", "made_up_key": "v"})) {
		t.Errorf("looksLikeLegacyGatewayRecord: presence of an unknown key must disqualify (legacy keys are closed)")
	}
	// Garbage.
	if looksLikeLegacyGatewayRecord([]byte("not json at all")) {
		t.Errorf("looksLikeLegacyGatewayRecord: garbage must NOT match")
	}
	// Empty JSON.
	if looksLikeLegacyGatewayRecord([]byte("{}")) {
		t.Errorf("looksLikeLegacyGatewayRecord: empty object must NOT match")
	}
	_ = path
}

// mustJSON marshals v, fataling on marshal error — keeps the canary
// tests readable.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}
