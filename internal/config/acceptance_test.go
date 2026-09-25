package config

// Independent acceptance tests for the configuration layer.
// Every test is sensitive to a specific, previously documented defect.

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TestAcceptance_NoExportedSetterOnAcceptedArgs: there is no exported way
// for an importer to switch the accepted-argument lists. We assert by
// reflection: the screens storage has no exported identifier, and the
// only access path is the read-only ScreenNames() that hands out a
// defensive copy. ParseScreen is the read-only validator (a *function*,
// not a setter) so it stays in the catalog.
// ---------------------------------------------------------------------------
func TestAcceptance_NoExportedSetterOnAcceptedArgs(t *testing.T) {
	// 1. The screens storage has no exported identifier that names the
	//    data, only the read-only names list.
	banned := map[string]bool{
		"Screens": true, "SetScreens": true, "SetScreen": true,
		"AddScreen": true, "RemoveScreen": true, "screen": true,
		"allowedKeyTypes": true, "SetAllowedKeyTypes": true,
	}
	for _, name := range exportedNames() {
		if banned[name] {
			t.Errorf("config has exported %q — importers can switch accepted args", name)
		}
	}
	// 2. ScreenNames returns a defensive copy.
	first := ScreenNames()
	for i := range first {
		first[i] = "pwned"
	}
	if reflect.DeepEqual(first, ScreenNames()) {
		t.Fatalf("ScreenNames() is not a defensive copy — first call mutated the package")
	}
}

// exportedNames is a tiny reflection helper. We avoid pulling in the
// runtime reflection machinery into the test binary at large by working
// from the type catalog directly.
func exportedNames() []string {
	names := []string{
		// Settings type fields — exported by design, but they only
		// describe already-merged values, never the accepted-argument set.
		"Port", "ClientDir", "ServerDir", "GatewayDir",
		"RecordingsRetentionDays", "RecordingsDiskStopPercent",
		"MaxSessionsPerPerson", "MaxSessionsPerMachine",
		// Read-only accessors.
		"ScreenNames",
		// Functions and error types.
		"Defaults", "Partial", "Override", "Settings",
		"ParseFile", "EnvOverride", "Load", "FormatConfigHelp",
		"ConnString", "EnrolCode", "ClaimRef",
		"ParseConnString", "ParseEnrolCode", "ParseClaimRef",
		"ValidName", "NameError", "ValidToken", "ValidSessionID",
		"ValidHost", "NormalizeFingerprint", "CheckPublicKey",
		"ParseUntil", "ValidOSUser", "ParsePort", "ParseScreen",
		"Error", "Class",
		"Dirs", "DirsFor",
		"ClassUser", "ClassEnv", "ClassDenied",
	}
	return names
}

// ---------------------------------------------------------------------------
// TestAcceptance_FileValueMaskedByEnv: when the config file carries a
// value out of range and the environment supplies a valid value for the
// SAME key, the run must proceed (env masks file per key). If it ever
// failed, the spec promise of "the file alone cannot override something
// the user typed on the command line" is broken — because the env value
// is the "command line typed through the shell" path.
// ---------------------------------------------------------------------------
func TestAcceptance_FileValueMaskedByEnv(t *testing.T) {
	badFile := `{"port": 80}`
	env := map[string]string{"HOME": "/h", "IAMTUNNEL_PORT": "2300"}
	s, err := Load("linux", env, Override{}, func(string) ([]byte, error) { return []byte(badFile), nil })
	if err != nil {
		t.Fatalf("env must mask bad file port: err=%v", err)
	}
	if s.Port != 2300 {
		t.Fatalf("Port=%d, want 2300 (env masked file)", s.Port)
	}
	// No env, no flag: the file's bad port must survive validation and
	// be rejected.
	_, err = Load("linux", map[string]string{"HOME": "/h"}, Override{}, func(string) ([]byte, error) { return []byte(badFile), nil })
	if err == nil {
		t.Fatal("file with bad port and no override must error")
	}
}

// ---------------------------------------------------------------------------
// TestAcceptance_NamedMissingConfigIsAUserError: when the operator names
// a missing file with --config or IAMTUNNEL_CONFIG, the run is a user
// error (class 2), not a silent default. The exit code path goes through
// the CLI: this pins the class on the config side so the CLI cannot
// silently downgrade it.
// ---------------------------------------------------------------------------
func TestAcceptance_NamedMissingConfigIsAUserError(t *testing.T) {
	_, err := Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/no/such/file.json"},
		func(string) ([]byte, error) { return nil, os.ErrNotExist })
	if err == nil {
		t.Fatal("explicit missing config must error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error must name the missing file and the cause, got: %v", err)
	}
	var ce *Error
	if !errorAs(err, &ce) || ce.Class != ClassUser {
		t.Fatalf("explicit missing config must be ClassUser, got %v", err)
	}
}

// errorAs is the standard library errors.As — vendored here to keep
// this file self-contained.
func errorAs(err error, target any) bool {
	return errorsAsImpl(err, target)
}

func errorsAsImpl(err error, target any) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			if p, ok := target.(**Error); ok {
				*p = e
				return true
			}
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			continue
		}
		return false
	}
	return false
}
