//go:build windows

// iamt257_gateway_dir_acl_windows_test.go — IAMT-257: the gateway's
// data directory on Windows must carry the ACL from SPEC §3.5.1 —
// inheritance off (SE_DACL_PROTECTED), full access for exactly three
// trustees: SYSTEM, Administrators, and the service account
// NT SERVICE\iamtunnel-gateway.
//
// Canaries:
//
//  1. change the serviceAccountSID algorithm (say, drop UpperInvariant
//     or change the byte order of the words) —
//     TestIAMT257_ServiceAccountSIDIsDeterministic turns red on a
//     verbatim mismatch with the S-IDs checked against live services;
//  2. drop any of the three trustees from hardenGatewayDirACL or
//     forget SE_DACL_PROTECTED — the corresponding assertion of
//     TestIAMT257_GatewayDirACLThreeTrustees turns red;
//  3. drop (OI)(CI) (windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) —
//     TestIAMT257_GatewayDirACLInheritsToChildren turns red: a file
//     created AFTER the hardening gets no inherited ACEs.
//
// Every ACL operation happens only on paths inside t.TempDir()
// (gate 11); system services, the registry, and real system directories
// are not touched. The ACL tests require an elevated token and are
// otherwise skipped with an explanation (gate 10) — like the IAMT-213
// tests.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// TestIAMT257_ServiceAccountSIDIsDeterministic — the
// S-1-5-80-SHA1(UTF-16LE(UPPER(name))) algorithm is pinned by literals.
// The values below were checked during development against real service
// SIDs by translating NT SERVICE\<name> → SecurityIdentifier (and
// against the documented value for TrustedInstaller): the algorithm
// must produce exactly those.
//
// Canary: any change to the algorithm (case, encoding, word order or
// size) changes at least one SID — the test turns red with the actual
// value in its text.
func TestIAMT257_ServiceAccountSIDIsDeterministic(t *testing.T) {
	cases := []struct {
		service string
		want    string
	}{
		// Four real services: the algorithm was checked on a live system.
		{"wuauserv", "S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788"},
		{"TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"},
		{"mpssvc", "S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052"},
		{"schedule", "S-1-5-80-4125092361-1567024937-842823819-2091237918-836075745"},
		// The gateway's own service: the SID hardenGatewayDirACL puts
		// into the data directory's DACL and that the service token gets
		// after SERVICE_SID_TYPE_UNRESTRICTED (IAMT-258).
		{"iamtunnel-gateway", "S-1-5-80-1758786130-1687455438-3094451596-1431056402-1714530634"},
	}
	for _, tc := range cases {
		sid, err := serviceAccountSID(tc.service)
		if err != nil {
			t.Fatalf("serviceAccountSID(%q): %v", tc.service, err)
		}
		if got := sid.String(); got != tc.want {
			t.Errorf("IAMT-257: serviceAccountSID(%q) = %s, want %s — the per-service SID algorithm must match what the SCM assigns",
				tc.service, got, tc.want)
		}
	}
	// Case-insensitivity: the service stores its name in its own case,
	// but the SID does not depend on it — the SCM upper-cases before
	// hashing.
	a, err := serviceAccountSID("IAMTUNNEL-Gateway")
	if err != nil {
		t.Fatalf("serviceAccountSID(mixed case): %v", err)
	}
	b, err := serviceAccountSID("iamtunnel-gateway")
	if err != nil {
		t.Fatalf("serviceAccountSID(lower): %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("IAMT-257: the SID must not depend on the service name's case: %s vs %s", a.String(), b.String())
	}
	if _, err := serviceAccountSID("  "); err == nil {
		t.Error("IAMT-257: an empty service name must be a refusal, not some SID or other")
	}
}

// gatewayServiceSIDString — the string form of the gateway service
// account's SID, for the assertions below.
func gatewayServiceSIDString(t *testing.T) string {
	t.Helper()
	sid, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		t.Fatalf("serviceAccountSID(%q): %v", gatewayServiceName, err)
	}
	return sid.String()
}

// assertGatewayDirDACL — the shared core: a protected DACL, zero
// inherited ACEs, exactly three ACCESS_ALLOWED ACEs (SYSTEM,
// Administrators, the service SID) with full access; wantInherit
// selects the directory variant (every ACE carries (OI)(CI)).
func assertGatewayDirDACL(t *testing.T, label, path string, wantInherit bool) {
	t.Helper()
	prot, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatalf("IAMT-257 %s: DACLProtected(%s): %v", label, path, err)
	}
	if !prot {
		t.Errorf("IAMT-257 %s: DACL %s must be protected (SE_DACL_PROTECTED, SPEC §3.5.1 \"inheritance off\"), got protected=false — parent entries leak inward", label, path)
	}
	aces := readDACLFull(t, path)
	var inherited []aceInfo
	for _, a := range aces {
		if a.inherited {
			inherited = append(inherited, a)
		}
	}
	if len(inherited) != 0 {
		t.Errorf("IAMT-257 %s: %s carries %d inherited ACEs %v, want exactly zero", label, path, len(inherited), inherited)
	}
	if len(aces) != 3 {
		t.Errorf("IAMT-257 %s: DACL %s must hold exactly 3 ACEs (SYSTEM + Administrators + %s), got %d: %v",
			label, path, gatewayServiceAccountName, len(aces), aces)
	}
	wantSIDs := []string{"S-1-5-18", "S-1-5-32-544", gatewayServiceSIDString(t)}
	for _, wantSID := range wantSIDs {
		found := false
		for _, a := range aces {
			if a.sid != wantSID {
				continue
			}
			found = true
			if !a.allow {
				t.Errorf("IAMT-257 %s: the ACE for %s on %s must be ACCESS_ALLOWED, not deny", label, wantSID, path)
			}
			if a.mask != testGenericAll && a.mask&testFileAllAccess != testFileAllAccess {
				t.Errorf("IAMT-257 %s: DACL %s must give %s full access, got mask %#x", label, path, wantSID, a.mask)
			}
			if wantInherit && a.inheritFlags != testOICI {
				t.Errorf("IAMT-257 %s: the directory DACL of %s must give %s with (OI)(CI) inheritance, got flags %#x", label, path, wantSID, a.inheritFlags)
			}
		}
		if !found {
			t.Errorf("IAMT-257 %s: DACL %s must grant access to %s; the actual trustees: %v", label, path, wantSID, aces)
		}
	}
}

// TestIAMT257_GatewayDirACLThreeTrustees — hardenGatewayDirACL on a
// fresh data directory: a protected DACL, three trustees with full
// access, every ACE carrying (OI)(CI).
//
// Canary: drop any trustee, clear SE_DACL_PROTECTED, or swap the mask
// for a partial one — the corresponding line below turns red.
func TestIAMT257_GatewayDirACLThreeTrustees(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayDirACL(dir, false, nil); err != nil {
		t.Fatalf("hardenGatewayDirACL: %v", err)
	}
	relaxACLOnCleanup(t, dir)
	assertGatewayDirDACL(t, "fresh dir", dir, true)
}

// TestIAMT257_GatewayDirACLInheritsToChildren — (OI)(CI) really works:
// a file created in the directory AFTER the hardening receives the
// inherited ACEs of the same three trustees. That is how state.json,
// events.jsonl and the session recordings get the service account's
// rights with no extra calls.
//
// Canary: drop windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT from
// hardenGatewayDirACL — the file ends up with no inherited ACEs and the
// test turns red.
func TestIAMT257_GatewayDirACLInheritsToChildren(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayDirACL(dir, false, nil); err != nil {
		t.Fatalf("hardenGatewayDirACL: %v", err)
	}
	child := filepath.Join(dir, "state.json")
	if err := os.WriteFile(child, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	relaxACLOnCleanup(t, dir, child)

	aces := readDACLFull(t, child)
	var inherited []aceInfo
	for _, a := range aces {
		if a.inherited {
			inherited = append(inherited, a)
		}
	}
	if len(inherited) == 0 {
		t.Fatalf("IAMT-257: file %s, created after the directory was hardened, received not a single inherited ACE — (OI)(CI) does not work, the service account will not be able to read the data", child)
	}
	saw := map[string]bool{}
	for _, a := range inherited {
		saw[a.sid] = true
	}
	for _, wantSID := range []string{"S-1-5-18", "S-1-5-32-544", gatewayServiceSIDString(t)} {
		if !saw[wantSID] {
			t.Errorf("IAMT-257: file %s has no inherited ACE for %s (only %v) — the service account may lose access to the data", child, wantSID, inherited)
		}
	}
}

// TestIAMT257_GatewayDirACLIsIdempotent — applying the ACL again gives
// the same result (a repeat install must be idempotent, SPEC §3.5): the
// second call neither adds ACEs nor drops the protection.
//
// Canary: make hardenGatewayDirACL non-idempotent (say, append ACEs to
// the existing DACL instead of replacing it) — the "exactly 3 ACEs"
// assertion after the second call turns red.
func TestIAMT257_GatewayDirACLIsIdempotent(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := hardenGatewayDirACL(dir, false, nil); err != nil {
			t.Fatalf("hardenGatewayDirACL pass %d: %v", i+1, err)
		}
	}
	relaxACLOnCleanup(t, dir)
	assertGatewayDirDACL(t, "after second pass", dir, true)
}
