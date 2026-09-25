//go:build windows

// Windows-specific gateway-install helpers for SPEC §3.5.1.
//
//   - serviceAccountSID  — the pure, documented SCM algorithm that maps a
//     service name to the per-service SID (S-1-5-80-…): the value the SCM
//     gives the service's token once it is created with
//     SERVICE_SID_TYPE_UNRESTRICTED (IAMT-258). Pure on purpose: the SID
//     depends only on the name, so it can be computed — and tested —
//     before the service exists.
//   - hardenGatewayDirACL — the gateway data directory's DACL from SPEC
//     §3.5.1: inheritance switched off, full control for SYSTEM,
//     Administrators and the service's own account, nothing else.

package main

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// gatewayServiceName and gatewayServiceAccountName (and the rest of the
// service's specification) live in gateway_service.go so the install
// sequence stays testable on any host OS.

// serviceAccountSID returns the per-service SID the SCM assigns to
// serviceName: S-1-5-80- followed by the five little-endian uint32
// words of SHA-1 over the UPPERCASED service name encoded UTF-16LE.
// This is the documented, deterministic mapping the SCM itself applies
// (verified against live services during development: wuauserv →
// S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788 and
// three more; see TestIAMT257_ServiceAccountSIDIsDeterministic).
//
// The value is usable in a DACL even before the service is created:
// a well-formed SID needs no account to exist, and once IAMT-258
// creates the service with SERVICE_SID_TYPE_UNRESTRICTED its token
// carries exactly this SID. Computing it (instead of
// windows.LookupAccountName on "NT SERVICE\…") keeps install working
// on a machine where the service does not exist yet and keeps the
// mapping testable without SCM access.
//
// The SID comes back through StringToSid (which Copy()s into Go
// memory) — the same allocation pattern as the two builtin trustees in
// hardenGatewayDirACL, so the Pin-before-BuildSecurityDescriptor
// discipline applies uniformly.
func serviceAccountSID(serviceName string) (*windows.SID, error) {
	if strings.TrimSpace(serviceName) == "" {
		return nil, fmt.Errorf("service name is empty")
	}
	// UTF-16LE without a terminating NUL — the SCM hashes the name's
	// code units only (a NUL would change the digest).
	units := utf16.Encode([]rune(strings.ToUpper(serviceName)))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	sum := sha1.Sum(buf)
	// The digest's five little-endian uint32 words are the five
	// subauthorities after the 80 (S-1-5-80-<w1>-<w2>-<w3>-<w4>-<w5>).
	sidStr := fmt.Sprintf("S-1-5-80-%d-%d-%d-%d-%d",
		binary.LittleEndian.Uint32(sum[0:4]),
		binary.LittleEndian.Uint32(sum[4:8]),
		binary.LittleEndian.Uint32(sum[8:12]),
		binary.LittleEndian.Uint32(sum[12:16]),
		binary.LittleEndian.Uint32(sum[16:20]),
	)
	return windows.StringToSid(sidStr)
}

// gatewayFileAllAccess is FILE_ALL_ACCESS (the fully specific "full
// control" mask). A directory ACE with the specific mask is stored as
// written — one ACE per trustee; the generic mask would be
// canonicalized into two stored ACEs per trustee (the same
// canonicalization internal/winkeys documents for the machine role's
// data directory, IAMT-213).
const gatewayFileAllAccess windows.ACCESS_MASK = 0x1F01FF

// hardenGatewayDirACL applies the gateway data directory's ACL from
// SPEC §3.5.1: a protected DACL (SE_DACL_PROTECTED — no inheritance
// from the parent) with exactly three ACCESS_ALLOWED ACEs — SYSTEM,
// Administrators and the service account NT SERVICE\iamtunnel-gateway
// (by its computed per-service SID) — each full control with
// (OI)(CI), so every state file, event log and recording the gateway
// creates below the directory starts from the same three trustees.
//
// Trustees are set by SID, never by localized name (the same rule
// winkeys' ACL primitives document); the service SID comes from
// serviceAccountSID, so the call works before the service exists.
// Existing children are NOT rewritten by THIS call alone — install
// locks the directory and everything already in it with
// lockGatewayDataTree (Code-rev rall_codex round, blocker 2; through
// handles since R2-CX F-12).
//
// replaceACL is the IAMT-315 opt-in flag the CLI threads through
// --replace-acl: when an explicit ACCESS_DENIED ACE for some other
// principal is already on the object, the helper refuses by default
// and proceeds (printing the dropped ACEs) when replaceACL is true.
// The check is shared with winkeys' LockDownDirACL: both lock through
// winkeys.LockObject.
//
// The layout is internal/winkeys' applyProtectedDACL (the machine
// role's ACL primitive) with the third trustee added. report is the
// caller-supplied destination for the dropped-ACE printout (the same
// writer the rest of
// `gateway install` uses so the message interleaves with the install
// narrative in the order the operator sees it).
func hardenGatewayDirACL(dir string, replaceACL bool, report io.Writer) error {
	return applyGatewayProtectedACL(dir, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, replaceACL, report)
}

// applyGatewayProtectedACL is the shared builder: the same three
// trustees (SYSTEM, Administrators, NT SERVICE\iamtunnel-gateway),
// the same full-control mask, the same SE_DACL_PROTECTED wrapper —
// only the inheritance flag differs. Directories use (OI)(CI) so
// children they later create inherit the protected DACL; files use
// inheritNone because inheritance on a file is meaningless and
// prevents the canonicalization double-ACE rule winkeys documents
// (IAMT-213) from re-introducing the problem on the file side.
//
// IAMT-315: the function reads the existing DACL before overwriting
// and refuses (or, under replaceACL=true, proceeds and reports) any
// non-inherited ACCESS_DENIED ACE. The check is shared with winkeys'
// applyProtectedDACL — both lock through winkeys.LockObject, so the
// refusal message and the dropped-ACE printout are identical for the
// two DACL shapes (this one is three trustees; winkeys' is two).
// report is the caller-supplied destination for the dropped-ACE
// printout (one line per ACE). A nil writer skips the printout —
// tests that don't capture it pass nil; production threads
// cmd/iamtunnel's `s.out` down the call chain so the report is on
// the CLI's captured stdout (interleaved with the rest of the
// install narrative), NOT on the process's bare os.Stderr.
func applyGatewayProtectedACL(path string, inheritance uint32, replaceACL bool, report io.Writer) error {
	// R2-CX F-07: the owner goes to Administrators with the DACL, and an
	// owner nobody here can vouch for is refused rather than handed over.
	// An owner can always rewrite the DACL: the data directory used to
	// keep whoever made it - --data-dir on a path another account could
	// create, and %ProgramData% lets every signed-in user create folders -
	// and that account could reopen the directory, host key and bootstrap
	// token with it, the moment install had locked it. The binary's
	// directory has had its owner handed over since IAMT-445.
	//
	// R2-CX F-12: all of it through one handle, opened without following
	// a reparse point (winkeys.LockObject), not by name twice.
	serviceSID, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return fmt.Errorf("derive the %s SID: %w", gatewayServiceAccountName, err)
	}
	dacl, err := gatewayDataDACL(inheritance)
	if err != nil {
		return err
	}
	return winkeys.LockObject(path, dacl, []*windows.SID{serviceSID}, replaceACL, report)
}

// gatewayDataDACL is the data directory's DACL (SPEC §3.5.1): SYSTEM,
// Administrators and the service account, full control, with the given
// inheritance. Every lockdown of the directory and its contents and the
// fresh directory's own descriptor (R2-CX F-05) are built from it.
func gatewayDataDACL(inheritance uint32) (*windows.ACL, error) {
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM SID: %w", err)
	}
	serviceSID, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return nil, fmt.Errorf("derive the %s SID: %w", gatewayServiceAccountName, err)
	}
	return winkeys.ProtectedDACL(gatewayFileAllAccess, inheritance, winkeys.AdministratorsSID(), systemSID, serviceSID)
}

// createGatewayDataDirLocked creates the data directory with its own
// protected DACL as part of the create itself (R2-CX F-05), so it never
// exists, even for an instant, with what its parent hands down - under
// %ProgramData% that is read access for every signed-in user and the
// right to create files in it. A directory that is already there is left
// to the hardening that follows. The parent must exist.
func createGatewayDataDirLocked(dir string) error {
	dacl, err := gatewayDataDACL(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return err
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil
		}
		return fmt.Errorf("create %s with its DACL: %w", dir, err)
	}
	return nil
}

// hardenGatewayFileACL applies the same protected DACL (SYSTEM,
// Administrators, NT SERVICE\iamtunnel-gateway, each full control,
// SE_DACL_PROTECTED) to an existing file. Inheritance is inheritNone:
// the file has nothing to propagate the ACEs to, and the canonicalized
// double-ACE rule winkeys documents (IAMT-213) means GENERIC bits on
// a non-container object would still be stored as one ACE each, but
// keeping inheritance off is the documented choice for the file
// half of the protected-pair lockdown. replaceACL is the IAMT-315
// opt-in (--replace-acl). report is the caller-supplied destination
// for the dropped-ACE printout; see hardenGatewayDirACL.
func hardenGatewayFileACL(path string, replaceACL bool, report io.Writer) error {
	return applyGatewayProtectedACL(path, 0, replaceACL, report)
}

// gatewayExeDirReadExecute is FILE_GENERIC_READ|FILE_GENERIC_EXECUTE —
// the mask hardenGatewayExeDirACL grants BUILTIN\Users and the service
// account on the binary's directory: enough to load and run the exe,
// nothing more. The elevated privilege stays in the service account
// (SPEC §3.5.1), not in file permissions.
var gatewayExeDirReadExecute = windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)

// hardenGatewayExeDirACL grants the gateway service account (and
// BUILTIN\Users, so a non-admin can still launch the very same binary as
// the desktop client) read+execute on the directory holding the binary
// the service runs (IAMT-312): a live Windows box created the SCM
// service and accepted the start request successfully, and the service
// still refused to run at all — "Access is denied" — because its own
// virtual account (NT SERVICE\iamtunnel-gateway) had no ACE at all on
// the binary's directory. Sitting under C:\Program Files is not enough
// by itself: a virtual service account is not a member of BUILTIN\Users
// or any other group Program Files' own inherited ACL already covers.
//
// (OI)(CI) inheritance only reaches objects the directory creates AFTER
// this call — it does nothing for the exe that already sits there,
// which is the ordinary case (the operator already copied it in).
// hardenGatewayExeFileACL below covers that file directly; this call
// alone is not sufficient (IAMT-312 round 5). replaceACL — the IAMT-315
// opt-in (--replace-acl): the same contract as for the data dir —
// a non-inherited ACCESS_DENIED ACE causes a refusal when
// replaceACL=false, and a printout plus continuation when true.
// report is the caller-supplied destination for the dropped-ACE
// printout; see hardenGatewayDirACL.
func hardenGatewayExeDirACL(dir string, replaceACL bool, report io.Writer) error {
	return applyGatewayExeACL(dir, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, replaceACL, report)
}

// hardenGatewayExeFileACL applies the same four trustees directly to an
// existing binary (IAMT-312 round 5): a repeated install can point the
// service's ImagePath at an exe that already existed under the target
// directory with whatever ACL it happened to carry — inheritance from
// hardenGatewayExeDirACL reaches only objects created afterward, so
// without this call a replaced exe could keep an ACL that denies the
// service SID outright, StartService could still report
// ERROR_SERVICE_ALREADY_RUNNING for the still-live OLD process, and
// waitRunning would then certify success over a configuration that
// cannot actually start once that old process ever stops. Inheritance
// is 0 (the same choice hardenGatewayFileACL makes for the data
// directory's own files): a file has nothing to propagate an ACE to.
// replaceACL — IAMT-315 opt-in. report is the caller-supplied
// destination for the dropped-ACE printout; see hardenGatewayDirACL.
func hardenGatewayExeFileACL(path string, replaceACL bool, report io.Writer) error {
	return applyGatewayExeACL(path, 0, replaceACL, report)
}

// applyGatewayExeACL is the shared builder behind hardenGatewayExeDirACL
// and hardenGatewayExeFileACL: the same four trustees — SYSTEM and
// Administrators at full control, BUILTIN\Users and the gateway service
// account at read+execute — the same protected DACL (SE_DACL_PROTECTED,
// same discipline as hardenGatewayDirACL), only the inheritance flag
// differs.
//
// The DACL is replaced wholesale rather than merged onto whatever
// inherited ACEs were already there: golang.org/x/sys/windows does not
// export SetEntriesInAcl (the API a true merge needs), and both the
// directory and the binary are the install's own dedicated territory
// (RUNBOOK §1.5 names C:\Program Files\iamtunnel as the sanctioned
// location) with nothing worth preserving beyond the four trustees named
// here.
//
// IAMT-315: the existing DACL is read first, and a non-inherited
// ACCESS_DENIED ACE for some other principal is refused (or, with
// replaceACL=true, printed and dropped). Finding 19 (IAMT-333): the
// checks and the write go through ONE handle, opened without following
// a reparse point — winkeys.LockObject, the same route the data side
// took in R2-CX F-12. The write this replaces was SetNamedSecurityInfo
// by name, and SetNamedSecurityInfo follows a reparse point: a junction
// on the exe directory's or the exe's path aimed the whole lockdown,
// owner included, at whatever the link named, and the name could mean
// something else between the DENY check and the write. A path that is
// itself a link is refused (the lockdown is for the object, and a link
// names another one); a refusal a caller cannot act on is another
// path — see hardenGatewayExeDirACL's callers.
//
// The owner rules are the data side's (R2-CX F-07/F-13): the owner goes
// to Administrators with the DACL (IAMT-445 — an owner can always
// rewrite the DACL), and an owner nobody here can vouch for — not
// Administrators, SYSTEM, TrustedInstaller, this process's account or
// the service account — is refused rather than handed over: a folder
// made by some other account - C:\iamtunnel is one anybody signed in
// may create at the root of the system drive - would otherwise stay
// that account's to reopen.
func applyGatewayExeACL(path string, inheritance uint32, replaceACL bool, report io.Writer) error {
	dacl, err := gatewayExeDACL(inheritance)
	if err != nil {
		return err
	}
	serviceSID, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return fmt.Errorf("derive the %s SID: %w", gatewayServiceAccountName, err)
	}
	return winkeys.LockObject(path, dacl, []*windows.SID{serviceSID}, replaceACL, report)
}

// gatewayExeDACL is the binary's directory DACL (IAMT-312): SYSTEM and
// Administrators at full control, BUILTIN\Users and the gateway service
// account at read+execute, with the given inheritance. The trustees'
// masks are two different values, so winkeys.ProtectedDACL's
// single-mask builder does not fit and the descriptor is built here,
// the way applyGatewayExeACL always built it.
func gatewayExeDACL(inheritance uint32) (*windows.ACL, error) {
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return nil, fmt.Errorf("parse SYSTEM SID: %w", err)
	}
	adminSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return nil, fmt.Errorf("parse Administrators SID: %w", err)
	}
	usersSID, err := windows.StringToSid("S-1-5-32-545")
	if err != nil {
		return nil, fmt.Errorf("parse BUILTIN\\Users SID: %w", err)
	}
	serviceSID, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return nil, fmt.Errorf("derive the %s SID: %w", gatewayServiceAccountName, err)
	}

	rp := &runtime.Pinner{}
	defer rp.Unpin()
	rp.Pin(systemSID)
	rp.Pin(adminSID)
	rp.Pin(usersSID)
	rp.Pin(serviceSID)

	trustee := func(sid *windows.SID) windows.TRUSTEE {
		return windows.TRUSTEE{
			MultipleTrustee:          nil,
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_USER,
			TrusteeValue:             windows.TrusteeValueFromSID(sid),
		}
	}
	ace := func(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee:           trustee(sid),
		}
	}
	eas := []windows.EXPLICIT_ACCESS{
		ace(systemSID, gatewayFileAllAccess),
		ace(adminSID, gatewayFileAllAccess),
		ace(usersSID, gatewayExeDirReadExecute),
		ace(serviceSID, gatewayExeDirReadExecute),
	}

	sd, err := windows.BuildSecurityDescriptor(nil, nil, eas, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("BuildSecurityDescriptor: %w", err)
	}
	return gatewayDACLFromSD(sd)
}

// reportGatewayForeignDeny mirrors winkeys' reportForeignDeny for
// the three- and four-trustee DACLs this file builds
// (applyGatewayProtectedACL has three; applyGatewayExeACL has four).
// Printout destination is the caller-supplied report writer — the
// SAME writer cmd/iamtunnel's CLI uses for the rest of the install
// narrative. There is no package-level reporter variable: an exported
// mutable writer is exactly what a future maintainer could flip to
// silence the operator's only signal that an explicit DENY was
// overwritten. The writer is threaded
// explicitly through runGatewayInstall → setupGatewayService → the
// harden*Dir seam closures → hardenGateway*ACL → here, so the report
// is capturable by every existing CLI-level test in this package (the
// same test driver `drive()` all the other install tests use) and
// stays in the order the operator sees the surrounding narrative on
// the install's success path. runGatewayInstall passes s.out:
// stdout is the right stream for a success-side audit (here is what
// I cleaned up, for the operator who opted in), and operators who
// redirect `> install.log` capture the full audit in one file. A nil
// writer skips the printout (callers without a CLI stream —
// standalone tests that drive hardenGatewayFileACL directly and
// capture os.Stderr via captureStderr — pass the OS writer
// explicitly).
func reportGatewayForeignDeny(path string, denies []winkeys.ForeignDenyACE, report io.Writer) {
	if report == nil {
		return
	}
	for _, d := range denies {
		principal := d.Name
		if principal == "" {
			principal = d.SID
		}
		fmt.Fprintf(report,
			"iamtunnel gateway install --replace-acl: dropping foreign ACCESS_DENIED ACE on %s: %s mask %#x (%s)\n",
			path, principal, d.Mask, winkeys.DescribeAccessMask(d.Mask))
	}
}

// gatewayDACLFromSD pulls the DACL pointer out of a self-relative
// SECURITY_DESCRIPTOR returned by BuildSecurityDescriptor (offset 16
// of the 20-byte header is the DACL offset, 0 = no DACL). Same walk
// winkeys.extractACLFromSD performs, which is private to winkeys;
// applyGatewayExeACL's descriptor is the one it reads.
func gatewayDACLFromSD(sd *windows.SECURITY_DESCRIPTOR) (*windows.ACL, error) {
	if sd == nil {
		return nil, fmt.Errorf("BuildSecurityDescriptor returned no security descriptor")
	}
	daclOff := *(*uint32)(unsafe.Add(unsafe.Pointer(sd), 16))
	if daclOff == 0 {
		return nil, fmt.Errorf("BuildSecurityDescriptor returned a descriptor without a DACL")
	}
	return (*windows.ACL)(unsafe.Add(unsafe.Pointer(sd), daclOff)), nil
}

// preflightGatewayACL is the IAMT-315 preflight for gateway install
// (called from runGatewayInstall, BEFORE MkdirAll, the host key, the
// bootstrap token, state.json and the printed bootstrap reference).
// dataDir may not exist yet on a fresh install — the function only
// reads it when it does. exeDir always exists (os.Executable returned
// a path, and the running binary must be on disk). Both reads share
// the same winkeys.CheckForeignExplicitDeny contract as the hardening
// functions below — the preflight is the early refusal; the
// hardening is the actual overwrite (it re-reads both DACLs after
// MkdirAll, after the binary has been confirmed read+executable).
//
// The shape of the refusal is the same on both paths:
// *ForeignDenyRefusalError is the documented CLI exit signal; the
// installer routes it to deniedErrf(... --replace-acl ...) for code 4.
// report is the caller-supplied destination for the dropped-ACE
// printout on the --replace-acl path (runGatewayInstall passes s.out
// so the report interleaves with the rest of the install narrative).
func preflightGatewayACL(dataDir, exeDir string, replaceACL bool, report io.Writer) error {
	if _, err := os.Stat(dataDir); err == nil {
		if err := preflightOneACL(dataDir, replaceACL, report); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read security descriptor of %s: %w", dataDir, err)
	}
	return preflightOneACL(exeDir, replaceACL, report)
}

// preflightOneACL reads the SD at path and, if replaceACL is false,
// refuses on any non-inherited ACCESS_DENIED ACE; if replaceACL is
// true, prints the list to the caller-supplied report writer
// (runGatewayInstall passes s.out — same writer as the rest of the
// install narrative; with that choice the report is capturable by
// the in-process CLI driver, ordered with the surrounding output,
// and assertable by every test that uses drive()) and proceeds. A
// read failure fails closed — never assume "there was nothing
// there".
func preflightOneACL(path string, replaceACL bool, report io.Writer) error {
	denies, err := winkeys.CheckForeignExplicitDeny(path)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	if len(denies) == 0 {
		return nil
	}
	if !replaceACL {
		return &winkeys.ForeignDenyRefusalError{Path: path, Denies: denies}
	}
	reportGatewayForeignDeny(path, denies, report)
	return nil
}

// lockGatewayDataTree locks the data directory and everything already in
// it down to the protected DACL (SPEC §3.5.1), owner Administrators, each
// object through the one handle it was classified by (winkeys.LockTree,
// R2-CX F-12), and keeps the directory pinned until release is called.
//
// The walk it replaces classified a child by the directory listing and
// set its DACL by name (Code-rev, blocker 2: install creates hostkey,
// state.json, bootstrap-token, enrol-hmac.key and state.lock before the
// service half, and the service account needs an ACE on each): a name
// that came to mean a hard link to a file outside the directory, or a
// directory link, between the two got the lockdown instead. Name
// surrogates and files with more than one name are still skipped and
// reported (IAMT-332), now as the handle sees them. A data directory that
// is a link, or is reached through one, is refused: install writes into
// it by name while the lock is held, and a link on the way is not
// pinned.
func lockGatewayDataTree(dir string, replaceACL bool, report io.Writer) (release func(), err error) {
	dirDACL, err := gatewayDataDACL(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return nil, err
	}
	fileDACL, err := gatewayDataDACL(0)
	if err != nil {
		return nil, err
	}
	serviceSID, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return nil, fmt.Errorf("derive the %s SID: %w", gatewayServiceAccountName, err)
	}
	return winkeys.LockTree(dir, winkeys.TreeACL{
		DirDACL:          dirDACL,
		FileDACL:         fileDACL,
		TrustedOwners:    []*windows.SID{serviceSID},
		BeforeApply:      gatewayTreeBeforeApply,
		RefuseLinkedPath: true,
	}, replaceACL, report)
}

// hardenGatewayDataDirForService is the production hardenDir seam's body.
// R2 supplementary round: refused first if another account can move the directory
// aside through a folder above it (data_dir_ancestors_windows.go). R2-CX
// F-05: a data directory that is not there yet is created with its own
// DACL, not with what the parent hands down (under %ProgramData%, read
// access for every signed-in user). R2-CX F-12: then it is locked object
// by object through handles, and stays pinned until install has written
// into it.
func hardenGatewayDataDirForService(dir string, replaceACL bool, report io.Writer) (func(), error) {
	if err := refuseGatewayDataDirAncestorWriters(dir); err != nil {
		return nil, err
	}
	if err := createGatewayDataDirLocked(dir); err != nil {
		return nil, err
	}
	return lockGatewayDataTree(dir, replaceACL, report)
}

// hardenGatewayDataTree is lockGatewayDataTree for a caller that writes
// nothing into the directory afterwards: the production seam minus the
// seam, which exists so that an install test that forgets to replace it
// cannot lock its own t.TempDir() - this is what a test that means to
// lock one calls.
func hardenGatewayDataTree(dir string, replaceACL bool, report io.Writer) error {
	release, err := lockGatewayDataTree(dir, replaceACL, report)
	if err != nil {
		return err
	}
	release()
	return nil
}

// gatewayTreeBeforeApply, when a test sets it, runs after a child of the
// data directory has been classified and before its DACL is set: the
// window R2-CX F-12 is about. Nil in the product.
var gatewayTreeBeforeApply func(path string)
