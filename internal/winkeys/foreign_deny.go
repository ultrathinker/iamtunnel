// foreign_deny.go — types and printable form for the IAMT-315
// foreign-explicit-ACCESS_DENIED contract. Platform-neutral on
// purpose: cmd/iamtunnel's gateway_service.go references
// *ForeignDenyRefusalError in its errors.As branch, and gateway_service.go
// compiles on every host OS. The Windows-only DACL walk that PRODUCES
// ForeignDenyACE values (CheckForeignExplicitDeny, collectForeignDenies,
// resolveSIDName) stays in doors_windows.go — those use win32 APIs
// that the unix build of this package does not have. On Unix there is
// no DACL concept, so the refusal type never fires; the type itself
// costs a few struct fields at compile time and an Error() method
// the unix build never runs.
//
// Why this lives here, not in doors_windows.go: the no-kill-switch
// gate (TestAcceptance_NoKillSwitch, internal/winkeys/acceptance_test.go)
// AST-walks every non-_test.go file in the package and reports any
// exported top-level var. There are no exported vars here; there are
// only exported types and an exported DescribeAccessMask function.
// None of those is mutable state — they describe the refusal and its
// message; the "no switch that disables the safety" rule does
// not apply to data.

package winkeys

import (
	"fmt"
	"strings"
)

// ForeignDenyACE describes one explicit ACCESS_DENIED ACE on an
// object we are about to harden with a fresh, smaller DACL. The
// principal and the mask are the operator's local decision about
// THIS object — an inherited DENY ACE came from a parent and is
// not in this list (it is not our business to audit parents, and
// SE_DACL_PROTECTED already drops inherited entries on write).
// SID is the textual form (LookupAccountSid may have resolved it
// to a friendly name in Name; Name is the empty string when the
// local account database did not know the SID).
//
// Defined here in a platform-neutral file because
// cmd/iamtunnel/gateway_service.go references *ForeignDenyRefusalError
// (which contains a slice of this type) in its errors.As branch, and
// that file builds on every host OS. The Windows-only DACL walk that
// PRODUCES values of this type stays in doors_windows.go.
type ForeignDenyACE struct {
	SID  string // textual form, e.g. "S-1-5-32-546"
	Name string // LookupAccountSid result, or "" if unresolved
	Mask uint32 // ACCESS_MASK value as a uint32
}

// ForeignDenyRefusalError is returned by an ACL hardening helper
// when the object already carries a non-inherited ACCESS_DENIED ACE
// for a principal the helper is about to overwrite. The caller
// refuses the install; on Windows the operator can re-run with
// --replace-acl to drop the ACEs (the same list is reported before
// the overwrite happens).
//
// The error message names the path and every principal+mask, so the
// person reading the failure can decide what to do without opening
// the file's properties dialog themselves. The CLI surfaces this
// as a refusal exit path with the same "remove the ACE(s) by hand
// or repeat with --replace-acl" hint.
//
// Defined platform-neutrally for the same reason as ForeignDenyACE:
// cmd/iamtunnel/gateway_service.go's errors.As(herr, &fdr) check has
// to compile on every host OS, even though the unix build of this
// package never produces one (there is no DACL concept on Unix).
type ForeignDenyRefusalError struct {
	Path   string
	Denies []ForeignDenyACE
}

func (e *ForeignDenyRefusalError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to overwrite security descriptor of %s: explicit ACCESS_DENIED ACE(s) found\n", e.Path)
	for _, d := range e.Denies {
		principal := d.Name
		if principal == "" {
			principal = d.SID
		}
		fmt.Fprintf(&b, "  - %s denied %#x (%s)\n", principal, d.Mask, DescribeAccessMask(d.Mask))
	}
	fmt.Fprint(&b, "remove the ACE(s) by hand, or repeat with --replace-acl to drop them and retry")
	return b.String()
}

// accessMaskKnownNames is the readable form of ACCESS_MASK bits we
// print in the refusal message: the most specific named mask wins
// (FILE_ALL_ACCESS prints as itself, not as the union of its bits).
// Generic bits come after the specific masks so a "0x1F01FF" lookup
// hits FILE_ALL_ACCESS first.
//
// Lives in the platform-neutral file because DescribeAccessMask only
// needs a uint32→string table; the Win32 access mask constants it
// names are public domain documentation, not API calls.
var accessMaskKnownNames = []struct {
	mask uint32
	name string
}{
	{0x1F01FF, "FILE_ALL_ACCESS"},
	{0x120089, "FILE_GENERIC_READ"},
	{0x1200BF, "FILE_GENERIC_WRITE"},
	{0x12019F, "FILE_GENERIC_EXECUTE"},
	{0x10000000, "GENERIC_ALL"},
	{0x80000000, "GENERIC_READ"},
	{0x40000000, "GENERIC_WRITE"},
	{0x20000000, "GENERIC_EXECUTE"},
	{0x0001, "FILE_READ_DATA"},
	{0x0002, "FILE_WRITE_DATA"},
	{0x0004, "FILE_APPEND_DATA"},
	{0x0008, "FILE_READ_EA"},
	{0x0010, "FILE_WRITE_EA"},
	{0x0020, "FILE_EXECUTE"},
	{0x0040, "FILE_DELETE_CHILD"},
	{0x0080, "FILE_READ_ATTRIBUTES"},
	{0x0100, "FILE_WRITE_ATTRIBUTES"},
	{0x10000, "DELETE"},
	{0x20000, "READ_CONTROL"},
	{0x40000, "WRITE_DAC"},
	{0x80000, "WRITE_OWNER"},
	{0x100000, "SYNCHRONIZE"},
}

// DescribeAccessMask returns a human-readable form of an
// ACCESS_MASK. An exact named match wins; otherwise the mask is
// disassembled into the union of named bits ("DELETE|READ_CONTROL").
//
// Exported so the gateway-side hardening in cmd/iamtunnel can reuse
// the same printable form (IAMT-315).
func DescribeAccessMask(m uint32) string {
	for _, k := range accessMaskKnownNames {
		if m == k.mask {
			return k.name
		}
	}
	var parts []string
	remaining := m
	for _, k := range accessMaskKnownNames {
		if remaining&k.mask == k.mask && k.mask != 0 {
			parts = append(parts, k.name)
			remaining &^= k.mask
		}
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "|")
}
