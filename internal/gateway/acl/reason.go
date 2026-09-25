package acl

// DenyReason is a typed reason for refusing access. There is no stringly
// typed path anywhere: the gateway prints DenyReason.String() to the
// person's terminal as one line (SPEC 6.4), and tests switch on the
// constant itself.
type DenyReason int

const (
	// ReasonNone marks an allowed decision; it is never a denial.
	ReasonNone DenyReason = iota
	// DenyUnknownPerson: no such person in the gateway state.
	DenyUnknownPerson
	// DenyUnknownMachine: no such machine in the gateway state.
	DenyUnknownMachine
	// DenyNoGrant: no permission for this person-machine pair.
	DenyNoGrant
	// DenyGrantRevoked: the permission was revoked by an administrator.
	DenyGrantRevoked
	// DenyGrantExpired: the permission deadline has passed.
	DenyGrantExpired
	// DenyMachineUnverified: the machine exists but is not in state
	// verified (SPEC 3.4).
	DenyMachineUnverified
	// DenyMachineOffline: the machine has no live tunnel to the gateway.
	DenyMachineOffline
	// DenyPersonSessionLimit: the person's live-session cap is full.
	DenyPersonSessionLimit
	// DenyMachineSessionLimit: the machine's live-session cap is full.
	DenyMachineSessionLimit
	// DenyMachineHostKeyMismatch: the machine's target sshd presented a host
	// key that does not match the pinned sshdHostKey, and the gateway remembers
	// it (state.Machine.HostKeyStatus == mismatch). SPEC §4.3 forbids opening a
	// door on such a machine, so this refuses the ACCESS, not the session, and
	// says which precondition failed instead of folding it into "not verified".
	//
	// It is declared before DenyAdminKilled on purpose: the sweep in
	// TestReasonsAreSingleLineAndDistinct runs from ReasonNone to
	// DenyAdminKilled, and a reason appended after that bound would fall out of
	// the sweep silently. These values are internal - nothing serialises a
	// DenyReason - so the position costs nothing.
	DenyMachineHostKeyMismatch
	// DenyMachineSSHDUnreachable: the machine's target sshd did not answer or refused connection.
	DenyMachineSSHDUnreachable
	// DenyMachineSSHAuthFailed: the machine's target sshd rejected the door key.
	DenyMachineSSHAuthFailed
	// DenyKeyRemoved: the key the session was opened with is no longer
	// the person's - removed on its own or with the person (IAMT-449).
	DenyKeyRemoved
	// DenyGrantChanged: an administrator narrowed the grant (shell to
	// exec) or moved its deadline closer; the grant stands on its new
	// terms, the sessions opened on the old ones end (IAMT-440).
	DenyGrantChanged
	// DenyPersonRenamed: an administrator renamed the person; the grants
	// moved to the new name, the sessions opened under the old one end.
	DenyPersonRenamed
	// DenyAdminKilled: an administrator ended this specific session
	// (SPEC §3.3 "sessions kill"), distinct from a grant revocation.
	DenyAdminKilled
)

// denyText is indexed by the DenyReason constants above. These are
// user-facing terminal lines, so they stay English and single-line
// (SPEC 7.1).
var denyText = [...]string{
	ReasonNone:                 "",
	DenyUnknownPerson:          "unknown person",
	DenyUnknownMachine:         "unknown machine",
	DenyNoGrant:                "no permission for this machine",
	DenyGrantRevoked:           "access revoked by administrator",
	DenyGrantExpired:           "access expired",
	DenyMachineUnverified:      "machine is not verified",
	DenyMachineOffline:         "machine is offline",
	DenyPersonSessionLimit:     "too many active sessions for your account",
	DenyMachineSessionLimit:    "too many active sessions on this machine",
	DenyMachineHostKeyMismatch: "machine sshd host key does not match the pinned key",
	DenyMachineSSHDUnreachable: "machine sshd is unreachable",
	DenyMachineSSHAuthFailed:   "machine sshd rejected door key",
	DenyKeyRemoved:             "the key this session was opened with was removed",
	DenyGrantChanged:           "access changed by administrator",
	DenyPersonRenamed:          "person renamed by administrator",
	DenyAdminKilled:            "session ended by administrator",
}

// String renders the reason as one user-facing line.
func (r DenyReason) String() string {
	if r < 0 || int(r) >= len(denyText) {
		return "unknown reason"
	}
	return denyText[r]
}

// DenyError turns a denial into an error value for callers that think in
// errors, e.g. OpenSession.
type DenyError struct {
	Reason DenyReason
}

func (e *DenyError) Error() string {
	return "acl: " + e.Reason.String()
}
