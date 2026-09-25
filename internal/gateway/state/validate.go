package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// nameRegex enforces the SPEC rule: [a-z0-9][a-z0-9._-]{0,31}
// Total length: 1 to 32 characters.
var nameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ValidateName checks an identifier against the rule [a-z0-9][a-z0-9._-]{0,31}.
// Returns a descriptive error for why the name failed validation.
func ValidateName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidName)
	}
	if len(name) > 32 {
		return fmt.Errorf("%w: %q exceeds maximum allowed length of 32 characters (got %d)", ErrInvalidName, name, len(name))
	}

	// Check for non-ASCII or whitespace first to provide clear diagnostics
	for _, r := range name {
		if r > 127 {
			return fmt.Errorf("%w: %q contains non-ASCII character %q", ErrInvalidName, name, r)
		}
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: %q contains whitespace", ErrInvalidName, name)
		}
		if unicode.IsUpper(r) {
			return fmt.Errorf("%w: %q contains uppercase letters (only lowercase [a-z0-9._-] allowed)", ErrInvalidName, name)
		}
	}

	// First character check: must be lowercase letter or digit
	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return fmt.Errorf("%w: %q starts with invalid character %q (must start with [a-z0-9])", ErrInvalidName, name, first)
	}

	if !nameRegex.MatchString(name) {
		return fmt.Errorf("%w: %q does not match required pattern [a-z0-9][a-z0-9._-]{0,31}", ErrInvalidName, name)
	}

	return nil
}

// ValidateOSUser validates the OS-user format per IAMT-271, SPEC
// §4.3 and PROTOCOL §1. The cross-platform shape accepts either of
// two forms; the per-machine gate decides which one the local OS
// recognises (see internal/config.ValidateOSUser):
//
//	(a) Windows principal — "DOMAIN\name" or "MACHINE\name";
//	    exactly one backslash, both parts non-empty, ASCII letters,
//	    digits, dot, _, -, @, $; length 1..64 per part.
//
//	(b) POSIX local name — Linux/macOS only; lowercase ASCII
//	    matching ^[a-z_][a-z0-9_-]{0,31}$.
//
// The gateway accepts both forms because the wire path carries the
// string from "iamtunnel admin machines enrol-code" on the admin
// machine to whichever machine is being enrolled; the per-OS gate
// at enrol-time and server-start is what rejects a Windows-form on
// a Linux machine (and vice versa).
//
// This function previously only accepted the Windows form (the
// IAMT-271 fix1 widens it to the union, matching ValidOSUser in
// internal/config).
func ValidateOSUser(user string) error {
	trimmed := strings.TrimSpace(user)
	if trimmed == "" {
		return fmt.Errorf("%w: osUser cannot be empty", ErrInvalidName)
	}
	if strings.Contains(trimmed, `\`) {
		// Windows principal form: exactly one backslash, both parts
		// non-empty, each part within the character set and the length
		// this function's own doc comment has always promised.
		//
		// Until 1.3 only the backslash and the non-emptiness were
		// checked, and that was survivable: the value reached here from
		// an administrator typing it into `machines.enrol-code`, so the
		// laxity was a gap between the comment and the code rather than
		// a way in. 1.3 moved the field to the ENROLLING MACHINE's own
		// report (SPEC §3.4), and the enrolling machine is whoever holds
		// an invitation — so a 200 kB "principal" became something a
		// stranger could write into state.json, permanently, and into
		// every journal line about it. The POSIX branch below was bounded
		// all along; this branch simply never was.
		parts := strings.Split(trimmed, `\`)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("%w: osUser %q must be in format DOMAIN\\name or MACHINE\\name (Windows), or a POSIX local name ^[a-z_][a-z0-9_-]{0,31}$ (Linux/macOS)", ErrInvalidName, clipName(user))
		}
		for _, part := range parts {
			if len(part) > 64 {
				return fmt.Errorf("%w: osUser %q has a %d-character part; each half of DOMAIN\\name is at most 64", ErrInvalidName, clipName(user), len(part))
			}
			for i := 0; i < len(part); i++ {
				if !windowsPrincipalByte(part[i]) {
					return fmt.Errorf("%w: osUser %q contains %q — a Windows principal allows only ASCII letters, digits and . _ - @ $", ErrInvalidName, clipName(user), part[i])
				}
			}
		}
		return nil
	}
	// POSIX local name form: lowercase ASCII only,
	// ^[a-z_][a-z0-9_-]{0,31}$ — start must be a letter or
	// underscore; digits and dashes only after the first char.
	if len(trimmed) > 32 {
		return fmt.Errorf("%w: osUser %q must match POSIX local name ^[a-z_][a-z0-9_-]{0,31}$ (32-char bound)", ErrInvalidName, clipName(user))
	}
	c := trimmed[0]
	if !(c >= 'a' && c <= 'z' || c == '_') {
		return fmt.Errorf("%w: osUser %q must start with a lowercase letter or underscore (POSIX local name)", ErrInvalidName, clipName(user))
	}
	for i := 1; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return fmt.Errorf("%w: osUser %q contains %q — POSIX local names allow only [a-z0-9_-] after the first character", ErrInvalidName, clipName(user), c)
		}
	}
	return nil
}

// windowsPrincipalByte reports whether one byte may appear in either
// half of a DOMAIN\name principal: ASCII letters, digits, and the four
// punctuation marks Windows account and domain names actually use.
func windowsPrincipalByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.', c == '_', c == '-', c == '@', c == '$':
		return true
	}
	return false
}

// clipName bounds a caller-supplied string before it goes into a
// refusal. Every refusal in this file quotes the value that was
// refused, which is the right thing to do for a name a person mistyped
// and the wrong thing for a name a stranger made 200 kB long: the
// refusal text travels onward into the journal and into whatever the
// caller sees, and neither should be a place where the length of an
// input decides the length of a record.
//
// The bound is above every valid length this file enforces, so a
// legitimate value is never clipped and only a refused one ever is.
func clipName(s string) string {
	const cap = 64
	if len(s) <= cap {
		return s
	}
	return s[:cap] + "… (" + strconv.Itoa(len(s)) + " bytes)"
}

// DecodeKeyBlob extracts the wire-format blob of an authorized_keys line.
//
// The blob is the only part that matters: OpenSSH hands PublicKeyCallback the decoded
// key, and both the fingerprint and the identity of a key follow from the blob alone.
// The optional type prefix and the trailing comment are decoration - "ssh-ed25519 B",
// "ssh-rsa B", bare "B" and "ssh-ed25519 B user@host" are one and the same key.
// A line whose blob does not decode is not a key and is rejected here; hashing its
// text instead would mint a fingerprint for a key SSH can never present.
func DecodeKeyBlob(pub string) ([]byte, error) {
	trimmed := strings.TrimSpace(pub)
	fields := strings.Fields(trimmed)
	var encoded string
	switch {
	case len(fields) >= 2:
		encoded = fields[1]
	case len(fields) == 1:
		encoded = fields[0]
	default:
		return nil, fmt.Errorf("%w: public key is empty", ErrInvalidKey)
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 body does not decode: %v", ErrInvalidKey, err)
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("%w: public key body is empty", ErrInvalidKey)
	}
	return blob, nil
}

// ComputeFingerprint computes the standard OpenSSH SHA256 fingerprint of a public key.
// It is computed from the decoded blob and from nothing else, so that it matches what
// PublicKeyCallback will compute for the key presented on the wire (§6.1).
func ComputeFingerprint(pub string) (string, error) {
	blob, err := DecodeKeyBlob(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:]), nil
}

// blobAlgorithm returns the algorithm name stored inside an SSH wire-format blob
// (4-byte big-endian length, then the name).
func blobAlgorithm(blob []byte) (string, bool) {
	if len(blob) < 4 {
		return "", false
	}
	n := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if n <= 0 || n > 64 || 4+n > len(blob) {
		return "", false
	}
	return string(blob[4 : 4+n]), true
}

// ValidateKeyMaterial checks that a public key line is a key at all and that its type
// prefix, when present, is not lying about the blob it carries.
func ValidateKeyMaterial(pub string) error {
	blob, err := DecodeKeyBlob(pub)
	if err != nil {
		return err
	}
	alg, ok := blobAlgorithm(blob)
	if !ok {
		return fmt.Errorf("%w: %.24q... is not an SSH wire-format public key", ErrInvalidKey, strings.TrimSpace(pub))
	}
	fields := strings.Fields(strings.TrimSpace(pub))
	if len(fields) >= 2 && fields[0] != alg {
		return fmt.Errorf("%w: key is labelled %q but its blob is %q", ErrInvalidKey, fields[0], alg)
	}
	return nil
}

// ValidateDeadlinePair validates that an idle deadline does not exceed a hard ceiling deadline.
// Directly mirrors BadDeadlines from umtunnel/Middle.cs (line 420).
// Does not collapse zero times into absent (Defect 7).
func ValidateDeadlinePair(idle, ceiling *ZonedTime) error {
	if idle == nil || ceiling == nil {
		return nil
	}
	if idle.After(ceiling.Time) {
		return fmt.Errorf("%w: idle deadline (%s) is after ceiling deadline (%s)", ErrInconsistentDeadlines, idle, ceiling)
	}
	return nil
}

// checkFreshDoorDeadlines is the write-path rule about door deadlines: a deadline
// assigned or changed by this transaction must be strictly in the future.
//
// Validate (above) deliberately does not look at the clock. A state.json that lay on
// disk overnight legitimately holds deadlines that have since passed - the doorwatch
// closes those when the gateway comes back up - and refusing to read such a file would
// keep the gateway down after every idle period. A deadline already in the file is
// history; Validate checks only that the two deadlines of a door do not contradict
// each other.
//
// A *newly assigned* deadline is a different thing: it is a promise about the future
// made by whoever opens or re-arms the door, and a promise that is already due is a
// defect - from that moment behaviour depends on whether the doorwatch or the next
// login attempt happens to read the clock first.
//
// This function therefore runs only on the two paths through which a deadline can
// enter the persisted state, Store.Set and Store.Update. A deadline counts as assigned
// here if the machine had no door, or a door with another id, or if this very deadline
// is absent from the door the store already holds or names another moment (compared by
// instant, so the same deadline written in another zone offset counts as carried over).
// A deadline carried over unchanged is never fresh, whatever the clock says: rewriting
// an unrelated field must not make the state unwritable, and an aged deadline that
// this transaction did not touch is not this transaction's claim.
func checkFreshDoorDeadlines(prev, draft *State, now time.Time) error {
	if draft == nil {
		return nil
	}

	prevDoors := make(map[string]*Door, len(prev.Machines))
	if prev != nil {
		for i := range prev.Machines {
			if d := prev.Machines[i].Door; d != nil {
				prevDoors[prev.Machines[i].ID] = d
			}
		}
	}

	for i := range draft.Machines {
		m := &draft.Machines[i]
		if m.Door == nil {
			continue
		}

		// What this machine's door held before the transaction. A different door id in
		// the draft means the old deadlines were re-stated for a new door, i.e. both
		// fields count as assigned here.
		var wasIdle, wasCeiling *ZonedTime
		if old := prevDoors[m.ID]; old != nil && old.ID == m.Door.ID {
			wasIdle, wasCeiling = old.ClosesWhenIdle, old.ClosesAtTheLatest
		}

		fields := []struct {
			name string
			was  *ZonedTime
			now  *ZonedTime
		}{
			{"closesWhenIdle", wasIdle, m.Door.ClosesWhenIdle},
			{"closesAtTheLatest", wasCeiling, m.Door.ClosesAtTheLatest},
		}
		for _, f := range fields {
			if f.now == nil || (f.was != nil && f.now.Equal(f.was.Time)) {
				continue // absent, or carried over unchanged: not assigned by this transaction
			}
			if !f.now.After(now) {
				return fmt.Errorf("%w: machine %q door %q assigns %s to %s, which is not in the future (now %s)",
					ErrDeadlineInThePast, m.ID, m.Door.ID, f.name, f.now.String(), now.Format(time.RFC3339Nano))
			}
		}
	}
	return nil
}

// Validate checks internal consistency, referential integrity, and specification adherence of the State.
func (s *State) Validate() error {
	if s == nil {
		return fmt.Errorf("state is nil")
	}

	if s.Schema != CurrentSchema {
		return &SchemaError{FileSchema: s.Schema, SupportedSchema: CurrentSchema}
	}

	personNames := make(map[string]bool)
	// The fingerprint of the decoded blob is the one and only key of uniqueness, for
	// people and machines alike: §6.1 wants fingerprint -> (person|machine, role) to be
	// a function, and a function may not map one fingerprint onto two identities.
	seenFingerprints := make(map[string]string) // fingerprint -> owner description

	for _, p := range s.People {
		if err := ValidateName(p.Name); err != nil {
			return fmt.Errorf("invalid person name: %w", err)
		}
		if personNames[p.Name] {
			return fmt.Errorf("duplicate person name: %q", p.Name)
		}
		personNames[p.Name] = true

		if p.Role != "user" && p.Role != "admin" {
			return fmt.Errorf("person %q has invalid role %q (must be 'user' or 'admin')", p.Name, p.Role)
		}

		for _, k := range p.Keys {
			if strings.TrimSpace(k.Fingerprint) == "" {
				return fmt.Errorf("person %q has key with empty fingerprint", p.Name)
			}
			if strings.TrimSpace(k.Pub) == "" {
				return fmt.Errorf("person %q has key with empty public key body", p.Name)
			}
			if k.Added.IsZero() {
				return fmt.Errorf("person %q key %q has zero or missing added timestamp", p.Name, k.Fingerprint)
			}
			if err := ValidateKeyMaterial(k.Pub); err != nil {
				return fmt.Errorf("person %q key %q: %w", p.Name, k.Fingerprint, err)
			}

			// The fingerprint written in the file is a claim, not evidence: recompute it
			// from the key itself and refuse a record that claims someone else's
			// fingerprint - the presenter of that key would be identified as this person.
			computed, err := ComputeFingerprint(k.Pub)
			if err != nil {
				return fmt.Errorf("person %q key %q: %w", p.Name, k.Fingerprint, err)
			}
			if computed != k.Fingerprint {
				return fmt.Errorf("person %q key records fingerprint %q but its public key hashes to %q (fingerprint must be derived from the key, not declared)", p.Name, k.Fingerprint, computed)
			}

			if owner, exists := seenFingerprints[computed]; exists {
				return fmt.Errorf("duplicate key fingerprint %q shared between %s and person %q (keys must be uniquely owned)", computed, owner, p.Name)
			}
			seenFingerprints[computed] = fmt.Sprintf("person %q", p.Name)
		}
	}

	machineIDs := make(map[string]string)   // id -> owning machine id (itself)
	machineNames := make(map[string]string) // name -> owning machine id
	machineFPs := make(map[string]string)   // machine id -> fingerprint of its machineKey

	for _, m := range s.Machines {
		if err := ValidateName(m.ID); err != nil {
			return fmt.Errorf("invalid machine ID: %w", err)
		}
		if err := ValidateName(m.Name); err != nil {
			return fmt.Errorf("invalid machine name: %w", err)
		}
		if _, dup := machineIDs[m.ID]; dup {
			return fmt.Errorf("duplicate machine ID: %q", m.ID)
		}
		if owner, dup := machineNames[m.Name]; dup {
			return fmt.Errorf("duplicate machine name: %q (already used by machine %q)", m.Name, owner)
		}
		machineIDs[m.ID] = m.ID
		machineNames[m.Name] = m.ID

		if m.State != "enrolled" && m.State != "verified" {
			return fmt.Errorf("machine %q has invalid state %q (must be 'enrolled' or 'verified')", m.ID, m.State)
		}
		if strings.TrimSpace(m.MachineKey) == "" {
			return fmt.Errorf("machine %q has empty machineKey", m.ID)
		}

		// The two §4.3 closed sets (IAMT-91 step 1). Empty is tolerated HERE and
		// only here, because a machine record read from a file written before
		// these fields existed carries neither, and both disk boundaries
		// (parseStateBytes on the way in, commitLocked on the way out) fill in
		// the default before the value is validated or written. Anything
		// non-empty has to be a member: the door rule of §4.3 compares
		// hostKeyStatus against "mismatch" and the login rule picks
		// verifiedOsUser by osUserStatus, so a value outside the set - a typo, a
		// capital, a trailing space - would disable one of those guards in
		// silence instead of failing loudly.
		if m.HostKeyStatus != "" && !IsValidHostKeyStatus(m.HostKeyStatus) {
			return fmt.Errorf("machine %q has invalid hostKeyStatus %q (must be %q, %q or %q)",
				m.ID, m.HostKeyStatus, HostKeyStatusUnverified, HostKeyStatusMatch, HostKeyStatusMismatch)
		}
		// Host-key verdict invariant (IAMT-132): unverified means there is no
		// observed key; match means both pinned and observed keys exist and their
		// decoded SSH blobs are equal; mismatch means both keys exist. Mismatch
		// deliberately does not require unequal blobs: it is sticky, so a later
		// matching probe may leave the earlier observed key in place.
		// Apply these rules only to a non-empty status so legacy in-memory records
		// remain tolerated until the disk boundary supplies their default.
		if m.HostKeyStatus != "" {
			switch m.HostKeyStatus {
			case HostKeyStatusUnverified:
				if m.ObservedSSHDHostKey != nil {
					return fmt.Errorf("machine %q has hostKeyStatus %q with an observed SSHD host key", m.ID, m.HostKeyStatus)
				}
			case HostKeyStatusMatch, HostKeyStatusMismatch:
				if m.ObservedSSHDHostKey == nil {
					return fmt.Errorf("machine %q has hostKeyStatus %q without an observed SSHD host key", m.ID, m.HostKeyStatus)
				}
				if m.SSHDHostKey == nil {
					return fmt.Errorf("machine %q has hostKeyStatus %q without a pinned SSHD host key", m.ID, m.HostKeyStatus)
				}
				if m.HostKeyStatus == HostKeyStatusMatch {
					pinned, err := DecodeKeyBlob(*m.SSHDHostKey)
					if err != nil {
						return fmt.Errorf("machine %q sshdHostKey: %w", m.ID, err)
					}
					observed, err := DecodeKeyBlob(*m.ObservedSSHDHostKey)
					if err != nil {
						return fmt.Errorf("machine %q observedSSHDHostKey: %w", m.ID, err)
					}
					if !bytes.Equal(pinned, observed) {
						return fmt.Errorf("machine %q has hostKeyStatus %q but observedSSHDHostKey does not match sshdHostKey", m.ID, m.HostKeyStatus)
					}
				}
			}
		}
		if m.OSUserStatus != "" && !IsValidOSUserStatus(m.OSUserStatus) {
			return fmt.Errorf("machine %q has invalid osUserStatus %q (must be %q, %q or %q)",
				m.ID, m.OSUserStatus, OSUserStatusPending, OSUserStatusVerified, OSUserStatusRejected)
		}
		if err := ValidateKeyMaterial(m.MachineKey); err != nil {
			return fmt.Errorf("machine %q machineKey: %w", m.ID, err)
		}

		fp, err := ComputeFingerprint(m.MachineKey)
		if err != nil {
			return fmt.Errorf("machine %q machineKey: %w", m.ID, err)
		}
		if owner, exists := seenFingerprints[fp]; exists {
			return fmt.Errorf("machine %q key fingerprint %q conflicts with %s (keys must be uniquely owned)", m.ID, fp, owner)
		}
		seenFingerprints[fp] = fmt.Sprintf("machine %q", m.ID)
		machineFPs[m.ID] = fp

		// Validate osUser format per §4.3 (Defect 15)
		if err := ValidateOSUser(m.OSUser); err != nil {
			return fmt.Errorf("machine %q: %w", m.ID, err)
		}

		if m.Door != nil {
			if strings.TrimSpace(m.Door.ID) == "" {
				return fmt.Errorf("machine %q door has empty id", m.ID)
			}
			if strings.TrimSpace(m.Door.PubKey) == "" {
				return fmt.Errorf("machine %q door has empty pubkey", m.ID)
			}
			// The door key is key material the gateway hands out (§6.3, layer 0), so it
			// shares the one namespace of fingerprints with people and machines.
			if err := ValidateKeyMaterial(m.Door.PubKey); err != nil {
				return fmt.Errorf("machine %q door pubkey: %w", m.ID, err)
			}
			doorFP, err := ComputeFingerprint(m.Door.PubKey)
			if err != nil {
				return fmt.Errorf("machine %q door pubkey: %w", m.ID, err)
			}
			if owner, exists := seenFingerprints[doorFP]; exists {
				return fmt.Errorf("machine %q door key fingerprint %q conflicts with %s (keys must be uniquely owned)", m.ID, doorFP, owner)
			}
			seenFingerprints[doorFP] = fmt.Sprintf("door %q of machine %q", m.Door.ID, m.ID)
			if m.Door.Opened.IsZero() {
				return fmt.Errorf("machine %q door has zero opened timestamp", m.ID)
			}
			if m.Door.Sessions != nil && *m.Door.Sessions < 0 {
				return fmt.Errorf("machine %q door has negative session count: %d", m.ID, *m.Door.Sessions)
			}

			// Validate deadline pair if present on door (Defect 7)
			if err := ValidateDeadlinePair(m.Door.ClosesWhenIdle, m.Door.ClosesAtTheLatest); err != nil {
				return fmt.Errorf("machine %q door deadlines: %w", m.ID, err)
			}
			if m.Door.ClosesWhenIdle != nil && m.Door.Opened.After(m.Door.ClosesWhenIdle.Time) {
				return fmt.Errorf("%w: machine %q door opened (%s) is after closesWhenIdle (%s)", ErrInconsistentDeadlines, m.ID, m.Door.Opened, m.Door.ClosesWhenIdle)
			}
			if m.Door.ClosesAtTheLatest != nil && m.Door.Opened.After(m.Door.ClosesAtTheLatest.Time) {
				return fmt.Errorf("%w: machine %q door opened (%s) is after closesAtTheLatest (%s)", ErrInconsistentDeadlines, m.ID, m.Door.Opened, m.Door.ClosesAtTheLatest)
			}
		}

		if m.EnrolPending != nil {
			// The pending entry is what makes the one-shot secret usable;
			// garbage here means a corrupted state.json that cannot grant
			// anything sensible. The secret hash is raw HMAC output, so it
			// is exactly 32 bytes; the public key must be a parseable SSH
			// ed25519 line (PROTOCOL §3.2); the expiry must be a zoned time.
			if len(m.EnrolPending.SecretHash) != 32 {
				return fmt.Errorf("machine %q enrolPending has malformed secretHash (got %d bytes, want 32)", m.ID, len(m.EnrolPending.SecretHash))
			}
			if strings.TrimSpace(m.EnrolPending.PublicKey) == "" {
				return fmt.Errorf("machine %q enrolPending has empty public key", m.ID)
			}
			if err := ValidateKeyMaterial(m.EnrolPending.PublicKey); err != nil {
				return fmt.Errorf("machine %q enrolPending public key: %w", m.ID, err)
			}
			if m.EnrolPending.Expires.IsZero() {
				return fmt.Errorf("machine %q enrolPending has zero expiry", m.ID)
			}
			// The ephemeral public key lives in the same fingerprint namespace as
			// people, machines and doors: a key offered here is the one the SSH
			// PublicKeyCallback will accept, so its fingerprint MUST NOT already
			// belong to a different identity (PROTOCOL §6.1).
			epFP, err := ComputeFingerprint(m.EnrolPending.PublicKey)
			if err != nil {
				return fmt.Errorf("machine %q enrolPending fingerprint: %w", m.ID, err)
			}
			if owner, exists := seenFingerprints[epFP]; exists {
				return fmt.Errorf("machine %q enrolPending fingerprint %q conflicts with %s (keys must be uniquely owned)", m.ID, epFP, owner)
			}
			seenFingerprints[epFP] = fmt.Sprintf("enrolPending of machine %q", m.ID)
		}
	}

	if s.BootstrapPending != nil {
		if len(s.BootstrapPending.SecretHash) != 32 {
			return fmt.Errorf("bootstrapPending has malformed secretHash (got %d bytes, want 32)", len(s.BootstrapPending.SecretHash))
		}
		if strings.TrimSpace(s.BootstrapPending.PublicKey) == "" {
			return fmt.Errorf("bootstrapPending has empty public key")
		}
		if err := ValidateKeyMaterial(s.BootstrapPending.PublicKey); err != nil {
			return fmt.Errorf("bootstrapPending public key: %w", err)
		}
		if s.BootstrapPending.Expires.IsZero() {
			return fmt.Errorf("bootstrapPending has zero expiry")
		}
		bpFP, err := ComputeFingerprint(s.BootstrapPending.PublicKey)
		if err != nil {
			return fmt.Errorf("bootstrapPending fingerprint: %w", err)
		}
		if owner, exists := seenFingerprints[bpFP]; exists {
			return fmt.Errorf("bootstrapPending fingerprint %q conflicts with %s (keys must be uniquely owned)", bpFP, owner)
		}
		seenFingerprints[bpFP] = "bootstrapPending"
	}

	pendingHashes := make(map[[32]byte]string)
	for _, pe := range s.PendingEnrolments {
		// IAMT-336 / 1.3: pending enrolments are unbound (no machine
		// name, no osUser at mint time). Legacy state.json files written
		// before IAMT-336 may still carry Name / OSUser fields; the
		// struct keeps them with `omitempty` so we ignore them here.
		// The Name / OSUser themselves are NOT consulted for collision
		// (no name binding to collide against) — the secret hash is.
		if len(pe.SecretHash) != 32 {
			return fmt.Errorf("pendingEnrolment has malformed secretHash (got %d bytes, want 32)", len(pe.SecretHash))
		}
		if other, dup := pendingHashes[pe.SecretHash]; dup {
			return fmt.Errorf("duplicate pendingEnrolment secretHash (also in %s)", other)
		}
		pendingHashes[pe.SecretHash] = "pendingEnrolment"
		if strings.TrimSpace(pe.PublicKey) == "" {
			return fmt.Errorf("pendingEnrolment has empty public key")
		}
		if err := ValidateKeyMaterial(pe.PublicKey); err != nil {
			return fmt.Errorf("pendingEnrolment public key: %w", err)
		}
		if pe.Expires.IsZero() {
			return fmt.Errorf("pendingEnrolment has zero expiry")
		}
		epFP, err := ComputeFingerprint(pe.PublicKey)
		if err != nil {
			return fmt.Errorf("pendingEnrolment fingerprint: %w", err)
		}
		if owner, exists := seenFingerprints[epFP]; exists {
			return fmt.Errorf("pendingEnrolment fingerprint %q conflicts with %s (keys must be uniquely owned)", epFP, owner)
		}
		seenFingerprints[epFP] = "pendingEnrolment"
	}

	// Machine ids and machine names are separate namespaces and may not cross: if one
	// machine were named "alpha" while another carried the id "alpha", a reference to
	// "alpha" would resolve to two different boxes depending on who resolves it.
	// A machine using its own id as its name is the ordinary case and stays legal.
	for name, owner := range machineNames {
		if idOwner, exists := machineIDs[name]; exists && idOwner != owner {
			return fmt.Errorf("machine %q is named %q, which is the id of machine %q (machine ids and names may not overlap)", owner, name, idOwner)
		}
	}

	seenGoalPairs := make(map[string]bool, len(s.Goals))
	for _, goal := range s.Goals {
		if err := ValidateName(goal.Person); err != nil {
			return fmt.Errorf("invalid goal person name: %w", err)
		}
		if err := ValidateName(goal.Machine); err != nil {
			return fmt.Errorf("invalid goal machine id: %w", err)
		}
		if !personNames[goal.Person] {
			return fmt.Errorf("goal references non-existent person %q", goal.Person)
		}
		if _, exists := machineIDs[goal.Machine]; !exists {
			return fmt.Errorf("goal references non-existent machine %q", goal.Machine)
		}
		pairKey := goal.Person + "\x00" + goal.Machine
		if seenGoalPairs[pairKey] {
			return fmt.Errorf("duplicate goal for %s -> %s", goal.Person, goal.Machine)
		}
		seenGoalPairs[pairKey] = true
		if err := ValidateGoalText(goal.Current); err != nil {
			return fmt.Errorf("goal %s -> %s current goal: %w", goal.Person, goal.Machine, err)
		}
		if goal.Current != "" {
			if len(goal.History) == 0 || goal.History[0].Goal != goal.Current {
				return fmt.Errorf("goal %s -> %s current goal is not the newest history entry", goal.Person, goal.Machine)
			}
		}
		if len(goal.History) > MaxGoalHistory {
			return fmt.Errorf("goal %s -> %s has %d history entries; maximum is %d", goal.Person, goal.Machine, len(goal.History), MaxGoalHistory)
		}
		for i, entry := range goal.History {
			if strings.TrimSpace(entry.Goal) == "" {
				return fmt.Errorf("goal %s -> %s history entry %d has an empty goal", goal.Person, goal.Machine, i)
			}
			if err := ValidateGoalText(entry.Goal); err != nil {
				return fmt.Errorf("goal %s -> %s history entry %d: %w", goal.Person, goal.Machine, i, err)
			}
			if entry.SetAt.IsZero() {
				return fmt.Errorf("goal %s -> %s history entry %d has zero setAt", goal.Person, goal.Machine, i)
			}
		}
	}

	// The recent-command buffer (IAMT-409) obeys the same referential
	// integrity as goals. The character budget is a write-time rule of
	// RecordCommand, not a load-time one: the gateway re-trims against its
	// live configuration when it builds a classifier request, and a
	// hand-edited oversized entry ages out on the next recorded command.
	seenHistoryPairs := make(map[string]bool, len(s.CommandHistory))
	for _, hist := range s.CommandHistory {
		if err := ValidateName(hist.Person); err != nil {
			return fmt.Errorf("invalid recent-command person name: %w", err)
		}
		if err := ValidateName(hist.Machine); err != nil {
			return fmt.Errorf("invalid recent-command machine id: %w", err)
		}
		if !personNames[hist.Person] {
			return fmt.Errorf("recent-command history references non-existent person %q", hist.Person)
		}
		if _, exists := machineIDs[hist.Machine]; !exists {
			return fmt.Errorf("recent-command history references non-existent machine %q", hist.Machine)
		}
		pairKey := hist.Person + "\x00" + hist.Machine
		if seenHistoryPairs[pairKey] {
			return fmt.Errorf("duplicate recent-command history for %s -> %s", hist.Person, hist.Machine)
		}
		seenHistoryPairs[pairKey] = true
		if len(hist.Entries) > MaxRecentCommands {
			return fmt.Errorf("recent-command history for %s -> %s has %d entries; maximum is %d",
				hist.Person, hist.Machine, len(hist.Entries), MaxRecentCommands)
		}
		for i, entry := range hist.Entries {
			if strings.TrimSpace(entry.Command) == "" {
				return fmt.Errorf("recent-command history %s -> %s entry %d has an empty command",
					hist.Person, hist.Machine, i)
			}
			if entry.At.IsZero() {
				return fmt.Errorf("recent-command history %s -> %s entry %d has zero at",
					hist.Person, hist.Machine, i)
			}
		}
	}

	if s.ExternalRiskKey != nil {
		if !s.ExternalRiskKey.Present {
			if s.ExternalRiskKey.Fingerprint != "" {
				return fmt.Errorf("externalRiskKey is absent but has a fingerprint")
			}
		} else if strings.TrimSpace(s.ExternalRiskKey.Fingerprint) == "" {
			return fmt.Errorf("externalRiskKey is present but has no fingerprint")
		} else if len(s.ExternalRiskKey.Fingerprint) > 128 {
			return fmt.Errorf("externalRiskKey fingerprint is too long")
		}
	}

	seenGrantPairs := make(map[string]bool, len(s.Grants))

	for _, g := range s.Grants {
		if err := ValidateName(g.Person); err != nil {
			return fmt.Errorf("invalid grant person name: %w", err)
		}
		if err := ValidateName(g.Machine); err != nil {
			return fmt.Errorf("invalid grant machine id: %w", err)
		}

		// Referential integrity checks (§4.3, Defect 3)
		if !personNames[g.Person] {
			return fmt.Errorf("grant references non-existent person %q", g.Person)
		}
		if _, exists := machineIDs[g.Machine]; !exists {
			if owner, byName := machineNames[g.Machine]; byName {
				return fmt.Errorf("grant references machine %q by name; grants must reference the machine id (%q) so that renaming or replacing a box cannot move the grant", g.Machine, owner)
			}
			return fmt.Errorf("grant references non-existent machine %q", g.Machine)
		}

		// A grant is bound to the identity of the machine, i.e. to the key it presented
		// when the grant was issued - not to the id, which can be handed to new hardware.
		if strings.TrimSpace(g.MachineKeyFingerprint) == "" {
			return fmt.Errorf("grant %s -> %s does not pin the machine key fingerprint (a grant must name the machine identity it was issued against)", g.Person, g.Machine)
		}
		if current := machineFPs[g.Machine]; current != g.MachineKeyFingerprint {
			return fmt.Errorf("grant %s -> %s is pinned to machine key %q but machine %q now presents %q (the grant must be revoked and re-issued)", g.Person, g.Machine, g.MachineKeyFingerprint, g.Machine, current)
		}

		pairKey := g.Person + "\x00" + g.Machine
		if seenGrantPairs[pairKey] {
			return fmt.Errorf("duplicate grant for %s -> %s (a pair may hold at most one grant; two grants would make the deadline and caps of the pair ambiguous)", g.Person, g.Machine)
		}
		seenGrantPairs[pairKey] = true

		if len(g.Caps) != 1 || (g.Caps[0] != "shell" && g.Caps[0] != "exec") {
			return fmt.Errorf("grant for %s -> %s must have caps [\"shell\"] or [\"exec\"] in 1.0", g.Person, g.Machine)
		}
	}

	return nil
}
