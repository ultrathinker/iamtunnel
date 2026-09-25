// Package auth authenticates gateway connections (SPEC 6.1, 5.1): it
// maps key fingerprints to subjects through a PURE PublicKeyCallback -
// no journal, no counters, no state changes, because the callback runs
// on unsigned probes too - pulls the identity from the Permissions
// x/crypto returns with NewServerConn (never from "the last offered
// key"), requires the person named in the username to own the key that
// actually authenticated, enforces the key algorithm policy and the
// MaxAuthTries floor, and hands rate limiting and events to explicit
// collaborators. Storage and journal are interfaces declared here and
// implemented by their owning packages. Time is always injected; the
// package never calls time.Now.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// Role says which kind of subject a key belongs to (SPEC 4.3): a person
// or a machine opening its tunnel. The two extra values cover the
// one-shot bootstrap paths (PROTOCOL §3.2, §3.3): the SSH handshake
// may resolve a key to a pending enrol code or to the bootstrap token,
// and the rest of the runtime treats them as separate principals with
// the right of exactly one wire operation each (the ones PROTOCOL §3.2
// and §3.3 explicitly list, and nothing else).
type Role string

const (
	RolePerson    Role = "person"
	RoleMachine   Role = "machine"
	RoleEnrol     Role = "enrol"
	RoleBootstrap Role = "bootstrap"
	RolePairing   Role = "pairing"
)

// Subject is what a fingerprint resolves to.
type Subject struct {
	Name string // person name, or machine id for RoleMachine
	Role Role
}

// Lookup is the slice of gateway state the pure callback reads. The
// state package implements it; the auth package owns no storage.
//
// Resolve must answer BOTH the persistent identities (people, machines)
// and the two short-lived identities (enrol-pending, bootstrap-pending):
// the SSH handshake happens before any business logic runs, so the
// runtime needs to know which of these three kinds of principal is on
// the wire just from the offered key fingerprint. The pending entries
// are read here too, exactly because the secret has not been presented
// yet — that comes later, in the "enrol"/"admin.claim" exec body.
type Lookup interface {
	// Resolve maps a SHA256 fingerprint to its subject. ok is false
	// for keys the gateway does not know.
	Resolve(fingerprint string) (Subject, bool, error)
}

// Typed refusal reasons; errors.Is-compatible sentinels.
var (
	ErrUnknownKey     = errors.New("auth: unknown key")
	ErrNameMismatch   = errors.New("auth: username does not match the key owner")
	ErrBadAlgorithm   = errors.New("auth: key algorithm not accepted")
	ErrBadPermissions = errors.New("auth: identity missing from permissions")
	ErrAuthFailed     = errors.New("auth: authentication failed")
)

// AuthLimits are parameters, not constants (SPEC 6.1): session caps per
// person and per machine, and the time a connection may spend inside
// the handshake before it is torn down. Zero session caps mean
// unlimited; a non-positive handshake timeout is rejected at construction.
type AuthLimits struct {
	MaxSessionsPerPerson  int
	MaxSessionsPerMachine int
	HandshakeTimeout      time.Duration
}

// EventSink is the journal seam. The pure callback never touches it;
// post-handshake code (FinishAuth) and the rate limiter do.
type EventSink interface {
	AuthAccepted(addr, user, fingerprint, subject string, role Role)
	AuthDenied(addr, user, fingerprint, reason string)
	RateExceeded(addr, fingerprint string, until time.Time)
}

// Handler wires the pure resolution logic to a state lookup.
type Handler struct {
	lookup Lookup
	limits AuthLimits
}

// NewHandler validates the parameters and returns the resolver.
func NewHandler(lookup Lookup, limits AuthLimits) (*Handler, error) {
	if lookup == nil {
		return nil, errors.New("auth: lookup is required")
	}
	if limits.MaxSessionsPerPerson < 0 || limits.MaxSessionsPerMachine < 0 {
		return nil, errors.New("auth: negative session limit")
	}
	if limits.HandshakeTimeout <= 0 {
		return nil, errors.New("auth: handshake timeout must be positive")
	}
	return &Handler{lookup: lookup, limits: limits}, nil
}

// Limits returns the limits this handler was built with.
func (h *Handler) Limits() AuthLimits { return h.limits }

// maxAuthTries is the SPEC 6.1 value: 32. The default six is an ambush:
// a person's ssh-agent walks every key it holds, and anyone carrying
// more than six - a second team key, an old laptop key, a hardware
// token - is dropped mid-walk with no visible reason. Thirty-two covers
// every realistic agent inventory while staying far below any brute
// force that the rate limiter exists for.
const maxAuthTries = 32

// Fingerprint is the OpenSSH-style SHA256 fingerprint of a key.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Identity is the authenticated subject, taken from Permissions - the
// record the PURE callback wrote for the key that actually completed
// the handshake. Anything read from the wire (username, offered keys)
// never reaches this struct.
type Identity struct {
	Subject     Subject
	Fingerprint string
}

// extension keys inside ssh.Permissions.
const (
	extSubject       = "iamtunnel-subject"
	extRole          = "iamtunnel-role"
	extFingerprint   = "iamtunnel-fingerprint"
	extPairingWindow = "iamtunnel-pairing-window"
)

// Resolve is the pure heart of authentication: username and key in,
// identity or a typed refusal out. It reads the lookup and nothing
// else; every path returns without touching any state, which is what
// makes it safe to call on unsigned probes (SPEC 6.1). A key that is
// known but does not match the username is refused exactly like an
// unknown one so the client walks on to its next key.
func (h *Handler) Resolve(username string, key ssh.PublicKey) (Identity, error) {
	if err := AcceptKey(key); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrBadAlgorithm, err)
	}
	fp := Fingerprint(key)
	subject, ok, err := h.lookup.Resolve(fp)
	if err != nil {
		return Identity{}, err
	}
	if !ok {
		return Identity{}, fmt.Errorf("%w: %s", ErrUnknownKey, fp)
	}
	switch subject.Role {
	case RolePerson:
		parsed, perr := ParseUsername(username)
		if perr != nil {
			return Identity{}, fmt.Errorf("%w: %w (key belongs to %q, username is %q)", ErrNameMismatch, perr, subject.Name, username)
		}
		if parsed.Person != subject.Name {
			return Identity{}, fmt.Errorf("%w: key belongs to %q, username is %q", ErrNameMismatch, subject.Name, username)
		}
	case RoleMachine:
		id, perr := ParseMachineUsername(username)
		if perr != nil {
			return Identity{}, fmt.Errorf("%w: %w (key belongs to machine %q, username is %q)", ErrNameMismatch, perr, subject.Name, username)
		}
		if id != subject.Name {
			return Identity{}, fmt.Errorf("%w: key belongs to machine %q, username is %q", ErrNameMismatch, subject.Name, username)
		}
	case RoleEnrol:
		// PROTOCOL §2.1: enrol-login is exactly the bytes "enrol", with
		// no machine suffix. Anything else (including "enrol:win01") is
		// rejected at the username-parsing layer below; here we only
		// confirm the bytes match the reserved literal.
		if username != "enrol" {
			return Identity{}, fmt.Errorf("%w: enrol-login requires username %q, got %q", ErrNameMismatch, "enrol", username)
		}
	case RoleBootstrap:
		// Same rule as enrol: PROTOCOL §2.1 reserves "bootstrap" as a
		// single byte-exact login form.
		if username != "bootstrap" {
			return Identity{}, fmt.Errorf("%w: bootstrap-login requires username %q, got %q", ErrNameMismatch, "bootstrap", username)
		}
	case RolePairing:
		// PROTOCOL §3.4: pairing-login is exactly the bytes "pairing". It
		// never resolves through the persistent state (a pairing client
		// carries its own future-admin key), so this case is only reachable
		// through the gateway's pairing-aware PublicKeyCallback wrapper;
		// the rule here keeps the shape check in one place.
		if username != "pairing" {
			return Identity{}, fmt.Errorf("%w: pairing-login requires username %q, got %q", ErrNameMismatch, "pairing", username)
		}
	default:
		return Identity{}, fmt.Errorf("auth: unknown role %q for key %s", subject.Role, fp)
	}
	return Identity{Subject: subject, Fingerprint: fp}, nil
}

// PublicKeyCallback returns the function for ssh.ServerConfig. It is a
// thin wrapper over Resolve: it writes the resolved identity into
// Permissions - the only channel back through NewServerConn - and has
// no other effect. Errors here make x/crypto refuse the key and let the
// client offer the next one.
func (h *Handler) PublicKeyCallback() func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		id, err := h.Resolve(conn.User(), key)
		if err != nil {
			return nil, err
		}
		return &ssh.Permissions{
			Extensions: map[string]string{
				extSubject:     id.Subject.Name,
				extRole:        string(id.Subject.Role),
				extFingerprint: id.Fingerprint,
			},
		}, nil
	}
}

// PairingPermissions builds the Permissions for a pairing-login whose
// future-admin key has fingerprint fp (PROTOCOL §3.4). The subject is
// empty — the pairing client has no name until the PIN lands and the
// person record is created — and the role is RolePairing.
//
// windowBinding is the identity of the window that admitted this login
// (F-12, round-1 review 24.09.2026): the hex of the open window's secret
// hash at handshake time. The exec layer holds the connection to it - a
// connection whose window has since been replaced or stopped is refused
// stale without grading anything, so held connections can never spend
// their wrong PINs on a window they never saw. The gateway's pairing-aware
// PublicKeyCallback wrapper is the only caller: this is the one sanctioned
// way to mint Permissions outside PublicKeyCallback, and keeping it here
// keeps the extension keys in one place.
func PairingPermissions(fp, windowBinding string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			extSubject:       "",
			extRole:          string(RolePairing),
			extFingerprint:   fp,
			extPairingWindow: windowBinding,
		},
	}
}

// PairingWindowBinding reads back what PairingPermissions wrote: the
// identity of the window this pairing-login was admitted for, and whether
// the Permissions carry one at all.
func PairingWindowBinding(p *ssh.Permissions) (string, bool) {
	if p == nil {
		return "", false
	}
	v, ok := p.Extensions[extPairingWindow]
	return v, ok
}

// ServerConfig builds the x/crypto server config: key-only auth with the
// pure callback and MaxAuthTries pinned to the SPEC 6.1 value of 32.
// The ordered KEX/cipher/MAC lists from PROTOCOL §1 are applied here;
// see internal/sshx/policy.go for the single source of truth (IAMT-173).
func (h *Handler) ServerConfig(hostKey ssh.Signer) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		MaxAuthTries: maxAuthTries,
		// NoClientAuth stays false: public key only (SPEC 6.1).
		PublicKeyCallback: h.PublicKeyCallback(),
	}
	cfg.AddHostKey(hostKey)
	sshx.ApplyServerConfig(cfg)
	return cfg
}

// ExtractIdentity reads the identity back out of the Permissions that
// NewServerConn returned. This - not the username, not the last offered
// key - is the only source of who is on the other end (SPEC 6.1).
func ExtractIdentity(perm *ssh.Permissions) (Identity, error) {
	if perm == nil {
		return Identity{}, ErrBadPermissions
	}
	subject, ok := perm.Extensions[extSubject]
	role, okRole := perm.Extensions[extRole]
	fp, okFP := perm.Extensions[extFingerprint]
	if !ok || !okRole || !okFP {
		return Identity{}, fmt.Errorf("%w: extensions incomplete", ErrBadPermissions)
	}
	switch Role(role) {
	case RolePerson, RoleMachine, RoleEnrol, RoleBootstrap, RolePairing:
	default:
		return Identity{}, fmt.Errorf("%w: unknown role %q", ErrBadPermissions, role)
	}
	return Identity{Subject: Subject{Name: subject, Role: Role(role)}, Fingerprint: fp}, nil
}

// VerifyLogin is the second line of defence, run on the post-handshake
// identity: the person named in the username must be the owner of the
// key that authenticated. For a person key the username grammar is
// "<person>" or "<person>:<machine>"; for a machine key exactly
// "machine:<id>"; for the one-shot enrol/bootstrap paths the username
// must be exactly the reserved literal ("enrol" / "bootstrap"). The
// two latter cases do not consult the username for identity — that is
// already pinned by the key — only for shape (SPEC 5.1, 5.2, PROTOCOL
// §2.1).
func VerifyLogin(perm *ssh.Permissions, username string) (Identity, error) {
	id, err := ExtractIdentity(perm)
	if err != nil {
		return Identity{}, err
	}
	switch id.Subject.Role {
	case RolePerson:
		parsed, perr := ParseUsername(username)
		if perr != nil {
			return Identity{}, fmt.Errorf("%w: %v", ErrNameMismatch, perr)
		}
		if parsed.Person != id.Subject.Name {
			return Identity{}, fmt.Errorf("%w: key belongs to %q, username is %q", ErrNameMismatch, id.Subject.Name, username)
		}
	case RoleMachine:
		mid, merr := ParseMachineUsername(username)
		if merr != nil {
			return Identity{}, fmt.Errorf("%w: %v", ErrNameMismatch, merr)
		}
		if mid != id.Subject.Name {
			return Identity{}, fmt.Errorf("%w: key belongs to machine %q, username is %q", ErrNameMismatch, id.Subject.Name, username)
		}
	case RoleEnrol:
		if username != "enrol" {
			return Identity{}, fmt.Errorf("%w: enrol-login requires username %q, got %q", ErrNameMismatch, "enrol", username)
		}
	case RoleBootstrap:
		if username != "bootstrap" {
			return Identity{}, fmt.Errorf("%w: bootstrap-login requires username %q, got %q", ErrNameMismatch, "bootstrap", username)
		}
	case RolePairing:
		if username != "pairing" {
			return Identity{}, fmt.Errorf("%w: pairing-login requires username %q, got %q", ErrNameMismatch, "pairing", username)
		}
	}
	return id, nil
}

// HandshakeDeadline is the moment a connection must have finished
// authenticating by (SPEC 6.1: time to establish a connection). The
// gateway sets it on the accepted net.Conn before NewServerConn; now is
// injected.
func (h *Handler) HandshakeDeadline(now time.Time) time.Time {
	return now.Add(h.limits.HandshakeTimeout)
}

// ErrDenied wraps a denial with the connection context for the journal.
type ErrDenied struct {
	Addr   string
	User   string
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("auth: denied %s@%s: %s", e.User, e.Addr, e.Reason)
}

// FinishAuth runs the handshake to the end: NewServerConn, identity from
// Permissions, the username/owner cross-check, and journal events. This
// is the seam where side effects are allowed - never inside the pure
// callback. now is the gateway's clock, injected like everywhere else
// (used only for the handshake deadline). On any failure the connection
// is closed before returning.
func (h *Handler) FinishAuth(conn net.Conn, cfg *ssh.ServerConfig, sink EventSink, now time.Time) (*ssh.ServerConn, Identity, error) {
	if h.limits.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(h.HandshakeDeadline(now))
	}

	type offeredAuth struct {
		user   string
		fp     string
		reason string
	}
	var (
		offeredMu sync.Mutex
		offered   []offeredAuth
	)

	origCB := cfg.PublicKeyCallback
	serverCfg := *cfg
	serverCfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := Fingerprint(key)
		user := c.User()
		var perm *ssh.Permissions
		var err error
		if origCB != nil {
			perm, err = origCB(c, key)
		} else {
			perm, err = h.PublicKeyCallback()(c, key)
		}
		if err != nil {
			offeredMu.Lock()
			offered = append(offered, offeredAuth{
				user:   user,
				fp:     fp,
				reason: err.Error(),
			})
			offeredMu.Unlock()
			return nil, err
		}
		return perm, nil
	}

	sconn, _, _, err := ssh.NewServerConn(conn, &serverCfg)
	addr := conn.RemoteAddr().String()
	if err != nil {
		_ = conn.Close()
		offeredMu.Lock()
		attempts := append([]offeredAuth(nil), offered...)
		offeredMu.Unlock()
		if len(attempts) == 0 {
			denied := &ErrDenied{Addr: addr, Reason: "handshake or key authentication failed"}
			if sink != nil {
				sink.AuthDenied(addr, "", "", denied.Reason)
			}
			return nil, Identity{}, denied
		}
		last := attempts[len(attempts)-1]
		denied := &ErrDenied{Addr: addr, User: last.user, Reason: last.reason}
		if sink != nil {
			for _, a := range attempts {
				sink.AuthDenied(addr, a.user, a.fp, a.reason)
			}
		}
		return nil, Identity{}, denied
	}
	user := sconn.User()
	id, idErr := ExtractIdentity(sconn.Permissions)
	if idErr == nil {
		if _, verr := VerifyLogin(sconn.Permissions, user); verr != nil {
			idErr = verr
		}
	}
	if idErr != nil {
		_ = sconn.Close()
		fp := ""
		if id.Fingerprint != "" {
			fp = id.Fingerprint
		}
		denied := &ErrDenied{Addr: addr, User: user, Reason: idErr.Error()}
		if sink != nil {
			sink.AuthDenied(addr, user, fp, denied.Reason)
		}
		return nil, Identity{}, denied
	}
	_ = conn.SetDeadline(time.Time{})
	if sink != nil {
		sink.AuthAccepted(addr, user, id.Fingerprint, id.Subject.Name, id.Subject.Role)
	}
	return sconn, id, nil
}
