package gateway

// pairing_role.go implements PROTOCOL §3.4 (IAMT-323): the PIN-pairing
// trust bootstrap. An administrator opens a short pairing window — over
// the network with the "pairing.start" command, or locally on the gateway
// host with "iamtunnel gateway pair" when every admin key is lost — and
// while the window is open the gateway answers SSH logins on the
// byte-exact username "pairing" with ANY well-formed client key (the
// wrapper in gateway.go decides that; this file never sees a handshake).
// The pairing client then runs exactly one "admin.pair" exec with
// {proto, pin, pubkey, name}: a correct PIN permanently registers the client's
// own key as a new admin and burns the window in the same atomic
// Store.Update.
//
// The invariants this role keeps:
//   - the window carries no public key (state.PairingPending stores only
//     HMAC(enrolHMACKey, pin) and an expiry): the client brings its own
//     long-term key, so the pairing ref (host:port#fp) is checkable
//     before the PIN is spent — no TOFU in any role;
//   - "admin.pair" and nothing else on this login, the counterpart of
//     bootstrap's "admin.claim" rule (whoami is not here either: the
//     client is nobody until the PIN lands);
//   - every wrong or malformed PIN counts against the per-address pairing
//     limiter (g.pairRate — a second instance of the same auth.RateLimiter
//     machinery, PROTOCOL §1.5: 3 wrong PINs from one address → 3-minute
//     pairing ban; key rotation does not help, the count is the address's)
//     AND against the WINDOW itself: PairingWindowMissLimit misses from any
//     addresses burn it (M-13, code review 23.09.2026, review F-06). The
//     per-address limiter alone was worth nothing against an attacker with
//     an IPv6 /64 or a botnet — three guesses per address, never a ban,
//     against a 10^6 search inside a two-minute window. INACTIVE and
//     EXPIRED refusals record no failure — there is no PIN to grade — and
//     a success records nothing either: the address counter is never wiped
//     early, it simply ages out of the limiter's window.
//
// The PIN itself never reaches the journal: pairing.start logs the expiry
// only, and admin.pair logs the created person's name.

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// PairingWindowMissLimit is how many wrong PINs one pairing window
// tolerates IN TOTAL, across every address, before it is burned (M-13,
// code review 23.09.2026, review F-06). The per-address limiter bans an
// address after three misses; this is the ceiling that does not care how
// many addresses the attacker has.
//
// Where ten comes from (F-09, round-1 review 24.09.2026: the constant was
// chosen well and the arithmetic behind it was written down nowhere). The
// PIN is six decimal digits in v1 (Config.Pairing.PINDigits), so 10^6
// codes, and a window dies on the tenth miss whatever address sent it -
// searching the space therefore needs 10^5 windows. A window is not the
// attacker's to open: pairing.start is an admin command, one window exists
// at a time, and a new one replaces the last. The search is paced by the
// administrator, not by the attacker: at a window a minute - faster than
// any real pairing, where somebody reads a PIN out to a colleague - the
// whole space is 10^5 minutes, about seventy days; at a window an hour it
// is over eleven years. Ten is also small enough that a person mistyping
// has to be genuinely careless, which is the other half of the choice.
//
// That bound is the second line of defence, not the first: the burn is
// journaled (pairing.burn, §3.4) exactly because a window that died to
// guessing must be distinguishable from one that expired - so an attempt
// to spend those seventy days is visible to the operator in the first
// window it happens in.
//
// A v1 parameter, documented with the other pairing numbers in PROTOCOL
// §1.5 and §3.4.
const PairingWindowMissLimit = 10

// pairingRequest is the JSON body of the "admin.pair" exec (PROTOCOL
// §6): {proto, pin, pubkey, name}. pin is the numeric code the pairing
// window printed; pubkey is the client's own long-term OpenSSH public key
// line, which becomes the new admin's first key. name is optional and is
// only the person's display/login name; it never identifies the key.
type pairingRequest struct {
	Proto  int    `json:"proto"`
	Pin    string `json:"pin"`
	Pubkey string `json:"pubkey"`
	Name   string `json:"name,omitempty"`
}

// pairingResult is the success response shape PROTOCOL §6 prescribes for
// "admin.pair" — the same {person, role:"admin"} as admin.claim.
type pairingResult = bootstrapResult

// pairingStartResult is what "pairing.start" returns: the PIN itself
// (the operator passes it to the new admin over a side channel), the
// window expiry, and the pairing ref host:port#fp the new admin enters
// next to the PIN. The PIN deliberately never appears in the journal —
// the admin.op event records only the expiry.
type pairingStartResult struct {
	Pin     string `json:"pin"`
	Expires string `json:"expires"`
	Ref     string `json:"ref"`
}

// peerHost reduces a peer address to the identity both limiters count.
// Two steps, and both are the same idea: count something the attacker
// cannot change for free.
//
// The port goes first (PROTOCOL §3.4, §6.1 — "3 wrong PINs from one
// address"; SPEC §6.1 for logins): neither limiter counts per TCP
// connection, because a client that reconnects per attempt would draw a
// fresh failure counter every time and no ban would ever trigger over
// the network. That was found for pairing in the IAMT-330 review, and it
// stood for the main login limiter until IAMT-446 made both count by
// peerHost. The host is also what the pairing ref names (host:port#fp,
// §3.3), so counting by host matches the identity the paired client is
// told to check.
//
// Then IPv6 collapses to its /64 (M-13, code review 23.09.2026,
// F-06): a normal IPv6 subscriber holds 2^64 addresses, so a per-address
// counter there is not a slow counter, it is no counter at all — three
// guesses, a new address, three more, for the whole two-minute window.
// Three guesses per /64 is a ceiling that means something. Both limiters
// get this, and for the same reason: a ban has to be keyed on an address
// the attacker cannot change for free, and on IPv6 that is the /64, not
// the address inside it. IPv4 is unchanged, IPv4-mapped addresses
// (::ffff:a.b.c.d) are read as the IPv4 address they are, and anything
// that is not an address at all — the literal strings unit tests grade
// at — passes through untouched.
func peerHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, perr := netip.ParseAddr(host)
	if perr != nil {
		return host
	}
	if ip.Is4() || ip.Is4In6() {
		return ip.Unmap().String()
	}
	prefix, perr := ip.Prefix(64)
	if perr != nil {
		// A zoned address (fe80::1%eth0) has no prefix form; the zone it
		// carries is already the identity, so it is left as it is.
		return ip.String()
	}
	return prefix.String()
}

// handlePairing serves one "pairing"-login connection (PROTOCOL §3.4).
// Only "admin.pair" exec is permitted; anything else is E_EXEC_UNKNOWN.
// fp is the pairing client's own key fingerprint — the rate-limiting
// identity of every PIN attempt from this connection (counted per
// address, but the limiter API is keyed by the pair). binding is the
// identity of the window the handshake admitted this login for (F-12):
// the whole "admin.pair" is refused stale unless the window open at
// grading time is still that same window.
func (g *Gateway) handlePairing(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, fp, binding string) {
	defer sconn.Close()
	go func() {
		for r := range reqs {
			d := sshx.LookupGlobalRequest(r.Type)
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
		}
	}()
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session channels are allowed")
			continue
		}
		ch, chReqs, err := n.Accept()
		if err != nil {
			return
		}
		g.servePairingSession(sconn.RemoteAddr().String(), fp, binding, ch, chReqs)
		return
	}
}

// servePairingSession is the pairing-login counterpart of
// serveBootstrapSession: one "exec" request, one "admin.pair" command,
// one JSON body, one response. binding is the window identity the
// connection's handshake carried (F-12), passed through to runPairing.
func (g *Gateway) servePairingSession(addr, fp, binding string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	finished := false
	finish := func(result any, cerr *cmdError) {
		// Mark the one response as attempted before entering the wire writer: if
		// a broken channel implementation panics there, the recovery below must
		// not recursively try to write another response.
		finished = true
		g.finishCommand(ch, result, cerr)
	}
	// This is the request boundary: one accepted session channel carries one
	// exec request and one body. Recover here, rather than in handleConn, so a
	// pairing panic becomes an E_INTERNAL response for this channel only;
	// panics elsewhere in the runtime remain visible to their owning tests and
	// handlers.
	defer func() {
		if recovered := recover(); recovered != nil {
			g.appendEvent(events.Event{
				Type:   events.EventAdminOp,
				Actor:  "pairing",
				Object: "admin.pair",
				Result: "pairing:panic",
				Details: map[string]interface{}{
					"reason":  "panic",
					"panic":   fmt.Sprint(recovered),
					"errCode": "E_INTERNAL",
				},
			})
			if !finished {
				finish(nil, errPairingInternal("internal error handling pairing request"))
			}
		}
		_ = ch.Close()
	}()
	req, ok := <-reqs
	if !ok {
		return
	}
	go func() {
		for extra := range reqs {
			if extra.WantReply {
				_ = extra.Reply(false, nil)
			}
		}
	}()
	if req.Type != "exec" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errPairingExecUnknown(req.Type))
		return
	}
	execMsg, perr := sshx.ParseExec(req.Payload)
	if perr != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errPairingProtocol("malformed exec payload"))
		return
	}
	if execMsg.Command != "admin.pair" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errPairingExecUnknown(execMsg.Command))
		return
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	body, rerr := readBounded(ch, maxExecRequestBytes)
	if rerr != nil {
		finish(nil, errPairingProtocol(rerr.Error()))
		return
	}
	// IAMT-451: not while the audit journal cannot record it; and a
	// record this pairing lost while it ran is answered as lost, not
	// "ok" (F-15, 24.09.2026) -- runAuditedRole.
	now := g.cfg.Now()
	res, cerr := g.runAuditedRole("pairing", "the pairing", func() (any, *cmdError) {
		return g.runPairing(body, addr, fp, binding, now)
	})
	finish(res, cerr)
}

// afterPairingFastCheckFn is the seam the R2-CX F-04 test replaces or
// closes the window on, between the fast stale check and the transaction
// that grades the attempt - where a concurrent pairing.start or
// pairing.stop can land. Production leaves it nil.
var afterPairingFastCheckFn func()

// runPairing grades one "admin.pair" attempt: PIN in, admin out. addr and
// fp are the connection's rate-limiting identity; every wrong or
// malformed PIN records one per-address failure in g.pairRate. binding is
// the identity of the window the connection's handshake admitted it for
// (F-12, round-1 review 24.09.2026): the attempt is refused stale - with
// nothing debited, there is no window left its PIN could be a guess at -
// unless the window open at grading time is still that same window. The
// direct entry (tests) passes the window it means to grade against; an
// empty binding skips the check and is reachable no other way.
func (g *Gateway) runPairing(body []byte, addr, fp, binding string, now time.Time) (any, *cmdError) {
	// The state write and the line that records it are ONE publication
	// (R3 F-01, round-3 review 24.09.2026). This is the path that
	// creates a new ADMINISTRATOR - and the path that burns a window and
	// writes pairing.burn - and "gateway backup" accepts a pair of
	// state.json and events.jsonl only if nothing moved under it while it
	// read. Reading in the pause between the two writes used to yield an
	// archive whose state knows an administrator (or a burned window) that
	// its own journal never mentions. R2-CX F-10 put this lock on the
	// eight admin commands, on enrol and on bootstrap; pairing was left
	// out of that commit because the file belonged to another finding, and
	// this is the same lock in the same place.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	// The limiter counts per machine, not per connection: one pairing
	// connection lives for exactly one exec, so an ip:port key would hand
	// a reconnect-per-guess attacker a fresh counter every time (IAMT-330).
	// Normalizing here — at the point of use, the same as the handshake
	// layer's pairingKeyCallback — keeps every caller on the IP scale.
	addr = peerHost(addr)
	var req pairingRequest
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	// The limiter is consulted before the window: a banned address gets
	// E_PAIRING_LOCKED and nothing else, at the exec layer exactly as at
	// the handshake layer (pairingKeyCallback consults Allow first too) —
	// the fourth attempt learns nothing, not even whether a window is
	// open (IAMT-330 review, LOW). The window IS still read before any
	// PIN grading, so a closed or expired window keeps billing nobody:
	// there is no PIN to grade when there is no window to open. (A closed
	// window is normally not even reachable here — the handshake layer
	// refuses it already — but a window can expire or be stopped in the
	// microseconds between the handshake and this exec.)
	if d := g.pairRate.Allow(addr, fp, now); !d.Allow {
		// PROTOCOL §6.1: a banned address is refused before the window is
		// looked at and before the PIN is compared — it learns nothing.
		return nil, errPairingLocked(d.Until)
	}
	st := g.cfg.Store.Get()
	if st.PairingPending == nil {
		return nil, errPairingInactive()
	}
	if !st.PairingPending.Expires.After(now) {
		return nil, errPairingExpired(st.PairingPending.Expires.String())
	}
	// F-12: the fast half of the stale check. A window replaced or stopped
	// after this connection's handshake is not a window this connection's
	// PIN can be graded against - its answer is the stale refusal, before
	// any counter is touched (the authoritative re-check sits inside the
	// grading transaction below, against whatever window is open by then).
	if pairingBindingStale(binding, pairingWindowBindingHex(st.PairingPending)) {
		return nil, errPairingStaleWindow()
	}
	if afterPairingFastCheckFn != nil {
		afterPairingFastCheckFn()
	}
	// A malformed PIN is a wrong PIN: same counter, same code (SPEC §6.1).
	// Graded before the window is touched, so a garbage shape can neither
	// burn the window nor skip the count — it is counted against the window
	// too (M-13): a PIN that is the wrong shape is still a guess.
	//
	// R2-CX F-04: and billed to the address in the same order as a wrong
	// PIN of the right shape - only once the miss has been counted against
	// the connection's own window. The transaction may find that window
	// closed, expired or replaced since the fast check above; then there
	// was no PIN to guess, and nothing is billed anywhere. The address used
	// to be billed first, so a connection admitted to a window that was
	// then replaced could still run the address into a ban.
	if !validPin(req.Pin, g.cfg.Pairing.PINDigits) {
		misses, burned, refusal, merr := g.countPairingMiss(binding, now)
		if merr != nil {
			return nil, errPairingInternal("could not record the pairing miss: " + merr.Error())
		}
		if refusal != nil {
			return nil, refusal
		}
		g.pairRate.RecordFailure(addr, fp, false, now)
		if burned {
			g.burnPairingWindowEvent(misses)
			return nil, errPairingWindowBurned(misses)
		}
		return nil, errPairingPinInvalid()
	}
	presented := state.HashEnrolSecret(g.enrolHMAC, []byte(req.Pin))

	type result struct {
		res      *pairingResult
		err      *cmdError
		wrongPin bool
		burned   bool
		misses   int
		person   string
		keyFP    string
	}
	var out result
	err := g.cfg.Store.Update(func(st *state.State) error {
		pp := st.PairingPending
		// The window may have closed between the pre-check above and this
		// transaction (a concurrent pairing.stop, a newer pairing.start,
		// the expiry itself): the re-check inside the one atomic write is
		// what keeps the burn and the admin creation indivisible.
		if pp == nil {
			out.err = errPairingInactive()
			return nil
		}
		if !pp.Expires.After(now) {
			out.err = errPairingExpired(pp.Expires.String())
			return nil
		}
		// F-12: the authoritative half of the stale check, in the one
		// atomic write: the window this transaction sees must still be the
		// one the connection was admitted for. Grading - the miss debit,
		// the burn, the admin creation - happens only against that window;
		// anything else refuses stale with every counter untouched.
		if pairingBindingStale(binding, pairingWindowBindingHex(pp)) {
			out.err = errPairingStaleWindow()
			return nil
		}
		if !hmac.Equal(pp.SecretHash[:], presented[:]) {
			out.wrongPin = true
			// The miss is counted against the window in THIS transaction,
			// so the count and the window it belongs to can never drift
			// apart (M-13). The miss that reaches the limit burns the
			// window here, in the same atomic write that recorded it.
			out.misses, out.burned = pairingWindowMissLocked(pp)
			if out.burned {
				st.PairingPending = nil
			}
			return nil
		}
		// The PIN compared equal — from here the client is trusted.
		// Pubkey validation happens only after that comparison: a client
		// with a wrong PIN must never learn anything about its pubkey, and
		// a client with a malformed pubkey must never get a free look at
		// the PIN (its shape error would have skipped the failure
		// recording below had validation run first).
		if verr := state.ValidateKeyMaterial(req.Pubkey); verr != nil {
			out.err = errPairingProtocol("pubkey: " + verr.Error())
			return nil
		}
		keyFP, ferr := state.ComputeFingerprint(req.Pubkey)
		if ferr != nil {
			out.err = errPairingProtocol("presented pubkey fingerprint: " + ferr.Error())
			return nil
		}
		// The same key must not become a second person: a re-pairing
		// client (key already registered) is refused with the window left
		// open — refusing it does not spend the PIN, and the operator may
		// still be waiting to pair a different device.
		for _, p := range st.People {
			for _, k := range p.Keys {
				if k.Fingerprint == keyFP {
					out.err = errPairingConflict(keyFP)
					return nil
				}
			}
		}
		personName, nameErr := pairingPersonName(st, req.Name)
		if nameErr != nil {
			out.err = nameErr
			return nil
		}
		st.People = append(st.People, state.Person{
			Name: personName,
			Role: "admin",
			Keys: []state.Key{{Fingerprint: keyFP, Pub: req.Pubkey, Added: state.NewZonedTime(now)}},
		})
		// Burn the window in the same transaction that creates the admin:
		// a replayed PIN after a successful pair finds PairingPending ==
		// nil and gets E_PAIRING_INACTIVE (the §8 scenario pins this).
		st.PairingPending = nil
		out.res = &pairingResult{Person: personName, Role: "admin"}
		out.person = personName
		out.keyFP = keyFP
		return nil
	})
	if err != nil {
		return nil, errPairingInternal("could not commit pairing state: " + err.Error())
	}
	if out.wrongPin {
		g.pairRate.RecordFailure(addr, fp, false, now)
		if out.burned {
			g.burnPairingWindowEvent(out.misses)
			return nil, errPairingWindowBurned(out.misses)
		}
		return nil, errPairingPinInvalid()
	}
	if out.err != nil {
		return nil, out.err
	}
	// Success records nothing: the pairing limiter counts per address, and
	// a success neither wipes the address's earlier wrong PINs (they age
	// out of the limiter's own window) nor lifts an active ban — the same
	// rule PROTOCOL §1.4 already fixes for the main limiter.
	g.logAdminOp("pairing", "admin.pair", out.person, "ok", map[string]interface{}{"fingerprint": out.keyFP})
	return out.res, nil
}

// pairingWindowMissLocked counts one miss against the open window and
// reports whether this miss is the one that burns it (M-13, code review
// 23.09.2026, review F-06). The caller must hold the store transaction —
// the counting belongs to the same atomic write as the PIN grading, and
// the burning too, so a window can never be counted without the count
// and can never be burned without the miss that burned it being on the
// record.
func pairingWindowMissLocked(pp *state.PairingPending) (misses int, burned bool) {
	pp.Misses++
	return pp.Misses, pp.Misses >= PairingWindowMissLimit
}

// countPairingMiss records one miss against the window in a transaction
// of its own: the malformed-PIN path is graded before the window is read
// at all, so it never reaches the grading transaction. It answers the way
// that transaction does (R2-CX F-04): a window that is gone or expired is
// not counted — there is no PIN to guess — and neither is one that has
// been replaced since the connection's handshake (binding, F-12); each
// comes back as the refusal to give, with no counter moved, and the
// caller bills the address only for a miss that was counted.
func (g *Gateway) countPairingMiss(binding string, now time.Time) (misses int, burned bool, refusal *cmdError, err error) {
	err = g.cfg.Store.Update(func(st *state.State) error {
		pp := st.PairingPending
		switch {
		case pp == nil:
			refusal = errPairingInactive()
			return nil
		case !pp.Expires.After(now):
			refusal = errPairingExpired(pp.Expires.String())
			return nil
		case pairingBindingStale(binding, pairingWindowBindingHex(pp)):
			refusal = errPairingStaleWindow()
			return nil
		}
		misses, burned = pairingWindowMissLocked(pp)
		if burned {
			st.PairingPending = nil
		}
		return nil
	})
	return misses, burned, refusal, err
}

// pairingWindowBindingHex renders a window's binding identity: the hex of
// its secret hash. Nil-safe — no window binds to nothing, and the empty
// binding is what tells pairingBindingStale to skip the check (the direct
// entry, which names its window by being the caller; the wire path always
// carries the binding it was minted with).
func pairingWindowBindingHex(pp *state.PairingPending) string {
	if pp == nil {
		return ""
	}
	return hex.EncodeToString(pp.SecretHash[:])
}

// pairingBindingStale reports whether a connection admitted for binding is
// now presenting against a window whose identity is current — and is
// therefore to be refused stale rather than graded. An empty binding never
// goes stale: it is the direct entry's "no binding" (see
// pairingWindowBindingHex), and the wire path cannot produce it.
func pairingBindingStale(binding, current string) bool {
	if binding == "" {
		return false
	}
	return !hmac.Equal([]byte(binding), []byte(current))
}

// burnPairingWindowEvent puts the burn in the journal. Nothing else
// records it: the window is gone by the time anybody looks, and the
// operator who opened it has to be able to tell "somebody was guessing
// and I have to look at this" from "the two minutes were up" — the two
// look identical from the outside (M-13, review F-06). The count goes in
// the details, the PIN never does.
func (g *Gateway) burnPairingWindowEvent(misses int) {
	g.logAdminOp("pairing", "pairing.burn", "pairing", "ok", map[string]interface{}{
		"misses": misses,
		"limit":  PairingWindowMissLimit,
	})
}

// pairingPersonName applies the SPEC §3.3 naming rule inside the same state
// transaction that creates the admin. A client-supplied free name wins; an
// empty or already occupied name falls back to the first free name in the
// human-readable admin, admin2, admin3 sequence. The key fingerprint is not
// an input to this choice.
func pairingPersonName(st *state.State, requested string) (string, *cmdError) {
	if requested != "" {
		if err := state.ValidateName(requested); err != nil {
			return "", errf("E_JSON_INVALID", 3, "name: %v", err)
		}
		if reservedPersonNames[requested] {
			return "", errf("E_JSON_INVALID", 3, "name %q is reserved — it is an SSH login role of this gateway", requested)
		}
		if !personNameOccupied(st, requested) {
			return requested, nil
		}
	}
	if !personNameOccupied(st, "admin") {
		return "admin", nil
	}
	for n := 2; ; n++ {
		candidate := "admin" + strconv.Itoa(n)
		if !personNameOccupied(st, candidate) {
			return candidate, nil
		}
	}
}

func personNameOccupied(st *state.State, name string) bool {
	for _, person := range st.People {
		if person.Name == name {
			return true
		}
	}
	return false
}

// ---- pairing.start / pairing.stop (the admin role's window controls) -----

func cmdAdminPairingStart(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	pin, err := GeneratePin(g.cfg.Pairing.PINDigits)
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "could not generate a PIN: %v", err)
	}
	hash := state.HashEnrolSecret(g.enrolHMAC, []byte(pin))
	expires := now.Add(g.cfg.Pairing.WindowTTL)
	// The state write and the line that records it are ONE publication
	// (R3 F-01, round-3 review 24.09.2026). This is the path that
	// creates a new ADMINISTRATOR - and the path that burns a window and
	// writes pairing.burn - and "gateway backup" accepts a pair of
	// state.json and events.jsonl only if nothing moved under it while it
	// read. Reading in the pause between the two writes used to yield an
	// archive whose state knows an administrator (or a burned window) that
	// its own journal never mentions. R2-CX F-10 put this lock on the
	// eight admin commands, on enrol and on bootstrap; pairing was left
	// out of that commit because the file belonged to another finding, and
	// this is the same lock in the same place.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		// A start while a window is open replaces it in this one write:
		// the old PIN stops working the instant the new one lands, and no
		// observer ever sees two open windows (PROTOCOL §3.4). Since F-12
		// the replacement also strands the connections the old window had
		// admitted: each carries the old window's identity, and runPairing
		// refuses them stale without grading anything, so a pocket of
		// held connections cannot spend its wrong PINs on the new window's
		// miss counter.
		st.PairingPending = &state.PairingPending{
			SecretHash: hash,
			Expires:    state.NewZonedTime(expires.UTC()),
		}
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not open the pairing window: %v", err)
	}
	bareFp := strings.TrimPrefix(auth.Fingerprint(g.cfg.HostKey.PublicKey()), "SHA256:")
	ref := fmt.Sprintf("%s:%d#%s", g.cfg.PublicHost, g.cfg.PublicPort, bareFp)
	// The PIN goes to the caller, not to the journal: the admin.op line
	// carries the expiry only, so events.jsonl stays PIN-free.
	g.logAdminOp(person, "pairing.start", "pairing", "ok", map[string]interface{}{"expires": rfc3339(expires)})
	return pairingStartResult{Pin: pin, Expires: rfc3339(expires), Ref: ref}, nil
}

func cmdAdminPairingStop(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	stopped := false
	// The state write and the line that records it are ONE publication
	// (R3 F-01, round-3 review 24.09.2026). This is the path that
	// creates a new ADMINISTRATOR - and the path that burns a window and
	// writes pairing.burn - and "gateway backup" accepts a pair of
	// state.json and events.jsonl only if nothing moved under it while it
	// read. Reading in the pause between the two writes used to yield an
	// archive whose state knows an administrator (or a burned window) that
	// its own journal never mentions. R2-CX F-10 put this lock on the
	// eight admin commands, on enrol and on bootstrap; pairing was left
	// out of that commit because the file belonged to another finding, and
	// this is the same lock in the same place.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		stopped = st.PairingPending != nil
		st.PairingPending = nil
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	// Idempotent by construction: stopping a closed window still answers
	// {stopped: false} and still writes the event — the operator asked for
	// a state, the journal shows the ask.
	//
	// The ask and the answer both go in the record (F-11, round-1 review
	// 24.09.2026): without the answer, a script that stops the window every
	// few minutes to read the state leaves lines that cannot be told from
	// the ones that closed a window. The result stays "ok" — the ask did
	// succeed and the command is idempotent by design — and the effect sits
	// beside it, as pairing.start's expiry does.
	g.logAdminOp(person, "pairing.stop", "pairing", "ok", map[string]interface{}{"stopped": stopped})
	return map[string]bool{"stopped": stopped}, nil
}

// ---- helpers ---------------------------------------------------------------

// GeneratePin returns a uniformly random decimal PIN of exactly digits
// digits, leading zeros allowed (PROTOCOL §3.4: the PIN is a code, not a
// number — "000123" is as likely as "900001"). Uniformity comes from
// rejection sampling: draws at or above the largest multiple of 10^digits
// that fits in a uint32 are discarded, so the modulo never favours the
// low values. Exported because the gateway's own pairing.start and the
// local "iamtunnel gateway pair" path (cmd/iamtunnel) must mint PINs by
// exactly the same rule.
func GeneratePin(digits int) (string, error) {
	if digits < 1 || digits > 9 {
		return "", fmt.Errorf("gateway: PIN length %d is out of range 1..9", digits)
	}
	max := 1
	for i := 0; i < digits; i++ {
		max *= 10
	}
	limit := (1 << 32 / max) * max
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("gateway: read random PIN: %w", err)
		}
		n := binary.BigEndian.Uint32(b[:])
		if uint64(n) < uint64(limit) {
			s := strconv.Itoa(int(n) % max)
			for len(s) < digits {
				s = "0" + s
			}
			return s, nil
		}
	}
}

// validPin reports whether pin is exactly digits decimal digits — the
// shape a pairing client must present; anything else is graded as a
// wrong PIN (SPEC §6.1).
func validPin(pin string, digits int) bool {
	if len(pin) != digits {
		return false
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			return false
		}
	}
	return true
}

// err helpers.

func errPairingExecUnknown(name string) *cmdError {
	return errf("E_EXEC_UNKNOWN", 2, "unknown command %q on pairing-login (only \"admin.pair\" is accepted)", name)
}

func errPairingProtocol(msg string) *cmdError {
	return errf("E_JSON_INVALID", 3, "pairing request malformed: %s", msg)
}

func errPairingPinInvalid() *cmdError {
	return errf("E_PAIRING_PIN_INVALID", 2, "wrong PIN — check the code the pairing window printed")
}

func errPairingInactive() *cmdError {
	return errf("E_PAIRING_INACTIVE", 2, "no pairing window is open — ask an administrator to run \"iamtunnel admin pairing start\"")
}

// errPairingStaleWindow is the refusal a pairing connection gets when the
// window it was admitted for has been replaced by a newer pairing.start
// (F-12, round-1 review 24.09.2026). Same code family as the burned
// window's — E_PAIRING_INACTIVE, there is no window this connection can
// act on — but its own message, because the remedy is different: the
// window is not gone for good, a new one is open, and the client is to
// reconnect against the ref the new window printed. Nothing is debited
// anywhere: the PIN was never graded against a window that exists, so
// neither the new window's miss counter nor the address's limiter may
// learn of the attempt.
func errPairingStaleWindow() *cmdError {
	return errf("E_PAIRING_INACTIVE", 2, "the pairing window was replaced while this connection was open — reconnect and use the ref the new window printed")
}

// errPairingWindowBurned is the refusal the miss that reaches the limit
// gets: the window is gone, and the client is told what ended it rather
// than that some PIN was wrong. A legitimate client that mistyped has to
// know its own misses closed the window; an attacker learns that its
// guessing burned the thing it was guessing at — which is the outcome it
// wanted least, and the same code (E_PAIRING_INACTIVE, "there is no
// window") PROTOCOL §3.4 already gives every later attempt.
func errPairingWindowBurned(misses int) *cmdError {
	return errf("E_PAIRING_INACTIVE", 2, "the pairing window was closed after %d wrong PINs — ask an administrator to run \"iamtunnel admin pairing start\" again", misses)
}

func errPairingExpired(until string) *cmdError {
	return errf("E_PAIRING_EXPIRED", 2, "the pairing window expired at %s — ask for a new PIN", until)
}

func errPairingLocked(until time.Time) *cmdError {
	return errf("E_PAIRING_LOCKED", 2, "too many wrong PINs from your address — pairing is locked until %s", until.UTC().Format(time.RFC3339))
}

func errPairingConflict(keyFP string) *cmdError {
	return errf("E_CONFLICT", 2, "key %s is already registered — pair a device with a new key", keyFP)
}

func errPairingInternal(msg string) *cmdError {
	return errf("E_INTERNAL", 70, "%s", msg)
}
