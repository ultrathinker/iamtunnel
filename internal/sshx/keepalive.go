package sshx

// keepalive.go: keepalive in both directions for ssh.Conn.
//
// x/crypto/ssh does not do keepalive out of the box. The iamtunnel
// protocol uses its own global request "keepalive@iamtunnel" (PROTOCOL
// §5): the active side periodically sends it with WantReply=true, the
// passive side answers with a request success and an empty payload.
// Keepalive is symmetric: both sides are simultaneously both active
// and passive.
//
// PROTOCOL §5 considers a connection dead after "three consecutive
// error/failure/missing responses". The third case — a silent peer —
// is the main one: TCP is alive, but there are no answers. So sending
// is moved to its own goroutine, and the result is collected via a
// select over three branches: an answer arrived, the interval expired,
// a stop was requested. No answer within the interval counts as a miss
// just like an error or a refusal does; the maximum detection time is
// exactly Interval × MaxMisses.
//
// Default values are from SPEC §3.2 and §5.2: 20 seconds, 3 misses.

import (
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultKeepaliveInterval — the default from SPEC §3.2/§5.2 (20 seconds).
const DefaultKeepaliveInterval = 20 * time.Second

// DefaultKeepaliveMisses — the default from SPEC §3.2/§5.2 (3 misses).
const DefaultKeepaliveMisses = 3

// DefaultKeepaliveName — the request's name on the wire, PROTOCOL §5.
const DefaultKeepaliveName = "keepalive@iamtunnel"

// Keepalive describes the keepalive loop's parameters.
type Keepalive struct {
	// Interval between probes, and also the deadline for an answer.
	// If <= 0 — DefaultKeepaliveInterval.
	Interval time.Duration
	// MaxMisses — the threshold of consecutive misses. If <= 0 — DefaultKeepaliveMisses.
	MaxMisses int
	// Name — the request's name. If empty — DefaultKeepaliveName.
	Name string

	// FailureIsAlive switches how a request-failure answer is interpreted.
	// By default (false, as for §5 keepalive@iamtunnel) a failure is a
	// miss, on par with a transport error and a missing answer: there,
	// only our own agent answers the request, and a failure is a
	// protocol violation.
	//
	// PROTOCOL §4.2 (IAMT-220): for the human probe (keepalive@openssh.com),
	// true means any answer, including a failure, proves the transport
	// and the client are alive, because OpenSSH (and x/crypto/ssh's
	// default handler) answers with a request failure to a global
	// request it does not recognize. A transport error (SendRequest
	// returned err != nil) always remains a miss, regardless of this
	// field: it proves nothing but a broken connection.
	//
	// The only caller meant to set this field is
	// gateway.Config.HumanKeepalive (config.go's setDefaults, a
	// protocol-mandated default, not a test switch). Every other probe
	// (machine-side §5, admin, client→gateway) leaves it at zero.
	FailureIsAlive bool
}

// resolve fills in the default values.
func (k Keepalive) resolve() (time.Duration, int, string) {
	interval := k.Interval
	if interval <= 0 {
		interval = DefaultKeepaliveInterval
	}
	maxMisses := k.MaxMisses
	if maxMisses <= 0 {
		maxMisses = DefaultKeepaliveMisses
	}
	name := k.Name
	if name == "" {
		name = DefaultKeepaliveName
	}
	return interval, maxMisses, name
}

// Resolved is resolve for callers outside this package: the interval, the
// miss count and the request name the probe will actually use, with the
// package defaults filled in. A caller that has to say in the journal
// which window it watched asks here rather than repeating this arithmetic
// and guessing at the same defaults (F-06, round-1 review 24.09.2026).
func (k Keepalive) Resolved() (interval time.Duration, misses int, name string) {
	return k.resolve()
}

// Probe starts the active-probe loop on conn. Every Interval it sends
// the request Name with WantReply=true. By default (FailureIsAlive ==
// false, PROTOCOL §5) a miss is counted for any of three outcomes: a
// transport error, a failure answer, or no answer within Interval.
// When FailureIsAlive == true (PROTOCOL §4.2), a failure answer is not
// counted as a miss for a live peer — then a miss is only a transport
// error or no answer. An answer that counts as success (for the
// purpose of misses) resets the counter. When the counter reaches
// MaxMisses, the loop calls onDead exactly once and exits; the maximum
// detection time is Interval × MaxMisses.
//
// conn must not be nil. nil triggers a panic.
//
// The returned stop function is idempotent and blocks until the loop
// exits. It is permitted to call it from within onDead itself: by the
// time onDead is called, the loop has already been declared finished,
// so no self-deadlock occurs.
//
// The only thing that can outlive stop is the goroutine for the last
// unanswered probe: it is blocked inside conn.SendRequest and will
// exit once conn closes. It holds nothing but a single-value buffered
// channel, and does not spawn repeated probes.
func (k Keepalive) Probe(conn ssh.Conn, onDead func()) (stop func()) {
	if conn == nil {
		panic("sshx: Keepalive.Probe: nil conn")
	}
	interval, maxMisses, name := k.resolve()

	stopCh := make(chan struct{})
	done := make(chan struct{})
	var doneOnce sync.Once
	finish := func() { doneOnce.Do(func() { close(done) }) }

	go func() {
		defer finish()
		miss := 0
		for {
			// Sending must not block the loop: a silent peer would hold
			// SendRequest forever, and no miss would ever be counted.
			type reply struct {
				ok  bool
				err error
			}
			answered := make(chan reply, 1)
			go func() {
				ok, _, err := conn.SendRequest(name, true, nil)
				answered <- reply{ok: ok, err: err}
			}()

			timer := time.NewTimer(interval)
			gotReply := false
			var rep reply
			select {
			case rep = <-answered:
				gotReply = true
			case <-timer.C:
				// PROTOCOL §5: a missing answer is a miss just the same.
			case <-stopCh:
				timer.Stop()
				return
			}

			// A transport error (SendRequest returned err != nil) is
			// always a miss, regardless of FailureIsAlive: it proves
			// nothing about the peer being alive, unlike a request
			// failure. An explicit request failure (err == nil, ok ==
			// false) is a miss unless FailureIsAlive says otherwise
			// (PROTOCOL §4.2).
			alive := gotReply && rep.err == nil && (rep.ok || k.FailureIsAlive)
			if alive {
				miss = 0
			} else {
				miss++
			}

			if miss >= maxMisses {
				timer.Stop()
				// Declare the loop finished first, then call onDead:
				// otherwise onDead calling stop() would deadlock itself.
				finish()
				if onDead != nil {
					onDead()
				}
				return
			}

			if gotReply {
				// The answer arrived before the interval — wait out the
				// remainder, so probes go out exactly once per Interval.
				select {
				case <-timer.C:
				case <-stopCh:
					timer.Stop()
					return
				}
			}
		}
	}()

	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() { close(stopCh) })
		<-done
	}
}

// Respond reads global requests from reqs and answers by a single
// policy: it decides via globalRequestTable through
// LookupGlobalRequest, i.e. exactly the same table the gateway judges
// by. There are no two different global-request policies in this package.
//
// The keepalive's own name (Name, DefaultKeepaliveName by default)
// gets a request success with an empty payload — PROTOCOL §5. This
// name cannot override an explicit table entry: otherwise the Name
// field would work as a switch.
//
// Respond cannot and must not forward a global request: the table has
// no Forward entries, and Answer/Drop/Reject all answer locally.
// Exits when reqs closes.
func (k Keepalive) Respond(reqs <-chan *ssh.Request) {
	_, _, name := k.resolve()
	for r := range reqs {
		if r == nil {
			continue
		}
		d := LookupGlobalRequest(r.Type)
		// The keepalive's own name is answered with a local success —
		// but only if the name has no explicit entry in the table.
		// Otherwise Keepalive.Name would work as a switch: a caller
		// could set it to "tcpip-forward" and get a success for a
		// request the policy forbids.
		if r.Type == name && !IsKnownGlobalRequest(r.Type) {
			d = Answer
		}
		_ = ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
	}
}
