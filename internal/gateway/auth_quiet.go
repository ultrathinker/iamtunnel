package gateway

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// IAMT-452: the journal grew without bound. Every login wrote its own
// auth.success - a window polling every second or two, a script in a loop,
// one line each time - and nothing ever rotated the file. This file holds
// the gateway's two answers: the same login is journaled once per quiet
// period with a count of the rest, and the journal is rotated by size.

// maxAuthQuietEntries bounds what the quiet period remembers. A login that
// finds it full is simply journaled, as every login was before: the bound
// costs lines, never records.
const maxAuthQuietEntries = 4096

// authQuietKey is what counts as "the same login": the SSH username, the
// key, and the host it came from (the port changes with every connection).
type authQuietKey struct {
	login, fingerprint, host string
}

// quietHost is the host of addr as the quiet period counts it: the
// address without its port, and nothing else taken off. Not peerHost,
// whose IPv6 /64 is what a limiter must count (M-13) - for the journal
// two computers in one /64 are two sources, and the second one's address
// has to reach it.
func quietHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// authQuietEntry is one login's quiet period: when its last line was
// written, and the logins since that were not.
type authQuietEntry struct {
	written     time.Time
	repeats     int
	first, last time.Time
	addr        string
	subject     string
	role        auth.Role
}

type authQuiet struct {
	mu      sync.Mutex
	entries map[authQuietKey]*authQuietEntry
}

// admit decides whether this login is journaled. It is when no line was
// written for the same login within quiet; then summary, if not nil, is
// the previous period's count, to be written first. Otherwise the login
// is counted towards the next line.
func (q *authQuiet) admit(k authQuietKey, addr, subject string, role auth.Role, now time.Time, quiet time.Duration) (write bool, summary *authQuietEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.entries == nil {
		q.entries = make(map[authQuietKey]*authQuietEntry)
	}
	e, ok := q.entries[k]
	if ok && now.Before(e.written.Add(quiet)) {
		e.repeats++
		if e.repeats == 1 {
			e.first = now
		}
		e.last, e.addr, e.subject, e.role = now, addr, subject, role
		return false, nil
	}
	if ok && e.repeats > 0 {
		s := *e
		summary = &s
	}
	if ok || len(q.entries) < maxAuthQuietEntries {
		q.entries[k] = &authQuietEntry{written: now, addr: addr, subject: subject, role: role}
	}
	return true, summary
}

// expired takes out every period that has ended, returning the ones that
// still owe a count.
func (q *authQuiet) expired(now time.Time, quiet time.Duration) map[authQuietKey]authQuietEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	var owed map[authQuietKey]authQuietEntry
	for k, e := range q.entries {
		if now.Before(e.written.Add(quiet)) {
			continue
		}
		if e.repeats > 0 {
			if owed == nil {
				owed = make(map[authQuietKey]authQuietEntry)
			}
			owed[k] = *e
		}
		delete(q.entries, k)
	}
	return owed
}

// authSuccessEvent is the auth.success line, for one login or, with
// repeats, for the logins of a quiet period that were not written one by
// one.
func authSuccessEvent(addr, login, fingerprint, subject string, role auth.Role, repeats *authQuietEntry) events.Event {
	details := map[string]interface{}{"role": string(role)}
	if repeats != nil {
		details["repeats"] = repeats.repeats
		details["firstRepeat"] = rfc3339(repeats.first)
		details["lastRepeat"] = rfc3339(repeats.last)
	}
	return events.Event{
		Type:        events.EventAuthSuccess,
		Actor:       subject,
		Object:      clipForJournalTo(login, maxLoginJournalBytes),
		Result:      "ok",
		Address:     addr,
		Fingerprint: fingerprint,
		Details:     details,
	}
}

// flushAuthQuiet writes the count of every quiet period that has ended
// with logins in it. The expiry sweep calls it every tick.
func (g *Gateway) flushAuthQuiet(now time.Time) {
	for k, e := range g.authQuiet.expired(now, g.cfg.AuthSuccessQuiet) {
		e := e
		g.appendEvent(authSuccessEvent(e.addr, k.login, k.fingerprint, e.subject, e.role, &e))
	}
}

// R4 F-11 (review, 24.09.2026): the same bound for the refusals. The
// gateway port is on the internet by construction, and before the fold
// every TCP connect that died before the first key cost the journal an
// auth.handshake_failure line, every offered key an auth.failure line -
// file lock, tail read, write, fsync each - and the rate limiter only
// decides whether a key is TRIED, not whether a line is WRITTEN: after a
// ban, `ssh -i k1 … -i k32` in a loop kept writing one line per key per
// connect. Lines are what filled the disk, and a full disk is what turns
// IAMT-451 into a denial of service for everyone. So refused attempts
// fold the way successes fold: the same host and refusal kind within the
// quiet period is one line, the rest counted, and the count is written
// when the period ends. A slow brute force still earns a line per
// attempt - each lands outside the quiet period - so what IAMT-118
// promised for it holds; a flood earns one line per period plus the
// count, which is the fact a person reads afterwards.

// authDenyKey is what counts as "the same refusal": the host it came
// from (quietHost, not the /64 - the journal is not the limiter) and the
// kind of the refusal. The kind is coarse on purpose, never the raw
// reason: reason texts embed the offered fingerprint ("auth: unknown
// key: <fp>"), and a key-spray would then make one bucket per key - the
// flood back, one bucket at a time.
type authDenyKey struct {
	host, kind string
}

// authDenyEntry is one refusal's quiet period: when its line was
// written, the attempts since that were not, and the identifying fields
// of the attempt seen last (the line a period ends with names the last
// attempt, the same choice IAMT-452 made for successes).
type authDenyEntry struct {
	written                          time.Time
	repeats                          int
	first, last                      time.Time
	addr, login, fingerprint, reason string
}

type authDenyQuiet struct {
	mu      sync.Mutex
	entries map[authDenyKey]*authDenyEntry
}

// admit decides whether this refusal is journaled. It is when no line was
// written for the same host and kind within quiet; otherwise the attempt
// is counted towards the period's count, and summary, when the period
// that just ended had uncounted attempts in it, is the line that says so
// first.
func (q *authDenyQuiet) admit(k authDenyKey, addr, login, fingerprint, reason string, now time.Time, quiet time.Duration) (write, summary *authDenyEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.entries == nil {
		q.entries = make(map[authDenyKey]*authDenyEntry)
	}
	e, ok := q.entries[k]
	if ok && now.Before(e.written.Add(quiet)) {
		if e.repeats == 0 {
			e.first = now
		}
		e.repeats++
		e.last, e.addr, e.login, e.fingerprint, e.reason = now, addr, login, fingerprint, reason
		return nil, nil
	}
	if ok && e.repeats > 0 {
		s := *e
		summary = &s
	}
	fresh := &authDenyEntry{written: now, addr: addr, login: login, fingerprint: fingerprint, reason: reason}
	// A refusal that finds the table full is simply journaled, as every
	// refusal was before the fold: the bound costs lines, never records -
	// the same trade maxAuthQuietEntries makes for successes.
	write = fresh
	if ok || len(q.entries) < maxAuthQuietEntries {
		q.entries[k] = fresh
	}
	return write, summary
}

// expired takes out every period that has ended, returning the ones that
// still owe a count.
func (q *authDenyQuiet) expired(now time.Time, quiet time.Duration) map[authDenyKey]authDenyEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	var owed map[authDenyKey]authDenyEntry
	for k, e := range q.entries {
		if now.Before(e.written.Add(quiet)) {
			continue
		}
		if e.repeats > 0 {
			if owed == nil {
				owed = make(map[authDenyKey]authDenyEntry)
			}
			owed[k] = *e
		}
		delete(q.entries, k)
	}
	return owed
}

// authDenyKind classifies a refusal for the fold. Handshake failures are
// their own kind; the rest are classed by the named error the refusal
// starts with, which is why the sentinels and not their callers own the
// prefixes. Anything else is one bucket: a refusal the classifier has no
// name for is still folded, because the flood does not care what it
// calls itself.
func authDenyKind(t events.EventType, reason string) string {
	if t == events.EventAuthHandshakeFailure {
		return "handshake"
	}
	switch {
	case strings.HasPrefix(reason, errAuthRateLimited.Error()),
		strings.HasPrefix(reason, errPairingRateLimited.Error()):
		return "rate limited"
	case strings.HasPrefix(reason, auth.ErrUnknownKey.Error()):
		return "unknown key"
	case strings.HasPrefix(reason, auth.ErrNameMismatch.Error()):
		return "name mismatch"
	default:
		return "refused"
	}
}

// authDenyEventType maps a kind back to the journal type the refusal is
// recorded under: only the pre-key handshake failure has a type of its
// own (R1-CX F-03); everything else is an auth.failure, whose validator
// the first line and every summary satisfy - each carries the address
// and the fingerprint of the attempt it names.
func authDenyEventType(kind string) events.EventType {
	if kind == "handshake" {
		return events.EventAuthHandshakeFailure
	}
	return events.EventAuthFailure
}

// authDenyEvent is the auth.failure / auth.handshake_failure line, for
// one refusal or, with repeats, for the attempts of a quiet period that
// were not written one by one. It is the line AuthDenied wrote before the
// fold, field for field - actor and object are the clipped login (or the
// address, for the pre-key handshake failure), and the result keeps the
// reason's own clip.
func authDenyEvent(kind string, e authDenyEntry) events.Event {
	var details map[string]interface{}
	if e.repeats > 0 {
		details = map[string]interface{}{
			"repeats":     e.repeats,
			"firstRepeat": rfc3339(e.first),
			"lastRepeat":  rfc3339(e.last),
		}
	}
	result := clipForJournalTo(e.reason, maxAuthReasonJournalBytes)
	// Each type spelled out where it is built: gate 13 finds a type's write
	// site by the constant in an Event literal, and a type chosen through a
	// variable reads to it as a type nobody writes.
	if authDenyEventType(kind) == events.EventAuthHandshakeFailure {
		return events.Event{
			Type:        events.EventAuthHandshakeFailure,
			Actor:       e.addr,
			Object:      e.addr,
			Result:      result,
			Address:     e.addr,
			Fingerprint: e.fingerprint,
			Details:     details,
		}
	}
	actor := clipForJournalTo(e.login, maxLoginJournalBytes)
	return events.Event{
		Type:        events.EventAuthFailure,
		Actor:       actor,
		Object:      actor,
		Result:      result,
		Address:     e.addr,
		Fingerprint: e.fingerprint,
		Details:     details,
	}
}

// flushAuthDenyQuiet writes the count of every quiet period that has
// ended with refused attempts in it. The expiry sweep calls it every
// tick, next to the successes' flush.
func (g *Gateway) flushAuthDenyQuiet(now time.Time) {
	for k, e := range g.authDeny.expired(now, g.cfg.AuthSuccessQuiet) {
		e := e
		g.appendEvent(authDenyEvent(k.kind, e))
	}
}

// rotateJournalIfLarge rotates events.jsonl into an archive beside it once
// it has reached JournalRotateBytes (IAMT-452). The archive is named by
// the time (events.ArchiveName), which is what ReadHistory reads back in
// order; a second rotation within the same second waits for the next tick
// rather than write over the first.
func (g *Gateway) rotateJournalIfLarge(now time.Time) {
	log := g.cfg.Log
	if log == nil {
		return
	}
	size, err := log.Size()
	if err != nil || size < g.cfg.JournalRotateBytes {
		return
	}
	archive := filepath.Join(filepath.Dir(log.Path()), events.ArchiveName(now))
	if _, err := os.Lstat(archive); err == nil || !errors.Is(err, os.ErrNotExist) {
		return
	}
	// A rotation that fails is deliberately not reported here as well
	// (F-19, review round 1 24.09.2026). The log reports itself, at the
	// moment it matters: the next write that has to be journaled opens a
	// file again, and what it says when it cannot - the rotation that
	// could not finish, and the archive it could not publish or could not
	// become - is what the audit state carries to gateway status, the
	// audit-health file and the service log (IAMT-451), and what every
	// command and session that needs a record is refused with. A second
	// line from the sweep would say less, and on the branch where the
	// rename keeps failing - the journal is still there, so Size is still
	// happy - it would say it once a second for as long as the disk stays
	// that way.
	_ = log.Rotate(archive)
}

// pruneJournalArchives is the retention's other half (R4 F-11): the
// rotation IAMT-452 introduced moved the growth into archives and nothing
// ever removed them, so a disk the flood filled stayed filled. An archive
// goes when it is older than JournalArchiveRetentionDays, or when there
// are more than JournalArchiveMaxCount of them - the newest survive the
// count, so a burst of rotations cannot push the oldest history out one
// archive at a time and then keep going.
//
// Only rotation archives go: a name that does not parse as ArchiveName's
// stamp - ArchiveNameFor's tagged restore names, anything a person or a
// tool put beside the journal - is stepped around, not deleted. The
// gateway deletes what it knows it created and nothing else.
//
// Every deletion is journaled first (PROTOCOL §8: an event says what was
// removed, by whom and when), and a removal that fails is left for the
// next tick rather than reported from the sweep - the same reasoning
// rotateJournalIfLarge carries above: the sweep would say it once a
// second, and say less than the log says itself when a write next needs
// the file.
func (g *Gateway) pruneJournalArchives(now time.Time) {
	log := g.cfg.Log
	if log == nil {
		return
	}
	dir, current := filepath.Dir(log.Path()), filepath.Base(log.Path())
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type archive struct {
		name  string
		stamp time.Time
	}
	var archives []archive
	for _, e := range entries {
		if e.IsDir() || e.Name() == current || !events.IsLogFileName(e.Name()) {
			continue
		}
		stamp, ok := events.ParseArchiveTime(e.Name())
		if !ok {
			continue // a tagged restore archive, or something else's file
		}
		archives = append(archives, archive{e.Name(), stamp})
	}
	if len(archives) == 0 {
		return
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].name < archives[j].name })
	maxAge := time.Duration(g.cfg.JournalArchiveRetentionDays) * 24 * time.Hour
	keep := len(archives) - g.cfg.JournalArchiveMaxCount
	if keep < 0 {
		keep = 0
	}
	for i, a := range archives {
		tooOld := maxAge > 0 && a.stamp.Before(now.Add(-maxAge))
		tooMany := i < keep
		if !tooOld && !tooMany {
			break // sorted oldest first: nothing later can be pruned either
		}
		path := filepath.Join(dir, a.name)
		if err := os.Remove(path); err != nil {
			continue // the next tick tries again; see the comment above
		}
		g.appendEvent(events.Event{
			Type:   events.EventAdminOp,
			Actor:  "gateway",
			Object: path,
			Result: "journal.archive.prune",
			Details: map[string]interface{}{
				"archived": rfc3339(a.stamp),
				"reason": map[bool]string{
					true:  "age",
					false: "count",
				}[tooOld],
			},
		})
	}
}
