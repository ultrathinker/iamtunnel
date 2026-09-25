package record

// sessionname.go — how a session claims its recording name (IAMT-332
// round 9i).
//
// A session's recording name is derived, through the gateway clock, from
// the person, the machine and the session id
// (internal/gateway/human_role.go:271 builds "<UnixNano>-<person>-
// <machine>"), and it carries no uniqueness guarantee of its own: any
// clock that does not advance between two sessions hands the same id to
// both. The e2e fixture is such a clock (test/e2e/harness_test.go:947
// pins cfg.Now to a fakeClock frozen at 2026-09-12 10:00:00 UTC), and a
// coarse or stepped platform clock is the production version of the same
// thing.
//
// Round nine opened the session's first file with datafile.Create —
// O_CREATE|O_EXCL, which is the right answer for a name that must be
// freshly claimed and the wrong answer for a name that merely repeats.
// The refusal it produced was not a refused write, it was a refused
// SESSION: the gateway answers a recording failure by dropping the
// session (human_role.go:297, "no unrecorded access"), so a clock that
// stood still turned the second session of the day into an outage —
// which is what TestScenario19_SessionLimitsEnforced and
// TestScenario21_DoorReopensAfterAutoClose caught, several layers away
// from this name.
//
// The rule here is the one this codebase already applies to its journal
// archives (internal/winkeys/file_sink.go's nextArchivePath: "a clock
// that does not advance between two rotations ... must still not
// silently overwrite an existing archive"): a name another recording
// already holds is not a reason to refuse the session and not a reason
// to destroy the earlier recording — it is a reason to take the next
// name. So the claim is the create itself (no check-then-create window
// at all: O_EXCL is the test and the set), and on the ONE ambiguity
// datafile.Create leaves open — a plain regular file, which is what a
// previous recording of ours looks like — the next name is tried.
//
// Every other outcome still refuses the session outright, because every
// other outcome means the recorder cannot be trusted to have written
// what it says it wrote: a typed plant refusal (symlink, FIFO, junction,
// directory) is an attacker's entry and is never stepped around
// silently, and any other error (permissions, no space, no directory) is
// a real failure. Only os.ErrExist on a regular file — the "legitimate
// concurrent-creator case" datafile.Create documents itself as handing
// to callers — advances the name.

import (
	"errors"
	"fmt"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// sessionNameAttempts bounds the walk to a free name. A collision costs
// one attempt per recording that already holds the timestamp, so hitting
// this bound means the timestamp is not a timestamp any more (a frozen
// clock plus a script opening sessions in a loop); refusing the session
// with that named is better than looping forever on a full disk.
const sessionNameAttempts = 64

// claimSessionName creates basePath+firstExt, which is the first file of
// the recording, and returns the base path it actually claimed (basePath
// itself, or basePath_1, basePath_2, ... when an earlier recording
// already holds the name) together with the open file. The caller builds
// every other path of the session — .txt, .meta, .exec.jsonl — from the
// base path this returns, so one session's files always share one base
// and stay one session to the recordings scanner
// (internal/gateway/record/rotation.go groups by base path).
//
// The separator is "_", not "-", and that is not cosmetic: a later
// session's name must sort AFTER the earlier one's. The recordings tree
// is scanned and read by name order (rotation.go sorts sessions by base
// path; the tests find "the newest transcript" by taking the last .txt in
// the walk), and "_" is the one separator that keeps that true — it
// compares greater than the "." that introduces the extension
// ("X_1.cast" > "X.cast"), while a "-" separator would sort the variant
// BEFORE the recording it is the successor of ("X-1.cast" < "X.cast",
// because "-" < "."). The rule is the one the journal archives state for
// themselves: archive names must sort chronologically as plain strings.
func claimSessionName(basePath, firstExt string, mode os.FileMode) (string, *os.File, error) {
	var lastErr error
	for attempt := 0; attempt < sessionNameAttempts; attempt++ {
		candidate := basePath
		if attempt > 0 {
			candidate = fmt.Sprintf("%s_%d", basePath, attempt)
		}
		f, err := datafile.Create(candidate+firstExt, mode)
		if err == nil {
			return candidate, f, nil
		}
		if errors.Is(err, os.ErrExist) {
			// A regular file is already at this name: the previous
			// recording of a session that carried the same id, which
			// must stay where it is. Take the next name.
			lastErr = err
			continue
		}
		// A plant (the typed refusal) or a real failure: neither is
		// something to step around.
		return "", nil, err
	}
	return "", nil, fmt.Errorf("no free recording name for %s%s: %d names are taken (%v)", basePath, firstExt, sessionNameAttempts, lastErr)
}
