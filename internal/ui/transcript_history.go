//go:build windows || linux || darwin

package ui

// Reading the transcript of a visit that is over (IAMT-427).
//
// The maintainer, 22.09.2026: they had just finished a session, opened History,
// pressed Transcript, and got a window reading "read 0 of 0 bytes" and
// "(nothing yet)". Nothing was broken in the window and nothing was lost
// on the gateway -- the recording was on disk the whole time. The button
// simply asked the wrong question.
//
// sessions.tail follows a session that is STILL RUNNING. It resolves an
// id against the gateway's in-memory registry of open recordings, and a
// session leaves that registry seconds after it ends. Ask it about
// yesterday and it answers, honestly, that there is nothing -- which is
// indistinguishable on screen from a session in which nobody typed.
//
// A finished recording is read with recordings.fetch, off the disk. Two
// things stand between a history row and that call, and both are the
// reason this file exists rather than a one-line change:
//
//  1. The ids differ. A row carries the id the session RAN under;
//     recordings.fetch takes a hash of the recording's path. Only
//     recordings.list holds both, so a row must be looked up before it
//     can be read.
//
//  2. The formats differ. A terminal session is asciicast, a single
//     command is a line-per-event journal, and the wrong reader on
//     either produces a blank page and no error at all. The mode comes
//     from the same lookup, so the reader is chosen before a byte is
//     fetched.

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// openHistoryTranscript opens the transcript window on a FINISHED
// session, named by the id the history row carries.
func (f *Frame) openHistoryTranscript(sessionID, person, machine string) {
	list := f.cfg.Actions.AdminRecordings
	fetch := f.cfg.Actions.AdminRecordingFetch
	if list == nil || fetch == nil {
		f.say(ctlHistory, noRuntime, design.BadKey)
		return
	}
	f.startTranscriptWindow(historyTranscriptFeed(list, fetch, sessionID, machine), sessionID, person, machine)
}

// historyTranscriptFeed resolves the row's session id to a recording
// once, then reads that recording.
//
// The lookup is done inside the feed rather than before the window opens
// so that a slow gateway shows an empty window that fills, not a frozen
// tab: opening is instant and the first answer carries the news, good or
// bad.
func historyTranscriptFeed(
	list func(ctx context.Context, machine, from, to string) ([]RecordingRef, error),
	fetch func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error),
	sessionID, machine string,
) transcriptFeed {
	var (
		once    sync.Once
		ref     RecordingRef
		refErr  error
		missing bool
	)
	resolve := func(ctx context.Context) {
		once.Do(func() {
			// Filtered by machine when the row names one: on a gateway
			// with months of recordings this is the difference between
			// scanning one machine's folder and scanning all of them.
			refs, err := list(ctx, machine, "", "")
			if err != nil {
				refErr = err
				return
			}
			for _, r := range refs {
				if r.SessionID == sessionID {
					ref = r
					return
				}
			}
			missing = true
		})
	}

	return func(ctx context.Context, offset int64) (transcriptChunk, error) {
		resolve(ctx)
		switch {
		case refErr != nil:
			return transcriptChunk{}, refErr
		case missing:
			// Not an error: the journal outlives the recordings by
			// design, and a row from before the pruning window is a
			// normal thing to press. An error line in red would read as
			// a fault, and the honest answer is that there is nothing
			// left to show.
			return transcriptChunk{
				Note: "No recording for this session — recordings are kept for ninety days, " +
					"and sooner deleted when the disk fills. The journal row above outlives them.",
			}, nil
		}
		chunk, next, total, err := fetch(ctx, ref.ID, ref.Part(), offset)
		if err != nil {
			return transcriptChunk{}, err
		}
		return transcriptChunk{
			Data:  chunk,
			Next:  next,
			Total: total,
			Live:  false,
			Exec:  ref.Mode == "exec",
		}, nil
	}
}

// exportLine is one line of the index an export writes: who, when, where,
// and what the journal made of it.
func exportLine(r HistoryRow) string {
	parts := []string{
		historyWhen(r.Started),
		orDash(r.Person),
		"→ " + orDash(r.Machine),
		r.Kind,
		r.Outcome,
	}
	if r.RiskLevel != "" {
		parts = append(parts, "risk "+r.RiskLevel)
	}
	if r.Goal != "" {
		parts = append(parts, "goal: "+strings.ReplaceAll(r.Goal, "\n", " "))
	}
	return strings.Join(parts, "  ·  ")
}

// exportFileName is the name one session's transcript is saved under.
// Sortable by eye and by ls, and it carries the three things a person
// looking at a folder of them needs: when, who, where.
//
// EVERY PART GOES THROUGH safeFileWord, the timestamp included
// (23.09.2026). The first version sanitised the person and the machine,
// because those are obviously words from the gateway, and left the time
// alone because a time is a number. But historyWhen hands back the
// gateway's RAW string whenever it does not parse as RFC3339, and this
// function only replaced colons and spaces in it: a "started" of
// "../../x" became a file name that filepath.Join resolves two
// directories ABOVE the folder the person chose. The export's one
// promise is that it writes where it was told to, and a name assembled
// from anything the gateway said cannot keep that promise unless every
// piece of it is filtered.
func exportFileName(r HistoryRow, n int) string {
	when := historyWhen(r.Started)
	when = strings.ReplaceAll(when, ":", "")
	when = strings.ReplaceAll(when, " ", "_")
	name := fmt.Sprintf("%03d_%s_%s_%s.txt", n, safeFileWord(when), safeFileWord(r.Person), safeFileWord(r.Machine))
	return name
}

// safeFileWord keeps a name a file system will take. A person's name and
// a machine's come from the gateway, and the gateway does not promise
// they are free of slashes.
func safeFileWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "unknown"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
