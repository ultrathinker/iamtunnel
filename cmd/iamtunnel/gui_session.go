//go:build (windows || linux || darwin) && !nogui

package main

// gui_session.go — the Session tab's three actions, connected at last
// (IAMT-346).
//
// Everything behind this file was built and merged during the 1.5 wave:
// the gateway can hand out a chunk of a live recording, the machine can
// relay the question, the window can render a terminal, the exporter can
// write the text to disk. None of it was reachable. The three function
// fields the tab asks its work through were never assigned in any of the
// three GUI entry points, and the tab's poll loop opens with
//
//	tail := a.SessionTail; if tail == nil { return }
//
// so on a real window the loop returned on its first line: an empty
// terminal over a running session, an Export button with nothing behind
// it, and five green items that had never once moved a byte end to end.
//
// That is the shape of the whole wave's mistake in one sentence: every
// half was verified against its own half, and nobody owned the seam. So
// this file is deliberately thin — it is nothing but the seam, and it
// adds no judgement of its own beyond keeping two statements apart:
// "the gateway said no" and "this machine never got to ask".

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/record/export"
	"github.com/ultrathinker/iamtunnel/internal/server"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// guiSessionList asks this machine's own server which sessions are live
// on it, and therefore what they are called. The ids come from the
// gateway (IAMT-345) — the machine cannot mint or guess one, and the
// window must never invent one, because an invented id finds no
// recording and shows an empty terminal over a session that is really
// running.
func guiSessionList(ctx context.Context, serverDir string) ([]ui.SessionInfo, error) {
	reply, contacted, err := sendControlSessions(serverDir)
	if err != nil {
		return nil, err
	}
	if !contacted {
		return nil, errors.New("this machine's server is not running, so there is nothing to watch")
	}
	if !reply.OK {
		return nil, errors.New(reply.Message)
	}
	out := make([]ui.SessionInfo, 0, len(reply.Sessions))
	for _, s := range reply.Sessions {
		out = append(out, ui.SessionInfo{
			ID:      s.ID,
			Person:  s.Person,
			Machine: "",
			Started: parseSessionTime(s.Started),
		})
	}
	return out, nil
}

// parseSessionTime turns the gateway's RFC 3339 stamp into a time. A
// stamp this side cannot read becomes the zero time, which every screen
// already draws as "—": a list that is otherwise correct is worth more
// than an error over one unreadable field, and the zero value says
// "unknown" rather than claiming a moment that was never sent.
func parseSessionTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// guiSessionTail carries one question about a live session to the
// running server and hands back what the gateway answered.
//
// The two kinds of "no" stay apart here, exactly as sendControlTail's
// own contract promises: a returned error means this side never got an
// answer (no server, no tunnel, no reply in time), while a refusal the
// gateway itself issued arrives as a reply and is reported in the
// gateway's own words. A window that blurred the two would tell its
// owner "the gateway refused" about a machine that was simply switched
// off.
func guiSessionTail(ctx context.Context, serverDir string, req ui.SessionTailReq) (ui.SessionTailResp, error) {
	reply, contacted, err := sendControlTail(serverDir, server.TailRequest{
		SessionID: req.ID,
		Offset:    req.Offset,
		Limit:     req.Limit,
	})
	if err != nil {
		return ui.SessionTailResp{}, err
	}
	if !contacted {
		return ui.SessionTailResp{}, errors.New("this machine's server is not running, so there is nothing to watch")
	}
	if reply.Tail == nil {
		if reply.Message != "" {
			return ui.SessionTailResp{}, errors.New(reply.Message)
		}
		return ui.SessionTailResp{}, errors.New("this machine's server gave no answer about the session")
	}
	if reply.Tail.Refusal != nil {
		return ui.SessionTailResp{}, fmt.Errorf("the gateway refused: %s: %s", reply.Tail.Refusal.Code, reply.Tail.Refusal.Message)
	}

	// §1's body, as the gateway built it. The window reads the gateway's
	// bytes; nothing between here and there rewrites them.
	var body struct {
		ID     string `json:"id"`
		Offset uint64 `json:"offset"`
		Total  uint64 `json:"total"`
		Live   bool   `json:"live"`
		Data   string `json:"data"`
		Mode   string `json:"mode"`
	}
	if err := json.Unmarshal(reply.Tail.Result, &body); err != nil {
		return ui.SessionTailResp{}, fmt.Errorf("the gateway's answer about the session is unreadable: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		return ui.SessionTailResp{}, fmt.Errorf("the gateway's session bytes are not valid base64: %w", err)
	}
	return ui.SessionTailResp{
		ID:     body.ID,
		Offset: body.Offset,
		Total:  body.Total,
		Live:   body.Live,
		Data:   raw,
		Mode:   body.Mode,
	}, nil
}

// sendControlSessions is the client half of the socket's "sessions"
// command (IAMT-345). Same contract as sendControlTail: an error means
// this side never got an answer.
func sendControlSessions(dir string) (reply controlReplyMsg, contacted bool, err error) {
	return controlRoundTrip(dir, controlRequestMsg{Cmd: "sessions"}, server.TailTimeout+2*time.Second)
}

// exportRootName is the folder the export tree grows under. No folder
// picker should exist — an export is a record-keeping act, not a save
// dialog — so Root is a fixed place next to everything else this
// registration owns: the server data directory.
// That directory is per-user since 1.4, so writing there needs no
// elevation and no negotiation with other accounts, and the Settings
// screen already shows that very path as DataDir — the person who
// pressed Export can find the folder without memorising anything new.
const exportRootName = "exports"

// guiSessionExport is the Export button's work (contract §5): the
// recording and the text read out of it, written to disk and journalled.
// The returned string is what the person sees under the button — the
// full path the export landed in.
//
// The window cannot see the recording file: it lives on the gateway,
// behind the tunnel. The one path to the bytes is the same sessions.tail
// the tab already watches, so the export walks it from byte 0 up to the
// total the first answer reports, one bounded chunk at a time. Walking
// from byte 0 is the whole point: the tab opens mid-session and its
// first fetch lands wherever the stream already is, so what it shows is
// a replay window, not a recording; a walk from zero feeds the terminal
// every byte in order, and the text below is exact, not approximate.
//
// It is a snapshot, and says so. The target total is fixed by the first
// answer; if the session keeps writing while the chunks are collected,
// the extra bytes simply wait for the next export — chasing a growing
// total would never finish on a live session. For the same reason
// EndedAt stays zero here: the sessions reply carries no end time, so
// the window never learns when the session ended even when it has. The
// exporter already speaks that dialect — a zero EndedAt is its printed
// "ended: still running", meaning "no end is known to this side", not a
// claim that the session is still going.
//
// One refusal comes before any of this. The gateway serves a session's
// bytes only while the session sits in its live registry (live_tail.go
// removes the entry when the session is over, and its tail then answers
// "nothing left to follow" — an empty body that would otherwise be
// walked into an empty recording and exported as if the session never
// said a word). A finished recording is reached by an admin through
// recordings.fetch, not from this button.
//
// The recording is streamed, not buffered. Each chunk the gateway
// answers for is written to a temp file BEFORE the next chunk is even
// asked for, and is fed to the VT emulator alongside — the same
// reader call the Session tab makes (record.ParserFor) — so the only bytes
// held in memory at any one moment are one chunk and the VT's bounded
// scrollback (maxHistoryLines = 10000 lines; the transcript is whatever
// that scrollback currently keeps). The exporter reads the temp file
// straight through `io.Copy`/`io.ReadAll`, so the recording never sits
// whole in this process twice. The two temp files (cast, transcript)
// sit next to the eventual export tree and are removed on every exit
// path, including the errors that interrupt the walk.
func guiSessionExport(serverDir, sessionID string) (string, error) {
	ctx := context.Background()
	dirs := config.Dirs{Server: serverDir}

	// The machine's name comes from what the window already knows: the
	// registration record machine.id, the same file the Set up screen
	// reads it from. A name that did not read or reads empty is refused,
	// never replaced — the name is half of the export folder's name, and
	// an invented one would file this session where nobody looks for it.
	raw, err := datafile.ReadFile(dirs.MachineID())
	if err != nil {
		return "", fmt.Errorf("this machine's registration record (%s) did not open: %w", dirs.MachineID(), err)
	}
	machine := strings.TrimSpace(string(raw))
	if machine == "" {
		return "", fmt.Errorf("this machine's registration (%s) does not say its own name, and the export folder is named with it", dirs.MachineID())
	}

	// The person and the start come from the same live list the tab
	// shows — the only place this side holds them. A session that is not
	// on it, a session without a person's name, a session with an
	// unreadable start: all three are refused loudly rather than filled
	// with a guess, because every one of those values names the export
	// folder.
	reply, contacted, err := sendControlSessions(serverDir)
	if err != nil {
		return "", err
	}
	if !contacted {
		return "", errors.New("this machine's server is not running, so there is nothing to export")
	}
	if !reply.OK {
		return "", errors.New(reply.Message)
	}
	var info *proto.MineSession
	for i := range reply.Sessions {
		if reply.Sessions[i].ID == sessionID {
			info = &reply.Sessions[i]
			break
		}
	}
	if info == nil {
		return "", fmt.Errorf("session %s is not on this machine's live list, so there is no person's name to export it under — the export refuses to guess", sessionID)
	}
	if info.Person == "" {
		return "", fmt.Errorf("the live list carries no person's name for session %s, and the export refuses to invent one", sessionID)
	}
	started := parseSessionTime(info.Started)
	if started.IsZero() {
		return "", fmt.Errorf("the live list does not say when session %s started (its stamp is %q), and the export folder is named with that start", sessionID, info.Started)
	}

	// The bytes. Chunk by chunk, reassembled in the order the gateway
	// answered for them: a terminal is a sequential state machine, and
	// feeding it its own recording out of order corrupts the text
	// silently — a wrong offset is a loud refusal, not a shrug.
	first, err := guiSessionTail(ctx, serverDir, ui.SessionTailReq{ID: sessionID, Offset: 0, Limit: server.TailChunkMax})
	if err != nil {
		return "", fmt.Errorf("the recording could not be read: %w", err)
	}
	if !first.Live {
		return "", errors.New("the gateway no longer serves this session's recording: once a session is over, its tail answers nothing, and an export of nothing would deny a session that happened — export while it is still live, or fetch the finished recording as an admin")
	}

	// Stream the cast to a temp file as each chunk arrives, and feed the
	// same chunk through the recording's reader (which already carries the
	// remainder across calls). One chunk + the bounded VT state is all
	// this process holds of the recording at any moment — the second
	// in-memory copy the old path took is gone.
	exportsDir := filepath.Join(serverDir, exportRootName)
	if err := os.MkdirAll(exportsDir, 0o700); err != nil {
		return "", fmt.Errorf("the export directory (%s) did not create: %w", exportsDir, err)
	}
	castTmp, err := os.CreateTemp(exportsDir, ".export-cast-*.cast.tmp")
	if err != nil {
		return "", fmt.Errorf("the cast temp file did not create under %s: %w", exportsDir, err)
	}
	castTmpPath := castTmp.Name()
	defer func() { _ = os.Remove(castTmpPath) }()

	vt := record.NewVT(80, 24)
	var remainder []byte
	// The reader the gateway named (IAMT-453): a live exec session is an
	// exec recording, and read as a cast it is an empty page.
	parse := record.ParserFor(first.Mode)

	if _, werr := castTmp.Write(first.Data); werr != nil {
		_ = castTmp.Close()
		return "", fmt.Errorf("the recording could not be staged to a temp file at byte 0: %w", werr)
	}
	remainder = parse(first.Data, remainder, vt)

	for next := uint64(len(first.Data)); next < first.Total; {
		resp, err := guiSessionTail(ctx, serverDir, ui.SessionTailReq{ID: sessionID, Offset: next, Limit: server.TailChunkMax})
		if err != nil {
			_ = castTmp.Close()
			return "", fmt.Errorf("the recording stopped at byte %d of %d: %w (the session may have ended while it was being read)", next, first.Total, err)
		}
		if resp.Offset != next {
			_ = castTmp.Close()
			return "", fmt.Errorf("the gateway answered from byte %d when byte %d was asked: the recording cannot be reassembled out of order", resp.Offset, next)
		}
		if len(resp.Data) == 0 {
			_ = castTmp.Close()
			return "", fmt.Errorf("the gateway stopped sending at byte %d of %d, and the walk cannot advance", next, first.Total)
		}
		if _, werr := castTmp.Write(resp.Data); werr != nil {
			_ = castTmp.Close()
			return "", fmt.Errorf("the recording could not be staged to a temp file at byte %d: %w", next, werr)
		}
		remainder = parse(resp.Data, remainder, vt)
		next += uint64(len(resp.Data))
	}
	if err := castTmp.Close(); err != nil {
		return "", fmt.Errorf("the cast temp file (%s) did not close: %w", castTmpPath, err)
	}

	if len(remainder) > 0 {
		// A recording that does not end in a newline still has a last
		// event, and it belongs in the export. Terminating it makes the
		// parser hand it to the emulator; whatever comes back is by
		// construction empty, and is deliberately dropped rather than
		// kept — there is no next chunk to carry it into.
		_ = parse(append(remainder, '\n'), nil, vt)
	}
	vt.Flush()
	transcript := vt.Transcript()
	dropped := vt.OmittedLines()

	// The transcript is bounded by the VT scrollback
	// (`maxHistoryLines = 10000` in internal/gateway/record/vt.go) — its
	// own ceiling, not ours — but it is still a string in this process
	// after `vt.Transcript()`. The exporter already accepts an
	// `io.Reader`, so hand it one backed by a temp file and let
	// `io.ReadAll` on its side do the work. The temp file's life is
	// this single export; `defer os.Remove` cleans it up whether the
	// exporter succeeded or refused mid-write.
	transcriptTmp, err := os.CreateTemp(exportsDir, ".export-transcript-*.txt.tmp")
	if err != nil {
		return "", fmt.Errorf("the transcript temp file did not create under %s: %w", exportsDir, err)
	}
	transcriptTmpPath := transcriptTmp.Name()
	defer func() { _ = os.Remove(transcriptTmpPath) }()
	if _, werr := transcriptTmp.WriteString(transcript); werr != nil {
		_ = transcriptTmp.Close()
		return "", fmt.Errorf("the transcript temp file (%s) did not accept the text: %w", transcriptTmpPath, werr)
	}
	if err := transcriptTmp.Close(); err != nil {
		return "", fmt.Errorf("the transcript temp file (%s) did not close: %w", transcriptTmpPath, err)
	}

	// The journal. The window role keeps no journal open of its own,
	// and that gap is not papered over with a sink that swallows
	// events. The one journal this side
	// already has is the machine's own events.jsonl, where the door and
	// the watchdog append their {"Op":...} records; the export adds the
	// gateway-style recording.export line to the same file, opened fresh
	// for this one event and closed right after. The two writers share
	// the file the way the two processes already do — append-only handles
	// — and an open that fails is a refusal, never a silent copy.
	journal, err := events.OpenLog(dirs.ServerEvents())
	if err != nil {
		return "", fmt.Errorf("the machine's own journal (%s) did not open: %w — an export that leaves no journal event is a silent copy, so the export refuses", dirs.ServerEvents(), err)
	}
	defer journal.Close()

	// Open the temp files as readers just before handing them to the
	// exporter. The exporter itself streams the cast through
	// `io.Copy(io.MultiWriter(file, sha256), cast)` and reads the
	// transcript via `io.ReadAll`; both accept any `io.Reader`, and the
	// temp files are positioned at zero because they were just
	// written-then-closed by `os.CreateTemp`. The re-open goes through
	// `datafile.OpenExisting` so a planted entry at the temp name is
	// refused the same way every other data-file re-open is — the
	// exporter's io.Copy and io.ReadAll do not expect a symlink or a
	// FIFO in the middle of an export, and this is the only door raw
	// file I/O has (gate 16 / IAMT-332 round 9).
	castFile, err := datafile.OpenExisting(castTmpPath, os.O_RDONLY)
	if err != nil {
		return "", fmt.Errorf("the cast temp file (%s) did not re-open for the exporter: %w", castTmpPath, err)
	}
	defer castFile.Close()

	transcriptFile, err := datafile.OpenExisting(transcriptTmpPath, os.O_RDONLY)
	if err != nil {
		return "", fmt.Errorf("the transcript temp file (%s) did not re-open for the exporter: %w", transcriptTmpPath, err)
	}
	defer transcriptFile.Close()

	// An exec recording is not asciicast, and the exporter would file it
	// as session.cast. Its text above is the whole of what it says - the
	// command and its output - so the export carries that alone, and
	// about.txt says there is no cast.
	var cast io.Reader = castFile
	if first.Mode == record.LiveModeExec {
		cast = nil
	}

	res, xerr := export.Export(export.Request{
		Root:       filepath.Join(serverDir, exportRootName),
		Transcript: transcriptFile,
		Cast:       cast,
		Person:     info.Person,
		Machine:    machine,
		SessionID:  sessionID,
		StartedAt:  started,
		// The journal event's Actor is the one name this side holds that
		// the PROTOCOL §2.1 grammar already vouched for: the machine's
		// registered name. The enrolment record's osUser is a report of
		// an OS account, not a name anything validated, and betting the
		// whole export on it would gamble a real recording on a string
		// the grammar may refuse.
		Exporter: machine,
		Version:  version,
		Journal:  journal,
	})
	if xerr != nil {
		if res.Dir != "" {
			// The exporter keeps whatever landed before the error and
			// names the folder in its Result even on failure; the human
			// needs both facts, not just the failure.
			return "", fmt.Errorf("%v (the files that made it to disk are in %s)", xerr, res.Dir)
		}
		return "", xerr
	}
	if dropped > 0 {
		// The terminal keeps the session's beginning and its end under a
		// cap, and the export text is what it kept — same as the gateway's
		// own transcript at close (R4 F-05). The count is the honest size
		// of the gap in the middle; the exported .cast has every line.
		return fmt.Sprintf("The session is exported to %s. The text leaves out %d lines from the middle of the session; the exported .cast has all of them.", res.Dir, dropped), nil
	}
	return "The session is exported to " + res.Dir + ".", nil
}

// guiReplayCast feeds the collected chunks one at a time through the
// VT interpreter the Session tab draws with — `record.ParseCast`,
// shared on purpose so the exported text cannot drift from what the
// tab showed — and, if `castOut` is not nil, writes each chunk's raw
// bytes to it as it arrives. The returned transcript is the same
// `vt.Transcript()` the live tab produces, and the returned dropped
// count is the same number of history lines the terminal itself had
// already dropped under its own cap.
//
// Passing `castOut == nil` is supported: the function is then a pure
// VT replay with no on-disk shadow. The production path does not go
// through this helper any more — the streaming loop in `guiSessionExport`
// is what an actual export uses, so the recording never sits whole in
// this process — but the helper stays alive because the chunk-canary
// and the replay-from-zero tests want to drive it with hand-split
// chunks without writing to disk.
//
// A recording whose last line lost its newline (a recorder cut off
// mid-write) still keeps that line's text: the parser finishes a line
// only on its newline, and the file's last record gets the same implied
// end that repairTornTail gives a journal's last record.
func guiReplayCast(chunks [][]byte, castOut io.Writer) (transcript string, dropped int64, err error) {
	vt := record.NewVT(80, 24)
	var remainder []byte
	for _, chunk := range chunks {
		if castOut != nil {
			if _, werr := castOut.Write(chunk); werr != nil {
				return "", 0, werr
			}
		}
		remainder = record.ParseCast(chunk, remainder, vt)
	}
	if len(remainder) > 0 {
		// A recording that does not end in a newline still has a last
		// event, and it belongs in the export. Terminating it makes the
		// parser hand it to the emulator; whatever comes back is by
		// construction empty, and is deliberately dropped rather than
		// kept — there is no next chunk to carry it into.
		_ = record.ParseCast(append(remainder, '\n'), nil, vt)
	}
	vt.Flush()
	return vt.Transcript(), vt.OmittedLines(), nil
}
