package events

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// IAMT-467: the gateway's journal is the evidence of who came in and why
// somebody was refused, and a damaged or hand-edited line used to leave no
// trace. Every line of a chained journal carries prev_hash: the
// SHA-256 of the line before it, byte for byte as it lies in the file
// (without its line end). Changing, removing or inserting a line breaks the
// link of the line after it - across a rotation too, since the first line
// of a fresh journal names the last line of the archive it follows.
//
// What the chain does not prove. It has no anchor outside the files: lines
// cut off the END, or a journal replaced wholesale by a new one that starts
// over, leave nothing behind to disagree. It proves that what is there is
// what was written, in that order, from the first chained line on - against
// damage and hand edits. The hash has no key (R4 F-06): whoever can write
// the file can edit a line and recompute every hash after it, and the chain
// agrees. Summary says so on every intact verdict.
//
// Journals from before the chain (1.13 and older) have no prev_hash at all.
// Those lines are counted as unchained, not as broken: the first chained
// line names the hash of the last unchained one, so the chain is anchored
// to whatever was already there, and from that line on it is checked. A
// line without prev_hash AFTER the chain began is a different matter - it
// was written by something that does not chain (an older binary, or a
// hand), and the report names it.
//
// Only the gateway's own journal is chained (OpenChainedLog). A machine's
// events.jsonl has writers in other processes that do not chain - the door
// watchdog among them - and would read as a string of gaps.

// genesisHash is the prev_hash of the first line of a chained journal that
// had no line before it.
const genesisHash = "genesis"

// chainLockWait bounds how long an append waits for another writer of the
// same journal (the service and "gateway rotate-hostkey" can both write).
const chainLockWait = 5 * time.Second

// OpenChainedLog is OpenLog for a journal whose every line carries
// prev_hash (IAMT-467): the gateway's events.jsonl.
func OpenChainedLog(path string) (*Log, error) {
	l, err := OpenLog(path)
	if err != nil {
		return nil, err
	}
	l.chain = true
	return l, nil
}

// LineHash is the prev_hash a line gets in the line after it: the SHA-256
// of the line's bytes without its line end.
func LineHash(line []byte) string {
	sum := sha256.Sum256(bytes.TrimRight(line, "\r"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// lockChain takes the journal's cross-process append lock, a file beside
// it. The hash of the line before has to be read from the file itself,
// not remembered: another process may have appended since, and a
// remembered hash would fork the chain.
func (l *Log) lockChain() (func(), error) {
	deadline := time.Now().Add(chainLockWait)
	for {
		fl, err := state.AcquireFileLock(l.path + ".lock")
		if err == nil {
			return func() { _ = fl.Unlock() }, nil
		}
		if !errors.Is(err, state.ErrLockHeld) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(time.Millisecond)
	}
}

// writeChainedLocked writes e as the next line with prev_hash prev, or,
// when prev is empty, with the hash of the file's last line. Must be called
// with l.mu and the chain lock held.
func (l *Log) writeChainedLocked(e Event, prev string) error {
	if prev == "" {
		last, torn, err := lastLine(l.path)
		if err != nil {
			return fmt.Errorf("event not written to %s: reading the line it follows: %w", l.path, err)
		}
		if torn {
			// A line another writer never finished: end it first, as
			// OpenLog does at start, or this one would be glued to it.
			if _, err := l.file.Write([]byte{'\n'}); err != nil {
				return fmt.Errorf("failed to append event to log: %w", err)
			}
		}
		prev = genesisHash
		if last != nil {
			prev = LineHash(last)
		}
	}
	e.PrevHash = prev
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}
	raw = append(raw, '\n')
	if _, err := l.file.Write(raw); err != nil {
		return fmt.Errorf("failed to append event to log: %w", err)
	}
	return l.file.Sync()
}

// lastLine returns the last non-empty line of the file at path, without
// its line end, or nil when there is none; torn reports that the file does
// not end with a line end.
func lastLine(path string) (line []byte, torn bool, err error) {
	f, err := state.OpenExistingDataFile(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if st.Size() == 0 {
		return nil, false, nil
	}
	end := make([]byte, 1)
	if _, err := f.ReadAt(end, st.Size()-1); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	torn = end[0] != '\n'
	const block = 4096
	var tail []byte
	for pos := st.Size(); pos > 0; {
		n := int64(block)
		if n > pos {
			n = pos
		}
		pos -= n
		chunk := make([]byte, n)
		if _, err := f.ReadAt(chunk, pos); err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		tail = append(chunk, tail...)
		body := bytes.TrimRight(tail, "\r\n\t ")
		if len(body) == 0 {
			continue
		}
		if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
			return bytes.TrimRight(body[i+1:], "\r"), torn, nil
		}
		if pos == 0 {
			return bytes.TrimRight(body, "\r"), torn, nil
		}
	}
	return nil, torn, nil
}

// ChainReport is what VerifyChain found.
type ChainReport struct {
	// Files and Lines are how much was read.
	Files, Lines int
	// Legacy counts the lines before the chain began: written before the
	// journal was chained, unchecked but not broken.
	Legacy int
	// Chained counts the lines that carry prev_hash.
	Chained int
	// Unreadable counts lines that are not JSON at all (a line cut short
	// by a crash, or damage). The chain still runs through them: the line
	// after one names its hash. They are events that are gone, so a
	// journal holding one is not intact (F-02, round-1 review 24.09.2026):
	// verify-journal exists to say whether the journal is whole, and a
	// line nobody can read is not whole whatever the chain says about its
	// neighbours.
	Unreadable int
	// FirstUnreadableFile/Line name the first of them.
	FirstUnreadableFile string
	FirstUnreadableLine int
	// UnreadableAtEnd is set when that line is the last line of the last
	// file: the shape a crash leaves - the line being written when the
	// power went - rather than damage in the middle of the journal. The
	// verdict is the same; the sentence is not.
	UnreadableAtEnd bool
	// Unvouched counts lines without prev_hash after the chain began.
	Unvouched          int
	FirstUnvouchedFile string
	FirstUnvouchedLine int
	// Broken is set at the first line whose prev_hash is not the hash of
	// the line before it: that line, or the one before it, is not what was
	// written - changed, removed or inserted.
	Broken      bool
	BreakFile   string
	BreakLine   int
	BreakReason string
}

// Intact is whether the journal is, as far as the chain can tell, what
// was written: no broken link, no line the chain does not vouch for, and
// no line nobody can read at all (F-02).
func (r ChainReport) Intact() bool { return !r.Broken && r.Unvouched == 0 && r.Unreadable == 0 }

// Summary is the report in one sentence, for the command and the tab.
func (r ChainReport) Summary() string {
	switch {
	case r.Broken:
		return fmt.Sprintf("BROKEN at %s line %d: %s", r.BreakFile, r.BreakLine, r.BreakReason)
	case r.Unreadable > 0:
		if r.UnreadableAtEnd {
			return fmt.Sprintf("%d line(s) at the end of %s could not be read (line %d): the last write was cut off, so an event is missing from the end of the journal — the chained lines before it agree with each other", r.Unreadable, r.FirstUnreadableFile, r.FirstUnreadableLine)
		}
		return fmt.Sprintf("%d line(s) could not be read at all, first at %s line %d: an event is gone from the middle of the journal, and the chain vouches only for the lines on either side of the hole", r.Unreadable, r.FirstUnreadableFile, r.FirstUnreadableLine)
	case r.Unvouched > 0:
		return fmt.Sprintf("%d line(s) written without the chain after it began, first at %s line %d; the chained lines agree with each other", r.Unvouched, r.FirstUnvouchedFile, r.FirstUnvouchedLine)
	case r.Chained == 0 && r.Legacy == 0:
		return "the journal is empty"
	case r.Legacy > 0:
		return fmt.Sprintf("intact: %d chained line(s) in %d file(s) agree; the %d line(s) before them were written before the chain and are not checked%s", r.Chained, r.Files, r.Legacy, chainLimit)
	default:
		return fmt.Sprintf("intact: %d line(s) in %d file(s), every one names the one before it%s", r.Chained, r.Files, chainLimit)
	}
}

// chainLimit is what an intact verdict says about itself (R4 F-06): the
// hashes carry no key, so the chain catches damage and hand edits, not a
// rewrite by someone who can write the file and recompute them.
const chainLimit = " (this catches damage and hand edits; it cannot catch someone who can write the file and recompute the hashes)"

// VerifyChain reads the journal in dir - its archives in order, then the
// current file, as ReadHistory does - and checks every link.
func VerifyChain(dir string) (ChainReport, error) {
	var rep ChainReport
	files, err := historyNames(dir)
	if err != nil {
		return rep, err
	}

	prev := "" // hash of the line before; "" before the first line
	started := false
	atEnd := false
	for _, name := range files {
		rep.Files++
		tail, err := verifyChainFile(filepath.Join(dir, name), name, &rep, &prev, &started)
		if err != nil {
			return rep, err
		}
		// Only the LAST file's torn tail is the end of the journal: an
		// unreadable line at the end of an archive has the live journal
		// after it, which makes it a hole rather than a cut-off write.
		atEnd = tail
	}
	rep.UnreadableAtEnd = atEnd && rep.Unreadable > 0
	return rep, nil
}

// verifyChainFile checks one file and reports whether its LAST line was
// the unreadable one - the torn tail a crash leaves.
func verifyChainFile(path, name string, rep *ChainReport, prev *string, started *bool) (tailUnreadable bool, err error) {
	f, err := state.OpenExistingDataFile(path, os.O_RDONLY)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for n := 1; ; n++ {
		raw, rerr := r.ReadBytes('\n')
		line := bytes.TrimRight(raw, "\r\n")
		if len(bytes.TrimSpace(line)) > 0 {
			rep.Lines++
			var head struct {
				PrevHash *string `json:"prev_hash"`
			}
			switch {
			case json.Unmarshal(line, &head) != nil:
				rep.Unreadable++
				if rep.Unreadable == 1 {
					rep.FirstUnreadableFile, rep.FirstUnreadableLine = name, n
				}
				// rerr != nil means ReadBytes returned at end of file:
				// this is the file's last line.
				if rerr != nil {
					tailUnreadable = true
				}
				if !*started {
					rep.Legacy++
				}
			case head.PrevHash == nil:
				if *started {
					rep.Unvouched++
					if rep.Unvouched == 1 {
						rep.FirstUnvouchedFile, rep.FirstUnvouchedLine = name, n
					}
				} else {
					rep.Legacy++
				}
			default:
				want := *prev
				if want == "" {
					want = genesisHash
				}
				*started = true
				rep.Chained++
				if *head.PrevHash != want && !rep.Broken {
					rep.Broken, rep.BreakFile, rep.BreakLine = true, name, n
					switch {
					case *head.PrevHash == genesisHash:
						rep.BreakReason = "the chain starts over here, after lines it does not name - the journal it followed was replaced"
					case *prev == "":
						rep.BreakReason = "the first line names a line before it that is not here"
					default:
						rep.BreakReason = "prev_hash is not the hash of the line before: that line or this one was changed, or a line between them was removed or inserted"
					}
				}
			}
			*prev = LineHash(line)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return tailUnreadable, nil
			}
			return false, fmt.Errorf("%s line %d: %w", name, n, rerr)
		}
	}
}
