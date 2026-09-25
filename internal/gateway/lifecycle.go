package gateway

// lifecycle.go holds the gateway's own disk lifecycle mechanics (SPEC
// §3.5, RUNBOOK §3-§4): the state backup archive, its restore, and the
// host key rotation. The local CLI verbs ("iamtunnel gateway
// backup|restore|rotate-hostkey", cmd/iamtunnel/gateway.go) and the
// remote admin exec commands (admin_lifecycle.go, PROTOCOL §6
// gateway.backup / gateway.rotate-hostkey) are two front ends over THIS
// one implementation, so the two paths cannot drift apart the way
// IAMT-162 finding G3 happened: the client promised, the gateway did
// not have the commands at all.
//
// Nothing here opens the state store's lock EXCEPT the restore: a
// backup only reads, but a restore replaces state.json and moves the
// journal, so it takes the same exclusive lock "gateway run" holds and
// refuses a live gateway the way "gateway pair" and "install
// --rebootstrap" do (M-8, code review 23.09.2026, review F-11). Reading
// the two member files straight off disk is safe for the backup because
// state.json is always written tmp-then-rename
// (internal/gateway/state/store.go), so a reader yields a complete
// previous or complete current file, never a torn one. The remote
// caller runs inside the gateway process itself, so no second lock is
// needed there either — which is why only "gateway.backup" and
// "gateway.rotate-hostkey" are remote commands and restore is not.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// HostKeyFileName is the gateway's own host key file inside the data
// dir; rotation keeps the previous key beside it as HostKeyFileName +
// ".old" (RUNBOOK §4.3: the old key remains as hostkey.old).
const HostKeyFileName = "hostkey"

// HostKeyRotateLockFile is the lock a rotation holds for as long as it
// runs, so the local verb and a live gateway's remote rotate-hostkey
// cannot rotate the same key under each other (F-06, round-1 review
// 24.09.2026). It is an OS-level lock: a process that dies releases it.
const HostKeyRotateLockFile = "hostkey.rotate.lock"

// BackupArchiveDir is where remote gateway.backup archives land inside
// the data dir (PROTOCOL §6: the gateway.backup archive is created in
// the gateway's local storage).
const BackupArchiveDir = "backups"

// Restore reads an archive whose bytes are not the gateway's to trust, so
// each member is refused by its DECLARED size before it is read, rather
// than unpacked into memory and judged afterwards (R2-CX F-11, round-2
// review 24.09.2026). An archive that lies is refused the same way
// as one that is merely enormous: the reader stops at the size it was
// willing to read, and the answer names the size and the limit.
//
// The limits are far above anything this build writes. state.json holds
// people, machines, keys and grants - kilobytes for a large fleet. The
// journal is rotated by the gateway itself at JournalRotateBytes (64 MiB
// by default, config.go), so a backup of a running gateway carries a
// little over that at most; the cap is four times it, because a gateway
// from before rotation existed (or one whose rotation is switched off)
// may legitimately hold more.
const (
	maxRestoreStateBytes   = 64 << 20
	maxRestoreJournalBytes = 4 * (64 << 20)
)

// InvalidArchiveError marks an otherwise readable archive that is not an
// iamtunnel backup: it has a foreign member or lacks state.json. It
// deliberately excludes malformed gzip/tar streams, member read failures, and
// opening or writing paths; those remain environment/permission failures.
// The CLI reports this narrow user-input class as exitUser.
type InvalidArchiveError struct{ err error }

func (e *InvalidArchiveError) Error() string { return e.err.Error() }
func (e *InvalidArchiveError) Unwrap() error { return e.err }

func invalidArchiveErrorf(format string, args ...interface{}) error {
	return &InvalidArchiveError{err: fmt.Errorf(format, args...)}
}

func hostKeyPath(dir string) string { return filepath.Join(dir, HostKeyFileName) }

// adoptOwnership is the ownership-adoption seam for every atomic replace
// this package performs (IAMT-332): a root-run "gateway restore" or
// "gateway rotate-hostkey" renames root-owned temporary files over
// state.json, events.jsonl and the host key, which the unprivileged
// service account must go on reading. The default is the real platform
// step, state.PreserveOwnership; tests swap in a recorder so nothing is
// chowned for real and root is never needed.
var adoptOwnership = state.PreserveOwnership

// ---- backup / restore -----------------------------------------------------

// restoreNowFn is the clock a restore labels its recovery points with.
// It is a seam (the same shape as probeDeadlineFn and openAfterRotate)
// because the property F-09 is about — two restores in the same second
// must not land on the same two names — is a question about the clock, and
// a test that waits for two restores to fall inside one second is a test
// that flakes on a slow machine and proves nothing on a fast one.
var restoreNowFn = func() time.Time { return time.Now().UTC() }

// restoreLabelTries bounds how many random tags one restore may burn
// looking for a free pair of names. A collision needs a previous restore
// in the same second AND the same four random bytes.
const restoreLabelTries = 8

// restoreLabelFor picks the label of one restore and the archive name that
// hangs off it: the UTC moment plus a random tag, retried while either
// name is already taken, and refused when no free pair is found. The
// moment alone was the whole label until F-09, so a second restore in the
// same second silently replaced the first one's state.json copy on Unix
// (and could fail mid-way on Windows, after the state had been replaced).
// An operator's recovery point is never overwritten; if it cannot be kept,
// the restore does not happen.
func restoreLabelFor(dir, statePath string, now time.Time) (label, journalArchive string, err error) {
	moment := now.Format("20060102T150405Z")
	for i := 0; i < restoreLabelTries; i++ {
		var tag [4]byte
		if _, rerr := rand.Read(tag[:]); rerr != nil {
			return "", "", fmt.Errorf("restore label: %w", rerr)
		}
		hexTag := hex.EncodeToString(tag[:])
		label = moment + "-" + hexTag
		journalArchive = filepath.Join(dir, events.ArchiveNameFor(now, hexTag))
		if !fileExists(statePath+".pre-restore-"+label) && !fileExists(journalArchive) {
			return label, journalArchive, nil
		}
	}
	return "", "", fmt.Errorf("cannot find a free name for this restore's recovery points in %s in %d tries: the names carry a random tag, so this many collisions means the directory is not behaving like one this command wrote — nothing has been changed",
		dir, restoreLabelTries)
}

// backupMembers lists exactly the two files SPEC §3.5 says a backup is
// ("state.json + events.jsonl in a tarball") and nothing else — no
// recordings, no lock file, no host key. events.jsonl is optional: a
// gateway that has never logged anything yet still has a valid backup
// of its (empty) state.
var backupMembers = []struct {
	name     string
	required bool
}{
	{state.StateFileName, true},
	{"events.jsonl", false},
}

// WriteBackupTarGz packs the gateway's state.json and events.jsonl from
// dir into the tar.gz archive at out. It is the one archive writer for
// both the local CLI verb and the remote gateway.backup exec. The
// archive lands wherever the operator points --out — often outside the
// 0700 data dir — so it is created 0600, the same discipline
// atomicWriteFile applies to state.json itself: the backup carries the
// full people/machines/grants state and must not be world-readable
// (IAMT-260; the mode is ignored on Windows).
//
// The archive streams, so this is WriteFileAtomicFunc (IAMT-332 round
// nine): the old os.OpenFile(out, O_TRUNC) opened the final name, and
// a plant there — a symlink on POSIX, or a hard link on Windows, which
// needs no privilege at all — aimed the whole backup (state, machines,
// grants) straight into somebody else's file. The replace acts on the
// entry, never through it, and every optional step runs before the
// rename.
func WriteBackupTarGz(out, dir string) error {
	members, rerr := readBackupMembers(dir)
	if rerr != nil {
		return rerr
	}
	return datafile.WriteFileAtomicFunc(out, func(f *os.File) error {
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for _, m := range members {
			hdr := &tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.data)), ModTime: time.Now()}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := tw.Write(m.data); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		return gz.Close()
	}, datafile.WithMode(0o600))
}

// backupMember is one file of the archive, read whole.
type backupMember struct {
	name string
	data []byte
}

// readBackupMembers reads the two files a backup is made of AS ONE PAIR
// (F-22, round-1 review 24.09.2026). RUNBOOK §3 promises the archive is
// packed under lock and says in the same breath why copying the
// directory of a running gateway is forbidden — the two files are written
// separately, so a reader can catch one of them from before a change and
// the other from after it, and the archive then holds a state and an audit
// trail that describe different gateways.
//
// Two things keep the pair together here, and since the third round of
// review the first one is structural rather than a list of names:
//
//   - accessPublishMu, which EVERY writer of the pair holds from its state
//     write to its journal line: the admin commands (admin_role.go), the
//     one-off roles (enrol, bootstrap, pairing — pairing joined in R3 F-01),
//     the automatic writers (the sshd probe and the host-key observation,
//     R3 F-03) and the risk-key replacement (R3 extra). The scenario the
//     finding names — a change landing while the backup runs — cannot be
//     read in two halves: the archive is not taken between those two
//     writes. (For the local CLI verb this mutex is this process's own and
//     nobody else holds it; what protects that case is the check below.)
//     One writer is deliberately outside it and stays there: the line
//     machines.verify writes about itself, after its probe has already
//     published the state change under the probe's own lock. Taking the
//     mutex there would meet that probe's locks on the same goroutine, and
//     the pair is consistent without it — the state's change is recorded by
//     the probe's own line, and the command's line is a second witness.
//   - reading the pair twice and keeping it only if neither file changed
//     in between. That is what the local verb has, and it is the backstop
//     for anything the mutex cannot see: another process, a writer from
//     before this rule, or the boundary named above. It REDUCES the window
//     rather than closing it — a pause of a writer that spans both reads
//     is accepted — which is why the writers above are the real answer and
//     this is the net under them. A gateway busy enough to change something
//     on every attempt is refused rather than archived: an operator is owed
//     a snapshot, not a guess.
func readBackupMembers(dir string) ([]backupMember, error) {
	for attempt := 0; attempt < backupReadTries; attempt++ {
		first, err := readBackupOnce(dir)
		if err != nil {
			return nil, err
		}
		second, err := readBackupOnce(dir)
		if err != nil {
			return nil, err
		}
		if sameBackupMembers(first, second) {
			return first, nil
		}
	}
	return nil, fmt.Errorf("%s: the gateway kept writing while the backup was being read (%d attempts): the state and the journal would come from different moments, and a backup is worth having only if they do not — try again when the gateway is quieter",
		dir, backupReadTries)
}

// backupReadTries bounds how many times a backup tries to catch a pair
// that does not move under it.
const backupReadTries = 5

// readBackupOnce reads the members under the access-publication lock.
func readBackupOnce(dir string) ([]backupMember, error) {
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	out := make([]backupMember, 0, len(backupMembers))
	for _, m := range backupMembers {
		src := filepath.Join(dir, m.name)
		data, rerr := state.ReadDataFile(src)
		if rerr != nil {
			if os.IsNotExist(rerr) && !m.required {
				continue
			}
			return nil, fmt.Errorf("%s: %w", src, rerr)
		}
		out = append(out, backupMember{name: m.name, data: data})
	}
	return out, nil
}

func sameBackupMembers(a, b []backupMember) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].name != b[i].name || !bytes.Equal(a[i].data, b[i].data) {
			return false
		}
	}
	return true
}

// CreateBackupArchive is the remote gateway.backup operation (PROTOCOL
// §6): it writes the archive into the gateway's own local storage under
// backups/<id> and reports the id, path, size and SHA-256 of the file.
// The id is the archive's file name, so an operator can feed
// `<data-dir>/backups/<id>` straight to "iamtunnel gateway restore".
func CreateBackupArchive(dir string, now time.Time) (id, path string, size int64, sum string, err error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", "", 0, "", fmt.Errorf("backup id: %w", err)
	}
	id = fmt.Sprintf("iamtunnel-gateway-backup-%s-%s.tar.gz",
		now.UTC().Format("20060102-150405"), hex.EncodeToString(suffix))
	path = filepath.Join(dir, BackupArchiveDir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", 0, "", fmt.Errorf("%s: %w", filepath.Dir(path), err)
	}
	if err := WriteBackupTarGz(path, dir); err != nil {
		return "", "", 0, "", err
	}
	info, serr := os.Stat(path)
	if serr != nil {
		return "", "", 0, "", fmt.Errorf("%s: %w", path, serr)
	}
	sum, herr := fileSHA256Hex(path)
	if herr != nil {
		return "", "", 0, "", herr
	}
	return id, path, info.Size(), sum, nil
}

// RestoreOutcome reports what a restore installed and where it put what
// it moved aside, so the CLI can tell the operator and the RUNBOOK can
// be matched word for word.
type RestoreOutcome struct {
	// Restored names the archive members installed: state.json always,
	// and events.jsonl only when this directory had no journal at all
	// (see RestoreBackupTarGz rule 1).
	Restored []string
	// StateKeptAs is the name of the copy the restore kept of the
	// state.json it replaced, state.json.pre-restore-<label>. Empty when
	// there was no state.json here to keep.
	StateKeptAs string
	// JournalKeptAs is the name the live journal was rotated to,
	// events-<label>.jsonl — a name the history reader already finds.
	// Empty when there was no journal here to keep.
	JournalKeptAs string
}

// RestoreBackupTarGz puts a backup back into dir.
//
// THREE RULES. Each of them is a thing the first version got wrong (M-8,
// code review 23.09.2026, review F-11), and each is stated here because
// the shape of this function is the rule:
//
//  1. THE JOURNAL IS NEVER ROLLED BACK. events.jsonl is append-only, and
//     the old restore replaced it with the archive's copy: every auth.*,
//     session.* and admin.op written after the backup vanished from the
//     history, and no copy of them was kept anywhere. A restore now
//     ROTATES the live journal aside as events-<label>.jsonl — the name
//     the history reader already knows (events.IsLogFileName, the naming
//     events.ArchiveName produces) — so ReadHistory, the History tab and
//     the exporter still see every event, and the log.rotate line the
//     rotation writes into the fresh journal says where it went. The
//     archive's own journal is installed only when this directory has no
//     journal at all: that is the disaster the member exists for (a
//     fresh disk). Installing it over a live journal would put every
//     pre-backup event into the history twice — once from the archive
//     and once from the restored file — and would be the rollback this
//     rule forbids, in a quieter voice.
//  2. IT TAKES THE STATE LOCK, like "gateway pair" and "install
//     --rebootstrap". A running gateway keeps its handle to the journal
//     and rewrites state.json from memory on its next transaction, so a
//     restore under it is a restore that undoes itself without a word.
//     A gateway that is running is refused; a corrupt state.json is not
//     (that is the case this command exists for, and state.Open returns
//     the lock with the read-only store).
//  3. AN ARCHIVE IS INPUT. It arrives from a backup directory, a USB
//     stick, another machine, so only regular-file members are read (a
//     link or a device entry named state.json carries no bytes of its
//     own), and the state.json inside must pass the state package's own
//     Validate BEFORE anything on disk is replaced. What is replaced is
//     kept first: state.json as state.json.pre-restore-<label>. The
//     whole restore lands in the journal as an admin.op event, because
//     an operator reading the history later has to be able to see that
//     the state was rolled back to a backup and which one.
//
// The two "kept as" names share one label — the UTC moment of the
// restore — so the operator can pair them up by eye.
func RestoreBackupTarGz(archivePath, dir string) (RestoreOutcome, error) {
	var out RestoreOutcome
	now := restoreNowFn()
	statePath := filepath.Join(dir, state.StateFileName)
	journalPath := filepath.Join(dir, events.DefaultLogFileName)
	// The label is that same moment in the canonical archive shape
	// (events-<label>.jsonl), so the name the journal is rotated to is the
	// name the history reader finds — and it carries a random tag, so two
	// restores in the same second keep two recovery points instead of
	// landing on one (F-09, review round 1 24.09.2026).
	label, journalArchive, lerr := restoreLabelFor(dir, statePath, now)
	if lerr != nil {
		return out, lerr
	}

	// What is here BEFORE the store opens: state.Open creates the
	// directory, a fresh state.json and the lock, so afterwards "was
	// there a state.json" cannot be answered any more.
	hadState := fileExists(statePath)
	hadJournal := fileSize(journalPath) > 0

	// Rule 3, first half — and it comes BEFORE the store is opened
	// (R2-CX F-09, round-2 review 24.09.2026). state.Open is not a
	// read: it creates the directory, takes the lock, creates
	// enrol-hmac.key and, with no state.json there, writes a fresh one.
	// Doing that first meant a malformed archive left a directory that
	// looks like an initialized gateway — lock, HMAC key, empty state —
	// although the restore installed nothing, which is exactly what the
	// "nothing here has been changed" refusals below promise it does not.
	// Everything the archive can be refused for is answered here, in
	// memory, before anything on disk is opened for writing.
	f, err := datafile.OpenExisting(archivePath, os.O_RDONLY)
	if err != nil {
		return out, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return out, fmt.Errorf("%s is not a valid gzip file: %w", archivePath, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	allowed := map[string]bool{}
	for _, m := range backupMembers {
		allowed[m.name] = true
	}
	// seen is what keeps a second member of the same name from slipping
	// past the size caps (F-11).
	seen := map[string]bool{}
	var stateBytes, journalBytes []byte
	sawState, sawJournal := false, false
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return out, fmt.Errorf("%s is not a valid tar archive: %w", archivePath, terr)
		}
		// Rule 3, first half. Only a regular file is read: a symlink, a
		// hard link, a device, a directory or anything else is refused in
		// words rather than read as a file that carries no bytes of its
		// own. TypeReg is the one typeflag this program writes
		// (WriteBackupTarGz above); a legacy archive spelling the same
		// thing as the pre-POSIX NUL byte is refused with the rest —
		// "regular file" here means the shape our own backups have.
		if hdr.Typeflag != tar.TypeReg {
			return out, invalidArchiveErrorf("archive entry %q is a %s, not a regular file — a backup of this gateway holds two plain files and nothing else, so an entry of another kind is not ours to install",
				hdr.Name, tarTypeName(hdr.Typeflag))
		}
		name := filepath.Base(hdr.Name)
		if !allowed[name] || name != hdr.Name {
			return out, invalidArchiveErrorf("archive entry %q is not one of the expected files — refusing an archive that does not look like our own backup", hdr.Name)
		}
		if seen[hdr.Name] {
			// A fixed set of names is not a bound on how much an archive
			// can carry: two members of one name would otherwise decide
			// the limit by their number rather than by the file they
			// stand for (F-11).
			return out, invalidArchiveErrorf("archive %s holds %s twice — a backup of this gateway holds two plain files, once each", archivePath, hdr.Name)
		}
		seen[hdr.Name] = true
		limit := int64(maxRestoreStateBytes)
		if name == events.DefaultLogFileName {
			limit = maxRestoreJournalBytes
		}
		if hdr.Size < 0 || hdr.Size > limit {
			// Refused by what the header CLAIMS, before a byte of it is
			// read: an archive that says it carries gigabytes is not one
			// this command unpacks to find out (F-11).
			return out, invalidArchiveErrorf("archive entry %q declares %d bytes, and this restore reads at most %d of it — refusing an archive whose size is not the size of a gateway's %s",
				hdr.Name, hdr.Size, limit, name)
		}
		data, rerr := io.ReadAll(io.LimitReader(tr, limit+1))
		if rerr != nil {
			return out, fmt.Errorf("reading %s from the archive: %w", name, rerr)
		}
		if int64(len(data)) > limit {
			return out, invalidArchiveErrorf("archive entry %q is longer than the %d bytes it declared, or than this restore reads — refusing an archive that is not the size it says it is", hdr.Name, limit)
		}
		if name == state.StateFileName {
			stateBytes, sawState = data, true
		} else {
			journalBytes, sawJournal = data, true
		}
	}
	if !sawState {
		return out, invalidArchiveErrorf("archive %s has no %s — it does not look like a backup made by \"gateway backup\"", archivePath, state.StateFileName)
	}

	// Rule 3, second half: the state the archive carries must be a state
	// this gateway could open. state.Validate is the state package's own
	// rule — the same one every open of state.json runs — so a foreign
	// file, a truncated one or a hand-edited one is refused here, while
	// nothing on disk has been touched yet.
	var probe state.State
	if uerr := json.Unmarshal(stateBytes, &probe); uerr != nil {
		return out, invalidArchiveErrorf("the %s in %s is not valid JSON (%v) — refusing to install a state the gateway cannot open",
			state.StateFileName, archivePath, uerr)
	}
	if verr := probe.Validate(); verr != nil {
		return out, invalidArchiveErrorf("the %s in %s does not validate (%v) — refusing to install it over this gateway's state; nothing here has been changed",
			state.StateFileName, archivePath, verr)
	}

	// Rule 2. state.Open takes the exclusive lock "gateway run" holds.
	store, openErr := state.Open(dir)
	if store != nil {
		defer func() { _ = store.Close() }()
	}
	if openErr != nil {
		var corrupt *state.CorruptStateError
		if !errors.As(openErr, &corrupt) {
			// ErrLockHeld (a gateway is running) or a directory that
			// cannot be used at all: nothing has been touched yet.
			return out, openErr
		}
		// A corrupt state.json is exactly what "gateway restore" is for.
		// The lock is held, and the backup is about to replace the file
		// the store could not read.
	}

	// Keep what is about to be replaced, before replacing it.
	if hadState {
		data, rerr := state.ReadDataFile(statePath)
		if rerr != nil {
			return out, fmt.Errorf("%s: %w", statePath, rerr)
		}
		keepPath := statePath + ".pre-restore-" + label
		if werr := atomicWriteFile(keepPath, data); werr != nil {
			return out, werr
		}
		out.StateKeptAs = filepath.Base(keepPath)
	}

	// Rule 4 (F-10, review round 1 24.09.2026): the ORDER is the safety.
	// The state write is the commit point, and everything that can fail is
	// done before it:
	//
	//   - the journal side first, because it is safe to leave half-done: a
	//     rotation keeps the whole history (rule 1), so a failure here
	//     leaves the gateway with its state untouched and its events all
	//     present, and the operator simply runs the restore again;
	//   - the state second: from here on the restore has happened;
	//   - the archive's own journal (only for a directory that had none)
	//     and the record last, and a failure there says in words that the
	//     state was installed - the operator's pre-restore copy is what
	//     they go back with, which is what keeping it is for.
	//
	// Before this the state was written first, so a failure at the journal
	// left a gateway running on the backup's state with a journal that
	// described the state before it, and nothing anywhere said a restore
	// had been attempted.
	if hadJournal {
		// Rule 4 (F-01, review round 1 24.09.2026): the journal is opened
		// CHAINED, exactly as "gateway run" opens it. This restore is one
		// of the gateway's own writers; opening unchained made its two
		// lines — the rotation's log.rotate and the admin.op that records
		// the restore — lines without prev_hash, and verify-journal, the
		// command whose whole job is to prove the journal was not
		// rewritten, reported the gateway's own journal from then on.
		log, lerr := events.OpenChainedLog(journalPath)
		if lerr != nil {
			return out, lerr
		}
		rerr := log.Rotate(journalArchive)
		cerr := log.Close()
		if rerr != nil {
			return out, fmt.Errorf("rotating the journal aside to %s: %w", filepath.Base(journalArchive), rerr)
		}
		if cerr != nil {
			return out, cerr
		}
		out.JournalKeptAs = filepath.Base(journalArchive)
	}

	// The commit point (rule 4): everything above can fail harmlessly,
	// everything below reports what the operator is left holding.
	if werr := atomicWriteFile(statePath, stateBytes); werr != nil {
		return out, werr
	}
	out.Restored = append(out.Restored, state.StateFileName)

	// Rule 1's second half, and the only journal branch left: a directory
	// with no journal of its own gets the archive's copy. It goes in after
	// the state, never before - installing it over a state this restore
	// did not replace would leave the history describing a gateway that
	// never existed.
	if !hadJournal && sawJournal {
		if werr := atomicWriteFile(journalPath, journalBytes); werr != nil {
			return out, fmt.Errorf("the state from %s is installed, but its journal could not be: %w", filepath.Base(archivePath), werr)
		}
		out.Restored = append(out.Restored, events.DefaultLogFileName)
	}

	// The restore is a journal fact — recorded in whichever journal the
	// two branches above left in place, so it survives in the history
	// next to the events it explains. Chained, like the branch above and
	// like every other writer of this journal (F-01).
	log, lerr := events.OpenChainedLog(journalPath)
	if lerr != nil {
		return out, lerr
	}
	details := map[string]interface{}{
		"archive":  filepath.Base(archivePath),
		"restored": out.Restored,
	}
	if out.StateKeptAs != "" {
		details["stateKeptAs"] = out.StateKeptAs
	}
	if out.JournalKeptAs != "" {
		details["journalKeptAs"] = out.JournalKeptAs
	}
	appErr := log.Append(events.Event{
		Time:    state.NewZonedTime(time.Now().UTC()),
		Type:    events.EventAdminOp,
		Actor:   "gateway",
		Object:  "restore",
		Result:  "ok",
		Details: details,
	})
	cerr := log.Close()
	if appErr != nil {
		// The state is installed and the history is whole; what is missing
		// is the line that says who did it. Saying exactly that is the
		// point (rule 4): rolling the state back because the journal could
		// not take a line would make a restore impossible in the one
		// situation it exists for - a gateway whose journal is broken.
		return out, fmt.Errorf("the state from %s is installed and the journal is in place, but the restore could not be recorded in it: %w", filepath.Base(archivePath), appErr)
	}
	if cerr != nil {
		return out, cerr
	}
	return out, nil
}

// fileExists reports whether path is there at all.
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// fileSize is the size of path, or 0 when it is missing or unreadable: a
// journal this cannot measure is treated as absent, which is the
// conservative branch (nothing is rotated away, and the archive's own
// copy is installed).
func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// tarTypeName names a tar entry type for a refusal message.
func tarTypeName(typeflag byte) string {
	switch typeflag {
	case tar.TypeSymlink:
		return "symbolic link"
	case tar.TypeLink:
		return "hard link"
	case tar.TypeDir:
		return "directory"
	case tar.TypeChar:
		return "character device"
	case tar.TypeBlock:
		return "block device"
	case tar.TypeFifo:
		return "FIFO"
	default:
		return fmt.Sprintf("type %q", typeflag)
	}
}

// ---- rotate-hostkey ---------------------------------------------------------

// RotateHostKey replaces the gateway's on-disk host key (RUNBOOK §4.3):
// the previous key is kept at hostkey.old, a fresh ed25519 key is
// written in its place, and the moment lands in the journal as a
// hostkey.rotate event — the record operators grep for when they need
// proof the key changed. The caller passes the open event log and the
// gateway's notion of "now".
//
// A gateway that never had a key file before this call still ends up
// with a ".old" copy of the key minted for it — harmless, and simpler
// than a second code path for "there was nothing to rotate away from".
// A LIVE gateway keeps presenting the in-memory old key until it is
// restarted (RUNBOOK §4.3 step 2); this function deliberately touches
// only the files.
func RotateHostKey(dir string, log *events.Log, now time.Time) (oldFP, newFP string, err error) {
	hkPath := hostKeyPath(dir)

	// One rotation at a time (F-06, review round 1 24.09.2026). Two can be
	// running: the local verb beside a live gateway's remote
	// gateway.rotate-hostkey. Both read the same old key, both write
	// hostkey.old and the active file, and the journal then holds two
	// records naming keys, one of which is not on disk. The lock is the
	// same OS-level, crash-released kind the state store takes, in its own
	// file: a rotation inside the gateway cannot take state.lock, which
	// that process already holds.
	lock, lerr := state.AcquireFileLock(filepath.Join(dir, HostKeyRotateLockFile))
	if lerr != nil {
		return "", "", fmt.Errorf("another rotation of %s is in progress: %w", hkPath, lerr)
	}
	defer func() { _ = lock.Unlock() }()

	oldSigner, err := loadOrGenerateHostKey(hkPath)
	if err != nil {
		return "", "", err
	}
	oldFP = auth.Fingerprint(oldSigner.PublicKey())
	oldData, rerr := state.ReadDataFile(hkPath)
	if rerr != nil {
		return "", "", fmt.Errorf("%s: %w", hkPath, rerr)
	}

	// The new key is minted in memory and only then written. Until F-06
	// the active file was REMOVED and a new key generated in its place, so
	// a failure between the two — a full disk, a directory that stopped
	// being writable — left the gateway with no host key at all: the next
	// "gateway run" could not speak SSH with the identity every client
	// pins. Now nothing is touched until a complete new key exists.
	newPEM, newSigner, gerr := newHostKey()
	if gerr != nil {
		return "", "", gerr
	}
	newFP = auth.Fingerprint(newSigner.PublicKey())

	// The old key stays valid through a transition period in the sense
	// that an administrator still has to hand out new connection strings
	// (PROTOCOL §6.2); this build keeps a single readable backup copy
	// rather than actually serving two host keys at once — "gateway run"
	// always presents the current file, and the running process keeps
	// its in-memory signer until restart.
	if len(oldData) > 0 {
		if err := atomicWriteFile(hkPath+".old", oldData); err != nil {
			return "", "", err
		}
	}
	if err := atomicWriteFile(hkPath, newPEM); err != nil {
		return "", "", err
	}

	// The record is what makes a rotation something an operator can prove
	// afterwards, so a rotation the journal cannot take must not stand:
	// the old key goes back. A gateway that had no key file before this
	// call is left without one, which is the state it was in.
	if err := log.Append(events.Event{
		Time:        state.NewZonedTime(now),
		Type:        events.EventHostKeyRotate,
		Actor:       "gateway",
		Object:      "hostkey",
		Result:      "ok",
		Fingerprint: newFP,
		Details: map[string]interface{}{
			"oldFingerprint": oldFP,
			"newFingerprint": newFP,
		},
	}); err != nil {
		rollback := func() error {
			if len(oldData) > 0 {
				return atomicWriteFile(hkPath, oldData)
			}
			if rmerr := os.Remove(hkPath); rmerr != nil && !os.IsNotExist(rmerr) {
				return rmerr
			}
			return nil
		}()
		if rollback != nil {
			return oldFP, newFP, fmt.Errorf("hostkey.rotate event: %w; the new key %s is installed and could NOT be taken back (%v) — the file and the journal disagree until an administrator rotates again",
				err, newFP, rollback)
		}
		return "", "", fmt.Errorf("hostkey.rotate event: %w; the key was put back, so nothing changed", err)
	}
	return oldFP, newFP, nil
}

// ---- host key file primitives ----------------------------------------------
//
// ed25519-key-in-a-PEM-file I/O for the gateway's own host key. The CLI
// keeps its own copy of this small primitive for the *machine* key
// (cmd/iamtunnel deliberately does not make one role's package serve
// another role's identity file); here it lives beside the only thing
// that rotates the gateway key.

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := state.ReadDataFile(path)
	switch {
	case err == nil:
		raw, perr := ssh.ParseRawPrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("%s: does not parse as a private key (%v)", path, perr)
		}
		signer, serr := ssh.NewSignerFromKey(raw)
		if serr != nil {
			return nil, fmt.Errorf("%s: is not a supported key type (%v)", path, serr)
		}
		return signer, nil
	case os.IsNotExist(err):
		return generateHostKey(path)
	default:
		return nil, fmt.Errorf("%s: %w", path, err)
	}
}

// newHostKey mints one ed25519 host key and hands back its PEM and its
// signer without touching any file: the caller decides when the gateway's
// identity changes, and a rotation that cannot finish must be able to
// leave the file it found (F-06).
func newHostKey() ([]byte, ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel gateway host key")
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(block), signer, nil
}

func generateHostKey(path string) (ssh.Signer, error) {
	pemBytes, signer, err := newHostKey()
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(path, pemBytes); err != nil {
		return nil, err
	}
	return signer, nil
}

// atomicWriteFile writes data to path — this package's one atomic
// replace, which is datafile.WriteFileAtomic since round nine (§5.6 of
// the audit): the hand-rolled CreateTemp dance below it used to be the
// fourth independent copy of the same writer, and the copy is what never
// got fixed in round 8's cousins. The temporary is a random O_EXCL
// creation, the final name is never opened, and the ownership step runs
// before the rename, on the open descriptor.
//
// The MkdirAll stays here because the roles differ in what a mkdir means
// (the backup/restore dir is provisioned by the caller; the state dir by
// the store), and datafile refuses to invent that policy.
//
// The rename below would hand the file to whoever runs this process:
// the documented sudo runs of "gateway restore" (RUNBOOK §3.3) and
// "gateway rotate-hostkey" (§4.3) would leave state.json, events.jsonl,
// the host key and its .old copy owned by root, and the service would
// die on the next start (IAMT-332) — hence the adoption, threaded
// through the adoptOwnership seam the tests swap.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return datafile.WriteFileAtomic(path, data, datafile.WithAdoptOwnerFn(adoptOwnership))
}
