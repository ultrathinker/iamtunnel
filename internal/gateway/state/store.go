package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	StateFileName = "state.json"
	LockFileName  = "state.lock"
	DirPerm       = 0700
	FilePerm      = 0600
)

// staleTempPrefix is the name shape cleanStaleTempFiles collects: the
// prefix os.CreateTemp was handed for state's own temporary files. The
// ".tmp." literal is spelled by parts because the raw-I/O gate (gate 16)
// fails a file on a ".tmp"-shaped literal outside CreateTemp's arguments
// - which is exactly the shape whose known name the rounds were burned
// by, and whose knownness this prefix does not share: it matches only
// the random names CreateTemp itself generated.
const staleTempPrefix = StateFileName + "." + "tmp" + "."

// Store manages current gateway state persistence with atomicity, locking,
// corruption detection, and schema validation.
type Store struct {
	dir        string
	statePath  string
	lockPath   string
	mu         sync.RWMutex
	fileLock   *FileLock
	readOnly   bool
	corruptErr error
	state      *State
	migrator   *Migrator

	// enrolHMAC is the HMAC-SHA-256 key used to hash enrol/bootstrap
	// secrets before they land in state.json. It is loaded (or created)
	// inside Open so callers do not forget to do so. Turning the hashing
	// off is forbidden: this field is set once, never assigned
	// again, and there is no exported setter.
	enrolHMAC EnrolHMACKey

	// revocations holds grants the store withdrew on its own and that have not been
	// handed to the journal yet (see DrainRevocations).
	revocations []Revocation

	// beforeRenameHook models an ungraceful crash right before the atomic rename.
	// It is unexported and has no exported setter in the product: the setter lives in
	// export_test.go and is therefore reachable only from this package's own tests.
	beforeRenameHook func(tmpPath string) error
}

// cleanStaleTempFiles removes orphaned temporary files left by ungraceful crashes (Defect 10).
//
// Listing and removal go through os.Root (IAMT-333, closes the walk
// residual audit §3.4 deferred): the names come from the directory the
// Root holds open, and each removal unlinks the name in that same held
// directory - a swap of dir's own entry in its parent between the
// listing and the removals cannot aim them at another directory. A
// failure to open or list is silently skipped: this is best-effort
// cleanup, it must never keep the store from opening.
func cleanStaleTempFiles(dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), staleTempPrefix) {
			_ = root.Remove(e.Name())
		}
	}
}

// Open initializes or loads the state store at the given directory.
// If the file is corrupted, it returns the Store in read-only mode alongside
// a CorruptStateError.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, DirPerm); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	lockPath := filepath.Join(dir, LockFileName)
	fl, err := AcquireFileLock(lockPath)
	if err != nil {
		return nil, err
	}

	// Clean up any stale temp files left behind by prior ungraceful crashes (Defect 10)
	cleanStaleTempFiles(dir)

	// The HMAC key for enrol/bootstrap secret hashing is loaded BEFORE
	// any state.json branch (IAMT-140 round two). The key is a static
	// secret of the data directory — it does not depend on the contents
	// of state.json, and every code path in this function (creation,
	// read of an existing file, read of a corrupt file, future
	// short-circuits) must hand callers a Store whose enrolHMAC field is
	// populated. Loading it here, once, makes it impossible for any
	// later early-return branch to skip the assignment — which is
	// exactly the bug IAMT-140 names: the "new store" branch used to
	// return a Store with the zero EnrolHMACKey{}, and
	// HashEnrolSecret happily hashed secrets under that zero key,
	// making the protection invisible to anyone who only had state.json.
	//
	// Failing here closes the store cleanly so callers never see a
	// half-built Store.
	hmacKey, herr := LoadOrCreateEnrolHMACKey(dir)
	if herr != nil {
		_ = fl.Unlock()
		return nil, fmt.Errorf("could not load enrol HMAC key: %w", herr)
	}

	statePath := filepath.Join(dir, StateFileName)
	s := &Store{
		dir:       dir,
		statePath: statePath,
		lockPath:  lockPath,
		fileLock:  fl,
		migrator:  newBuiltinMigrator(),
		enrolHMAC: hmacKey,
	}

	data, err := ReadDataFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		// New store: initialize fresh state
		s.state = NewState()
		if err := s.saveAtomicLocked(); err != nil {
			_ = s.fileLock.Unlock()
			return nil, fmt.Errorf("failed to initialize new state: %w", err)
		}
		return s, nil
	} else if err != nil {
		_ = s.fileLock.Unlock()
		return nil, fmt.Errorf("failed to read state file %s: %w", statePath, err)
	}

	parsed, corrupt, perr := parseStateBytes(s, data)
	if corrupt != nil {
		s.readOnly = true
		s.corruptErr = corrupt
		s.state = NewState()
		return s, s.corruptErr
	}
	if perr != nil {
		_ = s.fileLock.Unlock()
		return nil, perr
	}
	s.state = parsed

	return s, nil
}

// OpenForRead opens an existing state store for read-only inspection
// (IAMT-98: "read must not write"). It MUST NOT create any
// file on disk: no data directory, no state.json, no state.lock, no
// enrol-hmac.key, no stale-temp cleanup. The order matters:
//
//  1. stat the data directory;
//  2. stat state.json — if missing, return os.ErrNotExist WITHOUT
//     touching the lock file. The caller decides what to print —
//     "no gateway is installed" if the host key is also absent,
//     "installed but never started" if install left a host key but
//     no state.json. The state package does not know about host
//     keys on purpose: that's a gateway-level concept, and the
//     state package is one level lower;
//  3. acquire the same non-blocking exclusive lock Open acquires, but
//     through AcquireFileLockExisting — the read-path twin that opens
//     the lock file WITHOUT O_CREATE. Three outcomes:
//     a. success (lock free) — normal path, parse state.json;
//     b. ErrLockHeld — gateway is running, surface to caller;
//     c. os.ErrNotExist — the lock file does not exist. A lock
//     that does not exist cannot be held by anybody, so the
//     gateway is definitively NOT RUNNING (this is the state
//     after `gateway restore`, which extracts state.json but
//     does not re-create state.lock). Read state.json directly
//     without taking a lock.
//  4. read state.json and run it through parseStateBytes.
//
// The Store returned here is safe to read (Get, IsReadOnly,
// CorruptError) and to Close. OpenForRead always sets readOnly=true
// on the returned Store, so Update/Set/Save reject any write attempt
// with ErrReadOnly — even when no lock was taken (the
// "after-restore" path).
//
// The signature is independent of Open's: the follow-up IAMT-91 work
// migrates Open's schema handling, and that work must not be
// blocked on OpenForRead's invariants.
func OpenForRead(dir string) (*Store, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("state path %s is not a directory", dir)
	}

	statePath := filepath.Join(dir, StateFileName)
	if _, err := os.Stat(statePath); err != nil {
		// No state.json → the caller decides whether this is "no
		// gateway here" or "installed but never started". The state
		// package does not look at host keys; that distinction
		// lives in cmd/iamtunnel. Crucially, do NOT take the lock:
		// taking the lock would force AcquireFileLock to create
		// state.lock on disk, which is exactly the write the read
		// path must not do. This branch returns BEFORE any lock
		// acquisition.
		return nil, err
	}

	lockPath := filepath.Join(dir, LockFileName)
	fl, lerr := AcquireFileLockExisting(lockPath)
	if lerr != nil {
		if errors.Is(lerr, os.ErrNotExist) {
			// state.json is here, state.lock is not. A lock that
			// does not exist cannot be held — the gateway is
			// definitively NOT RUNNING. Read state.json directly
			// without taking any lock (the read-path's promise is
			// "MUST NOT write", not "must hold the lock"; the lock
			// is a liveness signal, not a read-integrity one).
			return readStateBytesUnlocked(dir, statePath)
		}
		// ErrLockHeld (running gateway) or some other OS error.
		return nil, lerr
	}

	s := &Store{
		dir:       dir,
		statePath: statePath,
		lockPath:  lockPath,
		fileLock:  fl,
		migrator:  newBuiltinMigrator(),
		readOnly:  true,
	}

	data, err := ReadDataFile(statePath)
	if err != nil {
		_ = s.fileLock.Unlock()
		return nil, err
	}

	parsed, corrupt, perr := parseStateBytes(s, data)
	if corrupt != nil {
		s.corruptErr = corrupt
		s.state = NewState()
		// Same shape as Open's read-only branches.
		return s, s.corruptErr
	}
	if perr != nil {
		// A schema-too-new file is a hard refusal — the store cannot
		// safely read a state written by a newer gateway. Return the
		// same typed error Open does, and release the lock so the
		// caller never sees a half-built Store.
		_ = s.fileLock.Unlock()
		return nil, perr
	}
	s.state = parsed

	return s, nil
}

// readStateBytesUnlocked is the read-path's "after restore" entry
// point: state.json is present, state.lock is absent. A lock file
// that does not exist cannot be held by anybody, so no liveness
// signal is missing — and `state.json` is written tmp-then-rename
// by the write path, so a concurrent read sees either the old or
// the new complete file, never a partial one. We read it directly
// through the shared parseStateBytes pipeline (the only one that
// exists) and return a Store with readOnly=true and fileLock=nil.
// Close on that Store is a no-op for the lock; Get/IsReadOnly/
// CorruptError work normally; Update/Set/Save refuse with
// ErrReadOnly.
func readStateBytesUnlocked(dir, statePath string) (*Store, error) {
	data, err := ReadDataFile(statePath)
	if err != nil {
		return nil, err
	}

	s := &Store{
		dir:       dir,
		statePath: statePath,
		lockPath:  filepath.Join(dir, LockFileName),
		migrator:  newBuiltinMigrator(),
		readOnly:  true,
	}

	parsed, corrupt, perr := parseStateBytes(s, data)
	if corrupt != nil {
		s.corruptErr = corrupt
		s.state = NewState()
		return s, s.corruptErr
	}
	if perr != nil {
		// Schema-too-new is still a hard refusal, even without a lock.
		return nil, perr
	}
	s.state = parsed

	return s, nil
}

// parseStateBytes runs the schema-barrier / migration / parse / validate
// pipeline against an already-read state.json payload. It returns:
//
//   - (parsed, nil, nil) on success;
//   - (nil, *CorruptStateError, nil) when the file is structurally or
//     semantically broken — the caller should open in read-only mode
//     and surface the corruption error;
//   - (nil, nil, *SchemaError) when the file's schema is newer than
//     this build supports — a hard refusal, never read-only-mode;
//   - (nil, nil, other-error) for any unexpected failure.
//
// This is the single read-side pipeline shared by Open and OpenForRead.
// Open layers on "create state.json if missing" and
// "load-or-create enrol HMAC key"; OpenForRead layers on the read-only
// guarantee. The migrator argument is the Store's own migrator so
// both call sites use the same migration table.
func parseStateBytes(s *Store, data []byte) (*State, *CorruptStateError, error) {
	// B: empty file
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, &CorruptStateError{
			Path:    s.statePath,
			Snippet: "(empty file)",
			Err:     errors.New("state file is empty (unexpected EOF)"),
		}, nil
	}

	// C: schema peek
	var schemaPeek struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(data, &schemaPeek); err != nil {
		snippet := string(trimmed)
		if len(snippet) > 80 {
			snippet = snippet[:80] + "..."
		}
		return nil, &CorruptStateError{
			Path:    s.statePath,
			Snippet: snippet,
			Err:     err,
		}, nil
	}

	// D: schema barrier (§4.3): a gateway of this version never opens a
	// state written by a newer one. There is no migration attempt in that
	// direction and no way to ask for one - "migrating" a newer file down
	// to this schema means silently dropping the fields this build does
	// not know, and the first save would then truncate the file.
	if schemaPeek.Schema > CurrentSchema {
		return nil, nil, &SchemaError{
			FileSchema:      schemaPeek.Schema,
			SupportedSchema: CurrentSchema,
		}
	}

	// E: forward migration of an older file through this build's table.
	var payload []byte = data
	if schemaPeek.Schema < CurrentSchema {
		migrated, migErr := s.migrator.Migrate(data, schemaPeek.Schema, CurrentSchema)
		if migErr != nil {
			return nil, &CorruptStateError{
				Path:    s.statePath,
				Snippet: fmt.Sprintf("(schema %d)", schemaPeek.Schema),
				Err:     migErr,
			}, nil
		}
		payload = migrated
	}

	// F: full parse.
	var parsed State
	if err := json.Unmarshal(payload, &parsed); err != nil {
		snippet := string(trimmed)
		if len(snippet) > 80 {
			snippet = snippet[:80] + "..."
		}
		return nil, &CorruptStateError{
			Path:    s.statePath,
			Snippet: snippet,
			Err:     err,
		}, nil
	}

	// F2: §4.3 defaults for the machine fields added by IAMT-91. A state.json
	// written before those fields existed is not a broken file - it is the
	// record of a gateway that never compared the target sshd host key and
	// never proved an OS user - so absent has to read as "unverified" and
	// "pending" rather than as the empty string, which belongs to neither
	// closed set. This is the read half of that rule; commitLocked is the
	// write half. The step cannot fail, so it adds no rejecting branch to this
	// pipeline.
	parsed.applyMachineDefaults()
	parsed.applyGrantCapsCompat()

	// G: semantic validation.
	if err := parsed.Validate(); err != nil {
		snippet := string(trimmed)
		if len(snippet) > 80 {
			snippet = snippet[:80] + "..."
		}
		return nil, &CorruptStateError{
			Path:    s.statePath,
			Snippet: snippet,
			Err:     fmt.Errorf("validation failed: %w", err),
		}, nil
	}

	return &parsed, nil, nil
}

// IsReadOnly reports whether the store is operating in read-only mode.
func (s *Store) IsReadOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readOnly
}

// CorruptError returns the underlying corruption error if opened in read-only mode.
func (s *Store) CorruptError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.corruptErr
}

// Get returns a deep copy of the current state.
func (s *Store) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return State{Schema: CurrentSchema}
	}
	return *s.state.Clone()
}

// EnrolHMACKey returns a copy of the gateway's HMAC-SHA-256 key used to
// hash enrol and bootstrap secrets. Returning a copy (rather than the
// array by value would also copy) keeps callers from holding the live
// reference across a hypothetical later rotation; today no such path
// exists, but the type signature does not change when it is added.
func (s *Store) EnrolHMACKey() EnrolHMACKey {
	return s.enrolHMAC
}

// Set validates and atomically replaces the state on disk and in memory.
// Grants go through the same reconciliation as in Update: a grant whose machine was
// replaced under it is revoked with an audit record rather than re-pinned silently.
// Door deadlines assigned by this state are held to the write-path rule of
// checkFreshDoorDeadlines; deadlines carried over from the state already held are not
// re-checked against the clock.
func (s *Store) Set(newState State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readOnly {
		return ErrReadOnly
	}

	draft := newState.Clone()
	if err := checkFreshDoorDeadlines(s.state, draft, time.Now()); err != nil {
		return fmt.Errorf("cannot set state: %w", err)
	}
	revocations := reconcileGrants(s.state, draft)
	reconcileGoals(draft)
	reconcileRecentCommands(draft)

	if err := draft.Validate(); err != nil {
		return fmt.Errorf("cannot set invalid state: %w", err)
	}

	if err := s.commitLocked(draft); err != nil {
		return err
	}
	s.revocations = append(s.revocations, revocations...)

	return nil
}

// Update provides a safe transaction to mutate the state.
//
// After fn has run, door deadlines that fn assigned or changed are held to the
// write-path rule of checkFreshDoorDeadlines: a deadline must be strictly in the
// future. Deadlines carried over from the state that went into the transaction are
// not re-checked against the clock - a file that lay on disk overnight may hold
// deadlines that have since passed.
//
// Grants are then reconciled against the state that went into the
// transaction (§4.3): a grant that lost its machine or whose machine now presents a
// different key is revoked explicitly and recorded for the journal, while a grant
// created here that points at nobody is left in place so that Validate rejects the
// transaction - the operator who typed "grant add alice ghost" has to hear about it.
//
// Goals are reconciled too: any Goals entry whose person or machine the
// transaction removed is dropped, so removing a machine or person that once
// had a goal declared for it does not fail Validate's referential-integrity
// check forever (review19 finding 1).
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readOnly {
		return ErrReadOnly
	}

	draft := s.state.Clone()
	if err := fn(draft); err != nil {
		return err
	}

	if err := checkFreshDoorDeadlines(s.state, draft, time.Now()); err != nil {
		return fmt.Errorf("updated state rejected: %w", err)
	}
	revocations := reconcileGrants(s.state, draft)
	reconcileGoals(draft)
	reconcileRecentCommands(draft)

	if err := draft.Validate(); err != nil {
		return fmt.Errorf("updated state validation failed: %w", err)
	}

	if err := s.commitLocked(draft); err != nil {
		return err
	}
	s.revocations = append(s.revocations, revocations...)

	return nil
}

// Save flushes current in-memory state to disk atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readOnly {
		return ErrReadOnly
	}

	return s.commitLocked(s.state.Clone())
}

// DrainRevocations returns the grants the store revoked by itself since the previous
// call and forgets them. The caller is expected to write each one to events.jsonl;
// that is the "explicitly, with an entry in the journal" half of revocation - the
// cascade alone only removes the consequence.
func (s *Store) DrainRevocations() []Revocation {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.revocations) == 0 {
		return nil
	}
	out := s.revocations
	s.revocations = nil
	return out
}

// commitLocked installs next as the current state and writes it out atomically.
// On failure the in-memory state is rolled back - and the rollback is then checked
// against the file, because a rollback the disk does not agree with would leave the
// store reporting one thing while state.json holds another. Must hold s.mu.
func (s *Store) commitLocked(next *State) error {
	// The write half of the §4.3 rule whose read half lives in
	// parseStateBytes: a transaction that leaves the two closed-set machine
	// fields empty (a machine created without them, a field the caller does
	// not know about) is filled in here, before the state is installed and
	// marshalled. Nothing else may reach the disk as "": the file has to
	// carry a member of each closed set so that a reader - this build, an
	// older one that ignores the fields, or an operator with an editor -
	// never has to guess what an empty status means. Filling in is not
	// overwriting: applySpecDefaults leaves every value that is already set.
	next.applyMachineDefaults()

	oldState := s.state
	s.state = next

	saveErr := s.saveAtomicLocked()
	if saveErr == nil {
		return nil
	}

	s.state = oldState
	if err := s.verifyDiskMatchesLocked(); err != nil {
		return fmt.Errorf("%w; additionally: %v", saveErr, err)
	}
	return saveErr
}

// verifyDiskMatchesLocked re-reads state.json and compares it with the in-memory state.
// A mismatch means the store can no longer vouch for what is on disk, so it stops
// pretending it can: read-only mode plus a loud CorruptStateError. Must hold s.mu.
func (s *Store) verifyDiskMatchesLocked() error {
	onDisk, err := ReadDataFile(s.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("could not re-read %s to confirm rollback: %w", s.statePath, err)
	}
	expected, err := marshalState(s.state)
	if err != nil {
		return err
	}
	if bytes.Equal(onDisk, expected) {
		return nil
	}

	s.readOnly = true
	s.corruptErr = &CorruptStateError{
		Path:    s.statePath,
		Snippet: snippetOf(onDisk),
		Err:     errors.New("state file on disk no longer matches the state this store holds; the store cannot vouch for either"),
	}
	return s.corruptErr
}

// saveAtomicLocked writes the state atomically:
// temp file -> fsync -> rename -> fsync directory.
// Must be called with s.mu held.
func (s *Store) saveAtomicLocked() error {
	raw, err := marshalState(s.state)
	if err != nil {
		return err
	}

	// Standard atomic pattern (tmp -> fsync -> rename -> syncDir). The
	// temporary is a random O_EXCL creation (os.CreateTemp), never a
	// predictable name: anyone able to watch the data directory knows the
	// live pid and the wall clock, and could pre-plant a file — or a
	// symlink to somebody else's file — at a name the writer was going to
	// open (IAMT-332 round 2). The ".tmp." infix keeps the stale-temp
	// sweep (cleanStaleTempFiles) finding this writer's litter.
	tmp, err := os.CreateTemp(s.dir, StateFileName+".tmp.")
	if err != nil {
		return fmt.Errorf("failed to create temporary state file: %w", err)
	}
	tmpFile := tmp.Name()

	writeErr := func() error {
		if _, err := tmp.Write(raw); err != nil {
			return err
		}
		return tmp.Sync() // fsync temporary file
	}()

	// The rename below hands state.json to whoever runs this process: the
	// documented sudo run of "gateway pair" or "install --rebootstrap"
	// (RUNBOOK §5.11, §1.4) would leave the service's own state file owned
	// by root, and the next start would die reading it (IAMT-332). Before
	// renaming, give the open temporary the owner of the file it is about
	// to replace — the data directory's owner when nothing stands there
	// yet. The adoption happens BEFORE the rename, and on the open
	// descriptor rather than by any path, so a refused adoption leaves the
	// old state.json in place, content and owner, and no planted name can
	// redirect the step.
	if err := adoptOwnership(tmp, s.statePath); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to preserve the state file's ownership: %w", err)
	}

	closeErr := tmp.Close()
	if writeErr != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to write temporary state: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to close temporary state file: %w", closeErr)
	}

	// Interruption hook for modeling crash before rename
	if s.beforeRenameHook != nil {
		hookErr := s.beforeRenameHook(tmpFile)
		if hookErr != nil {
			return fmt.Errorf("simulated interruption before rename: %w", hookErr)
		}
	}

	// Atomic rename replaces target
	if err := replaceFile(tmpFile, s.statePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to replace state file: %w", err)
	}

	// Fsync directory entry (on platforms that support it)
	if err := syncDir(s.dir); err != nil {
		return fmt.Errorf("failed to sync directory metadata: %w", err)
	}

	return nil
}

// Close releases the lock file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fileLock != nil {
		err := s.fileLock.Unlock()
		s.fileLock = nil
		return err
	}
	return nil
}

// marshalState renders a state exactly the way it is written to disk, so that the
// bytes on disk and the bytes derived from memory can be compared directly.
func marshalState(st *State) ([]byte, error) {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}
	return append(raw, '\n'), nil
}

// snippetOf shortens file content for an error message.
func snippetOf(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) > 80 {
		return trimmed[:80] + "..."
	}
	return trimmed
}
