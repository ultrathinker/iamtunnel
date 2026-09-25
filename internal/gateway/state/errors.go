package state

import (
	"errors"
	"fmt"
)

var (
	// ErrLockHeld indicates another process holds the gateway state lock file.
	ErrLockHeld = errors.New("gateway state lock is held by another process")

	// ErrReadOnly indicates the state store is currently in read-only mode.
	ErrReadOnly = errors.New("state store is in read-only mode; modifications are prohibited")

	// ErrSchemaTooNew indicates the file schema version exceeds the supported version.
	ErrSchemaTooNew = errors.New("state file schema version is newer than supported")

	// ErrMigrationRequired indicates forward migration is required to open the state.
	ErrMigrationRequired = errors.New("state file schema requires migration")

	// ErrInvalidName indicates a person or machine name failed validation.
	ErrInvalidName = errors.New("invalid identifier name")

	// ErrInvalidKey indicates public key material that is not a usable SSH key:
	// a body that does not decode, an empty blob, or a type prefix that contradicts
	// the algorithm stored inside the blob.
	ErrInvalidKey = errors.New("invalid public key material")

	// ErrInvalidTime indicates a timestamp lacks timezone or has invalid format.
	ErrInvalidTime = errors.New("invalid timestamp format: ISO-8601 with timezone required")

	// ErrInconsistentDeadlines indicates a deadline ordering violation (e.g. idle after ceiling).
	ErrInconsistentDeadlines = errors.New("inconsistent deadline pair")

	// ErrDeadlineInThePast indicates that a write assigned a door deadline that is
	// not in the future. It is a write-path rule only: a deadline already sitting in
	// state.json may legitimately be in the past (a file that lay on disk overnight),
	// so reading never produces this error.
	ErrDeadlineInThePast = errors.New("deadline is in the past")
)

// CorruptStateError provides clear, actionable context when the state file is damaged.
type CorruptStateError struct {
	Path    string
	Snippet string
	Err     error
}

func (e *CorruptStateError) Error() string {
	if e.Snippet != "" {
		return fmt.Sprintf("corrupt state file %q: %v; content snippet: %q (opened in read-only mode, run 'gateway restore <backup>' to recover)", e.Path, e.Err, e.Snippet)
	}
	return fmt.Sprintf("corrupt state file %q: %v (opened in read-only mode, run 'gateway restore <backup>' to recover)", e.Path, e.Err)
}

func (e *CorruptStateError) Unwrap() error {
	return e.Err
}

// SchemaError provides details on schema mismatches.
type SchemaError struct {
	FileSchema      int
	SupportedSchema int
}

func (e *SchemaError) Error() string {
	return fmt.Sprintf("unsupported schema version %d (gateway supports schema version %d); forward migration required", e.FileSchema, e.SupportedSchema)
}

func (e *SchemaError) Unwrap() error {
	return ErrSchemaTooNew
}
