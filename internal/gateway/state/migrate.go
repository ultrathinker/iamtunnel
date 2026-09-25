package state

import (
	"encoding/json"
	"fmt"
	"sync"
)

// MigrationFunc transforms raw state JSON from one schema version to another.
type MigrationFunc func(raw []byte) ([]byte, error)

// Migrator manages registered schema migrations.
type Migrator struct {
	mu         sync.RWMutex
	migrations map[int]MigrationFunc // fromVersion -> migration function
}

// builtinMigrations is the migration table the store actually uses. It is a fixed
// table of this build, not a registry an importer can add to: §4.3 says a gateway of
// the older version does not open a state of the newer one, and that barrier may not
// be liftable by a line of code in another package. There is nothing below schema 1,
// so the table is empty; when schema 2 arrives, its 1 -> 2 step is added right here.
var builtinMigrations = map[int]MigrationFunc{}

// newBuiltinMigrator returns a private registry holding this build's migrations.
func newBuiltinMigrator() *Migrator {
	m := NewMigrator()
	for from, fn := range builtinMigrations {
		m.Register(from, fn)
	}
	return m
}

// NewMigrator creates an empty migration registry.
func NewMigrator() *Migrator {
	return &Migrator{
		migrations: make(map[int]MigrationFunc),
	}
}

// Register registers a migration step for a given source schema version.
func (m *Migrator) Register(fromVersion int, fn MigrationFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.migrations[fromVersion] = fn
}

// Migrate moves raw JSON forward from fromVersion to targetVersion.
//
// Forward only, by construction: migration exists to open an *older* file with a newer
// gateway. Walking the other way is what §4.3 forbids - it would let an old gateway
// read a file written by a new one, silently dropping the fields it does not know and
// writing the truncated result back on the first save.
func (m *Migrator) Migrate(raw []byte, fromVersion, targetVersion int) ([]byte, error) {
	if fromVersion > targetVersion {
		return nil, fmt.Errorf("%w: refusing to downgrade state from schema %d to %d", ErrSchemaTooNew, fromVersion, targetVersion)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	currentVer := fromVersion
	currentRaw := raw

	for currentVer != targetVersion {
		fn, exists := m.migrations[currentVer]
		if !exists {
			return nil, fmt.Errorf("%w: no migration registered from schema %d to %d", ErrMigrationRequired, currentVer, targetVersion)
		}
		var err error
		currentRaw, err = fn(currentRaw)
		if err != nil {
			return nil, fmt.Errorf("migration from schema %d failed: %w", currentVer, err)
		}

		var peek struct {
			Schema int `json:"schema"`
		}
		if err := json.Unmarshal(currentRaw, &peek); err != nil {
			return nil, fmt.Errorf("migrated state produced invalid JSON: %w", err)
		}
		if peek.Schema <= currentVer {
			return nil, fmt.Errorf("migration from schema %d did not advance schema version (produced %d)", currentVer, peek.Schema)
		}
		if peek.Schema > targetVersion {
			return nil, fmt.Errorf("migration from schema %d overshot the target: produced %d, wanted %d", currentVer, peek.Schema, targetVersion)
		}
		currentVer = peek.Schema
	}

	return currentRaw, nil
}
