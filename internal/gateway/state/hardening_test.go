package state_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// packageDirs are the two packages whose exported surface is under scrutiny,
// relative to the directory a test of package state runs in.
var packageDirs = map[string]string{
	"state":  ".",
	"events": filepath.Join("..", "events"),
}

// parsePackage parses the product sources of a package (test files excluded).
func parsePackage(t *testing.T, dir string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	files := make(map[string]*ast.File)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = f
	}
	if len(files) == 0 {
		t.Fatalf("no product sources found in %s", dir)
	}
	return files
}

// ---------------------------------------------------------------------------
// Fix 3 (and the rule behind it). Nothing an importer can reach may weaken an
// invariant: no hook setters, no exported function-typed fields, no mutable
// exported package variables. The check is by shape, not by name, so it also
// catches the next switch someone invents.
// ---------------------------------------------------------------------------

func TestFix3_NoExportedSwitchCanWeakenAnInvariant(t *testing.T) {
	t.Run("no_hook_or_flag_setters_on_the_public_types", func(t *testing.T) {
		scan := func(rt reflect.Type) []string {
			var bad []string
			for i := 0; i < rt.NumMethod(); i++ {
				m := rt.Method(i)
				if !strings.HasPrefix(m.Name, "Set") {
					continue
				}
				for a := 1; a < m.Type.NumIn(); a++ {
					switch m.Type.In(a).Kind() {
					case reflect.Func, reflect.Bool:
						bad = append(bad, rt.String()+"."+m.Name+" "+m.Type.String())
					}
				}
			}
			return bad
		}
		var bad []string
		bad = append(bad, scan(reflect.TypeOf(&state.Store{}))...)
		bad = append(bad, scan(reflect.TypeOf(&events.Log{}))...)
		if len(bad) > 0 {
			t.Errorf("interceptors left in the product API: %v\n"+
				"such hooks belong in export_test.go, otherwise any importer of the package can pull them", bad)
		}
	})

	t.Run("no_exported_function_typed_fields", func(t *testing.T) {
		// An exported field is a setter without the ceremony.
		types := []reflect.Type{
			reflect.TypeOf(state.Store{}),
			reflect.TypeOf(state.State{}),
			reflect.TypeOf(state.Migrator{}),
			reflect.TypeOf(events.Log{}),
		}
		for _, rt := range types {
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				if !f.IsExported() {
					continue
				}
				if f.Type.Kind() == reflect.Func {
					t.Errorf("%s.%s is an exported function-typed field: an importer can replace behaviour through it",
						rt.String(), f.Name)
				}
			}
		}
	})

	t.Run("no_mutable_exported_package_variables", func(t *testing.T) {
		for pkg, dir := range packageDirs {
			for name, file := range parsePackage(t, dir) {
				for _, decl := range file.Decls {
					gen, ok := decl.(*ast.GenDecl)
					if !ok || gen.Tok != token.VAR {
						continue
					}
					for _, spec := range gen.Specs {
						vs := spec.(*ast.ValueSpec)
						for _, ident := range vs.Names {
							if !ident.IsExported() {
								continue
							}
							// Sentinel errors are the one accepted exception: they carry no
							// behaviour, they are only compared against.
							if strings.HasPrefix(ident.Name, "Err") {
								continue
							}
							t.Errorf("%s/%s: exported package variable %q is writable from any importer; "+
								"if it decides how an invariant behaves, that invariant has a switch",
								pkg, name, ident.Name)
						}
					}
				}
			}
		}
	})

	t.Run("the_crash_hook_exists_only_for_tests", func(t *testing.T) {
		for name := range parsePackage(t, ".") {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", name, err)
			}
			if strings.Contains(string(data), "SetBeforeRenameHook") {
				t.Errorf("%s is a product file and mentions SetBeforeRenameHook; it belongs in export_test.go", name)
			}
		}
		// And it is still available where it should be - Gate 2 uses it.
		if _, err := os.Stat("export_test.go"); err != nil {
			t.Fatalf("export_test.go is missing: the hook has to live somewhere tests can reach it: %v", err)
		}
	})
}

// TestFix3_StoreNeverDisagreesWithTheDiskSilently covers the consequence the hook had.
// Even with the hook - which only tests can reach now - the store may not report a
// failed write, roll memory back, and leave something else on disk without saying so.
func TestFix3_StoreNeverDisagreesWithTheDiskSilently(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	statePath := filepath.Join(dir, state.StateFileName)

	// The nastiest thing the hook can do: perform the rename itself, so the real one
	// fails and the store rolls back over a file that already holds the new content.
	state.SetBeforeRenameHook(s, func(tmp string) error {
		_ = os.Rename(tmp, statePath)
		return errors.New("power cut")
	})

	updErr := s.Update(func(st *state.State) error {
		st.People = append(st.People, personWith(t, "mallory", "admin", 5))
		return nil
	})
	if updErr == nil {
		t.Fatalf("Update was supposed to fail")
	}

	if !s.IsReadOnly() {
		t.Fatalf("the store rolled its memory back while the disk held something else, and kept working as if nothing happened")
	}
	var corrupt *state.CorruptStateError
	if !errors.As(s.CorruptError(), &corrupt) {
		t.Fatalf("expected a CorruptStateError explaining the divergence, got %v", s.CorruptError())
	}
	if !strings.Contains(updErr.Error(), "no longer matches") {
		t.Fatalf("the error returned to the caller must say the disk diverged, got %q", updErr)
	}
}

// ---------------------------------------------------------------------------
// Fix 4. The schema barrier of §4.3 has no switch.
// ---------------------------------------------------------------------------

func TestFix4_SchemaBarrierHasNoSwitch(t *testing.T) {
	writeSchema2 := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		content := []byte(`{
  "schema": 2,
  "people": [{"name": "mallory", "role": "admin", "keys": []}],
  "machines": [],
  "grants": []
}`)
		if err := os.WriteFile(filepath.Join(dir, state.StateFileName), content, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return dir
	}

	t.Run("a_newer_file_stays_shut_even_when_migrations_exist", func(t *testing.T) {
		dir := writeSchema2(t)

		// An importer builds a registry and registers a downgrade 2 -> 1. Under the
		// previous code one such line, anywhere in the program, opened the door.
		m := state.NewMigrator()
		m.Register(2, func(raw []byte) ([]byte, error) {
			return []byte(`{"schema":1,"people":[],"machines":[],"grants":[]}`), nil
		})

		s, err := state.Open(dir)
		if s != nil {
			defer s.Close()
			t.Fatalf("a gateway of schema %d opened a file of schema 2", state.CurrentSchema)
		}
		var schemaErr *state.SchemaError
		if !errors.As(err, &schemaErr) || schemaErr.FileSchema != 2 {
			t.Fatalf("expected SchemaError{FileSchema: 2}, got %v", err)
		}
	})

	t.Run("the_registry_itself_refuses_to_walk_backwards", func(t *testing.T) {
		m := state.NewMigrator()
		m.Register(2, func(raw []byte) ([]byte, error) {
			return []byte(`{"schema":1}`), nil
		})
		_, err := m.Migrate([]byte(`{"schema":2}`), 2, 1)
		if !errors.Is(err, state.ErrSchemaTooNew) {
			t.Fatalf("a downgrade must be refused by the migrator itself, got %v", err)
		}
	})

	t.Run("no_global_registry_is_exported", func(t *testing.T) {
		for name, file := range parsePackage(t, ".") {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					continue
				}
				for _, spec := range gen.Specs {
					for _, ident := range spec.(*ast.ValueSpec).Names {
						if ident.Name == "DefaultMigrator" {
							t.Errorf("%s still declares DefaultMigrator: the schema barrier is one assignment away from being lifted", name)
						}
					}
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Fix 9. What the platform guarantees is written in the code (the constants of
// sync_posix.go / sync_windows.go), and the tests hold those declarations against
// the platform instead of trusting them:
//
//   - TestFix9_PlatformGuaranteeHolds (below) checks the DurableReplace declaration
//     against what the platform actually does with an fsync of a directory handle;
//   - the weaker Windows guarantee (a replace survives a concurrent reader, i.e. the
//     MOVEFILE_WRITE_THROUGH path with its bounded retry) is held behaviourally by
//     TestFix9_WriteSurvivesAConcurrentReader;
//   - the POSIXPermissionsEnforced declaration is held by the mode assertions in
//     TestState_FilePermissions, which skip visibly where the modes are not enforced.
//
// The former TestFix9_PlatformGuaranteeIsDeclared only compared the constants with
// runtime.GOOS. The same build tags that select runtime.GOOS select the file that
// sets the constants, so the comparison could never fail - it verified the build
// system against itself.
// ---------------------------------------------------------------------------

// TestFix9_PlatformGuaranteeHolds checks that DurableReplace tells the truth about
// the platform it compiles for. Where it declares the full §3.5 formula, an fsync of
// a directory handle must actually succeed here - both when done by the product's own
// syncDir, which every save runs, and when done raw. Where it declares the step
// unavailable, a raw attempt must actually fail; if it ever succeeds, the declared
// reason for the weaker Windows guarantee is stale and §4.3/§3.5 have to be revisited.
func TestFix9_PlatformGuaranteeHolds(t *testing.T) {
	dir := t.TempDir()

	platformErr := state.FlushDirForTest(dir) // the §3.5 fourth step, done by hand
	productErr := state.SyncDirForTest(dir)   // what saveAtomicLocked actually calls

	if !state.DurableReplace {
		if platformErr == nil {
			t.Fatalf("DurableReplace=false on %s declares this platform cannot fsync a directory handle, "+
				"but the fsync succeeded: the declared limitation is stale and the fourth step of §3.5 may be available here",
				runtime.GOOS)
		}
		t.Logf("%s: fsync of a directory fails here as declared (%v); the weaker replace guarantee is held by TestFix9_WriteSurvivesAConcurrentReader",
			runtime.GOOS, platformErr)
		return
	}

	if platformErr != nil {
		t.Fatalf("DurableReplace=true declares the full §3.5 formula (tmp -> fsync -> rename -> fsync(dir)), "+
			"but an fsync of a directory handle fails on this platform: %v", platformErr)
	}
	if productErr != nil {
		t.Fatalf("DurableReplace=true, but syncDir - the function every state save runs - failed: %v", productErr)
	}
}

// TestFix9_WriteSurvivesAConcurrentReader models what routinely happens on Windows:
// an indexer or an antivirus holds state.json open for a moment. rename(2) does not
// care; MoveFileEx fails with ACCESS_DENIED, so the replace is retried instead of
// losing the write. On Linux this passes either way - the point is that it passes on
// both, rather than the Windows branch quietly being a worse store.
func TestFix9_WriteSurvivesAConcurrentReader(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	reader, err := os.Open(filepath.Join(dir, state.StateFileName))
	if err != nil {
		t.Fatalf("Open state file as a reader: %v", err)
	}
	closed := make(chan struct{})
	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = reader.Close()
		close(closed)
	}()

	if err := s.Update(func(st *state.State) error {
		st.People = append(st.People, personWith(t, "alice", "admin", 1))
		return nil
	}); err != nil {
		t.Fatalf("a state write was lost because another process had the file open for %v: %v",
			40*time.Millisecond, err)
	}
	<-closed

	if len(s.Get().People) != 1 {
		t.Fatalf("the update did not survive")
	}
}
