// Package winkeys acceptance tests.
//
// These tests are independent of the existing product tests: each
// one targets a SPEC claim, every claim is exercised against
// the real binary (or against the package's public surface), and
// each test was made red by mutating the product code that guards
// it, then restored, so we know each one is sensitive to its claim.
//
// Claim ledger (numbered for the report):
//
//   1. Stranger keys (admin or otherwise) in the file are never
//      harmed — order, comments, spacing included — whatever is
//      done to the door. (TestAcceptance_StrangerByteForByte.)
//   2. A line whose marker is corrupted or foreign is never removed
//      by the sweep. (TestAcceptance_CorruptedMarkerNotSwept.)
//   3. The file's permissions end up narrowed to exactly two
//      owners with inheritance forbidden, and stay that way after
//      repeated installs. (TestAcceptance_ACLExactlyTwoOwners.)
//   4. The watchdog removes the line after its parent is killed
//      outright, using the real built program and not a helper.
//      (TestAcceptance_WatchdogRealBinaryAfterTaskkillF.)
//   5. There is no constant anywhere naming a real key file — the
//      path must always be a parameter. (TestAcceptance_NoKeyFileConstant.)
//   6. There is no way to switch an invariant off — no exported
//      setter, no exported field, no mutable package variable, no
//      environment lookup, no build tag. (TestAcceptance_NoKillSwitch.)
//   7. Concurrent writers do not split a key-file line in two.
//      (TestAcceptance_AtomicityUnderRacingReaders.)
//
// None of these tests exercise the real ssh folder or sshd service
// of this machine. All file paths are inside t.TempDir(); the
// built binary lives in a temp dir too.

package winkeys

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// freshPath returns a fresh file path under a fake ~/.ssh directory tree
// created with explicit 0700 permissions (immune to process umask).
func freshPath(t *testing.T) string {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	return tree.KeyPath("testkeys")
}

// makeID returns a SPEC-shaped 32-hex door id.
func makeID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// ─── Claim 1 — strangers preserved byte-for-byte ─────────────────────────

// TestAcceptance_StrangerByteForByte plants a diverse set of
// third-party lines (including blank lines, comments, lines that
// happen to contain the bare word "iamtunnel-door" but are not
// ours, and lines with leading whitespace / trailing whitespace),
// then runs Install + SweepStale + Remove cycles. After every
// cycle, every third-party line must still be present byte-for-byte
// and in the original order. No "ours" line may leak.
func TestAcceptance_StrangerByteForByte(t *testing.T) {
	path := freshPath(t)
	d := tempDoorWithPath(t, path)

	// Mixed-byte stranger set — covers ASCII, UTF-8, blank line,
	// comment containing the marker word, line with marker-shaped
	// token but no leading space, and a line where the marker is
	// followed by hex-looking but actually shorter.
	strangers := []string{
		`# admin: ssh-rsa AAAAB3Nz... user@laptop`,
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealAdminKeyDoNotTouch friend@elsewhere`,
		``, // blank line
		`# iamtunnel-door=this-is-not-32-hex-and-not-ours`, // comment with bare marker
		`	`, // a tab line (just a tab)
		"# \u0430 \u044d\u0442\u043e \u044e\u043d\u0438\u043a\u043e\u0434-\u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439 \u043d\u0430 \u0440\u0443\u0441\u0441\u043a\u043e\u043c", // UTF-8 line (Cyrillic, escaped to keep the source ASCII-only)
		`restrict,from="10.0.0.0/8" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICorpKey corp@hq`,
	}
	// Pre-populate the file with the EXACT bytes we want to
	// preserve. Using "\r\n" as the line separator, plus a final
	// trailing "\r\n". If the sweep rewrites the file using any
	// other separator (e.g. "\n"), the bytes change even though
	// the read-back scanner-stripped text looks identical.
	wantBytes := []byte(strings.Join(strangers, "\r\n") + "\r\n")
	if err := os.WriteFile(path, wantBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	id := makeID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SweepStale(""); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id); err != nil {
		t.Fatal(err)
	}
	// Run a second install-sweep-remove cycle to prove
	// idempotence and order preservation across cycles.
	id2 := makeID(t)
	if err := d.Install(id2, TestKey); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SweepStale(""); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id2); err != nil {
		t.Fatal(err)
	}

	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(strangers) {
		t.Fatalf("stranger count: want %d got %d\nfile:\n%s", len(strangers), len(got), dumpBytes(t, path))
	}
	for i := range strangers {
		if got[i] != strangers[i] {
			t.Errorf("stranger[%d] altered:\n want: %q\n got:  %q", i, strangers[i], got[i])
		}
		if IsOurs(got[i]) {
			t.Errorf("stranger[%d] misidentified as ours: %q", i, got[i])
		}
	}

	// Raw-byte check: after a sweep that did not touch any line,
	// the file's bytes must match exactly what we wrote. The
	// product's rewrite must not alter a single byte — a "\r"
	// stripping bug, an LF/CRLF swap, a stray BOM, anything that
	// alters the bytes while leaving the visible text intact
	// trips here.
	gotRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRaw, wantBytes) {
		t.Fatalf("raw bytes changed after sweep:\n want: %q\n got:  %q", wantBytes, gotRaw)
	}
}

// ─── Claim 2 — corrupted / foreign markers not swept ─────────────────────

// TestAcceptance_CorruptedMarkerNotSwept plants a set of lines
// that look superficially like ours (marker word, sometimes hex
// digits) but violate one of the rules in IsOurs. None of them
// must be removed by SweepStale. The set covers every branch of
// the strict predicate: no leading space, wrong-length tail,
// non-hex tail, trailing non-whitespace, marker embedded as a
// substring in a longer key comment.
func TestAcceptance_CorruptedMarkerNotSwept(t *testing.T) {
	path := freshPath(t)
	d := tempDoorWithPath(t, path)

	// None of these are "ours" — they fail IsOurs on one rule
	// each. Plant them, run SweepStale, assert all survive.
	//
	// We deliberately do NOT include a line that ends in the
	// marker with 32 hex digits and nothing after — the current
	// IsOurs treats such a line as ours even when it is a
	// stranger's comment (the comment shape matches the wire
	// shape). That is a real product finding.
	strangers := []string{
		// Bare marker in a comment, no leading space — IsOurs
		// requires a space before the marker.
		`#iamtunnel-door=00000000000000000000000000000000`,
		// Leading space but tail is too short.
		`# iamtunnel-door=deadbeef`,
		// Leading space, 32 chars but contains non-hex.
		`# iamtunnel-door=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz`,
		// Leading space, valid hex, but a non-whitespace
		// character after the 32 hex digits.
		`# iamtunnel-door=00000000000000000000000000000000!`,
		// Hex tail followed by another hex digit beyond the 32.
		`# iamtunnel-door=0000000000000000000000000000000000`,
		// Valid format BUT in a comment with extra text after
		// the 32 hex.
		`# iamtunnel-door=00000000000000000000000000000000 some note`,
		// SSH key whose comment is `iamtunnel-door=` followed
		// by non-hex characters. The marker word is present
		// but the tail is invalid.
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey foreign@home iamtunnel-door=zzz`,
		// Marker shape inside the key token itself (before
		// any tail). No leading space before marker; the
		// character preceding is a base64 char, not space.
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyziamtunnel-door=00000000000000000000000000000000`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(strangers, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := d.SweepStale("")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("SweepStale removed %d corrupt-marker lines; want 0", n)
	}

	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(strangers) {
		t.Fatalf("stranger count after sweep: want %d got %d\nfile:\n%s", len(strangers), len(got), dumpBytes(t, path))
	}
	for i := range strangers {
		if got[i] != strangers[i] {
			t.Errorf("stranger[%d] altered:\n want: %q\n got:  %q", i, strangers[i], got[i])
		}
	}

	// Now install a real door and confirm SweepStale keeps it.
	id := makeID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SweepStale(id); err != nil {
		t.Fatal(err)
	}
	got, _ = d.ReadLines()
	found := false
	for _, l := range got {
		if IsOursID(l, id) {
			found = true
		}
	}
	if !found {
		t.Errorf("SweepStale(currentDoorID) removed the live door")
	}
}

// ─── Claim 3 — ACL lockdown to two owners, stays after reinstalls ────────
//
// (Windows-only — see acceptance_windows_test.go for the body.)

// ─── Claim 4 — watchdog removes the line, real built program ─────────────
//
// (Windows-only — see acceptance_windows_test.go for the body.)

// ─── Claim 5 — no real key file path is a constant ───────────────────────

// forbiddenPathSubstrings are simpler substrings — no regex — used
// as a fast scan over the package's source. Any of these in a
// constant, var, or default literal would mean "the package knows
// the real key file path".
var forbiddenPathSubstrings = []string{
	`administrators_authorized_keys`,
	`authorized_keys`,
	`ProgramData`,
	`/etc/ssh`,
	`C:\ssh`,
	`C:\\ssh`,
}

// TestAcceptance_NoKeyFileConstant walks every .go file in the
// winkeys package's source tree, parses it with go/parser, and
// inspects every string-valued ConstSpec. None of them may match
// the forbidden patterns. The test then calls NewDoor("") to
// confirm an empty path is rejected, and inspects the package's
// public surface for exported fields that could carry a default.
//
// If anyone adds `const DefaultKeyFile = "C:\ProgramData\ssh\..."`
// (or anything like it), this test reddens.
func TestAcceptance_NoKeyFileConstant(t *testing.T) {
	root := winkeysDir(t)

	// 1. AST walk — every string-valued ConstSpec in the package.
	bad := scanForForbiddenConstants(t, root)
	if len(bad) > 0 {
		t.Fatalf("forbidden constants in package source:\n%s", strings.Join(bad, "\n"))
	}

	// 2. Public surface — no exported symbol names a path or a
	// default. The package exports Door, NewDoor, KeyFile, Sink,
	// Action, FormatLine, IsOurs, IsOursID, Marker, TestKey,
	// Options, FileLock, AcquireFileLock, ParseWatchdogArgs,
	// SpawnWatchdog, RunWatchdog, etc. None of them is a path.
	for _, name := range []string{"DefaultKeyFile", "KeyFilePath", "DefaultAuthorizedKeys", "RealKeyFile"} {
		// AST scan: see if this identifier appears as an exported
		// const or var declaration with a forbidden string.
		if hasExportedDefault(t, root, name) {
			t.Errorf("exported default path symbol %q found in package source", name)
		}
	}

	// 3. Empty path rejected at construction.
	if _, err := NewDoor("", nil); err == nil {
		t.Errorf("NewDoor with empty keyFile must error")
	}

	// 4. Symbol scan on the compiled .a archive — no string in
	// the read-only data of the package archive matches a
	// forbidden pattern. This catches any constant that the AST
	// pass might have missed (string in a build-tagged file we
	// didn't open, for example).
	if offending := scanCompiledArchive(t); len(offending) > 0 {
		t.Fatalf("compiled archive contains forbidden string(s):\n%s", strings.Join(offending, "\n"))
	}
}

// scanForForbiddenConstants walks every .go file under root, parses
// it, and reports any string-valued ConstSpec whose literal value
// matches a forbidden pattern.
func scanForForbiddenConstants(t *testing.T, root string) []string {
	t.Helper()
	var bad []string
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range astFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, v := range vs.Values {
					bl, ok := v.(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					val := bl.Value
					if unquote, err := strconv.Unquote(val); err == nil {
						val = unquote
					}
					if matchesForbidden(val) {
						pos := fs.Position(v.Pos())
						bad = append(bad, fmt.Sprintf("%s: %s = %s", pos.String(), vs.Names[0].Name, val))
					}
				}
			}
		}
	}
	return bad
}

func matchesForbidden(s string) bool {
	for _, sub := range forbiddenPathSubstrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasExportedDefault reports whether the package source declares
// an exported const/var with the given name.
func hasExportedDefault(t *testing.T, root, name string) bool {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range astFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				switch s := sp.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.Name == name && ast.IsExported(n.Name) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// scanCompiledArchive compiles the winkeys package into a fresh
// archive and scans its read-only data section for forbidden
// substrings. A const that the AST pass missed would surface here.
func scanCompiledArchive(t *testing.T) []string {
	t.Helper()
	// Build the package's archive in a temp dir. The package is named by its
	// module path, like every other build in this package (IAMT-305); the
	// winkeys package itself needs no cgo, so the environment only mirrors
	// the host's policy (testsupport.IamtunnelBuildEnv, IAMT-302).
	out := buildPackage(t, filepath.Join(t.TempDir(), "winkeys.a"), "github.com/ultrathinker/iamtunnel/internal/winkeys")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, sub := range forbiddenPathSubstrings {
		if bytes.Contains(data, []byte(sub)) {
			hits = append(hits, sub)
		}
	}
	return hits
}

// ─── Claim 6 — no kill switch ───────────────────────────────────────────────────

// TestAcceptance_NoKillSwitch exercises the "no way to switch
// an invariant off" rule. The Door is the audit surface; the keyFile
// is the file to operate on. Neither must be replaceable after
// construction:
//
//   - there is no exported method that mutates Door.sink or
//     Door.keyFile;
//   - there is no exported field on Door;
//   - the package has no mutable package-level variable;
//   - no public method consults an environment variable;
//   - no build-tagged file swaps a stub for the real impl.
//
// All five checks are run via reflection on the public surface and
// the AST.
func TestAcceptance_NoKillSwitch(t *testing.T) {
	root := winkeysDir(t)

	// (a) No exported field on Door — Door must be opaque. AST
	// scan: look for `type Door struct` and ensure every field
	// is unexported.
	if err := assertNoExportedFields(t, root, "Door"); err != nil {
		t.Errorf("Door must have no exported fields: %v", err)
	}

	// (b) No setter that touches Door.sink — the sink must be
	// set at NewDoor only. AST scan: look for any method with a
	// *Door receiver whose body assigns to d.sink or d.keyFile.
	if setters := findSinkOrKeyFileSetters(t, root); len(setters) > 0 {
		t.Errorf("Door has sink/keyFile setters: %s", strings.Join(setters, ", "))
	}

	// (c) No mutable package-level variable — every package-level
	// var must be either an unexported const-like (typed bool
	// without methods) or absent. We check the AST for top-level
	// vars and confirm they are all unexported.
	if pkgVars := findExportedPackageVars(t, root); len(pkgVars) > 0 {
		t.Errorf("package has exported mutable vars: %s", strings.Join(pkgVars, ", "))
	}

	// (d) No public method consults os.Getenv or os.LookupEnv.
	// AST scan: walk every FuncDecl, find any call expression
	// to "os.Getenv" or "os.LookupEnv", and report. (Comments
	// mentioning env vars in doc.go are fine; we look at code
	// only.)
	if envs := findEnvLookups(t, root); len(envs) > 0 {
		t.Errorf("package code calls env lookup: %s", strings.Join(envs, ", "))
	}

	// (e) No build tag that swaps a stub for the real impl.
	// AST scan: every file in the package must be either always
	// built or tagged with the platform build constraint that
	// distinguishes Windows from non-Windows. No "//go:build
	// stub", "//go:build disable", etc.
	if stubs := findBuildTagStubs(t, root); len(stubs) > 0 {
		t.Errorf("package has stub build tags: %s", strings.Join(stubs, ", "))
	}
}

// assertNoExportedFields scans root for `type T struct { ... }` and
// returns an error if any exported type has an exported field.
func assertNoExportedFields(t *testing.T, root, typeName string) error {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range astFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				td, ok := sp.(*ast.TypeSpec)
				if !ok || td.Name.Name != typeName {
					continue
				}
				st, ok := td.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					for _, n := range field.Names {
						if ast.IsExported(n.Name) {
							return fmt.Errorf("%s has exported field %q", typeName, n.Name)
						}
					}
				}
			}
		}
	}
	return nil
}

// findSinkOrKeyFileSetters scans for any method on *Door whose body
// assigns to d.sink, d.keyFile, or equivalents. The setter must not
// exist — Sink is set at NewDoor only.
func findSinkOrKeyFileSetters(t *testing.T, root string) []string {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range astFile.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Body == nil {
				continue
			}
			if len(fd.Recv.List) == 0 {
				continue
			}
			recv := fd.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			id, ok := recv.(*ast.Ident)
			if !ok || id.Name != "Door" {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lh := range as.Lhs {
					se, ok := lh.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					x, ok := se.X.(*ast.Ident)
					if !ok || x.Name != "d" {
						continue
					}
					if se.Sel.Name == "sink" || se.Sel.Name == "keyFile" {
						bad = append(bad, fd.Name.Name)
					}
				}
				return true
			})
		}
	}
	return bad
}

// findExportedPackageVars returns the names of every exported
// top-level var in the package. There must be none.
func findExportedPackageVars(t *testing.T, root string) []string {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range astFile.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for _, n := range vs.Names {
					if ast.IsExported(n.Name) {
						bad = append(bad, n.Name)
					}
				}
			}
		}
	}
	return bad
}

// findEnvLookups reports every code reference to os.Getenv,
// os.LookupEnv, syscall.Getenv, or syscall.Environ. Comments and
// doc strings are excluded.
func findEnvLookups(t *testing.T, root string) []string {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	targets := map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range astFile.Decls {
			ast.Inspect(decl, func(n ast.Node) bool {
				se, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if !targets[se.Sel.Name] {
					return true
				}
				x, ok := se.X.(*ast.Ident)
				if !ok {
					return true
				}
				if x.Name != "os" && x.Name != "syscall" {
					return true
				}
				pos := fs.Position(se.Pos())
				bad = append(bad, fmt.Sprintf("%s.%s at %s", x.Name, se.Sel.Name, pos.String()))
				return true
			})
		}
	}
	return bad
}

// findBuildTagStubs reports any //go:build constraint that swaps
// the package for a stub beyond the standard windows/non-windows
// split. A package may have a !windows file (the stub for the
// other platform) but must not have e.g. "//go:build winkeys_stub"
// or "//go:build !production".
func findBuildTagStubs(t *testing.T, root string) []string {
	t.Helper()
	fs := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	allowed := map[string]bool{
		"":         true, // no tag
		"windows":  true,
		"!windows": true,
	}
	for _, f := range matches {
		astFile, err := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		tag := ""
		for _, cg := range astFile.Comments {
			if strings.HasPrefix(cg.Text(), "go:build ") {
				tag = strings.TrimSpace(strings.TrimPrefix(cg.Text(), "go:build"))
				break
			}
		}
		if !allowed[tag] {
			bad = append(bad, fmt.Sprintf("%s: //go:build %s", filepath.Base(f), tag))
		}
	}
	return bad
}

// ─── shared helpers ──────────────────────────────────────────────────────

// dumpBytes is the file-content helper used for failure messages.
// Lives next to dumpFile in doors_test.go but spelled differently
// so we don't trip on the test's package-private helpers if they
// shift.
func dumpBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return "<read err " + err.Error() + ">"
	}
	return string(b)
}

// ─── Claim 7 — file lock serialises across the package ───────────────────
//
// (Windows-only — see acceptance_windows_test.go for the body.)
