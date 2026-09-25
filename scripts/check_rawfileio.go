//go:build ignore

// check_rawfileio.go — raw file I/O on paths outside
// internal/datafile is forbidden (gate 16, IAMT-332).
//
// Why it exists. Eight rounds of IAMT-332 and its predecessors repaired
// the same wound piecewise: a predictable temp-file name, opening the
// final name through a plant (symlink/hard link/FIFO), writing through
// it. Round 2 fixed one shape, round 8 another, and three copies in
// internal/client survived until round 9 only because nobody grepped
// that particular directory. The audit (§5.3) named the root of the
// eight whack-a-mole rounds: there is no single door through which file
// I/O passes, and only a build-breaking guard fixes that. This is that
// guard: file I/O by name must now go through internal/datafile
// (Create/Open/ReadFile/WriteFileAtomic -- create-or-refuse, O_NOFOLLOW,
// random temp, rename-replacement), and everything left outside the door
// must stand in the allowlist below -- with a MANDATORY reason, printed
// on every run, so that drift is visible in the gate's output.
//
// WHAT is caught (by AST, not by text -- a comment saying "os.Remove"
// is not a finding, and an aliased import is caught anyway through the
// import map):
//
//  1. calls of os.Open|OpenFile|Create|ReadFile|WriteFile|Chmod|Chown|
//     Lchown|Truncate|ReadDir|Readlink|Symlink|Link and all of ioutil.*
//     -- operations that authorize a name: they read, write or chmod
//     THROUGH it.
//  2. the temp-name shape -- the very wound of rounds 2/8: a binary "+"
//     with a string literal equal to ".tmp"/".temporary"/".partial"/
//     ".old"/".lock"/".new" or containing ".tmp" (including an
//     fmt.Sprintf format with "%s.tmp").
//
// WHAT is NOT caught, and why this is a deliberate divergence from the
// audit (§5.3 also lists Stat|Lstat|Remove|RemoveAll|Rename|Mkdir|
// MkdirAll|CreateTemp|MkdirTemp): flagging them means half the tree
// lands in the allowlist on day one, and the gate turns from a barrier
// into noise (a gate that cries wolf is worse than a missing one -- the
// same principle as gate 14). Each of these operations either acts ON
// THE ENTRY rather than through it (Remove/Rename do not follow either
// end), or classifies the name without following it (Lstat/Stat -- the
// datafile refusal primitive itself), or creates a random name
// (CreateTemp/MkdirTemp). The audit's own §3.4 table justifies each such
// line in the same words -- here that reasoning is wired into the
// detector instead of thirty lines of allowlist.
//
// Allowlist. One entry per file (path → reason), the reason is required
// to be non-empty. A run prints the whole list. The second half of the
// guard is the stale entry: an allowlist file without a single finding
// fails the gate ("remove the stale allowlist entry"), so that the list
// does not rot into a standing indulgence.
//
// The second stage (IAMT-504, P2.10) is rawfileio_types.go next to this
// file: the same check by types (go/types on top of `go list -export`),
// which catches what does not look like an <os>.<Func>(...) call in the
// AST: a function value, a dot-import. The files run as a pair:
// go run check_rawfileio.go rawfileio_types.go.
//
// -selftest runs the engine against built-in samples: benign code
// (datafile/Stat/Rename/CreateTemp/MkdirAll) must produce zero findings,
// a writer through p+".tmp" -- exactly the expected findings, an aliased
// import -- be caught, and the allowlist mechanism -- catch a stale
// entry and pass a live one. The gate runs the selftest BEFORE the real
// check: a broken detector would otherwise pass silence off as consent.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// flaggedOSSelectors — os package selectors that authorize a name
// through themselves. Everything else in os.* (Stat, Lstat, Remove,
// Rename, Mkdir, MkdirAll, CreateTemp, MkdirTemp) is a deliberate
// divergence from the audit, see the header.
var flaggedOSSelectors = map[string]bool{
	"Open":      true,
	"OpenFile":  true,
	"Create":    true,
	"ReadFile":  true,
	"WriteFile": true,
	"Chmod":     true,
	"Chown":     true,
	"Lchown":    true,
	"Truncate":  true,
	"ReadDir":   true,
	"Readlink":  true,
	"Symlink":   true,
	"Link":      true,
}

// tempSuffixes — the temp-name shape: a string literal equal to "."+suffix
// or containing ".tmp". These are the names that wounded rounds 2/8:
// writing to <path>+".tmp", whose name the attacker knows in advance.
var tempSuffixes = []string{"tmp", "temporary", "partial", "old", "lock", "new"}

func isTempShapeLiteral(v string) bool {
	if strings.Contains(v, ".tmp") {
		return true
	}
	for _, s := range tempSuffixes {
		if v == "."+s {
			return true
		}
	}
	return false
}

// skippedDirNames — directories not scanned at all: test data and
// auxiliary trees. _test.go is filtered separately (by file name).
// internal/testsupport is excluded by the "testsupport" segment: its
// plant helpers DELIBERATELY plant symlink/hard link/FIFO entries with
// plain os.Symlink/os.Link.
var skippedDirNames = map[string]bool{
	".git":        true,
	"testdata":    true,
	"spikes":      true,
	"tools":       true,
	"scripts":     true,
	"testsupport": true,
}

// allowlist — every permitted finding outside internal/datafile, path →
// reason. The reason is required and non-empty: an entry without an
// explanation fails the gate just as loudly as a missing one. The list
// is printed on every run.
//
// The seed is the audit's §3.4 table (non-exploitable residues) plus the
// scanner's current findings. The internal/datafile entries are the door
// itself: the contract keeps all raw I/O in one leaf package, and no new
// file outside it receives that right.
var allowlist = map[string]string{
	"internal/datafile/datafile.go":             "the datafile contract itself — the one leaf package allowed raw pathname I/O (create-or-refuse, O_NOFOLLOW)",
	"internal/datafile/create_posix.go":         "the datafile contract itself — O_CREATE|O_EXCL|O_NOFOLLOW create (IAMT-332 round 9)",
	"internal/datafile/create_windows.go":       "the datafile contract itself — Windows create-or-refuse with the EISDIR classification (IAMT-332 round 9)",
	"internal/datafile/openexisting_posix.go":   "the datafile contract itself — O_NOFOLLOW open of an existing entry, FIFO refused via O_NONBLOCK",
	"internal/datafile/openexisting_windows.go": "the datafile contract itself — Windows open of an existing entry",

	"cmd/iamtunnel/console_windows.go":        "reopens CONOUT$/CONIN$ after ATTACH_PARENT_PROCESS — console device names, not filesystem paths; nothing on disk can answer to them (audit §3.4)",
	"cmd/iamtunnel/desktop_linux.go":          "read-only read of the icon bundled next to the process binary (os.Executable-derived); never an attacker-chosen directory (audit §3.4)",
	"cmd/iamtunnel/gateway.go":                "chmod of the data dir and of fixed root-owned system parents, the systemd unit written into root-owned /etc/systemd/system, and a '.old' mention inside an operator message — all audit §3.4",
	"cmd/iamtunnel/gateway_launchd_darwin.go": "LaunchDaemon plist written and chowned inside root:wheel /Library/LaunchDaemons; the directory, not the writer, is the protection (audit §3.4)",
	"cmd/iamtunnel/gui_linux.go":              "opens os.DevNull, a fixed device path, for a child's stderr",
	"cmd/iamtunnel/main.go":                   "os.ReadFile handed to config.Load as a value (found by the type stage, IAMT-504): it reads the ONE config file - the machine-wide default under /etc, /Library or %ProgramData% that only an administrator can write, or the file the operator named with --config/IAMTUNNEL_CONFIG; a read, never a write, and a symlinked config is a legitimate operator setup datafile would refuse",
	"cmd/iamtunnel/iohelpers.go":              "the POSIX lockdown chmod 0700 of the server data dir itself (IAMT-213); the chmod acts on a walked name — the remaining documented walk residual (IAMT-332; the pure-listing walks went through os.Root in IAMT-333)",
	"cmd/iamtunnel/server.go":                 "the POSIX lockdown chmod 0700 of the server data dir itself (IAMT-213, audit §3.4)",

	"internal/gateway/auth_quiet.go":        "pruneJournalArchives (R4 F-11) lists the journal's own directory - both names come from the Config log path, never from a scan - to find rotation archives by their stamped names; entries are only ReadDir'd and os.Remove'd by name, none is opened",
	"internal/gateway/events/chain.go":      "l.path+\".lock\" is the journal's append-lock sibling (IAMT-467), opened only through state.AcquireFileLock - OpenDataFile, create-or-refuse and no-follow - like the door lock",
	"internal/gateway/events/sync_posix.go": "fsync of a directory fd opened by name; worst case it syncs the wrong directory (audit §3.4)",
	"internal/gateway/lifecycle.go":         "hkPath+\".old\" is the deliberate RUNBOOK §4.3 backup copy written through the datafile-based atomicWriteFile, not a temp name",
	"internal/gateway/state/enrolhmac.go":   "O_CREATE|O_EXCL create-or-refuse of the enrol HMAC key: a plant at the name collides, nothing is written through it (audit §3.4)",
	"internal/gateway/state/sync_posix.go":  "fsync of a directory fd opened by name; worst case it syncs the wrong directory (audit §3.4)",

	"internal/ui/fonts_linux.go":       "read-only load of system font files for the TUI (audit §3.4)",
	"internal/ui/macfonts/macfonts.go": "read-only discovery and load of macOS system fonts (audit §3.4)",
	"internal/ui/winfonts/loader.go":   "read-only load of Windows font files (audit §3.4)",
	"internal/ui/shot_windows.go":      "screenshot --out path: the shot command holds no privilege and no other account's data (audit §3.4)",

	"internal/winkeys/doors.go":          "d.keyFile+\".lock\" is the door lock sibling name opened through datafile.Open (flock is per-inode, round 9d); os.Open is the diagnostic ReadLines of the door's own key file (audit §3.4)",
	"internal/winkeys/doors_unix.go":     "the .winkeys.tmp.<128-bit crypto/rand> staging name is random by construction (IAMT-246 fix1), written create-or-refuse",
	"internal/winkeys/doorwatch.go":      "watchdog stderr readback by path, test-capture mode only (audit §3.4)",
	"internal/winkeys/doorwatch_unix.go": "child stderr wired to os.DevNull, a fixed device path (audit §3.4)",
	"internal/winkeys/file_sink.go":      "marker draft and archive staging are O_EXCL create-or-refuse by construction; syncDir fsyncs a directory fd; retention ReadDir acts on walked names (audit §3.4)",

	"internal/winkeys/tree_lock_windows.go": "os.ReadDir lists a directory the lockdown walk holds open without FILE_SHARE_DELETE, so it cannot be renamed or replaced under the listing; every entry is then opened without following a reparse point and locked through its own handle (R2-CX F-12)",
}

// finding — one finding: file:line, what exactly was found.
type finding struct {
	file string
	line int
	what string
}

// problem — one reason to fail the gate.
type problem string

// scanFile parses one file and returns its findings. The import map
// resolves aliases: osh.ReadFile with import osh "os" is a finding.
//
// Literals inside os.CreateTemp/os.MkdirTemp argument lists are excluded
// from the temp-name shape: the CreateTemp pattern is the sanctioned
// random-name mechanism (base+".tmp.<random>"), the name itself is
// unpredictable, and all writers have collapsed onto it. The wound of
// rounds 2/8 is flat concatenation outside CreateTemp, and that is
// caught.
func scanFile(filename string, src any) ([]finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	imports := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		path, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = path
	}
	isTempFn := func(e *ast.CallExpr) bool {
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && imports[id.Name] == "os" && (sel.Sel.Name == "CreateTemp" || sel.Sel.Name == "MkdirTemp")
	}

	// The [from, to] spans of CreateTemp/MkdirTemp argument lists.
	type span struct{ from, to token.Pos }
	var tempArgSpans []span
	inTempArgs := func(p token.Pos) bool {
		for _, s := range tempArgSpans {
			if p >= s.from && p <= s.to {
				return true
			}
		}
		return false
	}

	var out []finding
	add := func(pos token.Pos, what string) {
		out = append(out, finding{file: filename, line: fset.Position(pos).Line, what: what})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					switch imports[id.Name] {
					case "os":
						if flaggedOSSelectors[sel.Sel.Name] {
							add(e.Pos(), "os."+sel.Sel.Name)
						}
					case "io/ioutil":
						add(e.Pos(), "ioutil."+sel.Sel.Name)
					}
				}
			}
			if isTempFn(e) && len(e.Args) > 0 {
				tempArgSpans = append(tempArgSpans, span{e.Args[0].Pos(), e.Args[len(e.Args)-1].End()})
			}
			// fmt.Sprintf("%s.tmp", ...) — the format carries a temp name
			// even when there is no concatenation (the conservative
			// version, audit §5.3 item 3).
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && imports[id.Name] == "fmt" && sel.Sel.Name == "Sprintf" && len(e.Args) > 0 {
					if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && !inTempArgs(lit.Pos()) {
						if v, uerr := strconv.Unquote(lit.Value); uerr == nil && isTempShapeLiteral(v) {
							add(lit.Pos(), fmt.Sprintf("temp-name shape (%s)", lit.Value))
						}
					}
				}
			}
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return true
			}
			for _, side := range []ast.Expr{e.X, e.Y} {
				if lit, ok := side.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if inTempArgs(lit.Pos()) {
						continue
					}
					v, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						continue
					}
					if isTempShapeLiteral(v) {
						add(lit.Pos(), fmt.Sprintf("temp-name shape (%s)", lit.Value))
					}
				}
			}
		}
		return true
	})
	return out, nil
}

// dedupFindings collapses duplicates by file:line:what (one literal can
// appear in two roles).
func dedupFindings(in []finding) []finding {
	seen := map[finding]bool{}
	var out []finding
	for _, f := range in {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// check merges the findings with the allowlist: unlisted and stale are
// both gate problems. The allowlist report is always printed (see main).
// alive — allowlist files where the second stage (by types) produced a
// finding: such an entry is alive too, even though the AST sees nothing
// in it.
// active — files the second stage checked on this platform; nil — there
// was no second stage (the first stage's selftest), and then staleness
// is judged by the AST stage alone, as before IAMT-504. A file absent
// from active here but carrying AST findings is alive; with no findings
// its OS's own gate judges it, not this one
// (review 116 C-03).
func check(findings []finding, allow map[string]string, alive, active map[string]bool) []problem {
	var probs []problem
	byFile := map[string][]finding{}
	for _, f := range findings {
		byFile[f.file] = append(byFile[f.file], f)
		if _, ok := allow[f.file]; !ok {
			probs = append(probs, problem(fmt.Sprintf(
				"%s:%d: raw os pathname I/O (%s) — route it through internal/datafile, or add an allowlist entry with a reason (see scripts/check_rawfileio.go)",
				f.file, f.line, f.what)))
		}
	}
	var keys []string
	for k := range allow {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(byFile[k]) == 0 && !alive[k] && (active == nil || active[k]) {
			probs = append(probs, problem(fmt.Sprintf(
				"stale allowlist entry for %s — the file has no flagged calls any more; remove the entry (see scripts/check_rawfileio.go)", k)))
		}
	}
	return probs
}

// printAllowlist — allowlist drift is visible in the gate's output on every run.
func printAllowlist() {
	keys := make([]string, 0, len(allowlist))
	for k := range allowlist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("raw pathname I/O allowlist (file -> reason):")
	for _, k := range keys {
		fmt.Printf("  %s\n      %s\n", k, allowlist[k])
	}
}

// selftest — the engine against built-in samples. Every probe must
// produce exactly the expected outcome; any gap turns the gate red here
// rather than staying silent in production.
func selftest() error {
	type probe struct {
		name    string
		src     string
		want    []string // the findings' what fields, sorted
		allow   map[string]string
		wantPro []string // substrings of the expected problems
	}
	probes := []probe{
		{
			name: "benign code has no findings",
			src: `package p

import (
	"os"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

func f(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	if err := os.Rename(path, path+".gone"); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "x.tmp")
	if err != nil {
		return err
	}
	_ = tmp
	_ = os.Lstat(path)
	return datafile.WriteFileAtomic(path, data)
}
`,
			want: nil,
		},
		{
			name: "the round-8 shape is caught: os.WriteFile through p+\".tmp\"",
			src: `package p

import "os"

func f(p string) error {
	tmp := p + ".tmp"
	return os.WriteFile(tmp, nil, 0o600)
}
`,
			want: []string{"os.WriteFile", `temp-name shape (".tmp")`},
		},
		{
			name: "the sanctioned random-name mechanism is clean",
			src: `package p

import (
	"fmt"
	"os"
)

func f(dir, base string) (string, error) {
	tmp, err := os.CreateTemp(dir, base+".tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	// The flat Sprintf shape outside CreateTemp stays a finding:
	name := fmt.Sprintf("%s.tmp", base)
	_ = name
	return tmp.Name(), nil
}
`,
			want: []string{`temp-name shape ("%s.tmp")`},
		},
		{
			name: "an aliased os import is still caught",
			src: `package p

import osh "os"

func f(p string) ([]byte, error) {
	return osh.ReadFile(p)
}
`,
			want: []string{"os.ReadFile"},
		},
		{
			name: "ioutil is caught",
			src: `package p

import "io/ioutil"

func f(p string) ([]byte, error) {
	return ioutil.ReadFile(p)
}
`,
			want: []string{"ioutil.ReadFile"},
		},
		{
			name: "a live allowlist entry is not stale",
			src: `package p

import "os"

func f(p string) error {
	return os.WriteFile(p, nil, 0o600)
}
`,
			want:  []string{"os.WriteFile"},
			allow: map[string]string{"a live allowlist entry is not stale.go": "operator's own output path"},
		},
		{
			name: "a stale allowlist entry fails",
			src: `package p

func f() error { return nil }
`,
			allow:   map[string]string{"benign.go": "once had a raw write"},
			wantPro: []string{"stale allowlist entry for benign.go"},
		},
	}
	for _, p := range probes {
		fs, err := scanFile(p.name+".go", []byte(p.src))
		if err != nil {
			return fmt.Errorf("selftest %s: %v", p.name, err)
		}
		fs = dedupFindings(fs)
		var got []string
		for _, f := range fs {
			got = append(got, f.what)
		}
		sort.Strings(got)
		want := append([]string(nil), p.want...)
		sort.Strings(want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Errorf("selftest %s: findings = %v, want %v", p.name, got, want)
		}
		if p.allow == nil {
			fmt.Printf("selftest: ok - %s\n", p.name)
			continue
		}
		probs := check(fs, p.allow, nil, nil)
		var gotPro []string
		for _, pr := range probs {
			gotPro = append(gotPro, string(pr))
		}
		if len(p.wantPro) == 0 && len(gotPro) != 0 {
			return fmt.Errorf("selftest %s: unexpected problems %v", p.name, gotPro)
		}
		for _, w := range p.wantPro {
			found := false
			for _, g := range gotPro {
				if strings.Contains(g, w) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("selftest %s: problems %v do not contain %q", p.name, gotPro, w)
			}
		}
		fmt.Printf("selftest: ok - %s\n", p.name)
	}

	// Stale is judged per platform (review 116 C-03, C-05): an
	// allowlisted file the type stage did not see here -- another OS's
	// file -- is not stale here, and the same file seen here with nothing
	// found by either stage is.
	allow := map[string]string{"doors_windows.go": "a Windows-only file"}
	if probs := check(nil, allow, map[string]bool{}, map[string]bool{}); len(probs) != 0 {
		return fmt.Errorf("selftest platform-aware stale: a file inactive on this platform was reported: %v", probs)
	}
	fmt.Println("selftest: ok - an allowlisted file of another platform is not stale here")
	probs := check(nil, allow, map[string]bool{}, map[string]bool{"doors_windows.go": true})
	if len(probs) != 1 || !strings.Contains(string(probs[0]), "stale allowlist entry for doors_windows.go") {
		return fmt.Errorf("selftest platform-aware stale: an active file with no findings was not reported stale: %v", probs)
	}
	fmt.Println("selftest: ok - an allowlisted file active here with no findings is stale")
	if probs := check(nil, allow, map[string]bool{"doors_windows.go": true}, map[string]bool{"doors_windows.go": true}); len(probs) != 0 {
		return fmt.Errorf("selftest platform-aware stale: a type-stage-only finding did not keep the entry alive: %v", probs)
	}
	fmt.Println("selftest: ok - a type-stage-only finding keeps its entry alive")
	return nil
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	selftestOnly := flag.Bool("selftest", false, "run the built-in selftest and exit")
	flag.Parse()

	if *selftestOnly {
		if err := selftest(); err != nil {
			fmt.Fprintf(os.Stderr, "check_rawfileio: %v\n", err)
			os.Exit(1)
		}
		if err := typeSelftest(); err != nil {
			fmt.Fprintf(os.Stderr, "check_rawfileio: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Every file travels as a pair: the path to read (as WalkDir handed
	// it over -- that may be absolute) and the key for findings and the
	// allowlist -- the path RELATIVE to root with slashes. The latter is
	// so that a run with -root <absolute> from scripts/ and a run with
	// -root . from the repository root produce the same keys, otherwise
	// the allowlist goes stale wholesale in front of the gate's eyes.
	type scannedFile struct{ openPath, key string }
	var files []scannedFile
	werr := filepath.WalkDir(*root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != *root && skippedDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(*root, p)
		if rerr != nil {
			rel = p
		}
		files = append(files, scannedFile{openPath: p, key: filepath.ToSlash(rel)})
		return nil
	})
	if werr != nil {
		fmt.Fprintf(os.Stderr, "check_rawfileio: %v\n", werr)
		os.Exit(1)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].key < files[j].key })

	var all []finding
	for _, f := range files {
		data, rerr := os.ReadFile(f.openPath)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "check_rawfileio: %v\n", rerr)
			os.Exit(1)
		}
		fs, err := scanFile(f.openPath, data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check_rawfileio: %v\n", err)
			os.Exit(1)
		}
		for j := range fs {
			fs[j].file = f.key
		}
		all = append(all, fs...)
	}
	all = dedupFindings(all)

	// allowlist keys in the same slash paths as the findings.
	normAllow := map[string]string{}
	for k, v := range allowlist {
		if strings.TrimSpace(v) == "" {
			fmt.Fprintf(os.Stderr, "check_rawfileio: allowlist entry for %s has an empty reason\n", k)
			os.Exit(1)
		}
		normAllow[filepath.ToSlash(k)] = v
	}

	printAllowlist()
	if len(all) == 0 {
		fmt.Println("no raw pathname I/O outside internal/datafile and the allowlist")
	}
	// The second stage: by types, over the current OS's packages.
	astSeen := map[string]bool{}
	for _, f := range all {
		astSeen[fmt.Sprintf("%s:%d", f.file, f.line)] = true
	}
	typeProbs, alive, active, checked, terr := typeStage(*root, astSeen, normAllow)
	if terr != nil {
		fmt.Fprintf(os.Stderr, "check_rawfileio: type stage: %v\n", terr)
		os.Exit(1)
	}
	fmt.Printf("type stage: %d package(s) checked, %d finding(s) the AST stage missed outside the allowlist\n", checked, len(typeProbs))
	probs := check(all, normAllow, alive, active)
	probs = append(probs, typeProbs...)
	if len(probs) > 0 {
		for _, pr := range probs {
			fmt.Println(string(pr))
		}
		fmt.Fprintf(os.Stderr, "check_rawfileio: %d problem(s)\n", len(probs))
		os.Exit(1)
	}
}
