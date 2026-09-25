//go:build ignore

// check_runbookevents.go -- the events of RUNBOOK against the code
// (gate 13, IAMT-120).
//
// Why it exists. Gate 12 (check_eventdict.go) holds the event
// dictionary of PROTOCOL §1.7 against the EventType constants. Nobody
// checks docs/RUNBOOK.md, yet that is exactly what the on-duty
// engineer reads at three in the morning: they do not re-read the
// code, they trust the document. On 13.09 five event names were found
// in RUNBOOK that the code never writes (IAMT-95), and six false
// promises of another kind. Without a separate guard they will come
// back with the first edit.
//
// THE MAIN DIFFICULTY is the same as gate 12's, and it is solved by
// the same trick. An event and an operation are written the same way:
// `door.close` is both a journal event type and the op of the control
// channel; `door.status` and `door.sanitize` are ONLY operations, and
// in RUNBOOK they are exactly that, operations. A naive grep over "a
// word with a dot" gave three wrong conclusions in a single day, one
// of them in the opposite direction: while counting by hand, the
// writers took the string literal of the operation "door.open" (five
// places in machine_conn.go) for "five records of the door.open
// event", and missed the real grant.revoke record because it goes
// through the events.NewGrantRevokedEvent factory, not through a
// constant identifier. Therefore there is not a single regular
// expression over the prose here, and not a single count over string
// literals:
//
//   - exactly ONE tagged fenced block with the info-string
//     iamtunnel-runbook-events-v1 is taken from RUNBOOK -- the list
//     of event names the document mentions, each with a mark of
//     whether the code writes it ("written") or it exists in the
//     dictionary but is not written in this build
//     ("notWrittenThisBuild" -- and then the document text must carry
//     the corresponding caveat, which is what was done for
//     hostkey.mismatch and hostkey.rotate). Everything else in
//     RUNBOOK -- prose, commands, JSON examples -- is not read at all;
//   - a Go AST is taken from the code: the EventType constants and
//     the branches of IsValidEventType (as in gate 12), PLUS two
//     exact kinds of write sites: (1) a composite literal of type
//     Event with a Type field equal to a constant identifier, and
//     (2) a factory call -- a function from event.go whose body
//     constructs an Event of that type (this is how grant.revoke is
//     written). An occurrence of the identifier in
//     events.Filter.Types is a READING of the journal, not a write,
//     and does not count as a writer (admin_role.go:972 is a live
//     example).
//
// The gate checks seven things, not one:
//
//  1. the block is exactly one, a JSON object {"written": [...],
//     "notWrittenThisBuild": [...]}, no empty names and no repeats;
//  2. every name of the block is an existing EventType constant (a
//     phantom like auth.unknown_key, or the door.status operation in
//     the role of an event -- red);
//  3. every name from "written" is really written by the code: the
//     "written" mark on a non-written event is a document promising a
//     trail that does not exist -- the very IAMT-95 error;
//  4. every name from "notWrittenThisBuild" is NOT written by the
//     code: a stale caveat is no less harmful -- it stops the
//     engineer from looking for a record that exists;
//  5. every name of the block occurs in the rest of the RUNBOOK text
//     (a dead entry of the block -- the document out of sync with its
//     own signature);
//  6. the other way, prose -> block: any name equal to the value of
//     a real EventType constant that occurs in the document as a
//     standalone token MUST be in the block. Without this the gate
//     only checks what it was handed: the block could be silently
//     shrunken to empty -- and the canary of 13.09 showed exactly
//     that (auth.failure was removed from written while left in the
//     prose -- the gate stayed green). Understanding the prose is not
//     needed for this: the list of names is known from the code, an
//     exact occurrence with clean boundaries is searched for;
//     door.status is not an EventType value -- and is not touched,
//     and if an operation ever becomes an event (door.sanitize), the
//     name really must get into the block, and the rule is right to
//     demand it.
//  7. declared means written: every EventType constant must have a
//     write site in internal/ or cmd/. The exception is exactly one --
//     a name honestly declared in "notWrittenThisBuild" (and then
//     rules 4 and 5 demand a caveat in the text). The six checks
//     above compared the block with the code, but not the code with
//     itself: a constant nobody writes and the block does not even
//     name passed them all. This is the acceptance item of IAMT-119,
//     and it only became feasible on 13.09, when the last silent name
//     got a writer (19 of 19). This project's earlier history is five
//     names promised by the document and never written by the code;
//     rule 7 keeps a sixth from appearing even when the document says
//     nothing about it.
//
// RUNBOOK does not have to mention all nineteen types -- but every
// event name it mentions must be in the block, and the block may not
// name what does not exist.
//
// -selftest runs the built-in samples; among the lures are the
// door.open operation in a JSON example and in dispatcher cases, the
// reading of EventHostKeyMismatch through events.Filter, and the
// grant.revoke factory call. It must stay green: a detector that
// counts filters as writers or operation strings as records fails on
// these samples. The gate runs the selftest BEFORE the real
// comparison, so that a broken detector does not pass green off as an
// absence of disagreements.
package main

import (
	"encoding/json"
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

// fenceInfo -- the info-string of the tagged block. Only blocks with
// this info-string are read.
const fenceInfo = "iamtunnel-runbook-events-v1"

// eventTypeName is the name of the type an event constant must be
// declared with (as in gate 12: a constant without an explicit type
// does not enter the sample -- its membership in the dictionary is
// unprovable).
const eventTypeName = "EventType"

// validatorName is the function whose switch branches count as
// allowing.
const validatorName = "IsValidEventType"

// dictKeys is exactly the set of keys allowed in the block. An extra
// key is an error, not silence: a typo in "notWrittenThisBuild" would
// otherwise turn the caveat into an empty set.
var dictKeys = map[string]bool{"written": true, "notWrittenThisBuild": true}

func main() {
	selftest := flag.Bool("selftest", false, "run the built-in samples and exit")
	runbookPath := flag.String("runbook", "docs/RUNBOOK.md", "path to the RUNBOOK")
	codePath := flag.String("code", "internal/gateway/events/event.go", "path to the event constants file")
	root := flag.String("root", ".", "repository root: write sites are searched in <root>/internal and <root>/cmd")
	flag.Parse()

	if *selftest {
		if err := runSelftest(); err != nil {
			fmt.Fprintf(os.Stderr, "check_runbookevents: selftest failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("selftest: every sample parsed correctly")
		return
	}

	dict, docWithoutBlock, err := readRunbookDict(*runbookPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_runbookevents: %s: %v\n", *runbookPath, err)
		os.Exit(2)
	}
	code, err := readCodeDictionary(*codePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_runbookevents: %s: %v\n", *codePath, err)
		os.Exit(2)
	}
	writers, err := scanWriters(*root, *codePath, code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_runbookevents: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("event names in %s: %d written, %d not-written-this-build\n",
		*runbookPath, len(dict.Written), len(dict.NotWritten))
	fmt.Printf("event types in %s: %d, actually written by internal/ or cmd/: %d of %d\n",
		*codePath, len(code.Consts), len(writers), len(code.Consts))

	bad := 0

	// 2. Every name of the block exists in the code.
	for _, name := range append(append([]string{}, dict.Written...), dict.NotWritten...) {
		if _, ok := code.Consts[name]; !ok {
			bad++
			fmt.Printf("  ! %q is marked as an event in the block, but %s has no EventType constant with that value -- a phantom (or it is a channel operation that has no place in this block)\n", name, filepath.Base(*codePath))
		}
	}

	// 3. "written" must be written by the code.
	for _, name := range dict.Written {
		if _, ok := code.Consts[name]; !ok {
			continue // already reported above
		}
		if len(writers[name]) == 0 {
			bad++
			fmt.Printf("  ! %q is marked written, but the code nowhere writes an event of this type -- either remove the name from the block, or move it to \"notWrittenThisBuild\" and add the \"not written in this build\" caveat to the text\n", name)
		}
	}

	// 4. "notWrittenThisBuild" must NOT be written: a stale caveat is
	//    no less harmful than a phantom.
	for _, name := range dict.NotWritten {
		if _, ok := code.Consts[name]; !ok {
			continue
		}
		if places := writers[name]; len(places) > 0 {
			bad++
			fmt.Printf("  ! %q is marked notWrittenThisBuild, but the code already writes this event (%s) -- the caveat is stale, move the name to \"written\"\n", name, strings.Join(places, ", "))
		}
	}

	// 5. A dead entry: a name from the block must occur in the rest of
	//    the RUNBOOK text. An exact search for a concrete line -- not
	//    "a naive grep over a word with a dot": the list of names is
	//    known in advance, and operation decoys cannot get in here.
	inBlock := map[string]bool{}
	for _, name := range append(append([]string{}, dict.Written...), dict.NotWritten...) {
		inBlock[name] = true
		if !occursAsName(docWithoutBlock, name) {
			bad++
			fmt.Printf("  ! the name %q is declared in the block but never occurs in the rest of the RUNBOOK text -- a dead entry: a name in the block must be a name the document actually mentions\n", name)
		}
	}

	// 6. Prose -> block: a name equal to the value of a real EventType
	//    constant that occurs in the document as a standalone token
	//    must be in the block. Without this check the gate only checks
	//    what it was handed: a block silently shrunken to empty would
	//    stay green (the canary of 13.09: auth.failure was removed
	//    from written, it stayed in the prose).
	var dictNames []string
	for name := range code.Consts {
		dictNames = append(dictNames, name)
	}
	sort.Strings(dictNames)
	for _, name := range dictNames {
		if inBlock[name] {
			continue
		}
		if occursAsName(docWithoutBlock, name) {
			bad++
			fmt.Printf("  ! the event name %q occurs in the rest of the RUNBOOK text but is missing from the block -- the block must not shrink silently: every event the document names must stand in \"written\" or \"notWrittenThisBuild\"\n", name)
		}
	}

	// 7. Declared means written. An EventType constant nobody writes
	//    and the block does not even name passed every check above:
	//    the gate compared the block with the code, but not the code
	//    with itself. This is the acceptance item of IAMT-119, and it
	//    only became feasible today, when the last silent name got a
	//    write site (19 of 19). The exception is exactly one -- a name
	//    honestly declared in the block: there "written" is checked by
	//    item 3, and "notWrittenThisBuild" together with the caveat in
	//    the text by items 4 and 5.
	for _, name := range dictNames {
		if inBlock[name] {
			continue
		}
		if len(writers[name]) == 0 {
			bad++
			fmt.Printf("  ! the EventType constant with value %q is written nowhere in internal/ or cmd/ and is not declared in the block -- a declared but silent event: either write it, or list it in \"notWrittenThisBuild\" and add the \"not written in this build\" caveat to the text\n", name)
		}
	}

	if bad > 0 {
		fmt.Printf("the runbook event block and the code disagree in %d way(s)\n", bad)
		os.Exit(1)
	}
	fmt.Println("every event name the runbook block claims matches a real EventType, each not-written-this-build caveat is still true, and every declared EventType has a write site")
}

// ---------------------------------------------------------------- document

// runbookDict -- the contents of the tagged block.
type runbookDict struct {
	Written    []string `json:"written"`
	NotWritten []string `json:"notWrittenThisBuild"`
}

// readRunbookDict extracts the single tagged block, checks its shape,
// and returns it together with the document text without the block
// (for the dead-entry check). The uniqueness requirement is not
// pedantry: two blocks mean two different signatures of the document,
// and there is nothing to compare.
func readRunbookDict(path string) (runbookDict, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return runbookDict{}, "", err
	}
	src := string(raw)
	blocks := taggedBlocks(src)
	switch len(blocks) {
	case 1:
		// the normal case
	case 0:
		return runbookDict{}, "", fmt.Errorf("no ```%s block: the RUNBOOK event list must be machine-readable, otherwise there is nothing to compare", fenceInfo)
	default:
		return runbookDict{}, "", fmt.Errorf("there must be exactly one ```%s block, found %d", fenceInfo, len(blocks))
	}

	// Keys are checked before the unmarshal: json.Unmarshal silently
	// ignores unknown fields, and a key typo must be an error, not
	// silence.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(blocks[0]), &keys); err != nil {
		return runbookDict{}, "", fmt.Errorf("the ```%s block is not a JSON object {\"written\":[...],\"notWrittenThisBuild\":[...]}: %v", fenceInfo, err)
	}
	for k := range keys {
		if !dictKeys[k] {
			return runbookDict{}, "", fmt.Errorf("the ```%s block contains an unknown key %q -- exactly %q and %q are allowed", fenceInfo, k, "written", "notWrittenThisBuild")
		}
	}
	if _, ok := keys["written"]; !ok {
		return runbookDict{}, "", fmt.Errorf("the ```%s block has no \"written\" key", fenceInfo)
	}
	if _, ok := keys["notWrittenThisBuild"]; !ok {
		return runbookDict{}, "", fmt.Errorf("the ```%s block has no \"notWrittenThisBuild\" key (an empty list is a valid value, a missing key is not)", fenceInfo)
	}

	var d runbookDict
	if err := json.Unmarshal([]byte(blocks[0]), &d); err != nil {
		return runbookDict{}, "", fmt.Errorf("the ```%s block does not parse: %v", fenceInfo, err)
	}

	seen := map[string]bool{}
	for _, name := range append(append([]string{}, d.Written...), d.NotWritten...) {
		if strings.TrimSpace(name) == "" {
			return runbookDict{}, "", fmt.Errorf("the ```%s block has an empty name", fenceInfo)
		}
		if seen[name] {
			return runbookDict{}, "", fmt.Errorf("the name %q repeats in the ```%s block", name, fenceInfo)
		}
		seen[name] = true
	}

	return d, strings.Replace(src, blocks[0], "", 1), nil
}

// taggedBlocks is a line-by-line fence scan, the same one as in gate
// 12: the function sees nothing outside the tagged blocks, and that is
// its main property.
func taggedBlocks(doc string) []string {
	var out []string
	lines := strings.Split(doc, "\n")
	i := 0
	for i < len(lines) {
		open, info := fenceOf(lines[i])
		if open == 0 {
			i++
			continue
		}
		j := i + 1
		var body []string
		closed := false
		for ; j < len(lines); j++ {
			if n, inf := fenceOf(lines[j]); n >= open && strings.TrimSpace(inf) == "" {
				closed = true
				break
			}
			body = append(body, lines[j])
		}
		if strings.TrimSpace(info) == fenceInfo {
			out = append(out, strings.Join(body, "\n"))
		}
		if !closed {
			break
		}
		i = j + 1
	}
	return out
}

func fenceOf(line string) (int, string) {
	t := strings.TrimLeft(line, " \t")
	n := 0
	for n < len(t) && t[n] == '`' {
		n++
	}
	if n < 3 {
		return 0, ""
	}
	return n, strings.TrimRight(t[n:], " \t\r")
}

// occursAsName reports whether name occurs in doc as a standalone,
// name-shaped token: the bytes around a hit must not themselves be name
// bytes (letters, digits, '_', '-', '.'), so a shorter EventType value
// hidden inside a longer token — "door.open" inside "door.opened" — does
// not count, while quotes, backticks, spaces and line breaks around the
// name are fine. This is a literal scan for strings whose full list is
// known in advance (the EventType values), not a pattern over prose: the
// decoys an operation could plant never enter it.
func occursAsName(doc, name string) bool {
	from := 0
	for {
		i := strings.Index(doc[from:], name)
		if i < 0 {
			return false
		}
		at := from + i
		after := at + len(name)
		if (at == 0 || !isNameByte(doc[at-1])) && (after >= len(doc) || !isNameByte(doc[after])) {
			return true
		}
		from = at + 1
	}
}

// isNameByte reports whether b can continue a name-shaped token.
func isNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_' || b == '-' || b == '.':
		return true
	}
	return false
}

// -------------------------------------------------------------------- code

// codeDict -- everything the gate extracts from event.go.
type codeDict struct {
	Consts    map[string]string   // "door.open" -> "EventDoorOpen"
	byIdent   map[string]string   // "EventDoorOpen" -> "door.open"
	Allowed   map[string]string   // the ones IsValidEventType allows
	Factories map[string][]string // "NewGrantRevokedEvent" -> {"grant.revoke"}
}

func readCodeDictionary(path string) (codeDict, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return codeDict{}, err
	}
	return parseCodeDictionary(path, src)
}

// parseCodeDictionary parses the constants file: the constants with
// the explicit EventType type (as in gate 12), the branches of
// IsValidEventType and -- beyond gate 12 -- the factories: functions
// of this file that construct an Event with a Type field. A factory
// call from another package is a full-fledged write site (grant.revoke
// is written exactly that way), and a count of "constant identifiers
// outside event.go" loses it -- measured on 13.09 on live code.
func parseCodeDictionary(name string, src []byte) (codeDict, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return codeDict{}, err
	}

	d := codeDict{
		Consts:    map[string]string{},
		byIdent:   map[string]string{},
		Allowed:   map[string]string{},
		Factories: map[string][]string{},
	}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != eventTypeName {
				continue
			}
			for k, n := range vs.Names {
				if k >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[k].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return codeDict{}, fmt.Errorf("constant %s of type %s is not given as a string literal", n.Name, eventTypeName)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return codeDict{}, fmt.Errorf("constant %s: %v", n.Name, err)
				}
				if prev, dup := d.Consts[v]; dup {
					return codeDict{}, fmt.Errorf("value %q is declared twice: %s and %s", v, prev, n.Name)
				}
				d.Consts[v] = n.Name
				d.byIdent[n.Name] = v
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil {
			return true
		}
		if fd.Name.Name == validatorName {
			// The validator's branches -- the allowing of names.
			ast.Inspect(fd.Body, func(m ast.Node) bool {
				cc, ok := m.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cc.List {
					if id, ok := e.(*ast.Ident); ok {
						if v, known := d.byIdent[id.Name]; known {
							d.Allowed[v] = id.Name
						} else {
							d.Allowed["?"+id.Name] = id.Name
						}
					}
				}
				return true
			})
			return false
		}
		// Any other function with a body is a factory candidate: does
		// it construct an Event whose Type field equals a constant?
		if fd.Body == nil {
			return true
		}
		made := eventTypesConstructedIn(fd.Body, d.byIdent)
		if len(made) > 0 {
			d.Factories[fd.Name.Name] = made
		}
		return true
	})

	return d, nil
}

// eventTypesConstructedIn returns the constant values the body fills
// the Type field of an Event-typed composite literal with. Used twice:
// to find the factories in event.go and -- with the same code -- to
// find write sites in the other files.
func eventTypesConstructedIn(body ast.Node, byIdent map[string]string) []string {
	var out []string
	ast.Inspect(body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isEventType(cl.Type) {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Type" {
				continue
			}
			if v, ok := byIdent[identifierName(kv.Value)]; ok {
				out = append(out, v)
			}
		}
		return true
	})
	return out
}

// isEventType recognises the type of a composite literal: Event
// (inside the events package) or pkg.Event (outside, usually
// events.Event).
func isEventType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "Event"
	case *ast.SelectorExpr:
		return t.Sel != nil && t.Sel.Name == "Event"
	}
	return false
}

// identifierName extracts the bare name from an Ident or a pkg.Name
// selector.
func identifierName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if e.Sel != nil {
			return e.Sel.Name
		}
	}
	return ""
}

// --------------------------------------------------------------- writers

// scanWriters walks <root>/internal and <root>/cmd (non-test .go,
// except the constants file itself) and collects, per event name, the
// list of "file:line" write sites. A write site is a composite literal
// Event{Type: <constant>} or a call of a factory from event.go. A read
// through events.Filter.Types is NOT a write site.
func scanWriters(root, codePath string, code codeDict) (map[string][]string, error) {
	writers := map[string][]string{}
	add := func(name, place string) { writers[name] = append(writers[name], place) }

	codeAbs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, err
	}

	for _, dir := range []string{filepath.Join(root, "internal"), filepath.Join(root, "cmd")} {
		err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil // no such directory -- not an error
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			abs, aerr := filepath.Abs(path)
			if aerr != nil {
				return aerr
			}
			if abs == codeAbs {
				return nil // the constants and factories themselves are not a write site
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if serr := scanFileForWriters(path, string(src), code, add); serr != nil {
				return serr
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	for name := range writers {
		sort.Strings(writers[name])
	}
	return writers, nil
}

// scanFileForWriters finds both kinds of write sites in one file. A
// file that does not parse as Go is not a silently skipped detail: the
// checker must refuse, not decide there are no records.
func scanFileForWriters(path, src string, code codeDict, add func(name, place string)) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return fmt.Errorf("%s: does not parse as Go: %w", path, err)
	}

	// The names by which the events package is available to this file
	// ("events" or an import alias) -- so that a factory call is
	// recognised honestly, not by a coincidental method name somewhere
	// else.
	eventsNames := map[string]bool{}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasSuffix(p, "/events") && p != "github.com/ultrathinker/iamtunnel/internal/gateway/events" {
			continue
		}
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name != "." && name != "_" {
			eventsNames[name] = true
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		// (1) Event{..., Type: <constant>, ...}
		if cl, ok := n.(*ast.CompositeLit); ok && isEventType(cl.Type) {
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Type" {
					continue
				}
				if v, ok := code.byIdent[identifierName(kv.Value)]; ok {
					add(v, fmt.Sprintf("%s:%d", filepath.ToSlash(path), fset.Position(kv.Pos()).Line))
				}
			}
			return true
		}
		// (2) a factory call events.NewXxx(...)
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		if _, isFactory := code.Factories[sel.Sel.Name]; !isFactory {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || !eventsNames[x.Name] {
			return true
		}
		for _, v := range code.Factories[sel.Sel.Name] {
			add(v, fmt.Sprintf("%s:%d", filepath.ToSlash(path), fset.Position(ce.Pos()).Line))
		}
		return true
	})
	return nil
}

// ------------------------------------------------------------ selftest

// runSelftest runs the built-in samples. The gate runs it BEFORE the
// real comparison: a detector that finds nothing is otherwise
// indistinguishable from an absence of disagreements.
func runSelftest() error {
	// A sample event.go: five constants, all allowed, and one factory --
	// like the real NewGrantRevokedEvent.
	goodCode := `package events
type EventType string
const (
	EventAuthFailure EventType = "auth.failure"
	EventDoorClose EventType = "door.close"
	EventGrantRevoke EventType = "grant.revoke"
	EventDoorOpen EventType = "door.open"
	EventHostKeyMismatch EventType = "hostkey.mismatch"
)
func IsValidEventType(t EventType) bool {
	switch t {
	case EventAuthFailure, EventDoorClose, EventGrantRevoke, EventDoorOpen, EventHostKeyMismatch:
		return true
	default:
		return false
	}
}
func NewGrantRevokedEvent() Event { return Event{Type: EventGrantRevoke} }
`

	// Samples of "the rest of the code": real writers, a read through
	// Filter (NOT a writer) and the operation string "door.open" (also
	// not a writer).
	goodWriters := map[string]string{
		"internal/gateway/gw.go": `package gateway
import "github.com/ultrathinker/iamtunnel/internal/gateway/events"
func (g *G) deny() {
	g.appendEvent(events.Event{Type: events.EventAuthFailure, Actor: "x"})
	g.appendEvent(events.Event{Type: events.EventDoorClose, Actor: "gateway"})
}
`,
		"internal/gateway/admin.go": `package gateway
import "github.com/ultrathinker/iamtunnel/internal/gateway/events"
func (g *G) revoke() {
	g.appendEvent(events.NewGrantRevokedEvent())
}
`,
		// DECOY (a read): a filter over a non-written event. A detector
		// that counts any occurrence of an identifier as a record would
		// decide hostkey.mismatch is written -- and fail the
		// "agreement" sample.
		"internal/gateway/history.go": `package gateway
import "github.com/ultrathinker/iamtunnel/internal/gateway/events"
func history() {
	filter := events.Filter{Types: []events.EventType{events.EventHostKeyMismatch}}
	_ = filter
}
`,
		// DECOY (an operation): the string literal "door.open" -- five
		// dispatcher cases, as in the real machine_conn.go. None of
		// them is a record of the door.open event.
		"internal/gateway/machine_conn.go": `package gateway
func dispatch(op string) string {
	switch op {
	case "door.open":
		return "open"
	case "door.close":
		return "close"
	}
	if op == "door.open" {
		return "again"
	}
	return ""
}
`,
	}

	// THE MAIN DOCUMENT SAMPLE. Next to the correct block -- the
	// `door.status` operation in backticks, `"op":"door.open"` in a
	// JSON example and a grep with a pattern: none of them enters the
	// sample.
	goodDoc := "# RUNBOOK\n" +
		"\n" +
		"Look for `auth.failure`; the machine leaves `machine.disconnected`.\n" +
		"The `door.close` event is written, so is `grant.revoke`.\n" +
		"The `door.status` operation is not an event, and neither is `door.sanitize`.\n" +
		"Example: {\"op\":\"door.open\"}. Grep: grep 'session\\.' events.jsonl.\n" +
		"Not written in this build: `hostkey.mismatch`; the `door.open`\n" +
		"operation does not appear in the journal.\n" +
		"\n" +
		"```" + fenceInfo + "\n" +
		"{\"written\":[\"auth.failure\",\"door.close\",\"grant.revoke\"],\"notWrittenThisBuild\":[\"door.open\",\"hostkey.mismatch\"]}\n" +
		"```\n"

	type sample struct {
		name    string
		doc     string
		code    string
		writers map[string]string
		wantErr string // a substring; empty -- the sample must be consistent
		// checkSilent turns on check 7 ("declared means written"). It is
		// off by default: see the comment in checkSample.
		checkSilent bool
	}
	samples := []sample{
		{
			name:    "decoys (operations, filter reads, a factory) do not count as event records",
			doc:     goodDoc,
			code:    goodCode,
			writers: goodWriters,
		},
		{
			// The acceptance item of IAMT-119: the constant is declared,
			// nobody writes it, and the block does not even know about
			// it. All six earlier checks skipped such a case -- the gate
			// compared the block with the code, but not the code with
			// itself. The name is deliberately absent from the prose,
			// otherwise check 6 would go red and the sample would prove
			// nothing.
			name:        "a declared but silent event: a constant with no write site and outside the block",
			doc:         goodDoc,
			code:        goodCode + "\nconst EventSessionDrop EventType = \"session.drop\"\n",
			writers:     goodWriters,
			wantErr:     "is written nowhere",
			checkSilent: true,
		},
		{
			name:    "a phantom: the name is in the block, the constant is not in the code",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\",\"auth.unknown_key\"],\"notWrittenThisBuild\":[]}\n```\nText with `auth.failure` and `auth.unknown_key`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "a phantom",
		},
		{
			name:    "the name is marked written, but the code does not write it",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\",\"hostkey.mismatch\"],\"notWrittenThisBuild\":[]}\n```\nText with `auth.failure` and `hostkey.mismatch`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "is marked written",
		},
		{
			name:    "a stale caveat: notWrittenThisBuild, but the code writes it (through a factory)",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\"],\"notWrittenThisBuild\":[\"grant.revoke\"]}\n```\nText with `auth.failure` and `grant.revoke`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "the caveat is stale",
		},
		{
			name:    "a dead entry: the name is in the block, absent from the text",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\",\"door.close\"],\"notWrittenThisBuild\":[]}\n```\nThe text mentions only `auth.failure`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "a dead entry",
		},
		{
			// The canary of 13.09 (round 3): the name was removed from
			// the block and left in the prose -- the gate must go red,
			// not "check only what it was handed".
			name:    "the prose names an event the block does not -- the block was silently shrunken",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"door.close\"],\"notWrittenThisBuild\":[]}\n```\nText: look for `auth.failure` in the journal; `door.close` is also mentioned.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "missing from the block",
		},
		{
			// A substring lure: door.open inside door.opened is NOT an
			// occurrence of the name. A detector built on
			// strings.Contains would demand door.open in the block and
			// fail this sample.
			name:    "a substring name: door.opened in the prose does not demand door.open in the block",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\"],\"notWrittenThisBuild\":[]}\n```\nText with `auth.failure` and the word door.opened (a protocol field).",
			code:    goodCode,
			writers: goodWriters,
		},
		{
			name:    "the door.status operation in the role of an event -- a phantom",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"door.status\"],\"notWrittenThisBuild\":[]}\n```\nText with the operation `door.status`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "a phantom",
		},
		{
			name:    "no block at all",
			doc:     "# RUNBOOK\n\nThe events are described in words: auth.failure and so on.\n",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "no ```",
		},
		{
			name:    "two blocks",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\"],\"notWrittenThisBuild\":[]}\n```\n```" + fenceInfo + "\n{\"written\":[\"door.close\"],\"notWrittenThisBuild\":[]}\n```\nText: `auth.failure`, `door.close`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "exactly one",
		},
		{
			name:    "a name repeats in the block",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\",\"auth.failure\"],\"notWrittenThisBuild\":[]}\n```\nText with `auth.failure`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "repeats",
		},
		{
			name:    "an empty name",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\",\"\"],\"notWrittenThisBuild\":[]}\n```\nText with `auth.failure`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "an empty name",
		},
		{
			name:    "the block is not a JSON object (an array, as in gate 12)",
			doc:     "```" + fenceInfo + "\n[\"auth.failure\"]\n```\nText with `auth.failure`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "is not a JSON object",
		},
		{
			name:    "an unknown key in the block (a typo in notWrittenThisBuild)",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\"],\"notWritten\":[\"hostkey.mismatch\"]}\n```\nText with `auth.failure` and `hostkey.mismatch`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "an unknown key",
		},
		{
			name:    "no notWrittenThisBuild key",
			doc:     "```" + fenceInfo + "\n{\"written\":[\"auth.failure\"]}\n```\nText with `auth.failure`.",
			code:    goodCode,
			writers: goodWriters,
			wantErr: "has no",
		},
	}

	for _, s := range samples {
		got := checkSample(s.doc, s.code, s.writers, s.checkSilent)
		if s.wantErr == "" {
			if got != "" {
				return fmt.Errorf("sample %q: expected consistency, got: %s", s.name, got)
			}
			continue
		}
		if !strings.Contains(got, s.wantErr) {
			return fmt.Errorf("sample %q: expected a mention of %q, got: %q", s.name, s.wantErr, got)
		}
	}
	return nil
}

// checkSample returns a description of a disagreement or an empty
// string. It works on strings, like the selftest of gate 12, but there
// are several writer files.
func checkSample(doc, code string, writers map[string]string, checkSilent bool) string {
	tmpDoc, err := os.CreateTemp("", "runbookevents-*.md")
	if err != nil {
		return "could not create a temporary file: " + err.Error()
	}
	defer os.Remove(tmpDoc.Name())
	if _, err := tmpDoc.WriteString(doc); err != nil {
		return "could not write the temporary file: " + err.Error()
	}
	tmpDoc.Close()

	dict, docWithout, derr := readRunbookDict(tmpDoc.Name())
	if derr != nil {
		return derr.Error()
	}
	codeDict, cerr := parseCodeDictionary("sample_event.go", []byte(code))
	if cerr != nil {
		return cerr.Error()
	}

	// The writers of the sample come from a name->text map, scanned by
	// the same scanner as the real run, so that the selftest checks the
	// detector itself.
	found := map[string][]string{}
	add := func(name, place string) { found[name] = append(found[name], place) }
	names := make([]string, 0, len(writers))
	for n := range writers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := scanFileForWriters(n, writers[n], codeDict, add); err != nil {
			return err.Error()
		}
	}

	var problems []string
	all := append(append([]string{}, dict.Written...), dict.NotWritten...)
	for _, name := range all {
		if _, ok := codeDict.Consts[name]; !ok {
			problems = append(problems, fmt.Sprintf("%q is marked as an event in the block, but there is no EventType constant with that value -- a phantom", name))
		}
	}
	for _, name := range dict.Written {
		if _, ok := codeDict.Consts[name]; !ok {
			continue
		}
		if len(found[name]) == 0 {
			problems = append(problems, fmt.Sprintf("%q is marked written, but the code nowhere writes an event of this type", name))
		}
	}
	for _, name := range dict.NotWritten {
		if _, ok := codeDict.Consts[name]; !ok {
			continue
		}
		if len(found[name]) > 0 {
			problems = append(problems, fmt.Sprintf("%q is marked notWrittenThisBuild, but the code already writes this event (%s) -- the caveat is stale", name, strings.Join(found[name], ", ")))
		}
	}
	for _, name := range all {
		if !occursAsName(docWithout, name) {
			problems = append(problems, fmt.Sprintf("the name %q is declared in the block but never occurs in the rest of the RUNBOOK text -- a dead entry", name))
		}
	}
	inBlock := map[string]bool{}
	for _, name := range all {
		inBlock[name] = true
	}
	var dictNames []string
	for name := range codeDict.Consts {
		dictNames = append(dictNames, name)
	}
	sort.Strings(dictNames)
	for _, name := range dictNames {
		if inBlock[name] {
			continue
		}
		if occursAsName(docWithout, name) {
			problems = append(problems, fmt.Sprintf("the event name %q occurs in the rest of the RUNBOOK text but is missing from the block", name))
		}
	}
	// Selftest check 7 runs ONLY when the sample asks for it
	// (checkSilent). The reason is not laziness: almost every sample
	// deliberately shrinks the block to one or two names to isolate the
	// rule under test, and in such a world declared silent events are
	// the norm, not a defect. Applying the "declared means written"
	// rule to them would demand of a sample what it was not built for,
	// and the red would be a false one. The absence of false positives
	// in the other direction is checked by the real run: in this
	// repository 19 constants out of 19 have a write site, and the gate
	// is green.
	if checkSilent {
		for _, name := range dictNames {
			if inBlock[name] {
				continue
			}
			if len(found[name]) == 0 {
				problems = append(problems, fmt.Sprintf("the EventType constant with value %q is written nowhere", name))
			}
		}
	}
	return strings.Join(problems, "; ")
}
