//go:build ignore

// check_eventdict.go -- the event dictionary in the document and in
// the code (gate 12).
//
// Why it exists. In a single night of 12-13.09 the documents and the
// code diverged in four different ways (IAMT-95, 99, 100, 104), and no
// run noticed any of them. The worst case was measured: PROTOCOL §1.7
// held thirty-nine event names, the code held nineteen, three matched.
// The events.jsonl journal is the proof of who came in and why they
// were refused; its list of allowed names is an interface, not a
// decoration.
//
// THE MAIN DIFFICULTY, AND IT IS NOT THE SET COMPARISON. An event and
// an operation are written the same way. `door.open` is both a journal
// event type and the value of the `op` field in a control message.
// `idleDeadline` is a field in both state.json and the wire object of
// the door, and in §4.3 it was false while in §5.2 it was true. A
// naive grep over "a word with a dot" already gave a false conclusion
// THREE times in one day, and once it would have blessed an error
// while throwing away the truth. Therefore there is not a single
// regular expression over the document text here, and not a single one
// over the code text:
//
//   - exactly ONE tagged fenced block with the info-string
//     iamtunnel-event-types-v1 is taken from the document, and only
//     it. Everything else in PROTOCOL.md -- prose, examples, JSON
//     messages -- is not read at all;
//   - a Go AST is taken from the code: string constants with the
//     EXPLICIT EventType type and the identifiers in the switch
//     branches of IsValidEventType. No comments, no strings in other
//     files, no payloads take part.
//
// The gate checks three things, not one:
//
//  1. the set of names in the document matches the set of EventType
//     constants;
//  2. every EventType constant is allowed in IsValidEventType, and
//     the other way around. This catches a constant that was declared
//     and forgotten to be allowed: such an event can never be
//     written, and the failure is a silent one;
//  3. the block holds no duplicates and no empty names.
//
// -selftest runs the built-in samples, including a document where
// `"op": "door.open"` and `people.add` sit next to the correct block.
// It must stay green: that is the very proof that operations do not
// enter the sample. The gate runs the selftest BEFORE the real
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
	"sort"
	"strconv"
	"strings"
)

// fenceInfo -- the info-string of the tagged block. Only blocks with
// this info-string are read.
const fenceInfo = "iamtunnel-event-types-v1"

// eventTypeName is the name of the type an event constant must be
// declared with. A constant without an explicit type deliberately does
// not enter the sample: without the type it is just a string, and its
// membership in the dictionary is unprovable.
const eventTypeName = "EventType"

// validatorName is the function whose switch branches count as
// allowing.
const validatorName = "IsValidEventType"

func main() {
	selftest := flag.Bool("selftest", false, "run the built-in samples and exit")
	protoPath := flag.String("proto", "docs/PROTOCOL.md", "path to the protocol document")
	codePath := flag.String("code", "internal/gateway/events/event.go", "path to the event constants file")
	flag.Parse()

	if *selftest {
		if err := runSelftest(); err != nil {
			fmt.Fprintf(os.Stderr, "check_eventdict: selftest failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("selftest: every sample parsed correctly")
		return
	}

	docNames, err := readDocDictionary(*protoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_eventdict: %s: %v\n", *protoPath, err)
		os.Exit(2)
	}
	consts, allowed, err := readCodeDictionary(*codePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_eventdict: %s: %v\n", *codePath, err)
		os.Exit(2)
	}

	fmt.Printf("event types in %s: %d\n", *protoPath, len(docNames))
	fmt.Printf("event types in %s: %d, allowed by %s: %d\n", *codePath, len(consts), validatorName, len(allowed))

	bad := 0

	// 1. The document against the declared constants.
	onlyDoc := difference(docNames, keys(consts))
	onlyCode := difference(keys(consts), docNames)
	if len(onlyDoc) > 0 {
		bad++
		fmt.Printf("  ! %d name(s) in the document with no EventType constant:\n", len(onlyDoc))
		for _, n := range onlyDoc {
			fmt.Printf("      %s\n", n)
		}
	}
	if len(onlyCode) > 0 {
		bad++
		fmt.Printf("  ! %d EventType constant(s) missing from the document:\n", len(onlyCode))
		for _, n := range onlyCode {
			fmt.Printf("      %s (%s)\n", n, consts[n])
		}
	}

	// 2. A declared but not allowed constant -- an event that can
	//    never be written. And the other way: an allowance without a
	//    constant.
	declaredNotAllowed := difference(keys(consts), keys(allowed))
	allowedNotDeclared := difference(keys(allowed), keys(consts))
	if len(declaredNotAllowed) > 0 {
		bad++
		fmt.Printf("  ! %d EventType constant(s) declared but not allowed by %s:\n", len(declaredNotAllowed), validatorName)
		for _, n := range declaredNotAllowed {
			fmt.Printf("      %s (%s) — such an event can never be written\n", n, consts[n])
		}
	}
	if len(allowedNotDeclared) > 0 {
		bad++
		fmt.Printf("  ! %d name(s) allowed by %s with no matching constant:\n", len(allowedNotDeclared), validatorName)
		for _, n := range allowedNotDeclared {
			fmt.Printf("      %s\n", n)
		}
	}

	if bad > 0 {
		fmt.Printf("the event dictionary of the document and the code disagree in %d way(s)\n", bad)
		os.Exit(1)
	}
	fmt.Println("the document and the code agree on every event type")
}

// ---------------------------------------------------------------- document

// readDocDictionary extracts the names from the single tagged block.
//
// The uniqueness requirement is not pedantry: two blocks mean two
// dictionaries, and there is nothing to compare. A missing block is a
// failure too, not "nothing to check": otherwise deleting the block is
// enough to silence the gate.
func readDocDictionary(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blocks := taggedBlocks(string(raw))
	switch len(blocks) {
	case 1:
		// the normal case
	case 0:
		return nil, fmt.Errorf("no ```%s block: the event dictionary must be machine-readable, otherwise there is nothing to compare", fenceInfo)
	default:
		return nil, fmt.Errorf("there must be exactly one ```%s block, found %d", fenceInfo, len(blocks))
	}

	var names []string
	if err := json.Unmarshal([]byte(blocks[0]), &names); err != nil {
		return nil, fmt.Errorf("the ```%s block is not JSON (want an array of strings): %v", fenceInfo, err)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			return nil, fmt.Errorf("the ```%s block has an empty name", fenceInfo)
		}
		if seen[n] {
			return nil, fmt.Errorf("name %q repeats in the ```%s block", fenceInfo, n)
		}
		seen[n] = true
	}
	sort.Strings(names)
	return names, nil
}

// taggedBlocks returns the contents of all blocks with the needed
// info-string.
//
// The scan is line-by-line and deliberately dumb: a fenced block in
// Markdown opens with a line of three or more backticks and closes
// with a line of the same or a greater number of them. The function
// sees no text outside the blocks, and that is its main property.
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
		// Find the closing fence of the same or greater length.
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

// fenceOf returns the fence length and the info-string, or 0 if it is
// not a fence.
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

// -------------------------------------------------------------------- code

// readCodeDictionary parses the constants file through the AST and
// returns two maps: value -> constant name for the declared ones, and
// value -> name for the ones the validator allows.
func readCodeDictionary(path string) (consts, allowed map[string]string, err error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return parseCodeDictionary(path, src)
}

func parseCodeDictionary(name string, src []byte) (map[string]string, map[string]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, nil, err
	}

	consts := map[string]string{}  // "door.open" -> "EventDoorOpen"
	byIdent := map[string]string{} // "EventDoorOpen" -> "door.open"

	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Only the explicit EventType type. A constant without a
			// type is just a string; its membership in the
			// dictionary is unprovable.
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
					return nil, nil, fmt.Errorf("constant %s of type %s is not given as a string literal", n.Name, eventTypeName)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, nil, fmt.Errorf("constant %s: %v", n.Name, err)
				}
				if prev, dup := consts[v]; dup {
					return nil, nil, fmt.Errorf("value %q is declared twice: %s and %s", v, prev, n.Name)
				}
				consts[v] = n.Name
				byIdent[n.Name] = v
			}
		}
	}

	allowed := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != validatorName {
			return true
		}
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			cc, ok := m.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				id, ok := e.(*ast.Ident)
				if !ok {
					continue
				}
				if v, known := byIdent[id.Name]; known {
					allowed[v] = id.Name
				} else {
					allowed["?"+id.Name] = id.Name
				}
			}
			return true
		})
		return false
	})

	return consts, allowed, nil
}

// ------------------------------------------------------------- comparison

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func difference(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------------------ selftest

// runSelftest runs the built-in samples. The gate runs it BEFORE the
// real comparison: a detector that finds nothing is otherwise
// indistinguishable from an absence of disagreements.
func runSelftest() error {
	// A code sample: two constants, both allowed.
	goodCode := `package events
type EventType string
const (
	EventDoorOpen EventType = "door.open"
	EventAuthSuccess EventType = "auth.success"
)
func IsValidEventType(t EventType) bool {
	switch t {
	case EventDoorOpen, EventAuthSuccess:
		return true
	default:
		return false
	}
}`

	// THE MAIN SAMPLE. Next to the correct block sit the name of a
	// control-channel operation and the name of an admin command -- in
	// the prose, in a JSON example and even inside a neighbouring block
	// with a different info-string. None of them may enter the sample.
	docWithDecoys := "# Protocol\n" +
		"\n" +
		"The `door.open` operation opens the door, `people.add` registers a person.\n" +
		"\n" +
		"```json\n" +
		"{\"proto\":1,\"op\":\"door.open\",\"id\":\"...\"}\n" +
		"{\"op\":\"people.add\"}\n" +
		"```\n" +
		"\n" +
		"### 1.7 Event dictionary\n" +
		"\n" +
		"```" + fenceInfo + "\n" +
		"[\"auth.success\",\"door.open\"]\n" +
		"```\n" +
		"\n" +
		"The `session.denied` event from the old revision is no longer listed here.\n"

	type sample struct {
		name    string
		doc     string
		code    string
		wantErr string // a substring; empty -- the sample must be consistent
	}

	samples := []sample{
		{
			name: "decoys next to the block do not enter the sample",
			doc:  docWithDecoys,
			code: goodCode,
		},
		{
			name:    "the name is in the document and not in the code",
			doc:     "```" + fenceInfo + "\n[\"auth.success\",\"door.open\",\"door.sanitized\"]\n```\n",
			code:    goodCode,
			wantErr: "door.sanitized",
		},
		{
			name: "the constant is in the code and not in the document",
			doc:  "```" + fenceInfo + "\n[\"auth.success\"]\n```\n",
			code: goodCode, wantErr: "door.open",
		},
		{
			name: "the constant is declared but not allowed by the validator",
			doc:  "```" + fenceInfo + "\n[\"auth.success\",\"door.open\"]\n```\n",
			code: `package events
type EventType string
const (
	EventDoorOpen EventType = "door.open"
	EventAuthSuccess EventType = "auth.success"
)
func IsValidEventType(t EventType) bool {
	switch t {
	case EventAuthSuccess:
		return true
	default:
		return false
	}
}`,
			wantErr: "declared but not allowed",
		},
		{
			name:    "no block at all",
			doc:     "# Protocol\n\nThe event dictionary is described in words.\n",
			code:    goodCode,
			wantErr: "no ```",
		},
		{
			name:    "two blocks",
			doc:     "```" + fenceInfo + "\n[\"door.open\"]\n```\n\n```" + fenceInfo + "\n[\"auth.success\"]\n```\n",
			code:    goodCode,
			wantErr: "exactly one",
		},
		{
			name:    "a name repeats in the block",
			doc:     "```" + fenceInfo + "\n[\"door.open\",\"door.open\",\"auth.success\"]\n```\n",
			code:    goodCode,
			wantErr: "repeats",
		},
		{
			name:    "the block is not JSON",
			doc:     "```" + fenceInfo + "\ndoor.open, auth.success\n```\n",
			code:    goodCode,
			wantErr: "is not JSON",
		},
	}

	for _, s := range samples {
		got := checkSample(s.doc, s.code)
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
// string.
func checkSample(doc, code string) string {
	tmp, err := os.CreateTemp("", "eventdict-*.md")
	if err != nil {
		return "could not create a temporary file: " + err.Error()
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(doc); err != nil {
		return "could not write the temporary file: " + err.Error()
	}
	tmp.Close()

	names, err := readDocDictionary(tmp.Name())
	if err != nil {
		return err.Error()
	}
	consts, allowed, err := parseCodeDictionary("sample.go", []byte(code))
	if err != nil {
		return err.Error()
	}

	var problems []string
	if d := difference(names, keys(consts)); len(d) > 0 {
		problems = append(problems, "in the document only: "+strings.Join(d, ", "))
	}
	if d := difference(keys(consts), names); len(d) > 0 {
		problems = append(problems, "in the code only: "+strings.Join(d, ", "))
	}
	if d := difference(keys(consts), keys(allowed)); len(d) > 0 {
		problems = append(problems, "declared but not allowed: "+strings.Join(d, ", "))
	}
	if d := difference(keys(allowed), keys(consts)); len(d) > 0 {
		problems = append(problems, "allowed but not declared: "+strings.Join(d, ", "))
	}
	return strings.Join(problems, "; ")
}
