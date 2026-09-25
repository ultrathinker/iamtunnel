//go:build ignore

// check_errdict.go -- the error-code dictionary in PROTOCOL against the
// code (gate 14, IAMT-115).
//
// Why it exists. Gate 12 holds the event dictionary of PROTOCOL §1.7,
// gate 13 -- the event names in RUNBOOK. The error-code dictionary of
// PROTOCOL §6.1 was checked by no one, ever: the
// iamtunnel-error-codes-v1 block was added (cd0d4d5) long after the code
// had long lived its own life. And an error code is what somebody
// else's parser reads out of the error envelope: a document/code
// disagreement here breaks the integration silently, on both sides.
//
// THE MAIN DIFFICULTY is that the block holds TWO KINDS of codes, and
// telling them apart is the whole task:
//
//   - 22 wire codes go to the wire as literals ("E_EXEC_UNKNOWN" in
//     errf, "E_CONTROL_DOOR_LIMIT" in errorResponse,
//     "E_TARGET_CHANNEL_INVALID" in the reason of
//     SSH_MSG_CHANNEL_OPEN_FAILURE) and therefore MUST exist in the
//     product code as exact string literals;
//   - internal codes -- the classification of causes
//     ("E_SESSION_DENIED", "E_AUTH_RATE_LIMITED", ...): a literal in
//     the product code is allowed only with an explicit
//     // errdict:internal mark on the same line; internal codes that
//     cannot be produced must be explicitly documented in
//     allowedUnproducedInternal.
//
// The gate checks:
//
//  1. every wire code of the block exists in the code as an exact
//     string literal -- the document may not promise a wire code that
//     does not exist;
//     1b. every internal code of the block is either produced by the code
//     with a // errdict:internal mark, or documented in
//     allowedUnproducedInternal;
//  2. every code literal of the product code stands in the block as
//     wire (without a mark) or internal (with the mandatory
//     // errdict:internal mark);
//  3. the shape of the block: exactly one tagged block, a JSON object
//     with the "wire" and "internal" keys (mandatory) and an optional
//     "absent", no empty names and no repeats -- within a list or
//     across lists;
//  4. prose -> block: any E_ token occurring in PROTOCOL outside the
//     block must stand in the block (wire/internal/absent). Without
//     this the block could be silently shrunken to empty -- and the
//     gate would "agree" with anything. The fifth canary of 13.09
//     showed exactly this on gate 13;
//  5. block -> prose (a dead entry): every code of the block must
//     occur in the rest of the document text;
//  6. absent -- a machine-readable exception for codes the document
//     names as NON-existent ("E_DOOR_CLOSED is absent in v1"): an
//     absent code must NOT be a literal in the code (otherwise the
//     mark went stale and the code moves to wire). The exception lives
//     in the document and is checked, not in the checker's allowlist --
//     the invariant cannot be switched off by editing a single file.
//
// On the "prose -> block" mechanism. In gate 13 occursAsName searched
// for CONCRETE names known from the code (19 constants) -- the
// anti-shrink check worked off a known list. Here a shrunken block
// hides the names itself, and internal codes have no literals, so a
// list taken from the code does not exist. The prose scan is therefore
// a discovery scan by name convention: a greedy read of "E_" +
// [A-Z0-9_]+ with byte boundaries (before and after -- not
// [A-Za-z0-9_]). The byte-boundary principle is the same, the alphabet
// narrower: a dot and a hyphen are part of an event name but not of a
// code, so "E_FOO." at the end of a phrase is a clean E_FOO token, and
// "SEE_EXEC_UNKNOWN" is no token at all (a letter stands before E_).
// No regular expressions over the prose -- bytes only.
//
// -selftest runs the built-in samples with lures (JSON examples,
// door.status, enrol-hmac.key, THE_END, SEE_EXEC_UNKNOWN, test fixtures
// outside the scan) and must stay green; the gate runs the selftest
// BEFORE the real comparison, so that a broken detector does not pass
// silence off as agreement.
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
const fenceInfo = "iamtunnel-error-codes-v1"

// dictKeysRequired / dictKeysOptional -- the shape of the block: wire
// and internal are mandatory, absent is an optional machine-readable
// exception for codes named in the prose as non-existent. Any other
// key is an error, not silence: a typo in "internal" would otherwise
// turn 31 codes into nothing.
var dictKeysRequired = []string{"wire", "internal"}

const absentKey = "absent"

// ErrOccurrence describes one place where an error-code literal occurs
// in the code.
type ErrOccurrence struct {
	Location  string // file:line
	Annotated bool   // true when the line carries a // errdict:internal comment
}

// allowedUnproducedInternal lists the internal codes of the dictionary
// that the product code does not produce as string literals, each with
// an explicit reason.
var allowedUnproducedInternal = map[string]string{
	"E_AUTH_KEY_UNKNOWN":             "internal auth reason; connection rejected before state lookup completes without wire code",
	"E_AUTH_RATE_LIMITED":            "internal rate limiting classification; connection throttled/dropped without wire code",
	"E_CONTROL_EPOCH_STALE":          "internal control epoch comparison in state/channel; drops channel without error payload",
	"E_CONTROL_TIMEOUT":              "internal watchdog timeout for machine control channel",
	"E_CONTROL_ONLY":                 "internal session classifier; target channel refused when machine is in control-only state",
	"E_GATEWAY_FINGERPRINT_MISMATCH": "internal client-side verification of gateway host key fingerprint",
	"E_GRANT_EXPIRED":                "internal grant check; interactive human receives E_SESSION_DENIED or connection drop",
	"E_GRANT_MISSING":                "internal grant check; interactive human receives E_SESSION_DENIED",
	"E_MACHINE_HOSTKEY_MISMATCH":     "internal host key verification against state record; triggers rekey proposal",
	"E_MACHINE_NOT_VERIFIED":         "internal machine state classification; distinct from wire E_MACHINE_UNVERIFIED",
	"E_PERSON_KEY_MISMATCH":          "internal auth check in Resolve/VerifyLogin; person key does not match claimed person",
	"E_RECORDING_DISK_FULL":          "internal disk quota check (>95%) before opening session recording",
	"E_SESSION_DENIED":               "internal policy rejection returned to interactive client instead of specific reasons",
	"E_SESSION_LIMIT_MACHINE":        "internal concurrent session limiter per machine",
	"E_SESSION_LIMIT_PERSON":         "internal concurrent session limiter per person",
	"E_SESSION_SETUP_TIMEOUT":        "internal timeout during door open and target handshake phase",
	"E_TIMEOUT":                      "internal sync admin operation timeout classifier",
}

func verifyErrDict(dict errDict, docWithoutBlock string, literals map[string][]ErrOccurrence) []string {
	var problems []string

	// 1. wire -> literals: every wire code must be a literal in the
	// product code.
	for _, code := range dict.Wire {
		if len(literals[code]) == 0 {
			problems = append(problems, fmt.Sprintf("wire code %q from the block never appears as a literal in the product code (internal/, cmd/, non-test files) -- the document promises a wire code the code never sends", code))
		}
	}

	// 1b. The reverse check: every internal code must either be
	// produced by the code (with a // errdict:internal mark), or be
	// explicitly documented in allowedUnproducedInternal (129-2).
	for _, code := range dict.Internal {
		produced := len(literals[code]) > 0
		reason, inExceptions := allowedUnproducedInternal[code]
		if produced {
			if inExceptions {
				problems = append(problems, fmt.Sprintf("the unproduced exception for %q is stale: the code is already produced by the product code (%s)", code, reason))
			}
		} else {
			if !inExceptions {
				problems = append(problems, fmt.Sprintf("code %q from dict.Internal is not produced by the product code and is not listed in the exceptions -- an orphan code", code))
			}
		}
	}

	// 2. Literals -> the dictionary (wire, or internal with an
	// annotation) (129-1).
	inWire := map[string]bool{}
	for _, code := range dict.Wire {
		inWire[code] = true
	}
	inInternal := map[string]bool{}
	for _, code := range dict.Internal {
		inInternal[code] = true
	}

	var litNames []string
	for code := range literals {
		litNames = append(litNames, code)
	}
	sort.Strings(litNames)

	for _, code := range litNames {
		occs := literals[code]
		if inWire[code] {
			for _, o := range occs {
				if o.Annotated {
					problems = append(problems, fmt.Sprintf("code %q is a wire code but is wrongly marked // errdict:internal (%s)", code, o.Location))
				}
			}
			continue
		}
		if inInternal[code] {
			for _, o := range occs {
				if !o.Annotated {
					problems = append(problems, fmt.Sprintf("code %q is an internal code but sits as a literal in the product code without the mandatory // errdict:internal mark (%s)", code, o.Location))
				}
			}
			continue
		}
		// The code is in neither wire nor internal:
		for _, o := range occs {
			if o.Annotated {
				problems = append(problems, fmt.Sprintf("code %q is marked // errdict:internal but is missing from the internal list of the dictionary (%s)", code, o.Location))
			} else {
				problems = append(problems, fmt.Sprintf("code %q leaves the product code as a literal (%s), and in the block it is not marked wire or internal", code, o.Location))
			}
		}
	}

	// 4. Prose -> block: the block must not shrink silently.
	inBlock := map[string]bool{}
	for _, code := range append(append(append([]string{}, dict.Wire...), dict.Internal...), dict.Absent...) {
		inBlock[code] = true
	}
	proseCodes := scanErrTokens(docWithoutBlock)
	var proseNames []string
	for code := range proseCodes {
		proseNames = append(proseNames, code)
	}
	sort.Strings(proseNames)
	for _, code := range proseNames {
		if !inBlock[code] {
			problems = append(problems, fmt.Sprintf("code %q is named in the PROTOCOL prose but is missing from the block -- the block must not shrink silently: every error code named by the document must stand in \"wire\", \"internal\" or \"%s\"", code, absentKey))
		}
	}

	// 5. Block -> prose (a dead entry): every code of the block must
	// occur in the rest of the PROTOCOL text.
	for _, code := range append(append(append([]string{}, dict.Wire...), dict.Internal...), dict.Absent...) {
		if !occursAsCode(docWithoutBlock, code) {
			problems = append(problems, fmt.Sprintf("code %q stands in the block but never occurs in the rest of the PROTOCOL text -- a dead entry", code))
		}
	}

	// 6. absent must remain true: there must be no literal of the code.
	for _, code := range dict.Absent {
		if occs := literals[code]; len(occs) > 0 {
			var locs []string
			for _, o := range occs {
				locs = append(locs, o.Location)
			}
			problems = append(problems, fmt.Sprintf("code %q is marked %s, yet the code already sends it as a literal (%s) -- move it to \"wire\"", code, absentKey, strings.Join(locs, ", ")))
		}
	}

	return problems
}

func main() {
	selftest := flag.Bool("selftest", false, "run the built-in samples and exit")
	docPath := flag.String("doc", "docs/PROTOCOL.md", "path to the protocol document")
	root := flag.String("root", ".", "repository root: literals are searched in <root>/internal and <root>/cmd")
	flag.Parse()

	if *selftest {
		if err := runSelftest(); err != nil {
			fmt.Fprintf(os.Stderr, "check_errdict: selftest failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("selftest: every sample parsed correctly")
		return
	}

	dict, docWithoutBlock, err := readErrDict(*docPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_errdict: %s: %v\n", *docPath, err)
		os.Exit(2)
	}
	literals, err := scanErrLiterals(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_errdict: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("codes in %s: %d wire, %d internal, %d absent\n",
		*docPath, len(dict.Wire), len(dict.Internal), len(dict.Absent))
	fmt.Printf("E_* literals in non-test internal/ or cmd/: %d\n", len(literals))

	problems := verifyErrDict(dict, docWithoutBlock, literals)
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Printf("  ! %s\n", p)
		}
		fmt.Printf("the error-code dictionary of the document and the code disagree in %d way(s)\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("every wire code is a real literal, every literal is marked wire, and the prose names no code outside the block")
}

// ---------------------------------------------------------------- document

// errDict -- the contents of the tagged block.
type errDict struct {
	Wire     []string
	Internal []string
	Absent   []string
}

// readErrDict extracts the single tagged block and checks its shape,
// returning it together with the document text without the block (for
// the "prose -> block" and "block -> prose" checks). The uniqueness
// requirement is not pedantry: two blocks mean two dictionaries, and
// there would be nothing to compare.
func readErrDict(path string) (errDict, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return errDict{}, "", err
	}
	src := string(raw)
	blocks := taggedBlocks(src)
	switch len(blocks) {
	case 1:
		// the normal case
	case 0:
		return errDict{}, "", fmt.Errorf("no ```%s block: the error-code dictionary must be machine-readable, otherwise there is nothing to compare", fenceInfo)
	default:
		return errDict{}, "", fmt.Errorf("there must be exactly one ```%s block, found %d", fenceInfo, len(blocks))
	}

	// Keys are checked before the values are parsed: json.Unmarshal
	// silently ignores unknown fields, and a key typo must be an
	// error, not silence.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(blocks[0]), &keys); err != nil {
		return errDict{}, "", fmt.Errorf("the ```%s block is not a JSON object {\"wire\":[…],\"internal\":[…]}: %v", fenceInfo, err)
	}
	allowed := map[string]bool{absentKey: true}
	for _, k := range dictKeysRequired {
		allowed[k] = true
	}
	for k := range keys {
		if !allowed[k] {
			return errDict{}, "", fmt.Errorf("the ```%s block contains an unknown key %q -- exactly %q, %q and the optional %q are allowed", fenceInfo, k, "wire", "internal", absentKey)
		}
	}
	for _, k := range dictKeysRequired {
		if _, ok := keys[k]; !ok {
			return errDict{}, "", fmt.Errorf("the ```%s block has no %q key", fenceInfo, k)
		}
	}

	var parsed struct {
		Wire     []string `json:"wire"`
		Internal []string `json:"internal"`
		Absent   []string `json:"absent"`
	}
	if err := json.Unmarshal([]byte(blocks[0]), &parsed); err != nil {
		return errDict{}, "", fmt.Errorf("the ```%s block does not parse: %v", fenceInfo, err)
	}
	d := errDict{Wire: parsed.Wire, Internal: parsed.Internal, Absent: parsed.Absent}

	// Empty names and duplicates -- within a list and across lists.
	// The list of occurrences is printed in full: "wire, wire" is a
	// duplicate within one list, "wire, internal" is a code declared
	// as both kinds at once.
	seen := map[string][]string{}
	for _, list := range []struct {
		name  string
		codes []string
	}{
		{"wire", d.Wire}, {"internal", d.Internal}, {absentKey, d.Absent},
	} {
		for _, code := range list.codes {
			if strings.TrimSpace(code) == "" {
				return errDict{}, "", fmt.Errorf("the ```%s block has an empty code", fenceInfo)
			}
			seen[code] = append(seen[code], list.name)
		}
	}
	for code, lists := range seen {
		if len(lists) > 1 {
			return errDict{}, "", fmt.Errorf("code %q repeats in the block (lists: %s)", code, strings.Join(lists, ", "))
		}
	}

	return d, strings.Replace(src, blocks[0], "", 1), nil
}

// taggedBlocks is a line-by-line fence scan, the same one as in gates
// 12 and 13: the function sees nothing outside the tagged blocks, and
// that is its main property.
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

// -------------------------------------------------------------------- code

// scanErrLiterals walks <root>/internal and <root>/cmd (non-test .go)
// and collects string literals matching the error-code convention:
// "E_" followed by [A-Z0-9_] only. It returns a map of code -> list of
// "file:line" locations. Tests and scripts/ itself are not scanned:
// test fixtures and checker samples are not product code, and the
// count of "all E_ strings in the repo" has already mistaken them for
// it twice these days.
func scanErrLiterals(root string) (map[string][]ErrOccurrence, error) {
	literals := map[string][]ErrOccurrence{}
	for _, dir := range []string{filepath.Join(root, "internal"), filepath.Join(root, "cmd")} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil // no such directory -- not an error
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			lines := strings.Split(string(src), "\n")
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, src, 0)
			if perr != nil {
				return fmt.Errorf("%s: does not parse as Go: %w", path, perr)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || !isErrCode(v) {
					return true
				}
				lineNum := fset.Position(lit.Pos()).Line
				annotated := false
				if lineNum >= 1 && lineNum <= len(lines) {
					annotated = strings.Contains(lines[lineNum-1], "// errdict:internal")
				}
				loc := fmt.Sprintf("%s:%d", filepath.ToSlash(path), lineNum)
				literals[v] = append(literals[v], ErrOccurrence{Location: loc, Annotated: annotated})
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for code := range literals {
		sort.Slice(literals[code], func(i, j int) bool {
			return literals[code][i].Location < literals[code][j].Location
		})
	}
	return literals, nil
}

// isErrCode is a byte check of the convention: "E_" plus only
// [A-Z0-9_]. There are deliberately no regular expressions here -- for
// the same reasons as in gates 12/13: the convention is simple, and an
// explicit loop reads and checks more easily than any pattern.
func isErrCode(s string) bool {
	if len(s) < 3 || s[0] != 'E' || s[1] != '_' {
		return false
	}
	for i := 2; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		default:
			return false
		}
	}
	return true
}

// scanErrTokens is a discovery scan of the prose (the document without
// the block) for code tokens by convention: a greedy read of "E_" +
// [A-Z0-9_]+ with clean byte boundaries. It is the same byte-boundary
// principle as gate 13's occursAsName, but the direction is opposite:
// there KNOWN concrete names were searched for, here names UNKNOWN in
// advance are read -- otherwise a shrunken block would hide the names
// from the gate itself. A dot and a hyphen stop the token (they are
// not part of a code), so "E_FOO." at the end of a phrase yields a
// clean E_FOO; a lowercase letter after the prefix swallows the
// occurrence whole ("E_FOObar" is not a token), and a letter before E_
// kills the start ("SEE_EXEC_UNKNOWN" does not contain the
// E_EXEC_UNKNOWN token).
func scanErrTokens(doc string) map[string]bool {
	tokens := map[string]bool{}
	for i := 0; i+1 < len(doc); i++ {
		if doc[i] != 'E' || doc[i+1] != '_' {
			continue
		}
		if i > 0 && isCodeNameByte(doc[i-1]) {
			continue
		}
		j := i + 2
		for j < len(doc) && isCodeNameByte(doc[j]) {
			j++
		}
		// The greedy scan stopped at a non-name byte -- no need to
		// check it: the loop would not have taken it anyway. The token
		// is valid if at least one convention character follows E_.
		if j > i+2 {
			tokens[doc[i:j]] = true
		}
		i = j - 1
	}
	return tokens
}

// occursAsCode is an exact occurrence of a code in the text with clean
// byte boundaries; the "block -> prose" check uses it.
func occursAsCode(doc, code string) bool {
	from := 0
	for {
		i := strings.Index(doc[from:], code)
		if i < 0 {
			return false
		}
		at := from + i
		after := at + len(code)
		if (at == 0 || !isCodeNameByte(doc[at-1])) && (after >= len(doc) || !isCodeNameByte(doc[after])) {
			return true
		}
		from = at + 1
	}
}

// isCodeNameByte is a byte that may continue a code: a letter, a digit
// or an underscore. A dot and a hyphen may not.
func isCodeNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		return true
	}
	return false
}

// ------------------------------------------------------------ selftest

// runSelftest runs the built-in samples. The gate runs it BEFORE the
// real comparison: a detector that finds nothing is otherwise
// indistinguishable from an absence of disagreements.
func runSelftest() error {
	// A sample of product code: two real code literals and junk that
	// does not satisfy the convention and must not enter the sample.
	goodCode := map[string]string{
		"internal/gateway/admin_role.go": `package gateway
func replies() {
	_ = errf("E_EXEC_UNKNOWN", 2, "unknown command")
	_ = errf("E_JSON_INVALID", 3, "bad json")
	_ = "not a code: exec-unknown without the E_ form"
	_ = "E_LOWER_case -- lowercase after the prefix is not a code by the convention"
}
`,
	}

	// THE MAIN DOCUMENT SAMPLE. Next to the correct block there are
	// lures: a JSON example with a code (a real mention), door.status,
	// enrol-hmac.key, THE_END and SEE_EXEC_UNKNOWN (the last two
	// contain no token: letters before E_ and inside swallow the
	// start).
	goodDoc := "# Protocol\n" +
		"\n" +
		"An unknown command yields E_EXEC_UNKNOWN, junk -- E_JSON_INVALID,\n" +
		"a timeout is classified as E_TIMEOUT, and E_DOOR_CLOSED does not exist in v1.\n" +
		"An example envelope: {\"error\":{\"code\":\"E_JSON_INVALID\"}}.\n" +
		"The door.status operation and the enrol-hmac.key key are not codes; THE_END and\n" +
		"SEE_EXEC_UNKNOWN must not enter the sample either.\n" +
		"\n" +
		"```" + fenceInfo + "\n" +
		"{\"wire\":[\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"],\"internal\":[\"E_TIMEOUT\"],\"absent\":[\"E_DOOR_CLOSED\"]}\n" +
		"```\n"

	type sample struct {
		name    string
		doc     string
		code    map[string]string
		wantErr string // a substring; empty -- the sample must be consistent
	}
	block := func(wire, internal, absent string) string {
		return "```" + fenceInfo + "\n{\"wire\":[" + wire + "],\"internal\":[" + internal + "],\"absent\":[" + absent + "]}\n```\n"
	}
	samples := []sample{
		{
			name: "lures (JSON example, door.status, THE_END, SEE_EXEC_UNKNOWN) are not taken for codes",
			doc:  goodDoc,
			code: goodCode,
		},
		{
			name:    "orphan code E_NAME_RESERVED is named in prose and dictionary but not produced by the code",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_NAME_RESERVED\",\"E_TIMEOUT\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_NAME_RESERVED means a failure, and E_TIMEOUT means a timeout.",
			code:    goodCode,
			wantErr: "an orphan code",
		},
		{
			name: "a producible internal code E_TIMEOUT with a stale exception -- a failure",
			doc:  block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT.",
			code: map[string]string{
				"internal/gateway/admin_role.go": `package gateway
func f() {
	_ = errf("E_EXEC_UNKNOWN", 2, "unknown")
	_ = errf("E_JSON_INVALID", 3, "bad")
	_ = "E_TIMEOUT" // errdict:internal
}
`,
			},
			wantErr: "is stale",
		},
		{
			name: "an unmarked internal literal in the code -- a failure",
			doc:  block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\",\"E_NAME_RESERVED\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT, E_NAME_RESERVED.",
			code: map[string]string{
				"internal/gateway/admin_role.go": `package gateway
func f() {
	_ = errf("E_EXEC_UNKNOWN", 2, "unknown")
	_ = errf("E_JSON_INVALID", 3, "bad")
	_ = "E_NAME_RESERVED"
}
`,
			},
			wantErr: "without the mandatory // errdict:internal mark",
		},
		{
			name: "a literal marked // errdict:internal is missing from the internal list -- a failure",
			doc:  block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT.",
			code: map[string]string{
				"internal/gateway/admin_role.go": `package gateway
func f() {
	_ = errf("E_EXEC_UNKNOWN", 2, "unknown")
	_ = errf("E_JSON_INVALID", 3, "bad")
	_ = "E_UNKNOWN_CODE" // errdict:internal
}
`,
			},
			wantErr: "missing from the internal list of the dictionary",
		},
		{
			name: "an internal literal marked in the dictionary -- success",
			doc:  block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\",\"E_NAME_RESERVED\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT, E_NAME_RESERVED.",
			code: map[string]string{
				"internal/gateway/admin_role.go": `package gateway
func f() {
	_ = errf("E_EXEC_UNKNOWN", 2, "unknown")
	_ = errf("E_JSON_INVALID", 3, "bad")
	_ = "E_NAME_RESERVED" // errdict:internal
}
`,
			},
			wantErr: "",
		},
		{
			name:    "a wire code without a literal in the code",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\",\"E_CAP_UNSUPPORTED\"", "\"E_TIMEOUT\"", "\"E_DOOR_CLOSED\"") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_CAP_UNSUPPORTED, E_TIMEOUT, E_DOOR_CLOSED.",
			code:    goodCode,
			wantErr: "never appears as a literal",
		},
		{
			name:    "a code literal is not marked wire (the block was shrunken)",
			doc:     block("\"E_EXEC_UNKNOWN\"", "\"E_TIMEOUT\"", "\"E_DOOR_CLOSED\"") + "Prose: E_EXEC_UNKNOWN, E_TIMEOUT, E_DOOR_CLOSED, E_JSON_INVALID.",
			code:    goodCode,
			wantErr: "not marked wire",
		},
		{
			name:    "a code is named in prose but is not in the block -- the block was silently shrunken",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\"", "") + "The prose names E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT and E_SESSION_LIMIT_PERSON.",
			code:    goodCode,
			wantErr: "missing from the block",
		},
		{
			name:    "a duplicate inside a list",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT.",
			code:    goodCode,
			wantErr: "repeats in the block",
		},
		{
			name:    "a code is declared both wire and internal",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\",\"E_TIMEOUT\"", "\"E_TIMEOUT\"", "") + "Prose: E_EXEC_UNKNOWN, E_JSON_INVALID, E_TIMEOUT.",
			code:    goodCode,
			wantErr: "repeats in the block",
		},
		{
			name:    "an absent code became a literal -- the mark is stale",
			doc:     block("\"E_EXEC_UNKNOWN\"", "\"E_TIMEOUT\"", "\"E_JSON_INVALID\"") + "Prose: E_EXEC_UNKNOWN, E_TIMEOUT, E_JSON_INVALID.",
			code:    goodCode,
			wantErr: "is marked absent",
		},
		{
			name:    "a dead entry: the code is in the block but not in the prose",
			doc:     block("\"E_EXEC_UNKNOWN\",\"E_JSON_INVALID\"", "\"E_TIMEOUT\",\"E_CONFLICT\"", "") + "Prose: only E_EXEC_UNKNOWN and E_TIMEOUT.",
			code:    goodCode,
			wantErr: "a dead entry",
		},
		{
			name:    "no block at all",
			doc:     "# Protocol\n\nThe codes are listed in words: E_EXEC_UNKNOWN and so on.\n",
			code:    goodCode,
			wantErr: "no ```",
		},
		{
			name:    "two blocks",
			doc:     block("\"E_EXEC_UNKNOWN\"", "\"E_TIMEOUT\"", "") + block("\"E_JSON_INVALID\"", "\"E_CONFLICT\"", "") + "Prose: E_EXEC_UNKNOWN, E_TIMEOUT, E_JSON_INVALID, E_CONFLICT.",
			code:    goodCode,
			wantErr: "exactly one",
		},
		{
			name:    "the block is not a JSON object (an array)",
			doc:     "```" + fenceInfo + "\n[\"E_EXEC_UNKNOWN\"]\n```\nProse: E_EXEC_UNKNOWN.",
			code:    goodCode,
			wantErr: "is not a JSON object",
		},
		{
			name:    "an unknown key in the block",
			doc:     "```" + fenceInfo + "\n{\"wire\":[\"E_EXEC_UNKNOWN\"],\"internal\":[\"E_TIMEOUT\"],\"onTheWire\":[\"E_JSON_INVALID\"]}\n```\nProse: E_EXEC_UNKNOWN, E_TIMEOUT, E_JSON_INVALID.",
			code:    goodCode,
			wantErr: "an unknown key",
		},
		{
			name:    "the mandatory internal key is missing",
			doc:     "```" + fenceInfo + "\n{\"wire\":[\"E_EXEC_UNKNOWN\"]}\n```\nProse: E_EXEC_UNKNOWN, E_TIMEOUT.",
			code:    goodCode,
			wantErr: "has no",
		},
		{
			// A bare substring lure: the prose scan must read the
			// token greedily with boundaries, otherwise
			// SEE_EXEC_UNKNOWN would demand E_EXEC_UNKNOWN in the
			// block and the sample would go red.
			name: "SEE_EXEC_UNKNOWN does not demand E_EXEC_UNKNOWN in the block",
			doc: block("\"E_JSON_INVALID\"", "\"E_TIMEOUT\"", "") +
				"Prose: E_JSON_INVALID and E_TIMEOUT; the phrase SEE_EXEC_UNKNOWN is a lure.",
			code: map[string]string{
				"internal/gateway/admin_role.go": `package gateway
func f() { _ = errf("E_JSON_INVALID", 3, "bad json") }
`,
			},
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
// string. It works on strings -- like the selftests of gates 12 and 13
// -- but the code is supplied as a file->text map, so that one sample
// can hold real literals and junk side by side.
func checkSample(doc string, code map[string]string) string {
	tmp, err := os.CreateTemp("", "errdict-*.md")
	if err != nil {
		return "could not create a temporary file: " + err.Error()
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(doc); err != nil {
		return "could not write the temporary file: " + err.Error()
	}
	tmp.Close()

	dict, docWithout, derr := readErrDict(tmp.Name())
	if derr != nil {
		return derr.Error()
	}

	literals := map[string][]ErrOccurrence{}
	names := make([]string, 0, len(code))
	for n := range code {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		src := code[n]
		lines := strings.Split(src, "\n")
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, n, src, 0)
		if perr != nil {
			return perr.Error()
		}
		ast.Inspect(f, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || !isErrCode(v) {
				return true
			}
			lineNum := fset.Position(lit.Pos()).Line
			annotated := false
			if lineNum >= 1 && lineNum <= len(lines) {
				annotated = strings.Contains(lines[lineNum-1], "// errdict:internal")
			}
			loc := fmt.Sprintf("%s:%d", n, lineNum)
			literals[v] = append(literals[v], ErrOccurrence{Location: loc, Annotated: annotated})
			return true
		})
	}

	problems := verifyErrDict(dict, docWithout, literals)
	return strings.Join(problems, "; ")
}
