//go:build ignore

// check_commands.go — a cross-check of the command lists of the client,
// the CLI and the gateway (gate 15, IAMT-154).
//
// Why it exists. Within one day, 12-13.09, the project stumbled three
// times over the same class of defects:
//  1. machines.rekey was declared by both sides except the executing one;
//  2. machines.mine was implemented by the client but missing from the
//     gateway's table (IAMT-137);
//  3. E_NAME_RESERVED was present in the refusal-code dictionary but
//     produced by nobody (IAMT-129).
//
// The class of defect: one side promises, the other does not execute,
// and nobody notices. The event dictionary has gates 12 and 13, the
// refusal-code dictionary has gate 14. The gateway's and the client's
// commands had no watchdog at all.
//
// The gate performs a TWO-SIDED cross-check of the three sources of
// truth:
//  1. The client library (internal/admin, internal/client): what the
//     code can send (calls of c.Exec(...) and execCommand(...));
//  2. The CLI help (cmd/iamtunnel/usage.go: the adminHelp and clientHelp
//     constants): what the interface promises a person;
//  3. The gateway command table (internal/gateway/admin_role.go:
//     commandTable): what is actually executed.
//
// A promised but unexecutable command is a defect.
// An executable command nobody calls is a defect (dead code).
//
// Legitimate exceptions (commands reserved for the future or with a
// special transport) are pinned down explicitly in the gate's code with
// a documented justification. If an exception goes stale (the command
// becomes supported), the gate demands the stale exception be removed.
//
// The project rule: the gate has its own selftest (-selftest) on planted
// samples, and it runs BEFORE the real cross-check, so that a broken
// detector cannot produce a false green.
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

// AllowedException describes a legitimate divergence between sources.
type AllowedException struct {
	Command string
	Reason  string
}

// Documented legitimate exceptions of the current build:
//
// 1. "whoami":
//    The version-preflight service command (PROTOCOL §1.2). It is run
//    automatically by the client library and the gateway before the
//    first application command, but it is not a separate CLI verb in
//    the usage.go help.
//
// 2. "admin.claim":
//    The primary admin claim command (PROTOCOL §3.3, §6). It is sent
//    through the special bootstrap-login and handled by the bootstrap
//    role, not by the admin role's commandTable.
//
// 3. "admin.pair":
//    The PIN pairing command (PROTOCOL §3.4, IAMT-323). It is sent
//    through the special pairing-login and handled by the pairing role
//    (internal/gateway/pairing_role.go), not by the admin role's
//    commandTable -- the same transport as admin.claim on the bootstrap
//    role.

var allowedClientNotGateway = map[string]string{
	"admin.claim": "bootstrap-login command (PROTOCOL §3.3); handled by bootstrap role, not admin commandTable",
	"admin.pair":  "pairing-login command (PROTOCOL §3.4); handled by pairing role, not admin commandTable",
}

var allowedUsageNotGateway = map[string]string{
	"admin.claim": "bootstrap-login command (PROTOCOL §3.3); handled by bootstrap role, not admin commandTable",
	"admin.pair":  "pairing-login command (PROTOCOL §3.4); handled by pairing role, not admin commandTable",
}

var allowedGatewayNotUsage = map[string]string{
	"whoami": "version-preflight protocol command (PROTOCOL §1.2), not a user-facing CLI verb",
}

var allowedClientNotUsage = map[string]string{
	"whoami": "version-preflight protocol command (PROTOCOL §1.2), not a user-facing CLI verb",
}

func main() {
	selftest := flag.Bool("selftest", false, "run the built-in selftest and exit")
	clientDirs := flag.String("client-dirs", "internal/admin,internal/client", "comma-separated client library directories")
	gwFile := flag.String("gw-file", "internal/gateway/admin_role.go", "gateway command table file")
	usageFile := flag.String("usage-file", "cmd/iamtunnel/usage.go", "CLI help file")
	flag.Parse()

	// The selftest MUST go first!
	if err := runSelftest(); err != nil {
		fmt.Fprintf(os.Stderr, "check_commands: selftest failed: %v\n", err)
		os.Exit(1)
	}
	if *selftest {
		fmt.Println("selftest: every sample parsed correctly, every anomaly caught")
		return
	}

	clientCmds, err := readClientCommands(strings.Split(*clientDirs, ","))
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_commands: error reading client commands: %v\n", err)
		os.Exit(2)
	}

	gwCmds, err := readGatewayCommands(*gwFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_commands: error reading gateway commands: %v\n", err)
		os.Exit(2)
	}

	usageCmds, err := readUsageCommands(*usageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check_commands: error reading CLI commands: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("commands discovered:\n")
	fmt.Printf("  client library (%s): %d\n", *clientDirs, len(clientCmds))
	fmt.Printf("  gateway commandTable (%s): %d\n", *gwFile, len(gwCmds))
	fmt.Printf("  CLI usage (%s): %d\n", *usageFile, len(usageCmds))

	problems := verifyTriad(clientCmds, gwCmds, usageCmds,
		allowedClientNotGateway, allowedUsageNotGateway, allowedGatewayNotUsage, allowedClientNotUsage)

	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "\ncheck_commands: command list divergences found (%d):\n", len(problems))
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  ! %s\n", p)
		}
		os.Exit(1)
	}

	fmt.Println("every client command is handled by the gateway, every gateway command is called, and CLI usage matches")
}

// readClientCommands extracts command names from calls of
// c.Exec("...", ...) and execCommand(..., "...", req) in the non-test Go
// files of the given directories.
func readClientCommands(dirs []string) (map[string]bool, error) {
	cmds := make(map[string]bool)
	var allNonLiteralErrors []string
	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			filePath := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, filePath, nil, 0)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filePath, err)
			}
			errs := extractCallsFromAST(fset, f, cmds)
			allNonLiteralErrors = append(allNonLiteralErrors, errs...)
		}
	}
	if len(allNonLiteralErrors) > 0 {
		return nil, fmt.Errorf("non-literal c.Exec calls found:\n  %s", strings.Join(allNonLiteralErrors, "\n  "))
	}
	return cmds, nil
}

// extractCallsFromAST extracts literal command names from the AST.
// A non-literal call of c.Exec(...) or execCommand(...) is returned as
// an error.
func extractCallsFromAST(fset *token.FileSet, file *ast.File, cmds map[string]bool) []string {
	var nonLiteralErrors []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var targetArg ast.Expr
		isCall := false
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exec" && len(call.Args) >= 1 {
			targetArg = call.Args[0]
			isCall = true
		} else if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "execCommand" && len(call.Args) >= 2 {
			// The command name is the second-to-last argument, the last
			// one is the request.
			// R1-CX F-08 put a context and a timeout in front of the
			// client (execCommand(ctx, client, timeout, "...", req));
			// counting from the end is correct for the older shape
			// execCommand(client, "...", req) too.
			targetArg = call.Args[len(call.Args)-2]
			isCall = true
		}
		if !isCall {
			return true
		}

		lit, ok := targetArg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			pos := fset.Position(call.Pos())
			nonLiteralErrors = append(nonLiteralErrors, fmt.Sprintf("%s:%d: call with a non-literal command name (calling through a variable is forbidden)", pos.Filename, pos.Line))
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err == nil && (strings.Contains(s, ".") || s == "whoami") {
			cmds[s] = true
		}
		return true
	})
	return nonLiteralErrors
}

// readGatewayCommands extracts the commandTable keys from admin_role.go.
func readGatewayCommands(filePath string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	return extractGatewayCommandsFromAST(f)
}

func extractGatewayCommandsFromAST(f *ast.File) (map[string]bool, error) {
	cmds := make(map[string]bool)
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range vs.Names {
			if name.Name == "commandTable" && len(vs.Values) > 0 {
				found = true
				if cl, ok := vs.Values[0].(*ast.CompositeLit); ok {
					for _, elt := range cl.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
								s, err := strconv.Unquote(lit.Value)
								if err == nil {
									cmds[s] = true
								}
							}
						}
					}
				}
			}
		}
		return true
	})
	if !found || len(cmds) == 0 {
		return nil, fmt.Errorf("commandTable not found or empty")
	}
	return cmds, nil
}

// readUsageCommands extracts the commands promised in usage.go, parsing
// strictly the two constants adminHelp and clientHelp.
func readUsageCommands(filePath string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return nil, err
	}
	var adminHelp, clientHelp string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			val, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range val.Names {
				if (name.Name == "adminHelp" || name.Name == "clientHelp") && i < len(val.Values) {
					if lit, ok := val.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						unquoted, err := strconv.Unquote(lit.Value)
						if err == nil {
							if name.Name == "adminHelp" {
								adminHelp = unquoted
							} else {
								clientHelp = unquoted
							}
						}
					}
				}
			}
		}
	}
	if adminHelp == "" {
		return nil, fmt.Errorf("%s: adminHelp constant not found", filePath)
	}
	if clientHelp == "" {
		return nil, fmt.Errorf("%s: clientHelp constant not found", filePath)
	}
	return parseUsageStrings(adminHelp, clientHelp)
}

var ignoredAdminUsageLines = map[string]bool{
	`"" issues an indefinite grant (§4.3)`: true,
}

var knownLocalClientUsageVerbs = map[string]bool{
	"connect-string": true,
	"connect":        true,
	// "exec" (IAMT-336-followup): "iamtunnel client exec" sends
	// a raw SSH "exec" channel request (sshx.MarshalExec) built from the
	// person's own command line — it is not a JSON commandTable verb like
	// "machines.mine" and has no gateway commandTable entry to match,
	// exactly like "connect" above never gaining one for pty-req/shell.
	"exec": true,
	// gateways/use/forget (IAMT-432): the list of remembered gateways is
	// a fact about THIS MACHINE and no gateway's business. Reading it,
	// switching between them and dropping one all happen inside
	// connection.json; nothing is dialled, and there is nothing for a
	// commandTable to answer. Asking a gateway which gateways a client
	// remembers would be the wrong question in the first place — it is
	// the one party that must not know about the others.
	"gateways": true,
	"use":      true,
	"forget":   true,
	// key (R4 F-14): prints this machine's own public key, creating it if
	// needed. Nothing is dialled - the key is what a person hands an
	// administrator before any gateway knows them.
	"key": true,
}

func isValidUsageIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// parseUsageStrings parses the adminHelp and clientHelp constants.
// Every command line is turned into group.verb.
// An unrecognized line in the command block fails the gate (an error is
// returned).
func parseUsageStrings(adminHelp, clientHelp string) (map[string]bool, error) {
	cmds := make(map[string]bool)

	// 1. Parsing adminHelp
	adminLines := strings.Split(adminHelp, "\n")
	inAdminCommands := false
	for _, raw := range adminLines {
		line := strings.TrimRight(raw, " \r\t")
		if !inAdminCommands {
			if strings.HasPrefix(line, "Usage: iamtunnel admin <group> <verb>") {
				inAdminCommands = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			// The end of the command block (lines "Names are...",
			// "Flags:...")
			break
		}
		if strings.HasPrefix(line, "   ") {
			// Continuation/argument-description lines indented 3+ spaces
			continue
		}
		trimmed := strings.TrimSpace(line)
		if ignoredAdminUsageLines[trimmed] {
			continue
		}
		// Cut off arguments and flags: everything from '<', '[', '(' or '--' on
		cleanLine := line
		cutIdx := len(cleanLine)
		for _, sep := range []string{"<", "[", "(", "--"} {
			if idx := strings.Index(cleanLine, sep); idx != -1 && idx < cutIdx {
				cutIdx = idx
			}
		}
		cleanLine = strings.TrimRight(cleanLine[:cutIdx], " \t")
		fields := strings.Fields(cleanLine)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "claim" {
			cmds["admin.claim"] = true
			continue
		}
		if fields[0] == "pair" {
			cmds["admin.pair"] = true
			continue
		}
		group := fields[0]
		if strings.Contains(cleanLine, "|") {
			// Lines with alternatives like "sessions active | history" or
			// "gateway status | fingerprint | backup"
			parts := strings.Split(cleanLine, "|")
			for i, p := range parts {
				f := strings.Fields(p)
				if i == 0 {
					if len(f) < 2 || !isValidUsageIdent(f[0]) || !isValidUsageIdent(f[1]) {
						return nil, fmt.Errorf("unrecognized piped command line in adminHelp: %q", line)
					}
					cmds[f[0]+"."+f[1]] = true
				} else {
					if len(f) < 1 || !isValidUsageIdent(f[0]) {
						return nil, fmt.Errorf("unrecognized alternative of a piped command in adminHelp: %q", line)
					}
					cmds[group+"."+f[0]] = true
				}
			}
			continue
		}
		if len(fields) >= 3 && fields[1] == "keys" {
			// people keys add / people keys remove -> people.keys.add / people.keys.remove
			if isValidUsageIdent(fields[0]) && isValidUsageIdent(fields[2]) {
				cmds[fields[0]+".keys."+fields[2]] = true
				continue
			}
			return nil, fmt.Errorf("unrecognized people keys line in adminHelp: %q", line)
		}
		if len(fields) >= 2 {
			verb := fields[1]
			if isValidUsageIdent(group) && isValidUsageIdent(verb) {
				cmds[group+"."+verb] = true
				continue
			}
		}
		return nil, fmt.Errorf("unrecognized command line in adminHelp: %q", line)
	}

	// 2. Parsing clientHelp
	clientLines := strings.Split(clientHelp, "\n")
	inClientCommands := false
	for _, raw := range clientLines {
		line := strings.TrimRight(raw, " \r\t")
		if !inClientCommands {
			if strings.TrimSpace(line) == "Usage:" {
				inClientCommands = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			break
		}
		if strings.HasPrefix(line, "    ") {
			// Command descriptions indented 4+ spaces
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "iamtunnel client ") {
			return nil, fmt.Errorf("unrecognized command line in clientHelp: %q", line)
		}
		sub := strings.TrimPrefix(trimmed, "iamtunnel client ")
		f := strings.Fields(sub)
		if len(f) == 0 {
			return nil, fmt.Errorf("empty command in clientHelp: %q", line)
		}
		verb := f[0]
		if verb == "machines" {
			cmds["machines.mine"] = true
			continue
		}
		if knownLocalClientUsageVerbs[verb] {
			continue
		}
		if isValidUsageIdent(verb) {
			cmds["client."+verb] = true
			continue
		}
		return nil, fmt.Errorf("unrecognized command verb in clientHelp: %q", line)
	}

	return cmds, nil
}

// verifyTriad performs a two-sided cross-check of the three command sets,
// taking the exceptions into account.
func verifyTriad(
	clientCmds, gwCmds, usageCmds map[string]bool,
	allowedClientNotGw, allowedUsageNotGw, allowedGwNotUsage, allowedClientNotUsage map[string]string,
) []string {
	var problems []string

	// 1. Client vs Gateway
	// Every client call must be executed by the gateway (or be in the
	// permitted exceptions)
	for c := range clientCmds {
		if !gwCmds[c] {
			if _, ok := allowedClientNotGw[c]; !ok {
				problems = append(problems, fmt.Sprintf("the client can call %q, but the gateway does not implement it in commandTable", c))
			}
		}
	}
	// The other way: every gateway command must be called by the client
	for g := range gwCmds {
		if !clientCmds[g] {
			problems = append(problems, fmt.Sprintf("the gateway implements command %q in commandTable, but the client library has no call for it (orphan)", g))
		}
	}

	// 2. CLI help vs Gateway
	// Every help command must be in the gateway (or in the exceptions)
	for u := range usageCmds {
		if !gwCmds[u] {
			if _, ok := allowedUsageNotGw[u]; !ok {
				problems = append(problems, fmt.Sprintf("the CLI help (usage.go) promises command %q, but the gateway does not implement it in commandTable", u))
			}
		}
	}
	// The other way: every gateway command must be reflected in the help
	// (or in the exceptions)
	for g := range gwCmds {
		if !usageCmds[g] {
			if _, ok := allowedGwNotUsage[g]; !ok {
				problems = append(problems, fmt.Sprintf("the gateway implements command %q, but it is not mentioned in the CLI help (usage.go)", g))
			}
		}
	}

	// 3. Client vs CLI help
	for c := range clientCmds {
		if !usageCmds[c] {
			if _, ok := allowedClientNotUsage[c]; !ok {
				problems = append(problems, fmt.Sprintf("the client can call command %q, but it is missing from the CLI help (usage.go)", c))
			}
		}
	}
	for u := range usageCmds {
		if !clientCmds[u] {
			problems = append(problems, fmt.Sprintf("the CLI help (usage.go) promises command %q, but the client library cannot call it", u))
		}
	}

	// 4. Stale-exception check (dead exceptions)
	// If a command from allowedClientNotGw is actually implemented in the
	// gateway, the exception has gone stale!
	for c, reason := range allowedClientNotGw {
		if gwCmds[c] {
			problems = append(problems, fmt.Sprintf("the client-not-gw exception for %q is stale: the command is already implemented in commandTable (%s)", c, reason))
		}
	}
	for u, reason := range allowedUsageNotGw {
		if gwCmds[u] {
			problems = append(problems, fmt.Sprintf("the usage-not-gw exception for %q is stale: the command is already implemented in commandTable (%s)", u, reason))
		}
	}

	sort.Strings(problems)
	return problems
}

// runSelftest exercises the detector on synthetic sources and ASTs.
func runSelftest() error {
	// -------------------------------------------------------------------------
	// 1. Checking the help detector (parseUsageStrings)
	// -------------------------------------------------------------------------
	sampleAdmin := `Usage: iamtunnel admin <group> <verb> [args] [--json]

  people add <name>
  people keys add <name> <pubkey>
  machines list
  sessions active | history
  gateway status | fingerprint
  claim <token>

Flags: --config <file>`

	sampleClient := `Usage:
  iamtunnel client connect-string <str>
  iamtunnel client machines
  iamtunnel client connect <machine>`

	parsed, err := parseUsageStrings(sampleAdmin, sampleClient)
	if err != nil {
		return fmt.Errorf("selftest: parseUsageStrings on the reference help returned an error: %v", err)
	}
	wantCmds := []string{
		"people.add", "people.keys.add", "machines.list",
		"sessions.active", "sessions.history", "gateway.status", "gateway.fingerprint",
		"admin.claim", "machines.mine",
	}
	for _, w := range wantCmds {
		if !parsed[w] {
			return fmt.Errorf("selftest: parseUsageStrings did not extract %q", w)
		}
	}
	if parsed["connect-string"] || parsed["connect"] {
		return fmt.Errorf("selftest: parseUsageStrings wrongly extracted local client commands as gateway commands")
	}

	// 1b. Detecting a phantom line in the help (canary 154-1):
	phantomAdmin := strings.Replace(sampleAdmin, "Flags:", "  machines clone <id>\n  sessions export <id>\n\nFlags:", 1)
	phantomParsed, err := parseUsageStrings(phantomAdmin, sampleClient)
	if err != nil {
		return fmt.Errorf("selftest: parseUsageStrings on the phantom help returned a parse error: %v", err)
	}
	if !phantomParsed["machines.clone"] || !phantomParsed["sessions.export"] {
		return fmt.Errorf("selftest: parseUsageStrings did not extract the phantom commands machines.clone or sessions.export")
	}
	// verifyTriad against the reference gateway must catch the phantom
	pPhantom := verifyTriad(parsed, parsed, phantomParsed, nil, nil, nil, nil)
	if !containsSubstring(pPhantom, "the CLI help (usage.go) promises command \"machines.clone\", but the gateway does not implement it") {
		return fmt.Errorf("selftest: verifyTriad did not catch the phantom command machines.clone: %v", pPhantom)
	}

	// 1c. Detecting an unrecognized line in the help:
	badAdmin := strings.Replace(sampleAdmin, "Flags:", "  ??? bad syntax line\n\nFlags:", 1)
	if _, err := parseUsageStrings(badAdmin, sampleClient); err == nil {
		return fmt.Errorf("selftest: parseUsageStrings returned no error on an unrecognized command line")
	}

	// -------------------------------------------------------------------------
	// 2. Checking the AST extractor of client calls (extractCallsFromAST)
	// -------------------------------------------------------------------------
	fset := token.NewFileSet()
	astCodeGood := `package test
func CallGood(c *Client) {
	c.Exec("machines.list", nil)
	execCommand(c, "grants.list", nil)
	execCommand(ctx, c, timeout, "people.list", nil)
	c.Exec("whoami", nil)
}`
	fGood, err := parser.ParseFile(fset, "good.go", astCodeGood, 0)
	if err != nil {
		return fmt.Errorf("selftest: parse good.go: %v", err)
	}
	astCmds := make(map[string]bool)
	errsGood := extractCallsFromAST(fset, fGood, astCmds)
	if len(errsGood) > 0 {
		return fmt.Errorf("selftest: extractCallsFromAST returned unexpected errors: %v", errsGood)
	}
	if !astCmds["machines.list"] || !astCmds["grants.list"] || !astCmds["people.list"] || !astCmds["whoami"] {
		return fmt.Errorf("selftest: extractCallsFromAST did not extract the literal calls: %v", astCmds)
	}

	// 2b. Detecting a non-literal c.Exec(varName, ...) call (154-3)
	astCodeNonLit := `package test
func CallBad(c *Client, name string) {
	c.Exec(name, nil)
}`
	fNonLit, err := parser.ParseFile(fset, "bad.go", astCodeNonLit, 0)
	if err != nil {
		return fmt.Errorf("selftest: parse bad.go: %v", err)
	}
	errsBad := extractCallsFromAST(fset, fNonLit, make(map[string]bool))
	if len(errsBad) == 0 || !strings.Contains(errsBad[0], "non-literal command name") {
		return fmt.Errorf("selftest: extractCallsFromAST did not catch the non-literal c.Exec(name) call: %v", errsBad)
	}

	// -------------------------------------------------------------------------
	// 3. Checking the AST extractor of the gateway table
	// (extractGatewayCommandsFromAST)
	// -------------------------------------------------------------------------
	astCodeGw := `package test
var commandTable = map[string]commandHandler{
	"machines.list": nil,
	"people.add":    nil,
}`
	fGw, err := parser.ParseFile(fset, "gw.go", astCodeGw, 0)
	if err != nil {
		return fmt.Errorf("selftest: parse gw.go: %v", err)
	}
	gwExtracted, err := extractGatewayCommandsFromAST(fGw)
	if err != nil || !gwExtracted["machines.list"] || !gwExtracted["people.add"] {
		return fmt.Errorf("selftest: extractGatewayCommandsFromAST did not extract the table keys: %v, %v", gwExtracted, err)
	}

	// 3b. Detecting an empty or missing commandTable
	astCodeGwEmpty := `package test
var otherTable = map[string]string{}`
	fGwEmpty, _ := parser.ParseFile(fset, "gw_empty.go", astCodeGwEmpty, 0)
	if _, err := extractGatewayCommandsFromAST(fGwEmpty); err == nil {
		return fmt.Errorf("selftest: extractGatewayCommandsFromAST returned no error on a missing commandTable")
	}

	// -------------------------------------------------------------------------
	// 4. Checking verifyTriad on command sets
	// -------------------------------------------------------------------------
	baseClient := map[string]bool{"whoami": true, "people.add": true, "machines.mine": true, "gateway.backup": true}
	baseGw := map[string]bool{"whoami": true, "people.add": true, "machines.mine": true}
	baseUsage := map[string]bool{"people.add": true, "machines.mine": true, "gateway.backup": true}

	excCNotG := map[string]string{"gateway.backup": "test"}
	excUNotG := map[string]string{"gateway.backup": "test"}
	excGNotU := map[string]string{"whoami": "test"}
	excCNotU := map[string]string{"whoami": "test"}

	if p := verifyTriad(baseClient, baseGw, baseUsage, excCNotG, excUNotG, excGNotU, excCNotU); len(p) > 0 {
		return fmt.Errorf("the reference set failed the check: %v", p)
	}

	brokenClient := copyMap(baseClient)
	brokenClient["machines.unknown"] = true
	p2 := verifyTriad(brokenClient, baseGw, baseUsage, excCNotG, excUNotG, excGNotU, excCNotU)
	if !containsSubstring(p2, "the client can call \"machines.unknown\", but the gateway does not implement it") {
		return fmt.Errorf("the detector did not catch a client command missing from the gateway: %v", p2)
	}

	brokenGw := copyMap(baseGw)
	brokenGw["machines.orphan"] = true
	p3 := verifyTriad(baseClient, brokenGw, baseUsage, excCNotG, excUNotG, excGNotU, excCNotU)
	if !containsSubstring(p3, "the gateway implements command \"machines.orphan\" in commandTable, but the client library has no call for it") {
		return fmt.Errorf("the detector did not catch an orphan command on the gateway: %v", p3)
	}

	brokenUsage := copyMap(baseUsage)
	brokenUsage["phantom.cmd"] = true
	p4 := verifyTriad(baseClient, baseGw, brokenUsage, excCNotG, excUNotG, excGNotU, excCNotU)
	if !containsSubstring(p4, "the CLI help (usage.go) promises command \"phantom.cmd\", but the gateway does not implement it") {
		return fmt.Errorf("the detector did not catch a phantom command in usage: %v", p4)
	}

	staleGw := copyMap(baseGw)
	staleGw["gateway.backup"] = true
	staleClient := copyMap(baseClient)
	p5 := verifyTriad(staleClient, staleGw, baseUsage, excCNotG, excUNotG, excGNotU, excCNotU)
	if !containsSubstring(p5, "the client-not-gw exception for \"gateway.backup\" is stale") {
		return fmt.Errorf("the detector did not catch a stale exception: %v", p5)
	}

	return nil
}

func copyMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func containsSubstring(items []string, sub string) bool {
	for _, item := range items {
		if strings.Contains(item, sub) {
			return true
		}
	}
	return false
}
