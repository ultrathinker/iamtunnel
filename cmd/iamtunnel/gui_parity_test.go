//go:build (windows || linux || darwin) && !nogui

package main

// gui_parity_test.go — P-06 of the R4 review, IAMT-499: SPEC §3.3 says "the
// tab and the console do the same thing". Until 24.09.2026 that was a
// sentence nobody checked, and eight admin verbs lived only in the console
// -- among them the one that lets a machine with a changed sshd key back
// in. This test is the check: every admin verb the CLI knows maps to the
// window action(s) that do its work, each named action exists on
// ui.Actions, and every one of them is wired in the window of all three
// platforms. A verb added to the console without a window twin fails here
// until it is given one, or listed below as console-only with the reason.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// adminVerbWindow is the window's twin of each "admin <group> <verb>".
// Several verbs are served by one fetch: AdminList carries people,
// machines, grants, active sessions, goals and the gateway's status in
// one connection (IAMT-357).
var adminVerbWindow = map[string][]string{
	"people add":               {"AdminPeopleAdd"},
	"people rename":            {"AdminRenamePerson"},
	"people remove":            {"AdminRemovePerson"},
	"people list":              {"AdminList"},
	"people keys":              {"AdminPersonKeyAdd", "AdminPersonKeyRemove"},
	"people connection-string": {"AdminPersonConnectionString"},
	"machines enrol-code":      {"AdminMachinesEnrolCode"},
	"machines list":            {"AdminList"},
	"machines rename":          {"AdminRenameMachine"},
	"machines remove":          {"AdminRemoveMachine"},
	"machines rekey":           {"AdminMachineRekey"},
	"machines verify":          {"AdminMachineVerify"},
	"machines set-user":        {"AdminMachineSetUser"},
	"grants grant":             {"AdminGrantWithCaps"},
	"grants extend":            {"AdminExtend"},
	"grants set-caps":          {"AdminSetGrantCaps"},
	"grants revoke":            {"AdminRevoke"},
	"grants list":              {"AdminList"},
	"sessions active":          {"AdminList"},
	"sessions history":         {"SessionsHistory"},
	"sessions kill":            {"AdminSessionKill"},
	"sessions tail":            {"AdminSessionTail"},
	"recordings list":          {"AdminRecordings"},
	"recordings fetch":         {"AdminRecordingFetch"},
	"gateway status":           {"AdminList"},
	"gateway fingerprint":      {"AdminGatewayFingerprint"},
	"gateway backup":           {"AdminGatewayBackup"},
	"gateway rotate-hostkey":   {"AdminGatewayRotateHostkey"},
	"goal set":                 {"AdminGrantGoal"},
	"goal current":             {"AdminList"},
	"goal history":             {"AdminList"},
	"goal list":                {"AdminList"},
	"risk check":               {"AdminRiskCheck"},
	"risk mode":                {"AdminRiskMode"},
	"risk source":              {"AdminRiskSource"},
	"risk pending":             {"ClientRiskPending"},
	"risk approve":             {"ClientRiskApprove"},
	"risk deny":                {"ClientRiskDeny"},
	"risk key":                 {"AdminSetClassifierKey"},
	"pairing start":            {"AdminPairingStart"},
	"pairing stop":             {"AdminPairingStop"},
}

// adminVerbConsoleOnly lists verbs that deliberately have no window twin,
// each with the reason. Empty since IAMT-499; an entry here is a decision,
// not an oversight.
var adminVerbConsoleOnly = map[string]string{}

func TestIAMT499EveryAdminVerbHasAWindowTwin(t *testing.T) {
	cli := map[string]bool{}
	for group, verbs := range adminGroups {
		for _, verb := range verbs {
			cli[group+" "+verb] = true
		}
	}
	var missing []string
	for v := range cli {
		if _, ok := adminVerbWindow[v]; ok {
			continue
		}
		if _, ok := adminVerbConsoleOnly[v]; ok {
			continue
		}
		missing = append(missing, v)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("admin verbs with no window twin (SPEC §3.3 \"the tab and the console do the same thing\"): %s — add the window action, or list the verb in adminVerbConsoleOnly with the reason", strings.Join(missing, ", "))
	}
	for v := range adminVerbWindow {
		if !cli[v] {
			t.Errorf("adminVerbWindow names %q, which the console does not have — a stale row", v)
		}
	}
}

func TestIAMT499WindowTwinsExistAndAreWiredOnEveryPlatform(t *testing.T) {
	actions := reflect.TypeOf(ui.Actions{})
	need := map[string]bool{}
	for _, fields := range adminVerbWindow {
		for _, f := range fields {
			if _, ok := actions.FieldByName(f); !ok {
				t.Errorf("ui.Actions has no field %s", f)
			}
			need[f] = true
		}
	}
	for _, file := range []string{"gui_windows.go", "gui_linux.go", "gui_darwin.go"} {
		wired := actionsWiredIn(t, file)
		var absent []string
		for f := range need {
			if !wired[f] {
				absent = append(absent, f)
			}
		}
		sort.Strings(absent)
		if len(absent) > 0 {
			t.Errorf("%s does not wire %s — that platform's window draws the control and does nothing", file, strings.Join(absent, ", "))
		}
	}
}

// actionsWiredIn returns the keys of every ui.Actions composite literal in
// one source file whose value actually reaches a gui* wrapper: either the
// wrapper itself (ClientConnect: guiClientConnect) or a function literal
// that calls one. A key set to nil, or to a function that does nothing, is
// not wired (review 116 C-04) -- the window would draw the control
// and it would do nothing. The file is read whatever its build tag, so the
// test checks all three platforms from any one of them.
func actionsWiredIn(t *testing.T, file string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	wired := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Actions" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			id, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if reachesGuiWrapper(kv.Value) {
				wired[id.Name] = true
			}
		}
		return true
	})
	if len(wired) == 0 {
		t.Fatalf("%s: found no ui.Actions literal — the parity check would pass on nothing", file)
	}
	return wired
}

// reachesGuiWrapper reports whether an Actions value is, or calls, a
// function whose name starts with "gui" -- the cmd/iamtunnel wrappers that
// dial the gateway.
func reachesGuiWrapper(v ast.Expr) bool {
	if id, ok := v.(*ast.Ident); ok {
		return strings.HasPrefix(id.Name, "gui")
	}
	fl, ok := v.(*ast.FuncLit)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(fl.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && strings.HasPrefix(id.Name, "gui") {
				found = true
			}
		}
		return !found
	})
	return found
}
