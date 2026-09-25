//go:build ignore

// check_noempty.go: the helper of the ninth gate. Not part of the
// product; it is fed to `go run` from gates.ps1 and gates.sh.
//
// The rule: a test function counts as an empty shell if its body holds
// neither a call of a failure/skip facility (t.Fatal, t.Errorf, t.Skip
// and the like) nor a call of a same-package helper that is passed a
// *testing.T.
//
// Subtests are taken into account: the check may live inside a closure
// passed to t.Run, so the AST walk enters the bodies of function
// literals that have a *testing.T.
//
// Usage:
//
//	go run scripts/check_noempty.go -allow "TestX==>reason;;TestY==>reason" \
//	    <pkg1> [<pkg2> ...]
//
// The -allow flag sets a list of "test_name ==> reason" exceptions
// separated by ";;". The double separator was chosen because lone ";"
// and "=" each occur in reason wordings, while the combination "==>"
// and ";;" never does. Every allowed exception found is printed
// together with its reason. Returns 0 if there are no empty shells
// (minus the allowed ones), and 1 otherwise.
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
	"strings"
)

// knownFailureMethods is the set of *testing.T (and *testing.B)
// methods that stop the test or mark it failed or skipped. Any
// occurrence of one in the body makes the function NOT an empty shell.
var knownFailureMethods = map[string]bool{
	"Fail":    true,
	"FailNow": true,
	"Failed":  true,
	"Fatal":   true,
	"Fatalf":  true,
	"Error":   true,
	"Errorf":  true,
	"Skip":    true,
	"Skipf":   true,
	"SkipNow": true,
	"Skipped": true,
	"Helper":  true,
}

// isTestingTParam returns true when the field is a parameter of type
// *testing.T or *testing.B (with any name).
func isTestingTParam(field *ast.Field) bool {
	if star, ok := field.Type.(*ast.StarExpr); ok {
		if sel, ok := star.X.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
				return sel.Sel.Name == "T" || sel.Sel.Name == "B"
			}
		}
	}
	return false
}

// firstTestingParamName returns the name of a *testing.T /
// *testing.B-typed parameter (or an empty string if there is none).
// Used when analysing closures: the closure `func(t *testing.T) { ... }`
// passes its t further down.
func firstTestingParamName(params *ast.FieldList) string {
	if params == nil {
		return ""
	}
	for _, p := range params.List {
		if !isTestingTParam(p) {
			continue
		}
		if len(p.Names) > 0 {
			return p.Names[0].Name
		}
		return ""
	}
	return ""
}

// hasFailureCall walks the AST and reports whether a known failure
// method is called on any *testing.T (including one that came in as a
// closure parameter).
func hasFailureCall(node ast.Node, tNames map[string]bool) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !knownFailureMethods[sel.Sel.Name] {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if tNames[id.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// hasHelperCall walks the AST and reports whether a same-package
// helper function is called with a *testing.T passed to it.
//
// sharedKeys extends this to helpers from OTHER packages of the
// project (see loadSharedHelpers): a test that relies entirely on the
// shared helper package (internal/testsupport -- an idiom introduced
// in IAMT-332 round 9) must count as able to go red. The key there is
// the qualified "package.Function" name, and the argument check is
// stricter: a shared helper has *testing.T as its FIRST parameter, so
// in the call it must be the first argument too -- otherwise we would
// trust a call whose signature does not match what we read in the
// other package.
func hasHelperCall(node ast.Node, tNames map[string]bool, fullKeys map[string]bool, methodNames map[string]bool, sharedKeys map[string]bool) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var key string
		var shortName string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			key = fun.Name
			shortName = fun.Name
		case *ast.SelectorExpr:
			key = fun.Sel.Name
			shortName = fun.Sel.Name
			if id, ok := fun.X.(*ast.Ident); ok {
				key = id.Name + "." + fun.Sel.Name
			}
		default:
			return true
		}
		if sharedKeys[key] {
			if len(call.Args) > 0 && isTestingArg(call.Args[0], tNames) {
				found = true
				return false
			}
			return true
		}
		isHelper := fullKeys[key]
		if !isHelper {
			// A selector chain: s.fake.waitForState(...) -- fun.X is not
			// an Ident, so the "exact key" cannot be assembled. We look
			// by the short name.
			if _, ok := call.Fun.(*ast.SelectorExpr); ok {
				isHelper = methodNames[shortName]
			}
		}
		if !isHelper {
			return true
		}
		for _, a := range call.Args {
			if id, ok := a.(*ast.Ident); ok && tNames[id.Name] {
				found = true
				return false
			}
		}
		for _, a := range call.Args {
			if star, ok := a.(*ast.StarExpr); ok {
				if sel, ok := star.X.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
						if sel.Sel.Name == "T" {
							found = true
							return false
						}
					}
				}
			}
		}
		return true
	})
	return found
}

// isTestingArg reports whether the expression is a testing object: an
// identifier of one of the known *testing.T/*testing.B values
// (including a subtest's t) or a *testing.T{...} literal.
func isTestingArg(expr ast.Expr, tNames map[string]bool) bool {
	if id, ok := expr.(*ast.Ident); ok {
		return tNames[id.Name]
	}
	if star, ok := expr.(*ast.StarExpr); ok {
		if sel, ok := star.X.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testing" {
				return sel.Sel.Name == "T" || sel.Sel.Name == "B"
			}
		}
	}
	return false
}

// sharedPkgCache caches parsed helper packages by directory: the same
// internal/testsupport is parsed once for the whole run.
var sharedPkgCache = map[string]map[string]bool{}

// loadSharedHelpers returns the set of qualified names
// ("testsupport.RequireRefusal") of functions defined in other
// packages of THIS project that take *testing.T/*testing.B as their
// first parameter.
//
// Why: gate 9 recognises as a helper a function that a testing object
// is passed to, but it looks for such functions only in the package
// being checked. With IAMT-332 round 9 the project gained a shared
// helper package (internal/testsupport: Plant*, Assert*,
// RequireRefusal, RunBounded), and a test that relies entirely on it
// started to look like an empty shell -- even though it can go red,
// and that is exactly how it fails. The error is systemic: the more
// tests are written in this idiom, the more false positives, so the
// helper list is not baked into the gate but read from the project
// packages themselves: a new helper in internal/testsupport is picked
// up automatically, and the gate needs to know nothing about it.
//
// The trust boundaries are deliberate:
//   - only packages of THIS module (the module prefix from go.mod) --
//     a foreign package from an external dependency is not parsed and
//     is not trusted;
//   - only top-level functions with *testing.T/*testing.B as the FIRST
//     parameter -- exactly the signature by which the first argument
//     is checked in a call;
//   - methods of foreign types are not collected: in the AST of the
//     call `x.Helper(t)` the receiver's type is not visible, and there
//     is nothing to trust there.
//
// If go.mod is not found or a package does not parse, the set is
// empty: the gate falls back to the old behaviour (a false positive),
// but it never starts silently passing empty shells.
func loadSharedHelpers(file *ast.File, modulePrefix, root string) map[string]bool {
	if modulePrefix == "" {
		return nil
	}
	out := map[string]bool{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasPrefix(path, modulePrefix+"/") {
			continue
		}
		qualifier := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			qualifier = imp.Name.Name
		}
		if qualifier == "_" || qualifier == "." {
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, modulePrefix+"/")))
		names, cached := sharedPkgCache[dir]
		if !cached {
			names = parseSharedHelpers(dir)
			sharedPkgCache[dir] = names
		}
		for name := range names {
			out[qualifier+"."+name] = true
		}
	}
	return out
}

// parseSharedHelpers reads a package directory and returns the names
// of its exported functions that have *testing.T/*testing.B as their
// first parameter.
func parseSharedHelpers(dir string) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Type.Params == nil {
				continue
			}
			if !fn.Name.IsExported() {
				continue
			}
			if len(fn.Type.Params.List) == 0 {
				continue
			}
			// Exactly the FIRST parameter: the call is checked by the
			// same one.
			if isTestingTParam(fn.Type.Params.List[0]) {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// modulePrefixAndRoot finds the module root (the directory with
// go.mod) and its module name, walking up from the current directory.
// Empty strings mean the module was not found -- then no shared
// helpers are collected.
func modulePrefixAndRoot() (modulePrefix, root string) {
	dir, err := os.Getwd()
	if err != nil {
		return "", ""
	}
	for {
		raw, rerr := os.ReadFile(filepath.Join(dir, "go.mod"))
		if rerr == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					return strings.TrimSpace(strings.TrimPrefix(line, "module ")), dir
				}
			}
			return "", dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ""
		}
		dir = parent
	}
}

// collectTNames returns the set of names that stand for a *testing.T
// in the given function: its own parameter plus the parameter names of
// nested func literals that have a *testing.T.
func collectTNames(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	if fn.Type.Params != nil {
		if name := firstTestingParamName(fn.Type.Params); name != "" {
			out[name] = true
		}
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		if name := firstTestingParamName(fl.Type.Params); name != "" {
			out[name] = true
		}
		return true
	})
	return out
}

// collectHelpers returns the names of the functions/methods in the
// package whose parameter list (after the receiver) contains a
// *testing.T. These are exactly "the helpers a testing object is
// passed to".
//
// The output is two sets: "exact keys" -- "Type.Method" for methods
// and "FuncName" for functions; and "methods" -- just the method name,
// because in a call like `s.fake.waitForState(t, ...)` the AST's
// selector chain does not keep the receiver's type, and a helper can
// only be recognised by the short name. A test in the same package
// calls a method whose first parameter position is a *testing.T, and
// that is a helper.
func collectHelpers(files []*ast.File) (map[string]bool, map[string]bool) {
	fullKeys := map[string]bool{}
	methodNames := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Benchmark") {
				continue
			}
			if firstTestingParamName(fn.Type.Params) == "" {
				continue
			}
			if fn.Recv == nil {
				fullKeys[fn.Name.Name] = true
				continue
			}
			// A method: register by type (if it can be recovered) and
			// by the short name.
			if len(fn.Recv.List) > 0 {
				t := fn.Recv.List[0].Type
				if id, ok := t.(*ast.Ident); ok {
					fullKeys[id.Name+"."+fn.Name.Name] = true
				}
				if star, ok := t.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok {
						fullKeys[id.Name+"."+fn.Name.Name] = true
					}
				}
			}
			methodNames[fn.Name.Name] = true
		}
	}
	return fullKeys, methodNames
}

// checkBody looks for a path to failure/skip or a helper call in the
// body and in all nested closures with a *testing.T (the typical
// t.Run subtests).
func checkBody(body ast.Node, tNames map[string]bool, fullKeys map[string]bool, methodNames map[string]bool, sharedKeys map[string]bool) bool {
	if hasFailureCall(body, tNames) {
		return true
	}
	if hasHelperCall(body, tNames, fullKeys, methodNames, sharedKeys) {
		return true
	}
	subFound := false
	ast.Inspect(body, func(n ast.Node) bool {
		if subFound {
			return false
		}
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		if firstTestingParamName(fl.Type.Params) == "" {
			return true
		}
		names := map[string]bool{}
		for k, v := range tNames {
			names[k] = v
		}
		if name := firstTestingParamName(fl.Type.Params); name != "" {
			names[name] = true
		}
		if hasFailureCall(fl.Body, names) {
			subFound = true
			return false
		}
		if hasHelperCall(fl.Body, names, fullKeys, methodNames, sharedKeys) {
			subFound = true
			return false
		}
		return true
	})
	return subFound
}

// checkFile returns the list of empty shells found in one file.
func checkFile(fset *token.FileSet, file *ast.File, fullKeys map[string]bool, methodNames map[string]bool, sharedKeys map[string]bool) []string {
	var empties []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		// TestMain(m *testing.M) is the package's test entry point, not a test:
		// it has no *testing.T and cannot go red by design. The compiler rejects
		// any other signature under this name, so matching the name is exact.
		if fn.Name.Name == "TestMain" {
			continue
		}
		if fn.Body == nil {
			continue
		}
		tNames := collectTNames(fn)
		if checkBody(fn.Body, tNames, fullKeys, methodNames, sharedKeys) {
			continue
		}
		pos := fset.Position(fn.Pos())
		empties = append(empties, fmt.Sprintf("%s:%d:%s", pos.Filename, pos.Line, fn.Name.Name))
	}
	return empties
}

func main() {
	allowSpec := flag.String("allow", "", "semi-colon-separated list of Name:reason exceptions")
	flag.Parse()

	allow := map[string]string{}
	if *allowSpec != "" {
		for _, e := range strings.Split(*allowSpec, ";;") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			parts := strings.SplitN(e, "==>", 2)
			name := strings.TrimSpace(parts[0])
			reason := ""
			if len(parts) == 2 {
				reason = strings.TrimSpace(parts[1])
			}
			allow[name] = reason
		}
	}
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: check_noempty [-allow \"TestX:reason;...\"] <pkg1> [<pkg2> ...]")
		os.Exit(2)
	}

	totalReal := 0
	totalAllowed := 0
	for _, pkgPath := range args {
		empties, err := checkPackage(pkgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR %s: %v\n", pkgPath, err)
			totalReal++
			continue
		}
		for _, e := range empties {
			name := testNameFromLine(e)
			if reason, ok := allow[name]; ok {
				fmt.Printf("ALLOW %s -- %s\n", e, reason)
				totalAllowed++
				continue
			}
			fmt.Println(e)
			totalReal++
		}
	}
	if totalReal > 0 {
		fmt.Fprintf(os.Stderr, "%d empty test(s) found (%d allowed)\n", totalReal, totalAllowed)
		os.Exit(1)
	}
	fmt.Printf("All Test* functions have a failure path or a helper call. (%d allowed exceptions inspected)\n", totalAllowed)
}

// testNameFromLine extracts the test name from a path:line:Name line.
func testNameFromLine(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// checkPackage parses all *_test.go files under the given path and
// returns the list of empty shells. The path is read the way go build
// reads it: ./cmd/foo, ./internal/..., and so on.
func checkPackage(pkgPath string) ([]string, error) {
	dir, err := resolvePkgDir(pkgPath)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(info os.FileInfo) bool {
		return strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var allEmpties []string
	modulePrefix, root := modulePrefixAndRoot()
	for _, pkg := range pkgs {
		var files []*ast.File
		for _, f := range pkg.Files {
			files = append(files, f)
		}
		helpers, methodNames := collectHelpers(files)
		for _, f := range pkg.Files {
			// Shared helpers are read per file: the set depends on the
			// file's own imports (and the aliases in them).
			shared := loadSharedHelpers(f, modulePrefix, root)
			allEmpties = append(allEmpties, checkFile(fset, f, helpers, methodNames, shared)...)
		}
	}
	sort.Strings(allEmpties)
	return allEmpties, nil
}

// resolvePkgDir turns ./internal/gateway/state into an absolute path
// to the package directory.
func resolvePkgDir(pkgPath string) (string, error) {
	if pkgPath == "./..." {
		return "", fmt.Errorf("./... not supported, list packages explicitly")
	}
	if !strings.HasPrefix(pkgPath, "./") && !strings.HasPrefix(pkgPath, "../") && pkgPath != "." {
		return pkgPath, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, pkgPath), nil
}
