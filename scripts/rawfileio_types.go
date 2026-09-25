//go:build ignore

// rawfileio_types.go — the second stage of gate 16 (IAMT-504, P2.10 from
// IAMT-333): the same check as check_rawfileio.go, but by TYPES, not by
// text.
//
// The first stage looks at the AST: a call of the form <name>.<Func>(...),
// where <name> is the import of the os package. It does not see what does
// not look like such a call:
//
//   - a function value: var readFile = os.ReadFile -- there is not a
//     single os.ReadFile call in the file, yet the raw by-name read is
//     there (this is exactly how test seams are built);
//   - a dot import: import . "os"; ReadFile(p);
//   - any other place where the package name never reaches the call.
//
// Here every identifier use is resolved by go/types down to the object:
// if the object is an os package function from the same list the first
// stage uses (flaggedOSSelectors), or any io/ioutil function, it is a
// finding however it is written. golang.org/x/tools is not in go.mod and
// no new dependency is needed for the gate's sake: the export data comes
// from `go list -export`, and the check is done by the standard
// go/types.
//
// Reporting matches the first stage: a finding in an allowlist file is
// accepted (the allowlist is per file), a finding the first stage
// already saw on the same line is not printed twice. A problem is only
// what the first stage missed in a file without an allowlist entry. An
// allowlist entry is stale only if NEITHER stage found anything in its
// file -- and only where the second stage actually saw the file: another
// OS's file is judged by that OS's gates (check receives the sets of
// "alive" and "checked here" files).
//
// The stage checks packages under the current GOOS -- the gates run on
// Windows, Linux and macOS alike, so each platform checks its own files.
// A package that cannot be type-checked here (a dependency does not
// build) fails the stage: a skip would be exactly the silence the stage
// was introduced against. go list runs with CGO_ENABLED=1 -- the window
// packages need it.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// listedPackage — the needed part of `go list -json` output.
type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	DepOnly    bool
	Module     *struct{ Path string }
	Error      *struct{ Err string }
	DepsErrors []struct{ Err string }
}

// goListExport runs `go list -e -export -deps -json` in dir and returns
// the packages and the export-data map keyed by import path.
func goListExport(dir string, patterns ...string) ([]listedPackage, map[string]string, error) {
	args := append([]string{"list", "-e", "-export", "-deps", "-json"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	// CGO on, whatever the gate exported for its own builds: the window
	// packages need it on Linux and macOS, and a package the stage cannot
	// type-check is a failed stage, not a skipped one (review 116
	// C-02). A host without a C toolchain says so here, loudly.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("go list -export: %v\n%s", err, errb.String())
	}
	var pkgs []listedPackage
	exports := map[string]string{}
	dec := json.NewDecoder(&out)
	for {
		var p listedPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("go list -export: decode: %v", err)
		}
		if p.Export != "" {
			exports[p.ImportPath] = p.Export
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, exports, nil
}

// exportImporter — importer.ForCompiler on top of the export-data map.
func exportImporter(fset *token.FileSet, exports map[string]string) types.Importer {
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		f := exports[path]
		if f == "" {
			return nil, fmt.Errorf("no export data for %q", path)
		}
		return os.Open(f)
	})
}

// typedFinding — a second-stage finding: the file (as named when
// parsed), the line, and the function name.
type typedFinding struct {
	file string
	line int
	what string
}

// scanTyped type-checks one package assembled from files and returns all
// uses of the raw functions. A type-check error is a stage error: a
// package that could not be understood cannot be declared clean.
func scanTyped(fset *token.FileSet, imp types.Importer, pkgPath string, files []*ast.File) ([]typedFinding, error) {
	var typeErrs []string
	conf := types.Config{
		Importer:    imp,
		FakeImportC: true,
		Error:       func(err error) { typeErrs = append(typeErrs, err.Error()) },
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf.Check(pkgPath, fset, files, info)
	if len(typeErrs) > 0 {
		if len(typeErrs) > 5 {
			typeErrs = append(typeErrs[:5], fmt.Sprintf("… and %d more", len(typeErrs)-5))
		}
		return nil, fmt.Errorf("type-checking %s failed:\n  %s", pkgPath, strings.Join(typeErrs, "\n  "))
	}
	var out []typedFinding
	for id, obj := range info.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil {
			continue
		}
		if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
			continue // methods like (*os.File).ReadDir do not authorize a name
		}
		var what string
		switch fn.Pkg().Path() {
		case "os":
			if flaggedOSSelectors[fn.Name()] {
				what = "os." + fn.Name()
			}
		case "io/ioutil":
			what = "ioutil." + fn.Name()
		}
		if what == "" {
			continue
		}
		pos := fset.Position(id.Pos())
		out = append(out, typedFinding{file: pos.Filename, line: pos.Line, what: what})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, nil
}

// skippedByDir — the same directory filtering as the first stage.
func skippedByDir(rel string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if skippedDirNames[seg] {
			return true
		}
	}
	return false
}

// typeStage — the second stage over the whole root module. astSeen is the
// first stage's findings (file:line keys), allow is the allowlist in
// slash paths.
//
// alive — allowlist files where the stage found a raw call: their entry
// is alive even if the first stage sees nothing there (a function
// value).
// active — every file the stage checked on this platform: only about
// those may it say "nothing here" (review 116 C-03).
func typeStage(root string, astSeen map[string]bool, allow map[string]string) ([]problem, map[string]bool, map[string]bool, int, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	pkgs, exports, err := goListExport(absRoot, "./...")
	if err != nil {
		return nil, nil, nil, 0, err
	}
	alive := map[string]bool{}
	active := map[string]bool{}
	fset := token.NewFileSet()
	imp := exportImporter(fset, exports)
	var probs []problem
	checked := 0
	for _, p := range pkgs {
		if p.DepOnly || p.Module == nil || p.Module.Path != "github.com/ultrathinker/iamtunnel" {
			continue
		}
		if p.Error != nil {
			return nil, nil, nil, checked, fmt.Errorf("go list: %s: %s", p.ImportPath, p.Error.Err)
		}
		if len(p.DepsErrors) > 0 {
			// Fail, not skip (review 116 C-02): the type stage exists
			// for what the AST stage cannot see, so "the AST stage still
			// covers it" is exactly the wrong comfort here.
			return nil, nil, nil, checked, fmt.Errorf("go list: %s: a dependency does not build, so the package cannot be type-checked: %s",
				p.ImportPath, strings.SplitN(p.DepsErrors[0].Err, "\n", 2)[0])
		}
		rel, rerr := filepath.Rel(absRoot, p.Dir)
		if rerr != nil || skippedByDir(rel) {
			continue
		}
		names := append(append([]string(nil), p.GoFiles...), p.CgoFiles...)
		if len(names) == 0 {
			continue
		}
		var files []*ast.File
		for _, n := range names {
			full := filepath.Join(p.Dir, n)
			f, perr := parser.ParseFile(fset, full, nil, parser.SkipObjectResolution)
			if perr != nil {
				return nil, nil, nil, checked, perr
			}
			files = append(files, f)
			if key, kerr := filepath.Rel(absRoot, full); kerr == nil {
				active[filepath.ToSlash(key)] = true
			}
		}
		found, terr := scanTyped(fset, imp, p.ImportPath, files)
		if terr != nil {
			return nil, nil, nil, checked, terr
		}
		checked++
		for _, f := range found {
			key, kerr := filepath.Rel(absRoot, f.file)
			if kerr != nil {
				key = f.file
			}
			key = filepath.ToSlash(key)
			if _, ok := allow[key]; ok {
				alive[key] = true
				continue
			}
			if astSeen[fmt.Sprintf("%s:%d", key, f.line)] {
				continue
			}
			probs = append(probs, problem(fmt.Sprintf(
				"%s:%d: raw os pathname I/O (%s) reached without a call the AST stage can see — a function value, a dot import; route it through internal/datafile, or add an allowlist entry with a reason (gate 16, second stage)",
				key, f.line, f.what)))
		}
	}
	if checked == 0 {
		return nil, nil, nil, 0, errors.New("the type stage checked no package — it would pass on nothing")
	}
	return probs, alive, active, checked, nil
}

// typeSelftest — the second stage against built-in samples. Every sample
// is checked by BOTH stages: the samples the stage exists for are the
// ones the first stage passes and the second catches -- otherwise the
// second stage adds nothing, and the selftest will show that.
func typeSelftest() error {
	_, exports, err := goListExport(".", "os", "io/ioutil", "fmt")
	if err != nil {
		return err
	}
	type probe struct {
		name     string
		src      string
		wantAST  []string
		wantType []string
	}
	probes := []probe{
		{
			name: "a function value is caught only by types",
			src: `package p

import "os"

var readFile = os.ReadFile

func f(p string) ([]byte, error) { return readFile(p) }
`,
			wantAST:  nil,
			wantType: []string{"os.ReadFile"},
		},
		{
			name: "a dot import is caught only by types",
			src: `package p

import . "os"

func f(p string) error { return WriteFile(p, nil, 0o600) }
`,
			wantAST:  nil,
			wantType: []string{"os.WriteFile"},
		},
		{
			name: "a plain call is caught by both",
			src: `package p

import "io/ioutil"

func f(p string) ([]byte, error) { return ioutil.ReadFile(p) }
`,
			wantAST:  []string{"ioutil.ReadFile"},
			wantType: []string{"ioutil.ReadFile"},
		},
		{
			name: "benign calls and methods stay clean",
			src: `package p

import (
	"fmt"
	"os"
)

func f(dir string, fh *os.File) error {
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	if _, err := fh.ReadDir(-1); err != nil {
		return err
	}
	fmt.Println(dir)
	return os.Rename(dir, dir+".gone")
}
`,
		},
	}
	for _, p := range probes {
		astFound, err := scanFile(p.name+".go", []byte(p.src))
		if err != nil {
			return fmt.Errorf("type selftest %s: %v", p.name, err)
		}
		var gotAST []string
		for _, f := range dedupFindings(astFound) {
			gotAST = append(gotAST, f.what)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p.name+".go", p.src, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("type selftest %s: %v", p.name, err)
		}
		typed, err := scanTyped(fset, exportImporter(fset, exports), "p", []*ast.File{f})
		if err != nil {
			return fmt.Errorf("type selftest %s: %v", p.name, err)
		}
		var gotType []string
		for _, t := range typed {
			gotType = append(gotType, t.what)
		}
		sort.Strings(gotAST)
		sort.Strings(gotType)
		if fmt.Sprint(gotAST) != fmt.Sprint(p.wantAST) {
			return fmt.Errorf("type selftest %s: AST stage found %v, want %v", p.name, gotAST, p.wantAST)
		}
		if fmt.Sprint(gotType) != fmt.Sprint(p.wantType) {
			return fmt.Errorf("type selftest %s: type stage found %v, want %v", p.name, gotType, p.wantType)
		}
		fmt.Printf("selftest: ok - %s\n", p.name)
	}
	return nil
}
