//go:build ignore

// check_skips.go — an inventory of skipped checks (gate 10).
//
// Why it exists. Gate 9 catches a test that cannot go red. But there is
// a second way to get a green run while checking nothing: t.Skip. A run
// of nineteen scenarios, four of which are skipped, prints "ok" and
// reads as nineteen checks -- while there are fifteen. That is exactly
// what happened on 12.09 with the SPEC §8 end-to-end scenarios: the
// skips were honest, with reasons, but they were only noticed because
// the -v output was read by eye.
//
// What this gate does:
//
//  1. finds EVERY call of t.Skip / t.Skipf / t.SkipNow in the test files
//     of the listed packages and prints a full inventory: file, line,
//     test, reason;
//  2. fails when a skip has no intelligible reason -- an empty string,
//     a bare t.SkipNow() or t.Skip() without arguments. A reasonless
//     skip cannot be removed or justified a month later by anyone;
//  3. fails when the reason is shorter than minReasonLen characters:
//     "TODO" and "later" are not reasons.
//
// What it deliberately does NOT do: it does not forbid skips and does
// not freeze their number. A platform skip is a legitimate thing (a
// watchdog test makes no sense on Linux). The gate's goal is that no
// skip goes unnoticed, not that there are none.
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

// minReasonLen — below this a reason is not a reason but an excuse.
const minReasonLen = 12

type skip struct {
	File   string
	Line   int
	Test   string
	Call   string
	Reason string
	Bad    string // non-empty when the skip is unusable
}

func main() {
	flag.Parse()
	pkgs := flag.Args()
	if len(pkgs) == 0 {
		fmt.Fprintln(os.Stderr, "check_skips: no packages given")
		os.Exit(2)
	}

	var all []skip
	for _, p := range pkgs {
		dir := strings.TrimPrefix(filepath.Clean(p), "."+string(filepath.Separator))
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check_skips: %s: %v\n", dir, err)
			os.Exit(2)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			found, err := scanFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "check_skips: %s: %v\n", path, err)
				os.Exit(2)
			}
			all = append(all, found...)
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})

	bad := 0
	for _, s := range all {
		if s.Bad != "" {
			bad++
		}
	}

	fmt.Printf("skipped checks in the suite: %d\n", len(all))
	for _, s := range all {
		mark := " "
		if s.Bad != "" {
			mark = "!"
		}
		reason := s.Reason
		if reason == "" {
			reason = "(no reason given)"
		}
		fmt.Printf("  %s %s:%d %s -> %s: %s\n", mark, s.File, s.Line, s.Test, s.Call, oneLine(reason))
		if s.Bad != "" {
			fmt.Printf("      REJECTED: %s\n", s.Bad)
		}
	}
	if bad > 0 {
		fmt.Printf("%d skip(s) without a usable reason\n", bad)
		os.Exit(1)
	}
}

// oneLine squeezes a multi-line reason into one line so that the
// inventory stays readable: reasons in the code sometimes span three
// lines.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 140
	if len(s) > max {
		r := []rune(s)
		if len(r) > max {
			return string(r[:max]) + "..."
		}
	}
	return s
}

func scanFile(path string) ([]skip, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var out []skip
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		owner := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			if name != "Skip" && name != "Skipf" && name != "SkipNow" {
				return true
			}
			// Only methods on something resembling *testing.T/B/F: an
			// identifier or a field. A string literal like strings.Skip
			// does not concern us.
			if _, isIdent := sel.X.(*ast.Ident); !isIdent {
				if _, isSelector := sel.X.(*ast.SelectorExpr); !isSelector {
					return true
				}
			}

			s := skip{
				File: filepath.ToSlash(path),
				Line: fset.Position(call.Pos()).Line,
				Test: owner,
				Call: name,
			}
			s.Reason, s.Bad = reasonOf(name, call.Args)
			out = append(out, s)
			return true
		})
	}
	return out, nil
}

// reasonOf extracts the skip reason and decides whether it is usable.
func reasonOf(call string, args []ast.Expr) (string, string) {
	if call == "SkipNow" {
		return "", "t.SkipNow() leaves no reason: use t.Skip(\"...\") with an explanation instead"
	}
	if len(args) == 0 {
		return "", "t." + call + " without arguments leaves no reason"
	}
	var parts []string
	literalSeen := false
	for _, a := range args {
		lit, ok := a.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			v = strings.Trim(lit.Value, "`\"")
		}
		parts = append(parts, v)
		literalSeen = true
	}
	if !literalSeen {
		// The reason is built in a variable or formatted from values:
		// that is allowed, but the text cannot be checked -- so say so.
		return "(reason built at run time)", ""
	}
	reason := strings.TrimSpace(strings.Join(parts, " "))
	if reason == "" {
		return "", "the skip reason is an empty string"
	}
	if len([]rune(strings.Join(strings.Fields(reason), ""))) < minReasonLen {
		return reason, fmt.Sprintf("the reason is shorter than %d meaningful characters -- an excuse, not an explanation", minReasonLen)
	}
	return reason, ""
}
