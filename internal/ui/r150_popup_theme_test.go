package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// V-06 (review of 1.50): the popup windows run on goroutines of their own,
// while CheckThemeSync replaces f.theme and f.isDark on the UI goroutine
// without f.mu. So a popup must be handed its theme by the UI goroutine
// and never read the frame's theme itself. A real window cannot be opened
// in a test, so this reads the source: the bodies of the popup functions
// must not call windowTheme or touch f.theme / f.isDark.
func TestR150_PopupsTakeTheirThemeOnTheUIGoroutine(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "popups.go", nil, 0)
	if err != nil {
		t.Fatalf("parse popups.go: %v", err)
	}
	popups := map[string]bool{"showFullText": false, "askRestartAsAdmin": false}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if _, watched := popups[fn.Name.Name]; !watched {
			continue
		}
		popups[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "f" {
				switch sel.Sel.Name {
				case "windowTheme", "theme", "isDark":
					t.Errorf("%s (a popup goroutine) reads f.%s at %s; take the theme on the UI goroutine and pass it in",
						fn.Name.Name, sel.Sel.Name, fset.Position(sel.Pos()))
				}
			}
			return true
		})
	}
	for name, seen := range popups {
		if !seen {
			t.Errorf("popups.go has no function %s any more; update this test", name)
		}
	}
}
