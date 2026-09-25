//go:build ignore

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

type finding struct {
	file   string
	line   int
	column int
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if r >= '\u0400' && r <= '\u04ff' {
			return true
		}
	}
	return false
}

func scanFile(filename string, src []byte) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	findings := make([]finding, 0)
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil || !hasCyrillic(value) {
			return true
		}
		position := fset.Position(literal.Pos())
		findings = append(findings, finding{
			file:   filename,
			line:   position.Line,
			column: position.Column,
		})
		return true
	})
	return findings, nil
}

func scanRoot(root string) ([]finding, error) {
	findings := make([]finding, 0)
	for _, name := range []string{"internal", "cmd"} {
		directory := filepath.Join(root, name)
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fileFindings, err := scanFile(path, src)
			if err != nil {
				return err
			}
			findings = append(findings, fileFindings...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		if findings[i].line != findings[j].line {
			return findings[i].line < findings[j].line
		}
		return findings[i].column < findings[j].column
	})
	return findings, nil
}

func selftest() error {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "comment is ignored",
			src:  "package p\n// \u0440\u0443\u0441\u0441\u043a\u0438\u0439 \u043a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439\nconst message = \"English\"\n",
			want: 0,
		},
		{
			name: "interpreted literal is found",
			src:  "package p\nconst message = \"\u0440\u0443\u0441\u0441\u043a\u0438\u0439\"\n",
			want: 1,
		},
		{
			name: "raw literal is found",
			src:  "package p\nconst message = `\u0440\u0443\u0441\u0441\u043a\u0438\u0439`\n",
			want: 1,
		},
		{
			name: "unicode escape is found after decoding",
			src:  "package p\nconst message = \"\\u0410\"\n",
			want: 1,
		},
	}

	for _, test := range cases {
		findings, err := scanFile(test.name+".go", []byte(test.src))
		if err != nil {
			return fmt.Errorf("%s: parse failed: %w", test.name, err)
		}
		if len(findings) != test.want {
			return fmt.Errorf("%s: got %d findings, want %d", test.name, len(findings), test.want)
		}
	}
	return nil
}

func main() {
	root := flag.String("root", ".", "repository root to scan")
	selftestFlag := flag.Bool("selftest", false, "run the checker self-test")
	flag.Parse()

	if *selftestFlag {
		if err := selftest(); err != nil {
			fmt.Fprintln(os.Stderr, "check_cyrillic selftest:", err)
			os.Exit(1)
		}
		fmt.Println("check_cyrillic selftest: PASS")
		return
	}

	findings, err := scanRoot(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check_cyrillic:", err)
		os.Exit(1)
	}
	for _, item := range findings {
		fmt.Printf("%s:%d:%d: string literal contains Cyrillic\n", filepath.ToSlash(item.file), item.line, item.column)
	}
	if len(findings) != 0 {
		os.Exit(1)
	}
	fmt.Println("check_cyrillic: no Cyrillic in user-facing string literals")
}
