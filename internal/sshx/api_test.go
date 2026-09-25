package sshx

// api_test.go: a guard on the package's exported surface.
//
// Round 3's rule: any way an importer could change an invariant's
// behavior is reason to return the whole piece of work. An exported
// package variable, an exported setter, an exported field with that
// same effect, a constructor parameter, reading an environment
// variable or a file, a build tag.
//
// The three tests below check this not by eye but by parsing the
// package's own sources:
//   - not a single exported package-level var;
//   - not a single exported field on a type that carries policy;
//   - not a single read of the environment or file system, and not a
//     single build tag.
//
// The full list of what is exported is printed by
// TestExportedSurfaceIsFunctionsOnly: it writes down everything the
// package exports.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// packageFiles parses the package's non-test .go files (excluding _test.go).
func packageFiles(t *testing.T) (*token.FileSet, []*ast.File, []string) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	var paths []string
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files = append(files, f)
		paths = append(paths, name)
	}
	if len(files) == 0 {
		t.Fatal("no package sources found")
	}
	return fset, files, paths
}

// TestNoExportedPackageVariables — the main guard. An exported mutable
// package variable hands write access to a security policy to any
// importer: one line, `sshx.AllowedEnvNames["LD_PRELOAD"] = struct{}{}`,
// from internal/gateway, would let an arbitrary variable through to the
// target machine, and `sshx.ChannelRequestTable[i].Disp = sshx.Forward`
// would enable sftp.
//
// Sentinel errors must also be constants: reassigning ErrShortPayload
// would break errors.Is for every caller.
func TestNoExportedPackageVariables(t *testing.T) {
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for _, name := range vs.Names {
					if name.Name == "_" {
						continue // var _ net.Conn = ... — a type check, not state
					}
					if ast.IsExported(name.Name) {
						t.Errorf("%s: exported package variable %s — any importer could overwrite it; make it unexported or a constant",
							fset.Position(name.Pos()), name.Name)
					}
				}
			}
		}
	}
}

// TestNoExportedFieldsOnPolicyTypes — an exported field on a type that
// carries policy is the same kind of switch, just through a value.
// Keepalive is deliberately configured from outside (interval and
// threshold are deployment parameters, not an invariant), while
// EnvBudget must be closed: the limit cannot be raised from outside.
func TestNoExportedFieldsOnPolicyTypes(t *testing.T) {
	closed := map[string]bool{"EnvBudget": true, "ChannelConn": true}
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				if !closed[ts.Name.Name] {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					if len(field.Names) == 0 {
						// An embedded type is also an exported field:
						// `cc.Channel = someoneElses` would bypass all deadline bookkeeping.
						t.Errorf("%s: %s embeds a type; embedding exposes the field — put it in an unexported field instead",
							fset.Position(field.Pos()), ts.Name.Name)
						continue
					}
					for _, name := range field.Names {
						if ast.IsExported(name.Name) {
							t.Errorf("%s: %s.%s is exported; this type's policy must not be changeable from outside",
								fset.Position(name.Pos()), ts.Name.Name, name.Name)
						}
					}
				}
			}
		}
	}
}

// TestNoExternalSwitches — no reading the environment, no files, no
// build tags, no init(). The package's behavior is determined only by its sources.
func TestNoExternalSwitches(t *testing.T) {
	_, _, paths := packageFiles(t)
	banned := []string{
		"os.Getenv", "os.LookupEnv", "os.Environ",
		"os.Open", "os.ReadFile", "os.Stat",
		"//go:build", "// +build",
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range banned {
			if strings.Contains(src, bad) {
				t.Errorf("%s: found an external switch %q", p, bad)
			}
		}
	}
	_, files, _ := packageFiles(t)
	for _, f := range files {
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "init" {
				t.Errorf("%s: init() in the package", f.Name.Name)
			}
		}
	}
}

// TestExportedSurfaceIsFunctionsOnly — the full list of what is
// exported, checked against what is expected. Any new exported name
// must be added here deliberately, along with an answer to "can this
// be used to weaken the invariant" in the report.
func TestExportedSurfaceIsFunctionsOnly(t *testing.T) {
	want := map[string]string{
		// types
		"Disposition":  "type",
		"Keepalive":    "type",
		"ChannelConn":  "type",
		"EnvBudget":    "type",
		"PTYRequest":   "type",
		"WindowChange": "type",
		"Exec":         "type",
		"Env":          "type",
		"Signal":       "type",
		"ExitStatus":   "type",
		"ExitSignal":   "type",
		// constants
		"Reject":                   "const",
		"Drop":                     "const",
		"Answer":                   "const",
		"Forward":                  "const",
		"MaxEnvNameLen":            "const",
		"MaxEnvValueLen":           "const",
		"MaxEnvRequests":           "const",
		"DefaultKeepaliveInterval": "const",
		"DefaultKeepaliveMisses":   "const",
		"DefaultKeepaliveName":     "const",
		"ExitStatusGrace":          "const",
		"ErrShortPayload":          "const",
		"ErrDeadlineExceeded":      "const",
		// channel-open with a deadline (IAMT-450): two sentinel
		// constants and a stateless function; no policy in them, nothing to weaken.
		"ErrOpenChannelTimeout": "const",
		"ErrOpenChannelStopped": "const",
		// functions
		"LookupChannelRequest":        "func",
		"LookupGlobalRequest":         "func",
		"EnvDisposition":              "func",
		"IsKnownChannelRequest":       "func",
		"IsKnownGlobalRequest":        "func",
		"IsChannelControlPacket":      "func",
		"IsCompatibilityNotification": "func",
		"ApplyDisposition":            "func",
		"OpenChannelWithDeadline":     "func",
		"NewEnvBudget":                "func",
		"NewChannelConn":              "func",
		"MarshalPTY":                  "func",
		"MarshalWindow":               "func",
		"MarshalExec":                 "func",
		"MarshalEnv":                  "func",
		"MarshalSignal":               "func",
		"MarshalExitStatus":           "func",
		"MarshalExitSignal":           "func",
		"ParsePTY":                    "func",
		"ParseWindow":                 "func",
		"ParseExec":                   "func",
		"ParseEnv":                    "func",
		"ParseSignal":                 "func",
		"ParseExitStatus":             "func",
		"ParseExitSignal":             "func",
		// PROTOCOL §1 crypto policy (IAMT-173): the lists are
		// unexported, only copies and application to ssh.Config are
		// exposed; an importer cannot weaken the policy through these names.
		"KEX":               "func",
		"Ciphers":           "func",
		"MACs":              "func",
		"HostKeyAlgos":      "func",
		"ApplyServerConfig": "func",
		"ApplyClientConfig": "func",
	}

	got := map[string]string{}
	fset, files, _ := packageFiles(t)
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil { // a method: counted via its own type
					continue
				}
				if ast.IsExported(d.Name.Name) {
					got[d.Name.Name] = "func"
				}
			case *ast.GenDecl:
				kind := ""
				switch d.Tok {
				case token.TYPE:
					kind = "type"
				case token.CONST:
					kind = "const"
				case token.VAR:
					kind = "var"
				default:
					continue
				}
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(s.Name.Name) {
							got[s.Name.Name] = kind
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if ast.IsExported(n.Name) {
								got[n.Name] = kind
								if kind == "var" {
									t.Errorf("%s: %s is exported as a var", fset.Position(n.Pos()), n.Name)
								}
							}
						}
					}
				}
			}
		}
	}

	var missing, extra []string
	for name, kind := range want {
		if g, ok := got[name]; !ok {
			missing = append(missing, name)
		} else if g != kind {
			t.Errorf("%s is declared as %s, wanted %s", name, g, kind)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("disappeared from the export: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("new exported names not added to the gate 3 list: %v", extra)
	}
}
