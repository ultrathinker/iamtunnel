package main

// R1-CX F-21: gatewayUnitFile and machineUnitFile put the binary's path
// and the data directory into ExecStart= and ReadWritePaths= as raw text.
// systemd reads those lines by its own rules, not a shell's: it splits
// them on whitespace, takes quotes and backslashes as syntax, expands
// %-specifiers on both lines and $-variables on the command line. So
// "gateway install --data-dir '/srv/IAM Tunnel'" wrote a unit that runs
// "gateway run --data-dir /srv/IAM Tunnel --port ..." - a data directory
// "/srv/IAM" and a stray argument - and hands the sandbox a different
// path again.
//
// There is no systemd on the machines these tests run on, so the reader
// below is systemd's own, written down: extract_first_word with
// EXTRACT_UNQUOTE (plus EXTRACT_CUNESCAPE on the command line), the
// specifier pass that turns %% into %, and the environment pass that
// turns $$ into $. Anything else after a % or a $ is an expansion
// systemd would make, and the test calls that out rather than guessing.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// r1cxF21Words splits one unit value into words the way systemd's
// extract_first_word does. cunescape says whether a backslash starts a
// C escape (the command line) or merely makes the next character literal
// (path lists).
func r1cxF21Words(value string, cunescape bool) ([]string, error) {
	var words []string
	i := 0
	for {
		for i < len(value) && strings.ContainsRune(" \t\n\r", rune(value[i])) {
			i++
		}
		if i >= len(value) {
			return words, nil
		}
		var b strings.Builder
		var quote byte
		for ; i < len(value); i++ {
			c := value[i]
			if c == '\\' {
				i++
				if i >= len(value) {
					return nil, fmt.Errorf("a backslash ends %q", value)
				}
				n := value[i]
				if cunescape {
					switch n {
					case '\\', '"', '\'', ' ':
						b.WriteByte(n)
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					default:
						return nil, fmt.Errorf("escape \\%c in %q is one this reader does not model", n, value)
					}
				} else {
					b.WriteByte(n)
				}
				continue
			}
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					b.WriteByte(c)
				}
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
				continue
			}
			if strings.ContainsRune(" \t\n\r", rune(c)) {
				break
			}
			b.WriteByte(c)
		}
		if quote != 0 {
			return nil, fmt.Errorf("unbalanced quote in %q", value)
		}
		words = append(words, b.String())
	}
}

// r1cxF21Expand undoes one of systemd's doubled characters (%% or $$)
// and refuses any other use of it: that one would be expanded.
func r1cxF21Expand(s string, mark byte) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != mark {
			b.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == mark {
			b.WriteByte(mark)
			i++
			continue
		}
		return "", fmt.Errorf("%q carries a bare %c that systemd would expand", s, mark)
	}
	return b.String(), nil
}

// r1cxF21Directive is the value of the one line of unit starting key=.
func r1cxF21Directive(unit, key string) (string, error) {
	var found []string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, key+"=") {
			found = append(found, strings.TrimPrefix(line, key+"="))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("the unit has %d %s= lines, want exactly one", len(found), key)
	}
	return found[0], nil
}

// r1cxF21Exec is the argv systemd starts from a unit's ExecStart=.
func r1cxF21Exec(unit string) ([]string, error) {
	line, err := r1cxF21Directive(unit, "ExecStart")
	if err != nil {
		return nil, err
	}
	if line, err = r1cxF21Expand(line, '%'); err != nil {
		return nil, err
	}
	words, err := r1cxF21Words(line, true)
	if err != nil {
		return nil, err
	}
	for i, w := range words {
		if words[i], err = r1cxF21Expand(w, '$'); err != nil {
			return nil, err
		}
	}
	return words, nil
}

// r1cxF21Paths is the path list systemd reads from a unit's key=.
func r1cxF21Paths(unit, key string) ([]string, error) {
	line, err := r1cxF21Directive(unit, key)
	if err != nil {
		return nil, err
	}
	words, err := r1cxF21Words(line, false)
	if err != nil {
		return nil, err
	}
	for i, w := range words {
		if words[i], err = r1cxF21Expand(w, '%'); err != nil {
			return nil, err
		}
	}
	return words, nil
}

// r1cxF21Paths are data directories and binaries an operator can
// really have, each one a different piece of systemd's syntax.
var r1cxF21Cases = []struct {
	name, bin, dataDir string
}{
	{"a space in the data directory", "/usr/local/bin/iamtunnel", "/srv/IAM Tunnel"},
	{"a space in the binary's path", "/opt/IAM Tunnel/iamtunnel", "/var/lib/iamtunnel"},
	{"a percent sign", "/usr/local/bin/iamtunnel", "/srv/iamt-100%"},
	{"a dollar sign", "/opt/$HOME/iamtunnel", "/srv/iamt$1"},
	{"quotes", "/usr/local/bin/iamtunnel", `/srv/it's a "gateway"`},
	{"a backslash", "/usr/local/bin/iamtunnel", `/srv/back\slash`},
}

func TestR1CX_F21_TheGatewayUnitStartsExactlyTheDirectoryInstallWasGiven(t *testing.T) {
	for _, c := range r1cxF21Cases {
		t.Run(c.name, func(t *testing.T) {
			unit := gatewayUnitFile(c.bin, c.dataDir, 2222, "gw.example.test")
			want := []string{c.bin, "gateway", "run", "--data-dir", c.dataDir, "--port", "2222", "--public-host", "gw.example.test"}
			if got, err := r1cxF21Exec(unit); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("systemd starts %q (%v) from the gateway unit, want %q", got, err, want)
			}
			if got, err := r1cxF21Paths(unit, "ReadWritePaths"); err != nil || !reflect.DeepEqual(got, []string{c.dataDir}) {
				t.Fatalf("systemd opens %q (%v) for writing in the gateway unit's sandbox, want exactly [%q]", got, err, c.dataDir)
			}
		})
	}
}

func TestR1CX_F21_TheMachineUnitStartsExactlyTheDirectoryInstallWasGiven(t *testing.T) {
	for _, c := range r1cxF21Cases {
		t.Run(c.name, func(t *testing.T) {
			unit := machineUnitFile(c.bin, c.dataDir)
			want := []string{c.bin, "server", "start", "--data-dir", c.dataDir}
			if got, err := r1cxF21Exec(unit); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("systemd starts %q (%v) from the machine unit, want %q", got, err, want)
			}
		})
	}
}

// What no unit line can carry is refused before install changes
// anything: a line break would end the directive and start another one
// under the service's own account, and a relative path would be
// resolved from / by systemd rather than from the operator's directory.
// runGatewayInstall and runServerInstall ask refuseSystemdUnitPaths on
// Linux before they create anything; the unit writers, which the other
// tests of this package drive on any host, ask the control-character
// half again right before they write.
func TestR1CX_F21_APathNoUnitCanCarryIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, c := range []struct {
		name, bin, dataDir string
		noLineCanHold      bool
	}{
		{"a line break in the data directory", "/usr/local/bin/iamtunnel", "/srv/iamt\nExecStartPre=/bin/sh -c id", true},
		{"a relative data directory", "/usr/local/bin/iamtunnel", "srv/iamt", false},
		{"a control character in the binary's path", "/opt/iam\x01/iamtunnel", "/var/lib/iamtunnel", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := refuseSystemdUnitPaths("gateway install", c.bin, c.dataDir); err == nil {
				t.Fatalf("refuseSystemdUnitPaths accepted bin %q, data directory %q", c.bin, c.dataDir)
			}
			if !c.noLineCanHold {
				return
			}
			rec := &systemdRecorder{}
			if err := setupSystemd(rec.setup(), c.bin, c.dataDir, 2222, "gw.example.test"); err == nil {
				t.Fatal("the gateway's systemd install accepted it")
			}
			if len(rec.createUserCalls) != 0 || len(rec.chownDirCalls) != 0 || rec.unitContent != "" || len(rec.systemctlCalls) != 0 {
				t.Fatalf("the gateway's systemd install refused only after changing something: users %v, chown %v, unit %q, systemctl %v", rec.createUserCalls, rec.chownDirCalls, rec.unitContent, rec.systemctlCalls)
			}
			rec = &systemdRecorder{}
			if err := setupMachineSystemd(rec.setup(), c.bin, c.dataDir); err == nil {
				t.Fatal("the machine's systemd install accepted it")
			}
			if rec.unitContent != "" || len(rec.systemctlCalls) != 0 {
				t.Fatalf("the machine's systemd install refused only after writing: unit %q, systemctl %v", rec.unitContent, rec.systemctlCalls)
			}
		})
	}
}
