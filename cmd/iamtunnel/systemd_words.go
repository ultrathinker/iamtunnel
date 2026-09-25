package main

import "strings"

// A systemd unit is not a shell script, and the paths install writes into
// one are written by systemd's own rules (R1-CX F-21). systemd splits
// ExecStart= and path lists such as ReadWritePaths= on whitespace, takes
// double and single quotes and backslashes as syntax, and expands
// %-specifiers on both lines and $-variables on the command line.
// gatewayUnitFile and machineUnitFile used to put the binary's path and
// the data directory in raw, so a data directory with a space in it
// reached the service as two arguments, and the sandbox as another path.

// refuseSystemdUnitPaths says, before install changes anything, that a
// path cannot be written into a systemd unit at all. Two kinds cannot: a
// relative one, which systemd resolves from / and not from the directory
// the operator typed it in, and one carrying a control character
// (refuseSystemdUnitControl). Everything else is quoted
// (systemdExecWord, systemdPathWord).
func refuseSystemdUnitPaths(path, bin, dataDir string) error {
	for _, p := range systemdUnitPaths(bin, dataDir) {
		if !strings.HasPrefix(p.value, "/") {
			return userErrf("iamtunnel %s: %s %q is not an absolute path, and systemd resolves a unit's paths from /, not from the directory this command was run in — give it as an absolute path and repeat.", path, p.what, p.value)
		}
	}
	return refuseSystemdUnitControl(path, bin, dataDir)
}

// refuseSystemdUnitControl refuses a path carrying a control character:
// no line of a unit can hold one, and a line break among them would end
// the directive and start another one, run under the unit's own account.
// It is the half of refuseSystemdUnitPaths the unit writers ask again
// themselves, right before they write.
func refuseSystemdUnitControl(path, bin, dataDir string) error {
	for _, p := range systemdUnitPaths(bin, dataDir) {
		for _, r := range p.value {
			if r < 0x20 || r == 0x7f {
				return userErrf("iamtunnel %s: %s %q carries a control character (%U), which no line of a systemd unit can hold — a line break would end the directive and start another one. Use a path without it.", path, p.what, p.value, r)
			}
		}
	}
	return nil
}

type systemdUnitPath struct{ what, value string }

func systemdUnitPaths(bin, dataDir string) []systemdUnitPath {
	return []systemdUnitPath{
		{"the path to this program", bin},
		{"the data directory", dataDir},
	}
}

// systemdExecWord writes one word of an ExecStart= line so that systemd
// reads back exactly it: % and $ doubled, since specifier and variable
// expansion would take them otherwise, and the word quoted when it holds
// anything systemd splits on or unescapes.
func systemdExecWord(w string) string {
	return systemdQuoted(strings.NewReplacer("%", "%%", "$", "$$").Replace(w))
}

// systemdPathWord writes one path of a path-list directive
// (ReadWritePaths=): specifiers are expanded there too, variables are not.
func systemdPathWord(p string) string {
	return systemdQuoted(strings.ReplaceAll(p, "%", "%%"))
}

// systemdQuoted wraps w in double quotes, with backslashes and double
// quotes escaped inside, when it holds whitespace, a quote or a
// backslash; systemd's word splitter takes the quotes and the escapes
// off again. A plain path stays as it was, so every unit an ordinary
// install has written reads the same as before.
func systemdQuoted(w string) string {
	if w != "" && !strings.ContainsAny(w, " \t\"'\\") {
		return w
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(w) + `"`
}
