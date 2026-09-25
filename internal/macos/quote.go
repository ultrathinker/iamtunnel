package macos

import (
	"fmt"
	"strings"
)

// ShellQuote returns s as exactly one word of sh(1) input: wrapped in
// single quotes, and an embedded single quote spelled the standard way —
// close the quote, emit a backslash-escaped quote, reopen it. Inside
// single quotes sh treats every byte literally — no expansion of $, `, \
// or !, no word splitting on spaces, no command separator — so this holds
// for any input whatsoever and needs no "known-dangerous character" list
// to maintain.
//
// This is the reason IAMT-262 chose a script file over AppleScript string
// interpolation for Connect: a machine name reaches the shell only
// through here, so the name cannot become syntax no matter what it
// contains. (config.ValidName already restricts names to
// [a-z0-9._-]; the quoting is the second, independent line of defence,
// and it is the only one an ad-hoc --machine or a future caller with a
// path gets.)
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellCommand returns program plus args as one sh(1) command line, every
// word quoted by ShellQuote.
func ShellCommand(program string, args ...string) string {
	var b strings.Builder
	b.WriteString(ShellQuote(program))
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(ShellQuote(a))
	}
	return b.String()
}

// AppleScriptString returns s as an AppleScript string literal, quotes
// included: backslash and double quote are backslash-escaped, everything
// else is copied verbatim.
//
// A control character (including a raw newline, which an AppleScript
// literal simply cannot represent) is refused rather than dropped or
// mangled: a string we cannot quote exactly is a string we must not hand
// to osascript(1), whose parser would otherwise see our bytes as its own
// syntax. The caller has already shell-quoted its text by the time it
// gets here, so what is left to escape is the AppleScript layer only —
// two layers, each escaping for its own parser, in that order.
func AppleScriptString(s string) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			return "", fmt.Errorf("macos: refusing to build an AppleScript literal from %q: it contains a control character (U+%04X)", s, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// AppleScriptDoShellWithAdmin returns the osascript(1) argument that runs
// command (already shell-quoted, see ShellCommand) with administrator
// privileges: "do shell script "<command>" with administrator privileges".
// macOS answers it with the standard SecurityAgent consent dialog — the
// same "the person must agree" step UAC performs on Windows, with no
// password ever passing through iamtunnel.
//
// The command is handed over as data inside the AppleScript literal, and
// osascript itself is invoked with exec argv (never through a shell), so
// neither layer re-parses anything of ours as anything but a string.
func AppleScriptDoShellWithAdmin(command string) (string, error) {
	literal, err := AppleScriptString(command)
	if err != nil {
		return "", err
	}
	return "do shell script " + literal + " with administrator privileges", nil
}
