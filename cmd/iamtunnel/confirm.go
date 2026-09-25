package main

import (
	"bufio"
	"fmt"
	"strings"
)

// confirm is the uniform gate of the destructive commands. Every
// command that removes access or rotates trust — and only those —
// passes through it, and every one of them behaves the same way:
//
//   - with --yes: proceed, no question;
//   - interactive terminal without --yes: print the consequence sentence
//     and require a typed "yes"; anything else cancels;
//   - non-interactive (pipe, script) without --yes: refuse with the
//     consequence and the instruction to pass --yes.
//
// The gate runs after parsing and validation but before any execution,
// so a refusal always means nothing was touched.
func confirm(s *streams, fs *flagSet, path, consequence string) error {
	if fs.has("yes") {
		return nil
	}
	if !s.interactive {
		return userErrf("iamtunnel %s: refusing to act without confirmation — this command %s Pass --yes to confirm, or run it from an interactive terminal and answer the question.", path, consequence)
	}
	fmt.Fprintf(s.errs, "iamtunnel %s: this command %s\nType \"yes\" to confirm (anything else cancels): ", path, consequence)
	sc := bufio.NewScanner(s.in)
	if !sc.Scan() {
		return userErrf("iamtunnel %s: no answer read — cancelled, nothing was changed.", path)
	}
	if !strings.EqualFold(strings.TrimSpace(sc.Text()), "yes") {
		return userErrf("iamtunnel %s: cancelled — nothing was changed.", path)
	}
	return nil
}
