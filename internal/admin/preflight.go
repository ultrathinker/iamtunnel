package admin

// preflight.go - the version preflight of PROTOCOL §1.1 (R2-CX F-06):
// before its first application operation a client runs whoami, the one
// request allowed before the gateway's version is known, and goes no
// further with a gateway that refuses it or answers in a protocol this
// client does not speak. Conn used to send the chosen command first -
// people.add, grants.revoke, any change - and learnt about an
// incompatibility, if at all, from the answer to a change already made.

import (
	"fmt"
	"sync"
)

// oneCommandLogins carry exactly one command of their own - enrol's
// enrol, bootstrap's admin.claim, pairing's admin.pair - and refuse whoami
// (PROTOCOL §1.1, §3.4): they are not preflighted.
var oneCommandLogins = map[string]bool{"enrol": true, "bootstrap": true, "pairing": true}

// preflight is one connection's version preflight: whoami, run once,
// before the first command that is not whoami itself.
type preflight struct {
	needed bool
	mu     sync.Mutex
	done   bool
}

// ensurePreflight runs the preflight before command, unless it has run,
// is not this connection's to run, or command is whoami. Commands issued
// together wait for the one preflight. A preflight that fails leaves the
// connection broken - a caller that keeps it (the window) dials anew - and
// its error is the command's: the command itself is never sent.
func (c *Conn) ensurePreflight(command string) error {
	if !c.preflight.needed || command == "whoami" {
		return nil
	}
	c.preflight.mu.Lock()
	defer c.preflight.mu.Unlock()
	if c.preflight.done {
		return nil
	}
	if _, err := c.Exec("whoami", map[string]any{"proto": 1}); err != nil {
		c.broken.Store(true)
		return fmt.Errorf("admin: the version preflight (whoami, PROTOCOL §1.1) before %q failed, so %q was not sent: %w", command, command, err)
	}
	c.preflight.done = true
	return nil
}
