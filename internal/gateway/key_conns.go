package gateway

// key_conns.go - a person's connection lasts only as long as the key it
// authenticated with is still that person's (IAMT-449).
//
// The handshake proves a key and resolves it to a person; after it, the
// connection used to carry only the person's name. runCommand checks that
// name's role afresh on every command, but nothing checked the key: a key
// taken away with people.keys.remove - or with its person, by
// people.remove - kept every connection it had opened, and on a command
// login that means every command the person may run, people.keys.add
// included. So every person connection is tracked with its key. A command
// login checks the key right before each command it runs, and after each
// command every connection whose key is no longer its person's is ended:
// a command login is closed, a session to a machine is killed the way
// sessions.kill kills one - machine side first, the person told why, the
// drop journaled with the reason.

import (
	"sync"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// keyConn is one person connection being served and the key it
// authenticated with.
type keyConn struct {
	person      string
	fingerprint string
	addr        string
	// close ends the connection.
	close func() error

	mu sync.Mutex
	// session is the session to a machine the connection carries once the
	// ACL engine has opened it; zero before that and on a command login.
	session acl.SessionID
}

// carries records the session the connection has opened, so that a cut
// ends it through the ACL engine rather than by dropping the connection
// under it.
func (kc *keyConn) carries(id acl.SessionID) {
	kc.mu.Lock()
	kc.session = id
	kc.mu.Unlock()
}

// trackKeyConn adds kc to the connections cutRemovedKeys looks at; the
// returned func takes it out again.
func (g *Gateway) trackKeyConn(kc *keyConn) (untrack func()) {
	g.keyConnsMu.Lock()
	if g.keyConns == nil {
		g.keyConns = map[*keyConn]struct{}{}
	}
	g.keyConns[kc] = struct{}{}
	g.keyConnsMu.Unlock()
	return func() {
		g.keyConnsMu.Lock()
		delete(g.keyConns, kc)
		g.keyConnsMu.Unlock()
	}
}

// keyHeld reports whether kc's key still belongs to kc's person in st.
func keyHeld(st state.State, kc *keyConn) bool {
	owner, ok := personWithKey(st, kc.fingerprint)
	return ok && owner == kc.person
}

// keyStillHeld is keyHeld against the state as it is now.
func (g *Gateway) keyStillHeld(kc *keyConn) bool {
	return keyHeld(g.cfg.Store.Get(), kc)
}

// afterKeyCheckFn is the seam the F-07 test parks a command session on,
// between the key check and the dispatch, to hold the race window open.
// It names the session's person and command so a test can pick one
// session out of many. Production leaves it nil.
var afterKeyCheckFn func(person, command string)

// keyGate binds a command session's key check to its command (F-07,
// 24.09.2026). The check alone was one state read, and a revocation could
// land between the check and the command, which then ran anyway and
// changed the state after a completed revocation. A command session now
// holds the gate for reading across the check and the whole command, and
// a key-revoking command holds it for writing across its own run: the
// revocation either waits for the in-flight command, which then ran
// while its key was still registered, or lands first, and the next
// command's check refuses it. The store's own lock cannot play this
// role: the command writes the state inside runCommand, so a store read
// lock held across it would deadlock its own write.
var keyGate sync.RWMutex

// commandsThatRevokeKeys are the admin commands that can leave a key no
// longer its person's: people.remove takes the person and the keys with
// them, people.keys.remove the key, and people.rename moves the keys to
// a name the open connections no longer carry. These hold the gate for
// writing; every other command holds it for reading.
var commandsThatRevokeKeys = map[string]bool{
	"people.remove":      true,
	"people.keys.remove": true,
	"people.rename":      true,
}

// cutRemovedKeys ends every tracked connection whose key is no longer its
// person's.
func (g *Gateway) cutRemovedKeys() {
	st := g.cfg.Store.Get()
	var gone []*keyConn
	g.keyConnsMu.Lock()
	for kc := range g.keyConns {
		if !keyHeld(st, kc) {
			gone = append(gone, kc)
		}
	}
	g.keyConnsMu.Unlock()
	for _, kc := range gone {
		g.cutKeyConn(kc)
	}
}

// cutKeyConn ends kc: a connection that carries a session through the ACL
// engine, anything else by closing the connection.
//
// A session the engine no longer knows has already ended or is ending - a
// revoke got there first (people.remove revokes the person's grants), or
// it closed on its own - and that path closes the connection itself.
// Closing it here as well would cut off the line the person is being told.
func (g *Gateway) cutKeyConn(kc *keyConn) {
	kc.mu.Lock()
	id := kc.session
	kc.mu.Unlock()
	if id.Valid() {
		g.aclE.Kill(id, g.cfg.Now(), acl.DenyKeyRemoved)
		return
	}
	_ = kc.close()
}
