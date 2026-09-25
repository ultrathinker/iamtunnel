package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// connectionFile is the file name of the persisted connection string
// inside the client data directory. The directory itself is resolved by
// cmd/iamtunnel (config.Dirs.Client / --data-dir); this package never
// guesses it and never falls back to a real ssh directory.
const connectionFile = "connection.json"

// ConnectionPath returns the path Save/LoadConnection use inside dir.
func ConnectionPath(dir string) string { return filepath.Join(dir, connectionFile) }

// LoadConnections reads everything this machine remembers about
// gateways. A missing file is reported as os.ErrNotExist (via
// errors.Is) so callers can tell "never configured" from "broken".
//
// The read is datafile.ReadFile (IAMT-332 round 9): the client directory
// may be attacker-controlled whenever a privileged command is aimed at
// it (SPEC §3.1), so a symlink or FIFO planted at the saved
// connection's name is refused instead of being read through or wedged
// on.
func LoadConnections(dir string) (Connections, error) {
	var zero Connections
	data, err := datafile.ReadFile(ConnectionPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return zero, err
		}
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("saved connections %s cannot be read: %v", ConnectionPath(dir), err)}
	}
	return decodeConnections(data, ConnectionPath(dir))
}

// LoadConnection reads the gateway every other command acts on.
//
// Its signature is untouched on purpose. Some thirty callers ask this
// package for "the connection" and mean "the one I am working with now";
// making each of them choose from a list would have spread the choice
// across the program instead of keeping it in the one place a person
// makes it. The list is a thing the Client tab and three CLI verbs know
// about; to everything else there is still exactly one gateway.
func LoadConnection(dir string) (config.ConnString, error) {
	set, err := LoadConnections(dir)
	if err != nil {
		return config.ConnString{}, err
	}
	g, ok := set.CurrentGateway()
	if !ok {
		// The file exists and names no gateway. To a caller that is the
		// same news as no file at all -- nothing is saved -- and it must
		// arrive as the same error, or every "have you connected yet?"
		// check in the program would have to learn a second shape of no.
		return config.ConnString{}, os.ErrNotExist
	}
	return g.ConnString(), nil
}

// midTransaction, when a test sets it, runs inside every change of the
// saved connections between its read and its write: the moment a second
// writer's change used to be lost (R1-CX F-17). Nil in the product.
var midTransaction func()

// loadForChange is LoadConnections for a change that is about to write
// back what it read.
func loadForChange(dir string) (Connections, error) {
	set, err := LoadConnections(dir)
	if midTransaction != nil {
		midTransaction()
	}
	return set, err
}

// SaveConnections writes the whole set, repairing the current pointer
// first. It is the one place the file is written.
//
// The write is made under the store's lock (R1-CX F-17), so it never
// lands in the middle of another writer's change. A caller that read the
// set on its own is still racing whoever writes after that read; the
// changes below read under the same lock they write under.
func SaveConnections(dir string, set Connections) error {
	set.normalise()
	return changeStore(dir, len(set.Gateways) > 0, func() error {
		return saveConnectionsLocked(dir, set)
	})
}

// saveConnectionsLocked is SaveConnections for a caller that already
// holds the store's lock.
func saveConnectionsLocked(dir string, set Connections) error {
	set.normalise()
	if len(set.Gateways) == 0 {
		_, err := forgetAllLocked(dir)
		return err
	}
	return atomicWriteJSON(dir, connectionFile, set)
}

// SelectConnection makes one remembered gateway the current one.
//
// Nothing is dialled and nothing is verified here: the key is already
// this machine's, and the gateway already holds it. That is the whole
// point of the owner's request -- switching is a pointer move, not a
// login.
func SelectConnection(dir, name string) (Gateway, error) {
	var selected Gateway
	err := changeStore(dir, false, func() error {
		set, err := loadForChange(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return &config.Error{Class: config.ClassUser, Msg: "no gateway is saved yet — save a connection string first"}
			}
			return err
		}
		g, ok := set.Find(name)
		if !ok {
			return &config.Error{Class: config.ClassUser, Msg: fmt.Sprintf(
				"no saved gateway is called %q — the saved ones are: %s", name, strings.Join(set.names(), ", "))}
		}
		set.Current = g.Name
		if err := saveConnectionsLocked(dir, set); err != nil {
			return err
		}
		selected = g
		return nil
	})
	return selected, err
}

// RenameConnection relabels one entry, keeping the current pointer on it
// if that is where it was.
func RenameConnection(dir, name, newName string) (Gateway, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return Gateway{}, &config.Error{Class: config.ClassUser, Msg: "a gateway needs a name — it is what you switch to it by"}
	}
	var renamed Gateway
	err := changeStore(dir, false, func() error {
		set, err := loadForChange(dir)
		if err != nil {
			return err
		}
		for i := range set.Gateways {
			if !strings.EqualFold(set.Gateways[i].Name, name) {
				continue
			}
			wasCurrent := strings.EqualFold(set.Current, set.Gateways[i].Name)
			set.Gateways[i].Name = uniqueName(set, newName, i)
			if wasCurrent {
				set.Current = set.Gateways[i].Name
			}
			if err := saveConnectionsLocked(dir, set); err != nil {
				return err
			}
			renamed = set.Gateways[i]
			return nil
		}
		return &config.Error{Class: config.ClassUser, Msg: fmt.Sprintf(
			"no saved gateway is called %q", name)}
	})
	return renamed, err
}

// names lists the saved labels, for a refusal that helps.
func (c Connections) names() []string {
	out := make([]string, 0, len(c.Gateways))
	for _, g := range c.Gateways {
		out = append(out, g.Name)
	}
	return out
}

// SaveConnection remembers cs and makes it the current gateway.
//
// It keeps the old signature so the CLI, the pairing path and the admin
// claim path need no change; SaveConnectionNamed is the same work with a
// label chosen by the person.
func SaveConnection(dir string, cs config.ConnString, replace bool) error {
	_, err := SaveConnectionNamed(dir, cs, "", replace)
	return err
}

// SaveConnectionNamed adds or updates one gateway and selects it.
//
// WHAT replace GUARDS NOW. It used to mean "yes, throw away the gateway
// I had": any second gateway tripped it, because there was room for
// exactly one. With a list, a second gateway threatens nothing, so
// adding one is simply allowed -- that is the owner's whole request.
//
// What remains guarded is the case that was always the dangerous one
// and was hidden inside the other: the SAME person on the SAME gateway,
// presenting a DIFFERENT host key. That is not a new place to connect
// to, it is the same address with a different lock, and the honest
// readings are "the gateway was rebuilt" and "somebody is standing
// between you and it". A person must say which. So the guard did not go
// away; it stopped firing on the harmless case and now fires only on
// the one it was written for.
func SaveConnectionNamed(dir string, cs config.ConnString, name string, replace bool) (Gateway, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultName(cs)
	}
	var saved Gateway
	err := changeStore(dir, true, func() error {
		set, err := loadForChange(dir)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrNotExist):
			set = Connections{}
		default:
			return err
		}

		for i := range set.Gateways {
			if !sameDoor(set.Gateways[i], cs) {
				continue
			}
			if set.Gateways[i].Fingerprint != cs.Fingerprint && !replace {
				return &config.Error{Class: config.ClassUser, Msg: fmt.Sprintf(
					"%s is already saved as %q, but with a different gateway key (%s, now %s) — "+
						"either that gateway was rebuilt, or something is standing between you and it. "+
						"Pass --replace once you know which.",
					cs.Person+"@"+cs.Host+":"+strconv.Itoa(cs.Port), set.Gateways[i].Name,
					set.Gateways[i].Fingerprint, cs.Fingerprint)}
			}
			set.Gateways[i].Fingerprint = cs.Fingerprint
			// A name given explicitly renames; an empty one leaves the label
			// the person already chose alone. Re-saving the same string must
			// not quietly rename "Work" back to its host.
			if strings.TrimSpace(name) != "" && name != defaultName(cs) {
				set.Gateways[i].Name = uniqueName(set, name, i)
			}
			set.Current = set.Gateways[i].Name
			if err := saveConnectionsLocked(dir, set); err != nil {
				return err
			}
			saved = set.Gateways[i]
			return nil
		}

		g := Gateway{
			Name: uniqueName(set, name, -1), Host: cs.Host, Port: cs.Port,
			Person: cs.Person, Fingerprint: cs.Fingerprint,
		}
		set.Gateways = append(set.Gateways, g)
		set.Current = g.Name
		if err := saveConnectionsLocked(dir, set); err != nil {
			return err
		}
		saved = g
		return nil
	})
	return saved, err
}

// ForgetConnection drops the CURRENT gateway, so this machine stops
// acting as anybody there (IAMT-356). It reports whether there was one
// to forget.
//
// With more than one saved, the next one in the list takes over rather
// than leaving the machine connected to nothing: forgetting one gateway
// is not a statement about the others.
//
// The KEY stays. It is this machine's identity, not the gateway's
// opinion of it, and deleting it would break every other gateway this
// machine is also enrolled with -- which, since today, is a thing that
// actually happens. Nor does this touch the gateway: the person record
// there survives, with this key still on it. That asymmetry is the
// honest one -- a client can always forget, only an administrator can
// revoke -- and the card that offers this says so.
func ForgetConnection(dir string) (bool, error) {
	return forgetOne(dir, func(set Connections) (Gateway, bool) { return set.CurrentGateway() })
}

// ForgetGateway drops one gateway by name.
func ForgetGateway(dir, name string) (bool, error) {
	return forgetOne(dir, func(set Connections) (Gateway, bool) { return set.Find(name) })
}

// forgetOne drops the gateway pick chooses from the list as it is under
// the store's lock, and reports whether there was one.
func forgetOne(dir string, pick func(Connections) (Gateway, bool)) (bool, error) {
	had := false
	err := changeStore(dir, false, func() error {
		set, err := loadForChange(dir)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrNotExist):
			return nil
		default:
			return err
		}
		g, ok := pick(set)
		if !ok {
			return nil
		}
		had = true
		return forget(dir, &set, g.Name)
	})
	return had, err
}

// forget writes set without name; the caller holds the store's lock.
func forget(dir string, set *Connections, name string) error {
	kept := set.Gateways[:0]
	for _, g := range set.Gateways {
		if !strings.EqualFold(g.Name, name) {
			kept = append(kept, g)
		}
	}
	set.Gateways = kept
	if strings.EqualFold(set.Current, name) {
		set.Current = ""
	}
	return saveConnectionsLocked(dir, *set)
}

// ForgetAll removes the record entirely -- the file, not one entry.
func ForgetAll(dir string) (bool, error) {
	had := false
	err := changeStore(dir, false, func() error {
		var err error
		had, err = forgetAllLocked(dir)
		return err
	})
	return had, err
}

// forgetAllLocked is ForgetAll for a caller that already holds the
// store's lock. The lock file stays where it is: a writer waiting for it
// holds it open, and a new one in its place would lock nobody out.
func forgetAllLocked(dir string) (bool, error) {
	err := os.Remove(ConnectionPath(dir))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, classifyPathErr(err, ConnectionPath(dir))
}

// atomicWriteJSON marshals v and writes it to dir/name via datafile's
// one atomic replace, so a crash mid-write never leaves a half-written
// file behind and a planted entry at the name is never written through
// (IAMT-332 round 9: this file used to build the predictable
// final+".tmp" itself; the same admin/--data-dir reachability as
// keys.go applies). Permissions are owner-only: the file holds the
// gateway's pinned fingerprint, which is a security-relevant fact even
// though it is not a secret by itself.
func atomicWriteJSON(dir, name string, v interface{}) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return classifyPathErr(err, dir)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("client: marshal %s: %w", name, err)
	}
	data = append(data, '\n')
	return datafile.WriteFileAtomic(filepath.Join(dir, name), data, datafile.WithMode(0o600))
}

// classifyPathErr turns a filesystem error into the CLI's error classes:
// permission problems are ClassDenied, everything else about a configured
// path is ClassEnv.
func classifyPathErr(err error, path string) error {
	if os.IsPermission(err) {
		return &config.Error{Class: config.ClassDenied, Msg: fmt.Sprintf("%s: %v", path, err)}
	}
	return &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("%s: %v", path, err)}
}
