package client

// More than one gateway on one machine (IAMT-430).
//
// The maintainer, 2026-09-22: the client app should be able to connect
// to different gateways, quickly enough that each one is remembered
// once and there is no need to type logins or passwords in again. The
// maintainer's personal gateway on the test VPS carries their own
// machines; a second one at work will carry the work machine.
//
// Until now this directory held exactly one saved connection, and
// SaveConnection refused to write a different one without --replace --
// that is, without destroying the first. Two gateways meant keeping two
// iamtunnel:// lines in a notes file and pasting them back and forth.
//
// WHAT DOES NOT CHANGE, and it is the important half: there are no
// logins and no passwords in this product at all. The whole of
// authentication is the ed25519 key in `key`, which is ONE per machine
// and says nothing about any gateway. Each gateway's administrator
// writes that same public key onto the person record there. So switching
// between gateways cannot require credentials -- there are none to
// require -- and anything slower than one press would be an invention of
// ours, not a fact of the protocol.
//
// ONE FILE, ONE TRUTH. The list lives in connection.json itself rather
// than in a second file beside it. A "current gateway" in one file and a
// "saved connection" in another are two copies of one fact, and this
// codebase has already paid for that shape once: the shadow snapshot
// that redrew the window over reality every three seconds. When they
// disagree there is no principled answer to which is right.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// connectionsVersion is the shape of the file this package writes.
// Version 1 was a bare ConnString and is still read (migrate below);
// nothing ever wrote a "version" field then, and its absence is exactly
// how the old shape is recognised.
const connectionsVersion = 2

// Gateway is one remembered gateway: where it is, who this machine is
// there, and which host key it must present.
//
// The fingerprint is not decoration. It is what makes the connection a
// connection to THAT gateway rather than to whoever answers on that
// address, so it travels with the entry and is compared on every dial.
type Gateway struct {
	// Name is the label a person picks. It identifies the entry to a
	// human and to "client use <name>"; it means nothing to the
	// protocol, and changing it changes nothing about the connection.
	Name string `json:"name"`

	Host        string `json:"host"`
	Port        int    `json:"port"`
	Person      string `json:"person"`
	Fingerprint string `json:"fingerprint"`
}

// ConnString is the entry as the rest of the program wants it.
func (g Gateway) ConnString() config.ConnString {
	return config.ConnString{Host: g.Host, Port: g.Port, Person: g.Person, Fingerprint: g.Fingerprint}
}

// Where is the address half, for a line a person reads.
func (g Gateway) Where() string { return g.Host + ":" + strconv.Itoa(g.Port) }

// sameDoor reports whether two entries are the same way in: the same
// person on the same gateway.
//
// The fingerprint is deliberately NOT part of this. A gateway whose host
// key changed is the same door with a new lock, and that is precisely
// the case that must be noticed rather than quietly added as a second
// entry beside the old one.
func sameDoor(a Gateway, b config.ConnString) bool {
	return a.Host == b.Host && a.Port == b.Port && a.Person == b.Person
}

// Connections is everything this machine remembers about gateways.
type Connections struct {
	Version  int       `json:"version"`
	Current  string    `json:"current"`
	Gateways []Gateway `json:"gateways"`
}

// Find returns the entry with this name, case-insensitively.
func (c Connections) Find(name string) (Gateway, bool) {
	for _, g := range c.Gateways {
		if strings.EqualFold(g.Name, name) {
			return g, true
		}
	}
	return Gateway{}, false
}

// CurrentGateway is the one every other command acts on.
//
// A file naming a current entry that is not in the list is repaired
// rather than refused: the list is the fact, the pointer is a
// convenience, and a person locked out of their own gateways by a
// dangling name would have no way to fix it from inside the product.
func (c Connections) CurrentGateway() (Gateway, bool) {
	if len(c.Gateways) == 0 {
		return Gateway{}, false
	}
	if g, ok := c.Find(c.Current); ok {
		return g, true
	}
	return c.Gateways[0], true
}

// normalise puts the set back into a shape the rest of this file may
// assume: a current pointer that resolves, and a version stamp.
func (c *Connections) normalise() {
	c.Version = connectionsVersion
	if g, ok := c.CurrentGateway(); ok {
		c.Current = g.Name
		return
	}
	c.Current = ""
}

// decodeConnections reads either shape of the file.
//
// The old one is a bare ConnString written by every version up to 1.38.
// It is read WITHOUT ceremony and without asking anybody: a person who
// upgrades must find their gateway where they left it, not a message
// about a file format. The migration is in memory; the new shape reaches
// the disk on the next write, so a downgrade back to 1.38 keeps working
// until then.
func decodeConnections(data []byte, path string) (Connections, error) {
	var zero Connections

	// Which shape is this? The old file has no "version" and no
	// "gateways"; the new one has both. Sniffing on a lenient decode
	// first is what lets the strict decode below stay strict.
	var probe struct {
		Version  *int              `json:"version"`
		Gateways []json.RawMessage `json:"gateways"`
		Host     *string           `json:"Host"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
			"saved connections %s do not parse (%v) — remove the file and save the connection string again", path, err)}
	}

	if probe.Version == nil && probe.Gateways == nil {
		cs, err := decodeStrict[config.ConnString](data, path)
		if err != nil {
			return zero, err
		}
		out := Connections{Gateways: []Gateway{{
			Name: defaultName(cs), Host: cs.Host, Port: cs.Port,
			Person: cs.Person, Fingerprint: cs.Fingerprint,
		}}}
		out.normalise()
		return out, nil
	}

	out, err := decodeStrict[Connections](data, path)
	if err != nil {
		return zero, err
	}
	if out.Version > connectionsVersion {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
			"saved connections %s were written by a newer iamtunnel (format %d, this one understands %d) — "+
				"upgrade, or remove the file to start over", path, out.Version, connectionsVersion)}
	}
	// A name is what a person uses to switch; an entry without one could
	// never be reached again. Repair rather than refuse, for the same
	// reason as the dangling current pointer.
	for i := range out.Gateways {
		if strings.TrimSpace(out.Gateways[i].Name) == "" {
			out.Gateways[i].Name = defaultName(out.Gateways[i].ConnString())
		}
	}
	out.normalise()
	return out, nil
}

// decodeStrict is the strict read both shapes get: unknown fields and
// trailing data are refused, because a file this program wrote should
// round-trip exactly and anything else is a sign it did not write it.
func decodeStrict[T any](data []byte, path string) (T, error) {
	var v T
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		var zero T
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
			"saved connections %s do not parse (%v) — save the connection string again", path, err)}
	}
	if dec.More() {
		var zero T
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
			"saved connections %s have trailing data — save the connection string again", path)}
	}
	return v, nil
}

// defaultName is the label an entry gets when nobody typed one: the
// gateway's host. Not "gateway 1" -- a number tells a person nothing a
// month later, and the host is the one thing about a gateway they have
// certainly seen.
func defaultName(cs config.ConnString) string {
	name := strings.TrimSpace(cs.Host)
	if name == "" {
		return "gateway"
	}
	return name
}

// uniqueName makes name unused among the entries this one is not
// allowed to collide with.
//
// A duplicate name is not merely untidy: the name is what "client use"
// takes, so two entries sharing one make the second unreachable.
func uniqueName(c Connections, name string, skipIndex int) string {
	taken := func(candidate string) bool {
		for i, g := range c.Gateways {
			if i == skipIndex {
				continue
			}
			if strings.EqualFold(g.Name, candidate) {
				return true
			}
		}
		return false
	}
	if !taken(name) {
		return name
	}
	for n := 2; ; n++ {
		candidate := name + " (" + strconv.Itoa(n) + ")"
		if !taken(candidate) {
			return candidate
		}
	}
}
