package main

import (
	"errors"
	"net"
	"strings"
)

// authRefused says whether a dial reached the gateway and was refused for
// its key (the SSH layer's "unable to authenticate"): the other half of
// "the gateway is not reachable".
func authRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unable to authenticate")
}

// enrolRefusal is the sentence for an enrol the gateway REFUSED at the SSH
// layer: it was reached, so "could not reach" would send the person to a
// firewall. A refused one-time key has three ordinary causes, and none of
// them can be told from the others from here: the code is older than its
// 15 minutes or was already used, or this machine's address was blocked by
// the gateway after repeated failed sign-ins (16.10.2026: a removed machine's
// agent kept knocking and blocked the address its re-registration came
// from, and the window showed a bare "unable to authenticate").
func enrolRefusal(addr string, err error) string {
	return "the gateway at " + addr + " refused this enrol code (" + err.Error() + "). " +
		"Either the code is older than 15 minutes or was already used - ask the administrator for a new one - " +
		"or this machine's address is blocked for up to 15 minutes after repeated failed sign-ins " +
		"(the gateway journal shows \"rate limited until\"); stop the agent here if it is running, " +
		"and try again after the time it names"
}

// reachHint is the next move for a gateway that could not be reached,
// appended to the "could not reach the gateway" line. The bare dial error
// named the symptom only: on 29.09.2026 a machine in the same cloud
// network as its gateway printed "i/o timeout" and nothing else, and the
// cause - the gateway's security group admitted the port only from three
// outside addresses - took a packet capture to find.
//
// Two failures are told apart because they want opposite moves. A timeout
// is packets dropped on the way, by a firewall or a cloud security group;
// a refusal is a host that answered with nothing listening on the port.
// Any other error keeps its own words.
func reachHint(addr string, err error) string {
	if err == nil {
		return ""
	}
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.As(err, &ne) && ne.Timeout(), strings.Contains(msg, "i/o timeout"):
		return " — nothing answered: a firewall or a cloud security group between this machine and " + addr +
			" is dropping the connection. Allow this machine to reach that address and port (on AWS: an inbound" +
			" rule on the gateway's security group for this machine's address; a machine in the gateway's own" +
			" private network can use the gateway's private address instead)."
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return " — the host answered, but nothing listens on that port: check that the gateway service is" +
			" running and that the port is the one it was installed with."
	}
	return ""
}
