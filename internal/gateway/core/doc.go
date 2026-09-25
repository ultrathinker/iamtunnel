// Package core wires together the ready-made parts of the gateway: the door
// automaton, reservations and sessions. It knows neither the path of
// administrators_authorized_keys nor Windows details: the connected machine
// owns those through the control channel.
package core
