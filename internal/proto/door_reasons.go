package proto

// door_reasons.go — the words door.close and door.sanitize may carry
// (PROTOCOL §5.1), shared by both ends (IAMT-469).
//
// Both dictionaries are closed: a machine refuses a request whose reason is
// not in them, and by the closing row of the door automaton (PROTOCOL §5.2)
// the gateway answers a refused close by cutting the machine off. The
// gateway used to close the door of a machine whose OS user an
// administrator changed with the reason "os-user-changed" - a word only the
// gateway knew. Every real machine refused it, and no test saw it: the
// gateway's fake machine took any reason. Both ends now spell the words
// from here, as IAMT-344 did for sessions.tail.

// The reasons of door.close.
const (
	// DoorCloseIdle: no session and no reservation is left on the door.
	DoorCloseIdle = "idle"
	// DoorCloseHard: the door's hard deadline has passed.
	DoorCloseHard = "hard"
	// DoorCloseStop: the gateway ends the door by its own decision rather
	// than by a timer - an administrator changed the machine's OS user, and
	// a door opened for one account must not serve the next.
	DoorCloseStop = "stop"
	// DoorCloseTunnelLost is in the dictionary and in no request: a lost
	// tunnel is cleaned up by the machine itself, without a door.close.
	DoorCloseTunnelLost = "tunnel-lost"
	// DoorCloseReconnect: door.status found a door the gateway does not
	// hold, left over from an earlier connection of the machine.
	DoorCloseReconnect = "reconnect"
	// DoorCloseLateReply: a door.open answered after the gateway had given
	// up on it installed a door nobody is waiting for.
	DoorCloseLateReply = "late-reply"
)

// DoorSanitizeCorrupted is the one reason of door.sanitize: a door line
// whose marker names no door id the gateway could close by name.
const DoorSanitizeCorrupted = "corrupted"

// ValidDoorCloseReason reports whether reason is a word door.close may
// carry.
func ValidDoorCloseReason(reason string) bool {
	switch reason {
	case DoorCloseIdle, DoorCloseHard, DoorCloseStop, DoorCloseTunnelLost, DoorCloseReconnect, DoorCloseLateReply:
		return true
	}
	return false
}
