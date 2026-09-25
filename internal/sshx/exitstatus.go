package sshx

import "time"

// exitstatus.go: the shared wait period for the final "exit-status" at
// both ends of one pipe (PROTOCOL §4.1: the exit-status line — "machine
// → person only... to relay").
//
// exit-status does not travel as data but as a channel request — the
// same request stream that dies along with the SSH channel itself.
// Closing the channel before this request has been read and forwarded
// means silently losing the return code. This is the same fact at both
// ends of one pipe: internal/client/connect.go waits for it on the
// human end (the request flows gateway → person), and
// internal/gateway/human_role.go on the machine end (the request flows
// machine → gateway → person). Hence a single constant: here, in sshx,
// rather than one of its own in client and one of its own in gateway —
// so the two ends of one pipe physically cannot drift apart in value
// when one of them is edited separately.
//
// The wait must be bounded: the peer may half-close (send EOF on data
// but not close the channel itself) and fall silent without sending an
// exit-status at all — that is the very deadlock the earlier "close
// first, then wait" ordering used to guard against. Keepalive is no
// substitute for a deadline: a side that died internally but whose SSH
// transport still answers keepalive (requests.go answers with Answer
// for both kinds — keepalive@iamtunnel and keepalive@openssh.com) is
// indistinguishable from a live one to any transport-level detector.
//
// Why 5 seconds: on a clean end, exit-status travels over the same
// ordered transport ahead of the data EOF that the byte copier sees —
// that is, by the time this wait begins, the message is usually
// already sitting in the local request buffer, and the wait only
// covers the time before the relay goroutine has even been scheduled
// to run. Five seconds is orders of magnitude longer than any
// scheduler delay, but reliably shorter than one keepalive interval
// (DefaultKeepaliveInterval, 20s) — so it is this deadline, not
// detection via three missed keepalives (a full minute), that bounds a
// silent peer.
const ExitStatusGrace = 5 * time.Second
