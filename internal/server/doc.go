// Package server is the machine-side role: the outgoing tunnel to the
// gateway, keepalive with reconnect and SweepStale, idle and hard
// timers, and the doorwatch child process (SPEC §3.2, §6.3). On Windows
// it drives winkeys and elevate. It must not contain gateway or GUI
// logic, and it never records sessions — only the gateway does. The one
// thing it does with a live session is carry the owner's question about
// it to the gateway and hand the gateway's answer back unaltered, since
// this machine cannot read its own session at all (IAMT-340, tail.go).
package server
