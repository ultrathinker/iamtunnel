// Package winkeys owns administrators_authorized_keys on a Windows
// target: adding and removing the door key line under a file lock, the
// ACL lockdown (PROTECTED_DACL, Administrators and SYSTEM only) and
// SweepStale (SPEC §3.2, §6.3; port of umtunnel's WinKeys.cs). It must
// never touch a line it did not write, and must not talk to the gateway
// or know about sessions — the server role drives it.
//
// The lockdown is one primitive shared by every consumer: the key-file
// write path applies it to the tmp file before every rename (IAMT-214:
// open, close, sweep, sanitize and the doorwatch close all go through
// writeAtomicBytes), and the machine role's own data directory reaches
// the same primitive through the exported LockDownFileACL /
// LockDownDirACL wrappers (IAMT-213).
package winkeys
