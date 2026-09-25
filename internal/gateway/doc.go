// Package gateway is the bastion core: the SSH server for people, admins
// and machines, the registry of machine connections, door keys, session
// proxying with recording, and the admin exec channel (SPEC §3.5, §5).
// It runs on Linux in production but must build on every platform. It
// must not know about Windows specifics (winkeys, elevate) or the GUI,
// and holds no role logic that belongs to client, server or admin.
package gateway
