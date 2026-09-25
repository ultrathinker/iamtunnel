// Package client is the person's role: storing the pinned connection
// string, managing the person's key, machines.mine and opening the
// interactive session itself over x/crypto/ssh — no external ssh.exe is
// launched. The gateway is trusted only by the fingerprint pinned from
// the connection string; the isolated known_hosts inside the client's
// data directory is a local record of the verified key, never a source
// of trust, and the local console is switched to raw mode for the
// session and restored afterwards (SPEC §3.1). It tunnels and forwards
// nothing — it is a directory and a button — and the recording notice
// comes from the gateway, not from here.
package client
