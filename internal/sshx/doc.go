// Package sshx is SSH plumbing shared by all roles: the re-declared
// payload structs (ptyRequestMsg and friends), keepalive loops that
// x/crypto does not provide, and the Channel→net.Conn adapter for the
// iamtunnel-target channel (SPEC §4.1, §5.2). Nothing role-specific and
// no policy belongs here.
package sshx
