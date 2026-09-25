// Package admin is the administrator's role: people, machines, grants,
// sessions, recordings and gateway lifecycle, all issued as exec-channel
// commands to the gateway, plus the one-time bootstrap claim (SPEC
// §3.3). It holds no policy of its own — the gateway decides; this
// package only issues commands and renders results.
package admin
