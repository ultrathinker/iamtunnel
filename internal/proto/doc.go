// Package proto is the JSON exec-channel protocol: request/response
// envelopes, the proto version and capability lists (SPEC §5.3). It is
// frozen at the end of phase 1, so it must contain marshaling and
// validation only — no transport, no SSH, no policy decisions.
package proto
