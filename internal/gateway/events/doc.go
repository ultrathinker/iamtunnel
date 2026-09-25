// Package events is the append-only events.jsonl journal on the gateway:
// admin operations, auth attempts, enrol transitions, door open/close,
// session lifecycle (SPEC §3.5). It is the system's only history and must
// never be rewritten or serve as a hot lookup path — current state lives
// in the state package.
package events
