// Package state owns state.json on the gateway: the data model (people,
// machines, grants, doors, schema version), validation, atomic
// tmp→fsync→rename writes and migrations (SPEC §4.3, §3.5). Only current
// facts live here — history belongs to the events package — and apart
// from that one file it performs no I/O.
package state
