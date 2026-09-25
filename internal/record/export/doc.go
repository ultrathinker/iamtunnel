// Package export saves a session the window is watching as a folder of
// plain text files a human can open later with eyes, not with a hex
// editor and heroics (IAMT-342). Sessions run for hours and produce tens
// of megabytes of text; one file of that size defeats a text editor, so
// the transcript is handed over split.
//
// The layout is fixed by contract §5 of the IAMT-338 live-session
// contracts:
//
//	<root>/2026-09-18/office-pc_alice_141205_<id>/
//	    about.txt     who, whose machine, when it started, when it ended
//	                  (or "still running"), byte counts, sha256 of the
//	                  .cast, product version
//	    0001.txt      at most one part limit each, zero-padded numbering
//	    0002.txt      so the names sort lexicographically
//	    session.cast  the recording, byte for byte as it was made
//
// The writer receives the finished transcript text and the metadata —
// the window already holds both in memory. It never dials the gateway
// and never reads a gateway path; the only things it opens are the
// files it writes, and every one of those opens and writes goes through
// internal/datafile (raw os.WriteFile is gate-16 red). After the files
// are on disk the exporter appends one recording.export event to the
// journal it is handed, so the record of who exported whose session and
// where it went lives with every other journal fact.
//
// The package is a leaf beside internal/gateway/record, deliberately
// outside internal/gateway: the consumer of an export is the WINDOW,
// not the gateway, and the window must be able to import this without
// importing the gateway's world.
package export
