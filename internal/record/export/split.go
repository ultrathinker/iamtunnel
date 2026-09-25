package export

import (
	"fmt"
	"unicode/utf8"
)

// DefaultPartLimit is the size of one text part: 5 MiB. One file of
// this size is still openable by a text editor; one file of a
// multi-hour session (tens of megabytes) is not, which is the whole
// point of splitting. Named constant, not a literal sprinkled around:
// the threshold lives nowhere but here.
const DefaultPartLimit = 5 * 1024 * 1024

// MinPartLimit is the floor under any explicit PartLimit: one
// maximum-size UTF-8 rune. The rune-safe cut of an overlong line must
// always make progress, and it can only guarantee that while the
// window it scans is at least utf8.UTFMax wide — within any four bytes
// after a rune boundary a valid UTF-8 stream always offers the next
// boundary, because no rune is longer than four bytes.
const MinPartLimit = utf8.UTFMax

// maxParts is what the zero-padded %04d numbering can name while
// keeping its promise: with four digits, 0010 sorts after 0002 for
// every count up to 9999. Part 10000 would sort before 0002 — the
// guarantee dies quietly exactly there, so reaching it is an error,
// not a wraparound.
const maxParts = 9999

// maxNameAttempts is how many _N suffixes claimSessionDir tries before
// giving up, the same bound internal/gateway/record/sessionname.go
// applies to session names.
const maxNameAttempts = 64

// Split divides a finished transcript into parts of at most limit
// bytes each (zero limit — DefaultPartLimit). The rules, each of which
// is easy to break silently:
//
//  1. Parts break at LINE boundaries: a file that begins with half a
//     line is garbage a human notices too late. A part only ends
//     between lines — right after a '\n' — or at the very end of the
//     input.
//  2. No UTF-8 rune is ever torn. Russian text is ordinary here.
//  3. A line longer than the limit (cat on a binary produces one
//     "line" megabytes long) is cut at rune boundaries instead — the
//     one case where a break falls inside a line, named in the loop
//     below, never bypassed silently.
//
// The parts concatenate back to the input byte for byte. An empty
// transcript yields exactly one empty part: the layout promises a
// 0001.txt, and its absence would read as a lost export, not an empty
// session.
func Split(transcript []byte, limit int) ([][]byte, error) {
	if limit == 0 {
		limit = DefaultPartLimit
	}
	if limit < MinPartLimit {
		return nil, fmt.Errorf("part limit %d bytes is below the minimum of %d (utf8.UTFMax): the rune-safe cut of an overlong line cannot guarantee progress below one maximum-size rune", limit, MinPartLimit)
	}
	if len(transcript) == 0 {
		return [][]byte{nil}, nil
	}

	parts := make([][]byte, 0, 1+len(transcript)/limit)
	partStart := 0 // first byte of the part being assembled
	pos := 0       // first byte of the line being considered
	for pos < len(transcript) {
		// End of the current line: the '\n' byte inclusive; the last
		// line of the input may carry no '\n' at all.
		end := pos
		for end < len(transcript) && transcript[end] != '\n' {
			end++
		}
		if end < len(transcript) {
			end++ // include the '\n'
		}

		if lineLen := end - pos; lineLen > limit {
			// THE OVERLONG LINE. A line longer than the part limit
			// exists in the wild: cat on a binary file streams a
			// single line of megabytes. No part can hold it whole, so
			// this is the ONE place where a part break falls inside a
			// line rather than at a line boundary — the pieces are cut
			// at rune boundaries (runeSafeCut keeps UTF-8 intact, and
			// where even that is impossible, in mangled binary bytes,
			// each cut byte decodes as one RuneError). The reader who
			// finds a part seam without a newline at it is looking at
			// this case; the parts still concatenate back to the input
			// byte for byte.
			if partStart < pos {
				// Lines assembled so far end the current part first:
				// the overlong line never shares a part with them.
				parts = append(parts, transcript[partStart:pos])
			}
			for off := pos; off < end; {
				cut := runeSafeCut(transcript, off, end, limit)
				parts = append(parts, transcript[off:cut])
				off = cut
			}
			partStart = end
			pos = end
			continue
		}

		if end-partStart > limit {
			// The line would overflow the part being assembled: the
			// part ends where the previous line ended (rule 1 — never
			// mid-line), and the line opens the next one. Safe because
			// the line itself fits in an empty part (checked above).
			parts = append(parts, transcript[partStart:pos])
			partStart = pos
		}
		pos = end
	}
	if partStart < len(transcript) {
		parts = append(parts, transcript[partStart:])
	}

	if len(parts) > maxParts {
		return nil, fmt.Errorf("transcript splits into %d parts; the zero-padded %04d numbering stays lexicographically sortable only up to %d parts, and beyond that 0010 would sort before 0002", len(parts), maxParts, maxParts)
	}
	return parts, nil
}

// runeSafeCut picks the break point for the overlong line inside the
// window data[lo:hi]: the largest cut in (lo, hi] such that no UTF-8
// rune straddles it, and never more than limit bytes per piece.
func runeSafeCut(data []byte, lo, hi, limit int) int {
	wanted := lo + limit
	if wanted > hi {
		wanted = hi
	}
	if wanted >= len(data) {
		// Everything up to the end of the line (and of the input)
		// fits: no cut to make, nothing to tear.
		return len(data)
	}
	cut := wanted
	for cut > lo && !utf8.RuneStart(data[cut]) {
		// data[cut] continues a rune started earlier: step back until
		// the byte under the cut begins a rune of its own. In valid
		// UTF-8 this walks back at most three bytes — no rune is
		// longer than four, and limit >= utf8.UTFMax guarantees the
		// walk never reaches lo.
		cut--
	}
	if cut == lo {
		// NOT REACHABLE FOR VALID UTF-8: a boundary always exists
		// within four bytes (see MinPartLimit). Getting here means the
		// byte stream is mangled binary — the same case as the
		// overlong line itself, cat on a binary file — where there are
		// no whole runes to protect and every byte decodes as one
		// RuneError. Cut after the first byte and move on; the walk
		// above never returns an empty piece either way.
		cut = lo + 1
	}
	return cut
}

// partName is the zero-padded name of one text part: 0001.txt, 0002.txt,
// … 0010.txt sorts after 0002, which is the whole point of the padding.
func partName(n int) string {
	return fmt.Sprintf("%04d.txt", n)
}
