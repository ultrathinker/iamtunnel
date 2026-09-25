package gateway

// r4cx_n05_response_lines_test.go — R4 review N-05.
//
// IAMT-409 keeps the first two lines of a command's answer for the risk
// classifier. The capture treated every Read chunk without a newline as a
// whole line: an answer that arrived as "first" + " line\nsecond\n" was
// kept as the two lines "first" and " line", and "second" was lost - the
// classifier was told the transport's packet boundaries, not the output.
// An unterminated last line was dropped at the end, too.

import "testing"

func TestR4CXN05_TheCaptureKeepsLinesNotPackets(t *testing.T) {
	c := newResponseCapture()
	c.add([]byte("first"))
	c.add([]byte(" line\r\nsec"))
	c.add([]byte("ond\n"))
	if got, want := c.Response(), "first line\nsecond"; got != want {
		t.Fatalf("R4 review N-05: the capture kept %q, want %q — lines were cut at Read boundaries", got, want)
	}
}

func TestR4CXN05_AnUnterminatedLastLineIsKept(t *testing.T) {
	c := newResponseCapture()
	c.add([]byte("done, no newline"))
	if got := c.Response(); got != "done, no newline" {
		t.Fatalf("an answer without a trailing newline was kept as %q", got)
	}
}
