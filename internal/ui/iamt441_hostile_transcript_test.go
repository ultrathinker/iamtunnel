//go:build windows || linux || darwin

package ui

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// IAMT-441 in the window. What the transcript window shows and what an
// export writes come out of the same emulator the gateway records with,
// fed from the recording's bytes: the printf that took the gateway down
// took down, just the same, whichever window read that recording back.
func TestIAMT441_WindowReadsAHostileRecordingBack(t *testing.T) {
	const hostile = "before\r\nA\x1b[9223372036854775807CX\r\n\x1b[-9223372036854775808Gafter\r\n"
	out, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	cast := []byte(`{"version":2,"width":80,"height":24}` + "\n" + `[0.1,"o",` + string(out) + "]\n")

	cases := []struct {
		name, mode string
		body       []byte
	}{
		{"asciicast", "", cast},
		{"exec journal", "exec", execJournal("printf hostile", hostile)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fetch := func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
				total := int64(len(tc.body))
				if offset >= total {
					return nil, offset, total, nil
				}
				return tc.body[offset:], total, total, nil
			}
			var text string
			var ferr error
			panicked := func() (p any) {
				defer func() { p = recover() }()
				text, ferr = exportOneTranscript(context.Background(), fetch, RecordingRef{ID: "r441", Mode: tc.mode})
				return nil
			}()
			if panicked != nil {
				t.Fatalf("reading the recording back panicked: %v", panicked)
			}
			if ferr != nil {
				t.Fatalf("exportOneTranscript: %v", ferr)
			}
			for _, want := range []string{"before", "A", "X", "after"} {
				if !strings.Contains(text, want) {
					t.Errorf("the transcript lost %q:\n%s", want, text)
				}
			}
		})
	}
}
