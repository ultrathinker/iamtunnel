//go:build windows || linux || darwin

package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// The colour the window reports in. This lives in its own test on
// purpose: it names exportNoteKey, which the fix introduced, so it
// cannot take part in a run against the tree the defect lived in — the
// package would not compile, and a test that fails to compile proves
// nothing about the defect. The two red rows above use only names that
// existed before the fix, which is what makes their red run meaningful.
func TestM5bExportIsGreenOnlyWhenNothingFailed(t *testing.T) {
	whole := exportResult{Sessions: 2, Transcripts: 2}
	if got := exportNoteKey(whole, nil); got != design.GoodKey {
		t.Errorf("a whole export is reported as %s, want green", got)
	}
	if line := exportDoneLine(whole); strings.Contains(line, "could not be read") {
		t.Errorf("the summary of a whole export mentions failures: %q", line)
	}

	// Pruning is the archive working as designed, not a failure: an
	// export of old visits must stay green or the colour means nothing.
	pruned := exportResult{Sessions: 3, Transcripts: 1, MissingBytes: 2}
	if got := exportNoteKey(pruned, nil); got != design.GoodKey {
		t.Errorf("an export whose recordings were pruned months ago is reported as %s, want green — pruning is a normal answer, not a failure", got)
	}

	failed := exportResult{Sessions: 3, Transcripts: 1, MissingBytes: 1, FailedTranscripts: 1}
	if got := exportNoteKey(failed, nil); got == design.GoodKey {
		t.Errorf("an export that could not read a recording is reported as %s — green tells the person the archive is whole when it is not (M-5b, review F-19)", got)
	}
	if got := exportNoteKey(exportResult{}, errors.New("the export folder did not open")); got != design.BadKey {
		t.Errorf("a failed export is reported as %s, want the bad key", got)
	}
}
