//go:build windows || linux || darwin

package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Canary: an answer that knows about PART of a struct does not
// replace the whole thing.
//
// 21.09.2026. The risk.mode command answers about the mode and is
// silent about the classifier. The handler wrote into the snapshot
// `s.Admin.RiskMode = RiskMode{Mode: ..., Source: ...}` -- and with
// that zeroed Classifier, ClassifierSource, ClassifierKey and the
// key's fingerprint until the next list fetch. Along with them the
// goal caveat lied too: "no effect while the classifier is rules"
// was shown regardless of what the classifier actually was.
//
// The most bitter part: the lesson was written RIGHT NEXT DOOR. In
// cmd/iamtunnel, above the same half of the action, stands the
// comment: "Mode/Source only: risk.mode carries no Classifier, and
// replacing the whole struct would drop the one AdminList last
// read". The same slip lived one file over, right under the note
// about it.
//
// The canary reads the source: assigning a whole RiskMode struct
// inside reviseSnapshot is forbidden. Fields -- yes; the struct --
// no.
func TestCanary_PartialUpdatesDoNotReplaceWholeStructs(t *testing.T) {
	files := []string{"live.go", "live_watch.go", "screens.go", "held.go", "history.go"}
	// `s.<Path> = <Type>{` inside reviseSnapshot: a composite literal,
	// that is, replacing everything at once.
	whole := regexp.MustCompile(`\bs\.[A-Za-z][A-Za-z0-9_.]*\s*=\s*(RiskMode|HistoryPage|SetupState|AdminState|ClientState)\{`)
	closure := regexp.MustCompile(`(?s)reviseSnapshot\(func\(s \*Snapshot\) \{(.*?)\n\t*\}\)`)

	seen := 0
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, m := range closure.FindAllStringSubmatch(string(src), -1) {
			seen++
			for _, bad := range whole.FindAllString(m[1], -1) {
				// An empty literal is a deliberate wipe, not a partial
				// answer: `= RiskMode{}` erases on purpose.
				if strings.HasSuffix(strings.TrimSpace(bad), "{") &&
					strings.Contains(m[1], strings.TrimSuffix(bad, "{")+"{}") {
					continue
				}
				t.Errorf("%s: %s... -- the answer replaces the whole struct inside reviseSnapshot. "+
					"Fields this answer knows nothing about will be zeroed until the next full fetch. "+
					"Assign fields one by one", name, bad)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no reviseSnapshot found -- the canary has gone blind")
	}
}
