package gateway

// R2-CX F-02 of the round-2 review (24.09.2026), medium:
// gateway.status promises the last 24 hours of risk, and read that from
// the current journal file alone. The gateway rotates its own journal by
// size (IAMT-452), and every event a rotation puts aside is exactly the
// kind this summary counts - so a gateway that had refused a session an
// hour ago answered with zeros, and the CLI prints that line as a fact
// ("last 24h"). The same difference between "the file being written" and
// "the history" was caught in the History tab on 21.09.2026 and is
// written down on Log.Read; this is the same mistake one caller further
// on, in the answer an operator reads first.

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR2CXF02_TheRiskSummarySurvivesAJournalRotation(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// One red risk event, the kind a refused session writes.
	f.gw.appendEvent(events.Event{
		Type:   events.EventSessionRisk,
		Actor:  f.person,
		Object: f.machineID,
		Result: "red",
		Details: map[string]interface{}{
			"action": "log",
			"rule":   "r2cx-f02",
		},
	})

	// What the sweep does once the journal reaches its size limit: the
	// file with the risk event in it becomes an archive.
	archive := filepath.Join(filepath.Dir(f.logPath), events.ArchiveName(time.Now()))
	if err := f.log.Rotate(archive); err != nil {
		t.Fatalf("rotating the journal: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"proto": 1})
	result, cerr := cmdGatewayStatus(f.gw, "admin", f.clock.Now(), body)
	if cerr != nil {
		t.Fatalf("cmdGatewayStatus: %v", cerr)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal status result: %v", err)
	}
	var status struct {
		Risk struct {
			Red       int `json:"red"`
			LatestRed *struct {
				Rule string `json:"rule"`
			} `json:"latestRed"`
		} `json:"risk"`
		Audit struct {
			ReadError string `json:"readError"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("unmarshal status result: %v", err)
	}

	if status.Risk.Red != 1 {
		t.Errorf("gateway.status counts %d red risk events in the last 24 hours, and there is one - in the archive the rotation left: the answer is about the file being written rather than about the history, so an operator reads a gateway that has refused nothing (F-02); readError=%q", status.Risk.Red, status.Audit.ReadError)
	}
	if status.Risk.LatestRed == nil || status.Risk.LatestRed.Rule != "r2cx-f02" {
		t.Errorf("gateway.status reports latestRed=%+v, want the rule of the red event that is in the archive: the one line an operator looks for after a refusal is the one a rotation hides (F-02)", status.Risk.LatestRed)
	}
}
