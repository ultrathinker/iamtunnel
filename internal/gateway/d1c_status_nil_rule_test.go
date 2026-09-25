package gateway

import (
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestD1c_GatewayStatusLatestRedNilRule — the canary for D1(c): if the
// EventSessionRisk event with result="red" has no "rule" key in
// Details (or it is nil), the LatestRed.Rule field of the gateway status
// answer must be an empty string, not the string "<nil>".
func TestD1c_GatewayStatusLatestRedNilRule(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Record a red event with no rule field.
	f.gw.appendEvent(events.Event{
		Type:   events.EventSessionRisk,
		Actor:  f.person,
		Object: f.machineID,
		Result: "red",
		Details: map[string]interface{}{
			"action": "log",
			// "rule" deliberately absent
		},
	})

	// Record another one with rule=nil.
	f.gw.appendEvent(events.Event{
		Type:   events.EventSessionRisk,
		Actor:  f.person,
		Object: f.machineID,
		Result: "red",
		Details: map[string]interface{}{
			"action": "log",
			"rule":   nil,
		},
	})

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
			LatestRed *struct {
				Rule string `json:"rule"`
			} `json:"latestRed"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status.Risk.LatestRed == nil {
		t.Fatal("D1(c) canary: latestRed is missing although red events exist")
	}
	if status.Risk.LatestRed.Rule == "<nil>" {
		t.Fatal("D1(c) canary: latestRed.rule = \"<nil>\" — fmt.Sprint over a nil interface is not handled")
	}
	if status.Risk.LatestRed.Rule != "" {
		t.Fatalf("D1(c) canary: latestRed.rule = %q, want an empty string for an absent rule", status.Risk.LatestRed.Rule)
	}
}
