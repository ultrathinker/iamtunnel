package gateway

// The maintainer's canaries for wave 1.7-B.
//
// The wave was delivered without a single test: its report lists five
// "canaries", and each refers to a check that does not exist. These
// three are written in their place and check exactly what the wave was
// made for: the maintainer must SEE the safety net working without
// opening the journal file in a text editor.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestCanary_17B_RiskCheckAnswersFromTheGatewaysOwnRules.
//
// risk.check answers the question "what will MY gateway do with this
// command". That is why the gateway does the judging, not the copy of
// the rules in the client binary: after an update the two can diverge,
// and they will diverge exactly when the answer matters most.
//
// The canary: make cmdRiskCheck return a fixed green -- it turns red
// on the red command.
func TestCanary_17B_RiskCheckAnswersFromTheGatewaysOwnRules(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	for _, c := range []struct {
		command   string
		wantLevel string
		wantRule  bool
	}{
		{"Get-Service | Where-Object Status -eq Stopped", "green", false},
		{"rm -rf /var/lib/postgresql", "red", true},
		{"git push --force origin main", "yellow", true},
	} {
		raw, err := root.Exec("risk.check", map[string]any{"proto": 1, "command": c.command})
		if err != nil {
			t.Fatalf("risk.check %q: %v", c.command, err)
		}
		var got struct {
			Level  string `json:"level"`
			Rule   string `json:"rule"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("risk.check %q: parsing the answer: %v", c.command, err)
		}
		if got.Level != c.wantLevel {
			t.Errorf("risk.check %q: level %q, want %q -- a dry run must give the same verdict as a real session, otherwise the maintainer will switch on block over a wrong picture",
				c.command, got.Level, c.wantLevel)
		}
		if c.wantRule && got.Rule == "" {
			t.Errorf("risk.check %q: the rule is empty -- the maintainer has nothing to explain to themselves WHY the command is not green", c.command)
		}
		if c.wantRule && got.Reason == "" {
			t.Errorf("risk.check %q: the reason is empty", c.command)
		}
	}

	// An empty command is a refusal, not "green". A silent "all good" on
	// empty input is the worst possible answer a checking command can
	// give.
	if _, err := root.Exec("risk.check", map[string]any{"proto": 1, "command": ""}); err == nil {
		t.Error("risk.check with an empty command answered success -- a checking command has no right to silently approve empty input")
	}
}

// TestCanary_17B_SessionsHistoryShowsRisk.
//
// The canary: drop events.EventSessionRisk from the filter in
// cmdSessionsHistory.
func TestCanary_17B_SessionsHistoryShowsRisk(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	f.gw.appendEvent(events.Event{
		Type:   events.EventSessionRisk,
		Actor:  f.person,
		Object: f.machineID,
		Result: "red",
		Details: map[string]interface{}{
			"rule": "rm-recursive-outside-temp", "reason": "data will be lost",
			"action": "block", "command": "rm -rf /var/lib/postgresql",
		},
	})

	raw, err := root.Exec("sessions.history", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("sessions.history: %v", err)
	}
	if !containsAll(string(raw), "\"riskLevel\":\"red\"", "data will be lost") {
		t.Fatalf("sessions.history = %s\ncontains no red event -- the only command with which the maintainer looks at what the person did must also show which of it was risky; otherwise risk is visible only in the journal file",
			raw)
	}
}

// TestCanary_17B_GatewayStatusSummarisesRisk.
//
// gateway status is the one place the maintainer already looks at.
//
// The canary: drop the risk reading from cmdGatewayStatus.
func TestCanary_17B_GatewayStatusSummarisesRisk(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// The empty case: there must be a summary, and it must be honest.
	raw, err := root.Exec("gateway.status", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("gateway.status: %v", err)
	}
	if !containsAll(string(raw), "risk") {
		t.Fatalf("gateway.status with no events = %s\ncarries no risk summary -- the maintainer must not have to guess whether the safety net works at all", raw)
	}

	f.gw.appendEvent(events.Event{
		Type: events.EventSessionRisk, Actor: f.person, Object: f.machineID, Result: "red",
		Details: map[string]interface{}{"rule": "rm-recursive-outside-temp", "action": "block"},
	})
	f.gw.appendEvent(events.Event{
		Type: events.EventSessionRisk, Actor: f.person, Object: f.machineID, Result: "yellow",
		Details: map[string]interface{}{"rule": "git-push-force", "action": "warn"},
	})

	raw, err = root.Exec("gateway.status", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("gateway.status after events: %v", err)
	}
	var got struct {
		Risk struct {
			Mode    string `json:"mode"`
			Yellow  int    `json:"yellow"`
			Red     int    `json:"red"`
			Blocked int    `json:"blocked"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("gateway.status: parsing: %v (answer %s)", err, raw)
	}
	if got.Risk.Red != 1 || got.Risk.Yellow != 1 {
		t.Errorf("summary = %+v, want red=1 yellow=1 -- the daily numbers are the entire answer to the question \"what is going on at all\"",
			got.Risk)
	}
	if got.Risk.Blocked != 1 {
		t.Errorf("stopped = %d, want 1 -- the maintainer must separately see how many times the safety net FIRED, not only how many times it noticed",
			got.Risk.Blocked)
	}
	if got.Risk.Mode == "" {
		t.Error("the mode in the summary is empty -- without it the numbers are unreadable: \"3 red\" means different things with stopping off and with it on")
	}
	_ = time.Now
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for i := 0; i+len(n) <= len(haystack); i++ {
			if haystack[i:i+len(n)] == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
