package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

func TestIAMT402_AdminGoalAndRulesDiagnosticAreExplicit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskClassifier = RiskClassifierRules })
	addPerson(t, f, "root", "admin", genSigner(t))

	const goal = "keep the site online while rotating --token=goal-secret"
	body, err := json.Marshal(map[string]any{"proto": 1, "person": "root", "machine": f.machineID, "goal": goal})
	if err != nil {
		t.Fatal(err)
	}
	result, cerr := f.gw.runCommand("root", "goal.set", body)
	if cerr != nil {
		t.Fatalf("goal.set: %s (%s)", cerr.message, cerr.code)
	}
	set, ok := result.(goalView)
	if !ok || set.Goal != "keep the site online while rotating --token=goal-secret" || len(set.History) != 1 {
		t.Fatalf("goal.set result = %#v, want current goal and one history entry", result)
	}

	current, cerr := f.gw.runCommand("root", "goal.current", []byte(`{"proto":1,"person":"root","machine":"vm1"}`))
	if cerr != nil {
		t.Fatalf("goal.current: %s (%s)", cerr.message, cerr.code)
	}
	currentView, ok := current.(goalView)
	if !ok || currentView.Goal == "" || currentView.History != nil {
		t.Fatalf("goal.current = %#v, want only current goal", current)
	}

	history, cerr := f.gw.runCommand("root", "goal.history", []byte(`{"proto":1,"person":"root","machine":"vm1"}`))
	if cerr != nil {
		t.Fatalf("goal.history: %s (%s)", cerr.message, cerr.code)
	}
	historyView, ok := history.(goalView)
	if !ok || len(historyView.History) != 1 || historyView.History[0].Goal != currentView.Goal {
		t.Fatalf("goal.history = %#v, want newest explicit declaration", history)
	}

	riskBody, err := json.Marshal(map[string]any{
		"proto": 1, "command": "rm -rf /var/lib/data", "goal": goal,
	})
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, cerr := f.gw.runCommand("root", "risk.check", riskBody)
	if cerr != nil {
		t.Fatalf("risk.check: %s (%s)", cerr.message, cerr.code)
	}
	diagnosticMap, ok := diagnostic.(map[string]any)
	if !ok {
		t.Fatalf("risk.check result = %T, want map", diagnostic)
	}
	if diagnosticMap["classifier"] != string(RiskClassifierRules) || diagnosticMap["goalApplied"] != false {
		t.Fatalf("rules diagnostic = %#v, want classifier=rules and goalApplied=false", diagnosticMap)
	}
	if diagnosticMap["goal"] != "keep the site online while rotating --token=<redacted>" {
		t.Fatalf("rules diagnostic goal = %#v, want scrubbed goal", diagnosticMap["goal"])
	}

	rawJournal, err := os.ReadFile(f.logPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if strings.Contains(string(rawJournal), "goal-secret") {
		t.Fatalf("goal secret leaked into journal: %s", rawJournal)
	}
	if !strings.Contains(string(rawJournal), "goal.set") || !strings.Contains(string(rawJournal), "\\u003credacted\\u003e") {
		t.Fatalf("journal does not show scrubbed goal.set event: %s", rawJournal)
	}
}

type iamt403KeyClassifier struct {
	err   error
	calls int
}

func (c *iamt403KeyClassifier) Classify(context.Context, string) (risk.ExternalAssessment, error) {
	c.calls++
	if c.err != nil {
		return risk.ExternalAssessment{}, c.err
	}
	return risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.1, "access": 0.1}}, nil
}

func TestIAMT403_RiskKeyProbesOnceThenSwapsWithoutReturningSecret(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "classifier.key")
	const oldKey = "old-classifier-test-key"
	const newKey = "new-classifier-test-key"
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"), 0o600); err != nil {
		t.Fatalf("write old key: %v", err)
	}
	candidates := map[string]*iamt403KeyClassifier{}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = RiskClassifierAI
		c.ExternalRiskObservationKeyFile = keyPath
		c.externalRiskClassifierFactory = func(key string) risk.ExternalClassifier {
			candidate := &iamt403KeyClassifier{}
			candidates[key] = candidate
			return candidate
		}
	})
	addPerson(t, f, "root", "admin", genSigner(t))

	result, cerr := f.gw.runCommand("root", "risk.key", []byte(`{"proto":1,"key":"`+newKey+`"}`))
	if cerr != nil {
		t.Fatalf("risk.key: %s (%s)", cerr.message, cerr.code)
	}
	status, ok := result.(riskKeyReplaceResult)
	if !ok || !status.Replaced || status.Fingerprint != externalRiskKeyFingerprint(newKey) {
		t.Fatalf("risk.key result = %#v, want replacement metadata only", result)
	}
	if candidates[newKey].calls != 1 {
		t.Fatalf("new key probe calls = %d, want exactly one", candidates[newKey].calls)
	}
	if candidates[oldKey].calls != 0 {
		t.Fatalf("old classifier calls during replacement = %d, want zero", candidates[oldKey].calls)
	}

	installed, err := datafile.ReadFile(keyPath)
	if err != nil || strings.TrimSpace(string(installed)) != newKey {
		t.Fatalf("installed key = %q, read error=%v", installed, err)
	}
	stateNow := f.store.Get()
	if stateNow.ExternalRiskKey == nil || stateNow.ExternalRiskKey.Fingerprint != externalRiskKeyFingerprint(newKey) || !stateNow.ExternalRiskKey.Present {
		t.Fatalf("state key metadata = %#v, want present new fingerprint", stateNow.ExternalRiskKey)
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedResult), newKey) || strings.Contains(string(encodedResult), oldKey) {
		t.Fatalf("risk.key result leaks a key: %s", encodedResult)
	}
	rawJournal, err := os.ReadFile(f.logPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if strings.Contains(string(rawJournal), newKey) || strings.Contains(string(rawJournal), oldKey) {
		t.Fatalf("journal leaks a classifier key: %s", rawJournal)
	}
	adminEvents, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin events: %v", err)
	}
	if !hasRiskKeyAdminEvent(adminEvents, "risk.key.replace:ok") {
		t.Fatalf("successful replacement has no risk.key.replace admin event: %+v", adminEvents)
	}

	classification := f.gw.classifyExec("safe-command", "", nil)
	if classification.ExternalError != nil || candidates[newKey].calls != 2 {
		t.Fatalf("next classification did not use the new key: classification=%+v calls=%d", classification, candidates[newKey].calls)
	}
}

func TestIAMT403_RejectedKeyLeavesOldKeyWorkingAndCategorizesFailure(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "classifier.key")
	const oldKey = "old-classifier-test-key"
	const rejectedKey = "rejected-classifier-test-key"
	if err := os.WriteFile(keyPath, []byte(oldKey+"\n"), 0o600); err != nil {
		t.Fatalf("write old key: %v", err)
	}
	candidates := map[string]*iamt403KeyClassifier{}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = RiskClassifierAI
		c.ExternalRiskObservationKeyFile = keyPath
		c.externalRiskClassifierFactory = func(key string) risk.ExternalClassifier {
			candidate := &iamt403KeyClassifier{}
			if key == rejectedKey {
				candidate.err = risk.NewExternalClassifierError(risk.ExternalFailureAuthentication, 401, errors.New("rejected"))
			}
			candidates[key] = candidate
			return candidate
		}
	})
	addPerson(t, f, "root", "admin", genSigner(t))

	_, cerr := f.gw.runCommand("root", "risk.key", []byte(`{"proto":1,"key":"`+rejectedKey+`"}`))
	if cerr == nil || cerr.code != "E_RISK_KEY_REJECTED" || !strings.Contains(cerr.message, "HTTP 401") {
		t.Fatalf("rejected risk.key = %#v, want E_RISK_KEY_REJECTED with HTTP 401 reason", cerr)
	}
	if candidates[rejectedKey].calls != 1 {
		t.Fatalf("rejected key probe calls = %d, want exactly one", candidates[rejectedKey].calls)
	}
	installed, err := datafile.ReadFile(keyPath)
	if err != nil || strings.TrimSpace(string(installed)) != oldKey {
		t.Fatalf("old key after rejection = %q, read error=%v", installed, err)
	}
	if f.store.Get().ExternalRiskKey.Fingerprint != externalRiskKeyFingerprint(oldKey) {
		t.Fatalf("state metadata changed after rejection: %#v", f.store.Get().ExternalRiskKey)
	}
	classification := f.gw.classifyExec("safe-command", "", nil)
	if classification.ExternalError != nil || candidates[oldKey].calls != 1 {
		t.Fatalf("old classifier did not remain usable: classification=%+v calls=%d", classification, candidates[oldKey].calls)
	}
	rawJournal, err := os.ReadFile(f.logPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if strings.Contains(string(rawJournal), rejectedKey) {
		t.Fatalf("rejected key leaked into journal: %s", rawJournal)
	}
	adminEvents, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin events: %v", err)
	}
	if !hasRiskKeyAdminEvent(adminEvents, "risk.key.replace:failed") {
		t.Fatalf("rejected replacement has no risk.key.replace failure event: %+v", adminEvents)
	}
}

func hasRiskKeyAdminEvent(eventsList []events.Event, result string) bool {
	for _, event := range eventsList {
		if event.Actor == "root" && event.Object == "external-risk-classifier" && event.Result == result {
			return true
		}
	}
	return false
}

func TestIAMT403_KeyFailureReasonsStayInOwnerCategories(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"auth", risk.NewExternalClassifierError(risk.ExternalFailureAuthentication, 403, errors.New("forbidden")), "HTTP 403"},
		{"timeout", context.DeadlineExceeded, "timeout"},
		{"server", risk.NewExternalClassifierError(risk.ExternalFailureUnavailable, 503, errors.New("busy")), "HTTP 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := externalRiskKeyReplacementReason(tc.err); !strings.Contains(got, tc.want) {
				t.Fatalf("reason = %q, want category containing %q", got, tc.want)
			}
		})
	}
}

func TestIAMT403_MalformedSubmittedKeyIsRejectedBeforeProbe(t *testing.T) {
	if _, err := normalizeExternalRiskKey("key with whitespace"); err == nil || !strings.Contains(err.Error(), "invalid form") {
		t.Fatalf("malformed key error = %v, want invalid-form refusal", err)
	}
}
