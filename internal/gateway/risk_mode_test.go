package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func seedRiskAdmin(t *testing.T, f *fixture) {
	t.Helper()
	key := genSigner(t)
	line := authorizedLine(key.PublicKey())
	err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "root", Role: "admin",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, key.PublicKey()), Pub: line, Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	})
	if err != nil {
		t.Fatalf("seed risk admin: %v", err)
	}
}

func runRiskMode(t *testing.T, f *fixture, person, mode string) (riskModeResponse, *cmdError) {
	t.Helper()
	body := []byte(`{"proto":1}`)
	if mode != "" {
		body = []byte(`{"proto":1,"mode":"` + mode + `"}`)
	}
	result, cerr := f.gw.runCommand(person, "risk.mode", body)
	if cerr != nil {
		return riskModeResponse{}, cerr
	}
	response, ok := result.(riskModeResponse)
	if !ok {
		t.Fatalf("risk.mode returned %T, want riskModeResponse", result)
	}
	return response, nil
}

// TestRiskMode_LiveSwitchAffectsNextClassificationAndStatus is the red-first
// canary for the in-process switch: no new Gateway and no restart may be
// needed before the next classified command sees block.
func TestRiskMode_LiveSwitchAffectsNextClassificationAndStatus(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionWarn })
	seedRiskAdmin(t, f)
	if got := f.gw.riskAction(risk.Red); got != RiskActionWarn {
		t.Fatalf("CANARY RISK-LIVE-1: initial red action = %q, want warn", got)
	}
	res, cerr := runRiskMode(t, f, "root", "block")
	if cerr != nil || !res.Changed || res.Mode != "block" || res.Source != "live" {
		t.Fatalf("CANARY RISK-LIVE-2: live change response = %+v, err=%v; want block/live/changed", res, cerr)
	}
	if got := f.gw.riskAction(risk.Red); got != RiskActionBlock {
		t.Fatalf("CANARY RISK-LIVE-3: next red classification = %q, want block without rebuilding Gateway", got)
	}
	result, cerr := f.gw.runCommand("root", "gateway.status", []byte(`{"proto":1}`))
	if cerr != nil {
		t.Fatalf("CANARY RISK-LIVE-4: gateway.status after live switch: %v", cerr)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("status JSON: %v", err)
	}
	var status struct {
		Risk struct {
			Mode   string `json:"mode"`
			Source string `json:"source"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("status decode: %v", err)
	}
	if status.Risk.Mode != "block" || status.Risk.Source != "live" {
		t.Fatalf("CANARY RISK-LIVE-5: status risk = %+v, want block/live", status.Risk)
	}
}

func TestRiskMode_AskKeepsYellowAtWarnAndRedAtAsk(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionWarn })
	seedRiskAdmin(t, f)
	res, cerr := runRiskMode(t, f, "root", "ask")
	if cerr != nil {
		t.Fatalf("risk.mode ask: %v", cerr)
	}
	if res.Mode != "ask" || res.Source != "live" {
		t.Fatalf("risk.mode ask response = %+v, want live ask", res)
	}
	if got := f.gw.riskAction(risk.Yellow); got != RiskActionWarn {
		t.Fatalf("yellow under ask = %q, want warn", got)
	}
	if got := f.gw.riskAction(risk.Red); got != RiskActionAsk {
		t.Fatalf("red under ask = %q, want ask", got)
	}
}

// TestRiskMode_InvalidLeavesStateUntouched is the red-first invalid-value
// canary: refusal must not alter the atomic source or create a live file.
func TestRiskMode_InvalidLeavesStateUntouched(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionWarn })
	seedRiskAdmin(t, f)
	_, cerr := runRiskMode(t, f, "root", "explode")
	if cerr == nil {
		t.Fatalf("CANARY RISK-INVALID-1: invalid mode was accepted")
	}
	if f.gw.currentRiskMode() != (riskModeState{mode: RiskActionWarn, source: "config"}) {
		t.Fatalf("CANARY RISK-INVALID-2: invalid mode changed effective state to %+v", f.gw.currentRiskMode())
	}
	if _, err := datafile.ReadFile(filepath.Join(f.gw.cfg.DataDir, riskModeFileName)); err == nil {
		t.Fatalf("CANARY RISK-INVALID-3: invalid mode created %q", riskModeFileName)
	}
}

// TestRiskMode_PersistsAcrossRestart is the red-first restart canary. The
// second Gateway deliberately uses a different config value; the live file
// must win in the same data directory.
func TestRiskMode_PersistsAcrossRestart(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionWarn })
	seedRiskAdmin(t, f)
	if _, cerr := runRiskMode(t, f, "root", "block"); cerr != nil {
		t.Fatalf("set live mode: %v", cerr)
	}
	old := f.gw
	if err := old.Close(); err != nil {
		t.Fatalf("close first Gateway: %v", err)
	}
	newCfg := old.cfg
	newCfg.RiskAction = RiskActionLog
	restarted, err := New(newCfg)
	if err != nil {
		t.Fatalf("CANARY RISK-RESTART-1: new Gateway with same data dir: %v", err)
	}
	defer restarted.Close()
	if got := restarted.currentRiskMode(); got != (riskModeState{mode: RiskActionBlock, source: "live"}) {
		t.Fatalf("CANARY RISK-RESTART-2: restarted mode = %+v, want block/live", got)
	}
}

// TestRiskMode_AdminOnly is the red-first authorization canary: an ordinary
// person gets the same unknown-command refusal as every other admin verb,
// while an admin can read the current mode.
func TestRiskMode_AdminOnly(t *testing.T) {
	f := newFixture(t, nil)
	seedRiskAdmin(t, f)
	if _, cerr := runRiskMode(t, f, f.person, ""); cerr == nil || cerr.code != "E_EXEC_UNKNOWN" {
		t.Fatalf("CANARY RISK-RBAC-1: ordinary person result = %v, want E_EXEC_UNKNOWN", cerr)
	}
	res, cerr := runRiskMode(t, f, "root", "")
	if cerr != nil || res.Mode != "warn" || res.Source != "config" || res.Changed {
		t.Fatalf("CANARY RISK-RBAC-2: admin read = %+v, err=%v; want warn/config/unchanged", res, cerr)
	}
}

// TestRiskMode_CorruptFileFallsBackAndJournals is the red-first startup
// canary: malformed persistent state must not make Gateway.New fail, and the
// operator must get an admin.op explanation in the existing journal.
func TestRiskMode_CorruptFileFallsBackAndJournals(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.RiskAction = RiskActionLog
		if err := datafile.WriteFileAtomic(filepath.Join(c.DataDir, riskModeFileName), []byte("not-a-mode\n"), datafile.WithMode(0o600)); err != nil {
			t.Fatalf("seed corrupt mode file: %v", err)
		}
	})
	if got := f.gw.currentRiskMode(); got != (riskModeState{mode: RiskActionLog, source: "config"}) {
		t.Fatalf("CANARY RISK-CORRUPT-1: corrupt file selected %+v, want config/log", got)
	}
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}, Result: "risk.mode:startup-ignored"})
	if err != nil {
		t.Fatalf("read startup warning: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("CANARY RISK-CORRUPT-2: startup warning events = %d, want 1", len(evs))
	}
}
