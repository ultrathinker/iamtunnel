package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

const riskModeFileName = "risk-mode"

// riskModeState is the effective value and its origin. The pointer carrying
// it is replaced as one unit, so a reader cannot observe a new mode with the
// old source (or the reverse).
type riskModeState struct {
	mode   RiskAction
	source string
}

func (g *Gateway) currentRiskMode() riskModeState {
	if current := g.riskLive.Load(); current != nil {
		return *current
	}
	mode := g.cfg.RiskAction
	if mode == "" {
		mode = RiskActionWarn
	}
	return riskModeState{mode: mode, source: "config"}
}

func riskModePath(dataDir string) string {
	return filepath.Join(dataDir, riskModeFileName)
}

// riskStartupWarning is why a persisted risk switch was ignored at
// startup, in the pieces an operator or a parser wants apart (F-05,
// round-1 review 24.09.2026): the file, what it held, and why the gateway
// did not use it. Until then all three sat inside one prose sentence in
// details.warning, so the offending value could only be read out of a
// string, not taken hold of.
type riskStartupWarning struct {
	file   string
	value  string // the file's own content; empty when it could not be read
	reason string
}

// details is the warning as the journal carries it. The value is clipped
// like every other string that came from outside the gateway (IAMT-447):
// the gateway refused this file, and a refused file must not set the size
// of a journal line.
func (w *riskStartupWarning) details() map[string]interface{} {
	d := map[string]interface{}{"file": w.file, "reason": w.reason}
	if w.value != "" {
		d["value"] = clipForJournal(w.value)
	}
	return d
}

// loadRiskMode is deliberately forgiving at startup. A missing file means
// the settings file owns the mode; a malformed or unreadable file is ignored
// in the same way, but is returned as a startup warning for the journal.
func loadRiskMode(cfg Config) (riskModeState, *riskStartupWarning) {
	fallback := riskModeState{mode: cfg.RiskAction, source: "config"}
	if fallback.mode == "" {
		fallback.mode = RiskActionWarn
	}
	if cfg.DataDir == "" {
		return fallback, nil
	}
	path := riskModePath(cfg.DataDir)
	raw, err := datafile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return fallback, &riskStartupWarning{file: path, reason: fmt.Sprintf("the file could not be read: %v", err)}
	}
	value := RiskAction(strings.TrimSpace(string(raw)))
	if !validRiskAction(value) {
		return fallback, &riskStartupWarning{
			file:   path,
			value:  string(raw),
			reason: "the value is not one of the risk modes: log, warn, ask, block",
		}
	}
	return riskModeState{mode: value, source: "live"}, nil
}

type riskModeResponse struct {
	Mode     string `json:"mode"`
	Source   string `json:"source"`
	Changed  bool   `json:"changed"`
	Previous string `json:"previous"`
}

// cmdRiskMode reads or changes the effective risk action. The write is one
// atomic datafile replacement followed by one atomic pointer replacement;
// if persistence fails, the in-memory mode remains unchanged.
func cmdRiskMode(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int        `json:"proto"`
		Mode  RiskAction `json:"mode"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}

	if req.Mode == "" {
		current := g.currentRiskMode()
		return riskModeResponse{
			Mode: string(current.mode), Source: current.source,
			Changed: false, Previous: string(current.mode),
		}, nil
	}
	if !validRiskAction(req.Mode) {
		return nil, errf("E_JSON_INVALID", 3, "mode %q must be one of \"log\", \"warn\", \"ask\" or \"block\"", req.Mode)
	}
	if g.cfg.DataDir == "" {
		return nil, errf("E_INTERNAL", 70, "gateway data directory is not configured; risk mode cannot be persisted")
	}

	g.riskModeWriteMu.Lock()
	defer g.riskModeWriteMu.Unlock()
	previous := g.currentRiskMode()
	if err := datafile.WriteFileAtomic(riskModePath(g.cfg.DataDir), []byte(req.Mode+"\n"), datafile.WithMode(0o600), datafile.WithSync()); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not persist risk mode: %v", err)
	}
	changed := previous.mode != req.Mode
	g.riskLive.Store(&riskModeState{mode: req.Mode, source: "live"})
	g.logAdminOp(person, "risk.mode", riskModeFileName, "ok", map[string]interface{}{
		"previous": string(previous.mode),
		"new":      string(req.Mode),
	})
	return riskModeResponse{
		Mode: string(req.Mode), Source: "live", Changed: changed, Previous: string(previous.mode),
	}, nil
}
