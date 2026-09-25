package gateway

// Which checkers judge a command, changed while the gateway runs.
//
// The gateway has had three answers since IAMT-401 -- rules, ai, both --
// and until 21.09.2026 the only way to pick one was to edit
// gateway.json on the gateway host and restart the service. That made it
// the single risk setting with no live control at all: the neighbouring
// risk MODE (log/warn/ask/block), which decides what happens to a red
// command, has been switchable from the window for far longer, and it is
// the less consequential of the two.
//
// The owner asked for the switch by the shorter road: a settings button
// on the machine row: internal check, or AI-only check, or both. This
// file is the gateway half, written deliberately as a
// twin of risk_mode.go -- same file-then-pointer order, same
// config/live source reporting -- because two settings that behave the
// same way should be two copies of one shape, not two inventions.
//
// THE GUARD. Choosing ai or both without a classifier key would be a
// foot-gun, and a worse one since IAMT-408: with no key every command
// fails closed and waits for a human, so the person who flipped the
// switch would have locked their own machines behind a queue of
// approvals. The switch refuses instead, and says what to do.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

const riskSourceFileName = "risk-classifier"

// riskSourceState is the effective classifier selection and its origin,
// replaced as one unit so a reader never sees a new value with the old
// source.
type riskSourceState struct {
	classifier RiskClassifier
	source     string
}

func (g *Gateway) currentRiskSource() riskSourceState {
	if current := g.riskSourceLive.Load(); current != nil {
		return *current
	}
	classifier := g.cfg.RiskClassifier
	if classifier == "" {
		classifier = RiskClassifierRules
	}
	return riskSourceState{classifier: classifier, source: "config"}
}

func riskSourcePath(dataDir string) string {
	return filepath.Join(dataDir, riskSourceFileName)
}

// loadRiskSource is forgiving at startup in the same way loadRiskMode is:
// a missing file means the settings file owns the choice, and a malformed
// one is ignored but reported for the journal.
func loadRiskSource(cfg Config) (riskSourceState, *riskStartupWarning) {
	fallback := riskSourceState{classifier: cfg.RiskClassifier, source: "config"}
	if fallback.classifier == "" {
		fallback.classifier = RiskClassifierRules
	}
	if cfg.DataDir == "" {
		return fallback, nil
	}
	path := riskSourcePath(cfg.DataDir)
	raw, err := datafile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return fallback, &riskStartupWarning{file: path, reason: fmt.Sprintf("the file could not be read: %v", err)}
	}
	value := RiskClassifier(strings.TrimSpace(string(raw)))
	if !validRiskClassifier(value) {
		return fallback, &riskStartupWarning{
			file:   path,
			value:  string(raw),
			reason: "the value is not one of the classification sources: rules, ai, both",
		}
	}
	return riskSourceState{classifier: value, source: "live"}, nil
}

type riskSourceResponse struct {
	Classifier string `json:"classifier"`
	Source     string `json:"source"`
	Changed    bool   `json:"changed"`
	Previous   string `json:"previous"`
}

// cmdRiskSource reads or changes which checkers judge a command.
func cmdRiskSource(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto      int            `json:"proto"`
		Classifier RiskClassifier `json:"classifier"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}

	if req.Classifier == "" {
		current := g.currentRiskSource()
		return riskSourceResponse{
			Classifier: string(current.classifier), Source: current.source,
			Changed: false, Previous: string(current.classifier),
		}, nil
	}
	if !validRiskClassifier(req.Classifier) {
		return nil, errf("E_JSON_INVALID", 3,
			"classifier %q must be one of \"rules\", \"ai\" or \"both\"", req.Classifier)
	}
	// The guard described at the top of this file.
	if req.Classifier != RiskClassifierRules && g.currentExternalRiskClassifier() == nil {
		return nil, errf("E_JSON_INVALID", 3,
			"%q needs the AI classifier, and this gateway has no key for it; set one first "+
				"(Admin sets it in the window, or \"iamtunnel admin risk key\") — without a key every "+
				"command would stop and wait for a person", req.Classifier)
	}
	if g.cfg.DataDir == "" {
		return nil, errf("E_INTERNAL", 70,
			"gateway data directory is not configured; the classifier choice cannot be persisted")
	}

	g.riskSourceWriteMu.Lock()
	defer g.riskSourceWriteMu.Unlock()
	previous := g.currentRiskSource()
	if err := datafile.WriteFileAtomic(riskSourcePath(g.cfg.DataDir), []byte(req.Classifier+"\n"),
		datafile.WithMode(0o600), datafile.WithSync()); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not persist the classifier choice: %v", err)
	}
	changed := previous.classifier != req.Classifier
	g.riskSourceLive.Store(&riskSourceState{classifier: req.Classifier, source: "live"})
	g.logAdminOp(person, "risk.source", riskSourceFileName, "ok", map[string]interface{}{
		"previous": string(previous.classifier),
		"current":  string(req.Classifier),
		"changed":  changed,
	})
	return riskSourceResponse{
		Classifier: string(req.Classifier), Source: "live",
		Changed: changed, Previous: string(previous.classifier),
	}, nil
}
