package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

const (
	externalRiskKeyMaxBytes = 4096
	externalRiskKeyProbe    = "iamtunnel classifier key probe"
)

// externalRiskKeyFingerprint is safe metadata: it lets an operator tell two
// installed keys apart without making the key recoverable from state or the
// journal.
func externalRiskKeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (c Config) newExternalRiskClassifier(key string) risk.ExternalClassifier {
	if c.externalRiskClassifierFactory != nil {
		return c.externalRiskClassifierFactory(key)
	}
	return risk.NewExternalClassifier(key)
}

func (g *Gateway) currentExternalRiskClassifier() risk.ExternalClassifier {
	g.externalRiskMu.RLock()
	defer g.externalRiskMu.RUnlock()
	return g.cfg.externalRiskClassifier
}

func (g *Gateway) externalRiskKeyStatus() state.ExternalRiskKeyState {
	st := g.cfg.Store.Get()
	if st.ExternalRiskKey != nil {
		return *st.ExternalRiskKey
	}
	g.externalRiskMu.RLock()
	fingerprint := g.cfg.externalRiskKeyFingerprint
	classifier := g.cfg.RiskClassifier
	g.externalRiskMu.RUnlock()
	return state.ExternalRiskKeyState{Present: classifier != RiskClassifierRules && fingerprint != "", Fingerprint: fingerprint}
}

func (g *Gateway) syncExternalRiskKeyState() error {
	status := state.ExternalRiskKeyState{}
	if g.cfg.RiskClassifier != RiskClassifierRules && g.cfg.externalRiskKeyFingerprint != "" {
		status.Present = true
		status.Fingerprint = g.cfg.externalRiskKeyFingerprint
	}
	current := g.cfg.Store.Get().ExternalRiskKey
	if current != nil && *current == status {
		return nil
	}
	return g.cfg.Store.Update(func(st *state.State) error {
		copyStatus := status
		st.ExternalRiskKey = &copyStatus
		return nil
	})
}

// externalRiskKeyProbeError keeps the admin response's failure categories
// separate from ordinary file/state errors. Its cause contains only provider
// status and safe transport/decoding text; the submitted key is never wrapped.
type externalRiskKeyProbeError struct {
	cause error
}

func (e *externalRiskKeyProbeError) Error() string {
	if e == nil || e.cause == nil {
		return "external classifier probe failed"
	}
	return externalRiskKeyReplacementReason(e.cause)
}

func (e *externalRiskKeyProbeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func normalizeExternalRiskKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", fmt.Errorf("key has invalid form: it is empty")
	}
	if len(key) > externalRiskKeyMaxBytes {
		return "", fmt.Errorf("key has invalid form: it exceeds %d bytes", externalRiskKeyMaxBytes)
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("key has invalid form: it contains whitespace or a control character")
		}
	}
	return key, nil
}

// replaceExternalRiskKey probes the candidate exactly once, atomically swaps
// the existing key file, records metadata, and only then publishes the new
// classifier pointer. A failed probe returns before any write, so the old key
// and in-memory classifier remain usable.
func (g *Gateway) replaceExternalRiskKey(raw string) (state.ExternalRiskKeyState, error) {
	var zero state.ExternalRiskKeyState
	newKey, err := normalizeExternalRiskKey(raw)
	if err != nil {
		return zero, err
	}
	if g.cfg.RiskClassifier == RiskClassifierRules {
		return zero, fmt.Errorf("external classifier is disabled while risk_classifier=rules")
	}
	path := g.cfg.ExternalRiskObservationKeyFile
	if strings.TrimSpace(path) == "" {
		return zero, fmt.Errorf("external classifier key file is not configured")
	}

	g.externalRiskKeyWriteMu.Lock()
	defer g.externalRiskKeyWriteMu.Unlock()

	oldBytes, err := datafile.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read current external classifier key file: %w", err)
	}
	if strings.TrimSpace(string(oldBytes)) == "" {
		return zero, fmt.Errorf("current external classifier key file is empty")
	}
	candidate := g.cfg.newExternalRiskClassifier(newKey)
	if candidate == nil {
		return zero, &externalRiskKeyProbeError{cause: risk.NewExternalClassifierError(
			risk.ExternalFailureConfiguration, 0, fmt.Errorf("external classifier candidate is not configured"))}
	}

	ctx, cancel := context.WithTimeout(context.Background(), risk.ExternalClassifierTimeout)
	_, probeErr := candidate.Classify(ctx, externalRiskKeyProbe)
	cancel()
	if probeErr != nil {
		return zero, &externalRiskKeyProbeError{cause: probeErr}
	}

	newStatus := state.ExternalRiskKeyState{Present: true, Fingerprint: externalRiskKeyFingerprint(newKey)}
	if err := datafile.WriteFileAtomic(path, []byte(newKey+"\n"), datafile.WithMode(0o600), datafile.WithAdoptOwner(), datafile.WithSync()); err != nil {
		return zero, fmt.Errorf("persist new external classifier key: %w", err)
	}
	if err := g.cfg.Store.Update(func(st *state.State) error {
		copyStatus := newStatus
		st.ExternalRiskKey = &copyStatus
		return nil
	}); err != nil {
		// The key file was already replaced, so restore the exact prior bytes
		// before reporting failure. The rollback also goes through datafile;
		// raw file I/O is not an alternative at this boundary.
		rollbackErr := datafile.WriteFileAtomic(path, oldBytes, datafile.WithMode(0o600), datafile.WithAdoptOwner(), datafile.WithSync())
		if rollbackErr != nil {
			return zero, fmt.Errorf("persist key metadata: %v; key-file rollback failed: %v", err, rollbackErr)
		}
		return zero, fmt.Errorf("persist key metadata: %w", err)
	}

	g.externalRiskMu.Lock()
	g.cfg.externalRiskClassifier = candidate
	g.cfg.externalRiskKeyFingerprint = newStatus.Fingerprint
	g.externalRiskMu.Unlock()
	return newStatus, nil
}

// The risk.key reply's failure categories (IAMT-404, PROTOCOL §1.2).
// They ride the error envelope beside the prose so a window never has
// to substring-read the sentence again.
const (
	riskKeyCategoryRejected    = "rejected"
	riskKeyCategoryUnavailable = "unavailable"
)

// externalRiskKeyFailureCategory is the machine-readable twin of
// externalRiskKeyReplacementReason: it answers "rejected" exactly when
// the reason names a refusal of the key itself, "unavailable" for every
// inconclusive trial. The twin property is pinned by
// TestIAMT404_TheRiskKeyReplyNamesTheFailureCategory — if these two
// ever disagree, a window too old for the field reads a different truth
// from the words than a new one does from the field.
func externalRiskKeyFailureCategory(err error) string {
	if risk.ExternalFailureKindOf(err) == risk.ExternalFailureAuthentication {
		return riskKeyCategoryRejected
	}
	return riskKeyCategoryUnavailable
}

func externalRiskKeyReplacementReason(err error) string {
	if err == nil {
		return "external classifier accepted the key"
	}
	kind := risk.ExternalFailureKindOf(err)
	status := risk.ExternalFailureStatusCode(err)
	switch kind {
	case risk.ExternalFailureAuthentication:
		if status != 0 {
			return fmt.Sprintf("new key rejected by the classifier service (HTTP %d; key invalid or expired)", status)
		}
		return "new key rejected by the classifier service (key invalid or expired)"
	default:
		if risk.ExternalFailureTimedOut(err) {
			return "classifier service unavailable while probing the new key (timeout)"
		}
		if status >= 500 {
			return fmt.Sprintf("classifier service unavailable while probing the new key (HTTP %d)", status)
		}
		if kind == risk.ExternalFailureUnavailable {
			if status != 0 {
				return fmt.Sprintf("classifier service unavailable while probing the new key (HTTP %d)", status)
			}
			return "classifier service unavailable while probing the new key"
		}
		return "classifier rejected the new key because its response was malformed"
	}
}
