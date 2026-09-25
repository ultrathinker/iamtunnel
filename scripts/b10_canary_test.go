package scripts

import (
	"os"
	"strings"
	"testing"
)

// TestCanary_B10_THREATSMatchesEventDictionaryAndGatewayUnit is a document
// canary, not a coverage suite: stale names in the incident playbook are a
// security defect because they send an operator looking for a journal entry
// the gateway never writes.
func TestCanary_B10_THREATSMatchesEventDictionaryAndGatewayUnit(t *testing.T) {
	threats := readB10(t, "../docs/THREATS.md")
	for _, stale := range []string{
		"`grants.grant`", "`people.keys.add`", "`recordings.fetch`",
		"`auth_success", "`auth.accepted", "`auth.unknown_key",
		"`auth.rate_limited", "`session.denied", "`enrol.code_parsed",
		"`enrol.sshd_probe_failed", "`systemctl stop iamtunnel`",
	} {
		if strings.Contains(threats, stale) {
			t.Fatalf("THREATS.md still contains stale token %q", stale)
		}
	}
	for _, current := range []string{
		"iamtunnel-runbook-events-v1", "admin.op", "auth.failure", "auth.success",
		"enrol.failed", "session.drop", "systemctl stop iamtunnel-gateway",
	} {
		if !strings.Contains(threats, current) {
			t.Fatalf("THREATS.md is missing current token %q", current)
		}
	}

	for _, gate := range []string{"gates.ps1", "gates.sh"} {
		text := readB10(t, gate)
		if !strings.Contains(text, "-runbook docs/THREATS.md") {
			t.Fatalf("%s gate 13 does not check docs/THREATS.md", gate)
		}
	}
}

func readB10(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
