package main

// IAMT-451: `admin gateway status` prints what the gateway says about its
// audit journal - and nothing when a gateway from before 1.14 says
// nothing, since silence is not "ok".

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestIAMT451_AdminGatewayStatusPrintsTheAuditState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		audit *admin.GatewayAuditStatus
		want  string
	}{
		{"failing", &admin.GatewayAuditStatus{OK: false, Since: "2026-09-23T18:00:00Z", Error: "no space left on device", LostWrites: 4}, "audit: PROBLEM: the audit journal is NOT being written"},
		{"ok", &admin.GatewayAuditStatus{OK: true, LostWrites: 0}, "audit: ok"},
		{"not said", nil, ""},
	} {
		var out bytes.Buffer
		s := &streams{out: &out, errs: &bytes.Buffer{}, env: map[string]string{}}
		printGatewayStatus(s, admin.GatewayStatusResult{Audit: tc.audit})
		got := out.String()
		if tc.want == "" {
			if strings.Contains(got, "audit:") {
				t.Errorf("%s: a gateway that says nothing about its journal is reported on anyway:\n%s", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: want %q in:\n%s", tc.name, tc.want, got)
		}
	}
}
