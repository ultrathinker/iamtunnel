package risk

import (
	"strings"
	"testing"
)

// TestCanary_B3Fix_HiddenFormsAreNotGreen protects the second-round B3
// parser boundary. These are deliberately different spellings from the
// original B3 canary: bundled shell flags, PowerShell abbreviations, and a
// PowerShell service-cmdlet alias.
func TestCanary_B3Fix_HiddenFormsAreNotGreen(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		want     Level
		outer    string
		wantRule string
	}{
		{name: "bash-bundled-login-command", cmd: `bash -lc 'rm -rf /var/lib/postgresql'`, want: Red, outer: "bash -c"},
		{name: "bash-bundled-multiple-flags", cmd: `bash -lic 'rm -rf /var/lib/postgresql'`, want: Red, outer: "bash -c"},
		{name: "pwsh-command-short", cmd: `pwsh -c "Stop-Service -Name sshd -Force"`, want: Red, outer: "pwsh -Command"},
		{name: "pwsh-command-prefix", cmd: `pwsh -Com "Stop-Service -Name sshd -Force"`, want: Red, outer: "pwsh -Command"},
		{name: "pwsh-command-longer-prefix", cmd: `pwsh -Comm "Stop-Service -Name sshd -Force"`, want: Red, outer: "pwsh -Command"},
		{name: "pwsh-encoded-short", cmd: `pwsh -e SQBFAFgA`, want: Yellow},
		{name: "pwsh-encoded-prefix", cmd: `pwsh -enc SQBFAFgA`, want: Yellow},
		{name: "pwsh-file-short", cmd: `pwsh -f C:\Temp\maintenance.ps1`, want: Yellow},
		{name: "pwsh-file-full", cmd: `pwsh -File C:\Temp\maintenance.ps1`, want: Yellow},
		{name: "stop-service-alias", cmd: `spsv sshd -Force`, want: Red, wantRule: "ssh-or-tunnel-service-action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.cmd)
			if got.Level != tc.want {
				t.Fatalf("Classify(%q) = level=%s rule=%q reason=%q; want %s", tc.cmd, got.Level, got.Rule, got.Reason, tc.want)
			}
			if tc.outer != "" && !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(tc.outer)) {
				t.Fatalf("Classify(%q) reason=%q does not name outer wrapper %q", tc.cmd, got.Reason, tc.outer)
			}
			if tc.wantRule != "" && got.Rule != tc.wantRule {
				t.Fatalf("Classify(%q) rule=%q; want %q", tc.cmd, got.Rule, tc.wantRule)
			}
		})
	}
}
