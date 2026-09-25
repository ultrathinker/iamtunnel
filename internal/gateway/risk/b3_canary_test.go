package risk

import (
	"strings"
	"testing"
)

// B3 security canaries verify that textual evaluators do not hide the inner
// command. A wrapper reason must retain both the outer wrapper and inner rule.
func TestCanary_B3_CommandWrappersInheritInnerVerdict(t *testing.T) {
	cases := []struct {
		name  string
		cmd   string
		want  Level
		part  string
		inner string
	}{
		{"bash", `bash -c 'rm -rf /var/lib/postgresql'`, Red, "bash -c", "data"},
		{"sh", `sh -c 'shutdown -h now'`, Red, "sh -c", "shuts"},
		{"powershell", `powershell -NoProfile -Command "Remove-Item -Recurse -Force C:\Data"`, Red, "powershell -Command", "data"},
		{"pwsh", `pwsh -Command "Stop-Service sshd"`, Red, "pwsh -Command", "access"},
		{"cmd", `cmd /c "rm -rf /var/lib/postgresql"`, Red, "cmd /c", "data"},
		{"invoke-expression", `Invoke-Expression("rm -rf /var/lib/postgresql")`, Red, "invoke-expression", "data"},
		{"iex", `iex "shutdown -h now"`, Red, "iex", "shuts"},
		{"runas", `runas /user:Administrator "rm -rf /var/lib/postgresql"`, Red, "runas", "data"},
		{"sudo-env", `sudo env A=1 rm -rf /var/lib/postgresql`, Red, "sudo", "data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.cmd)
			if got.Level != tc.want {
				t.Fatalf("%s wrapper canary: level=%s rule=%q reason=%q; want %s", tc.name, got.Level, got.Rule, got.Reason, tc.want)
			}
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(tc.part)) {
				t.Fatalf("%s wrapper canary: reason=%q does not name outer %q", tc.name, got.Reason, tc.part)
			}
			if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(tc.inner)) {
				t.Fatalf("%s wrapper canary: reason=%q does not retain inner consequence", tc.name, got.Reason)
			}
		})
	}
}

func TestCanary_B3_OpaqueCommandsAreYellow(t *testing.T) {
	cases := []string{
		`powershell -EncodedCommand SQBFAFgA`,
		`base64 -d payload | sh`,
		`python -c 'import os; os.remove("/var/lib/data")'`,
		`perl -e 'system("rm -rf /")'`,
		`node -e 'require("child_process")'`,
		`ruby -e 'system("rm -rf /")'`,
		`awk 'system("rm -rf /")'`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := Classify(cmd)
			if got.Level == Green {
				t.Fatalf("opaque canary: %q classified green (rule=%q reason=%q)", cmd, got.Rule, got.Reason)
			}
		})
	}
}

func TestCanary_B3_WrapperDepthBecomesYellow(t *testing.T) {
	cmd := `bash -c sh -c zsh -c dash -c rm -rf /var/lib/postgresql`
	got := Classify(cmd)
	if got.Level != Yellow || got.Rule != "wrapper-depth" {
		t.Fatalf("wrapper-depth canary: level=%s rule=%q reason=%q; want yellow/wrapper-depth", got.Level, got.Rule, got.Reason)
	}
}
