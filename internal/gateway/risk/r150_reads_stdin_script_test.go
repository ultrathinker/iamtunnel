package risk

import (
	"strings"
	"testing"
)

// 1.50: the gateway peeks at stdin only for commands whose script arrives
// there; every other command starts without waiting.
func TestR150_ReadsStdinScript(t *testing.T) {
	for _, c := range []struct {
		command string
		want    bool
	}{
		{"powershell", true},
		{"pwsh -NoProfile", true},
		{"powershell -NoProfile -Command -", true},
		{"powershell -File -", true},
		{"cmd", true},
		{"bash", true},
		{"sh -s", true},
		{"python3 -", true},
		{"node", true},
		{"perl", true},
		{"ruby", true},
		{"powershell -Command Get-Date", false},
		{"bash script.sh", false},
		{"python3 tool.py", false},
		{"cmd /c dir", false},
		{"whoami", false},
		{"scp -t C:/TEST111/", false},
		// Fixup round 1, V-02: executable spellings and paths.
		{"powershell.exe -Command -", true},
		{"PowerShell.EXE -NoProfile -Command -", true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command -`, true},
		{`"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -Command -`, true},
		{"/usr/bin/python3 -", true},
		{"cmd.exe", true},
		{"bash.exe -s", true},
		{"powershell.exe -Command Get-Date", false},
		{`"C:\Program Files\PowerShell\7\pwsh.exe" -File build.ps1`, false},
		// Launchers the classifier unwraps.
		{"cmd /c powershell -NoProfile -Command -", true},
		{"cmd.exe /c powershell.exe -Command -", true},
		{"CMD.EXE /C pwsh -", true},
		{"cmd /k python", true}, // cmd /k itself reads stdin afterwards
		{"start /wait /b powershell -Command -", true},
		{`start "title" /wait pwsh -`, true},
		{`start /wait "title" pwsh -`, true},
		{"bash -c 'python3 -'", true},
		{`powershell -Command "cmd /c node"`, true},
		{`cmd /c dir C:\TEST111`, false},
		{"start /wait notepad.exe", false},
		// Any segment of a compound command.
		{`cd C:\TEST111 && powershell -Command -`, true},
		{"whoami; hostname", false},
		// Deeper than the classifier follows: unresolved, so treated as
		// reading stdin.
		{"cmd /c cmd /c cmd /c cmd /c whoami", true},
		// Fixup round 2, V-08: help/version/query switches read no script.
		{"python --version", false},
		{"python -V", false},
		{"python3 -VV", false},
		{"python -v", true}, // verbose, not version: still reads stdin
		{"node --version", false},
		{"node -v", false},
		{"perl -v", false},
		{"ruby -v", false},
		{"bash --version", false},
		{"sh --help", false},
		{"cmd /?", false},
		{"pwsh -?", false},
		// Fixup round 3, V-11: Windows PowerShell's -Version selects the
		// engine; only pwsh's bare -Version / -v is the display query, and
		// no informational switch outweighs a named stdin form.
		{"powershell.exe -Version 2.0 -Command -", true},
		{"powershell -Version 5.1 -Command -", true},
		{"powershell -Version 2.0", true},
		{"powershell -Version", true},
		{"pwsh -Version", false},
		{"pwsh -v", false},
		{"pwsh -ve", false},
		{"pwsh -NoProfile -ve", false},
		// Fixup round 4, V-13: pwsh -Version / -v ignores every other
		// parameter, a nominal -Command - included.
		{"pwsh -NoProfile -Version", false},
		{"pwsh -Version -NoProfile", false},
		{"pwsh -Version -Command -", false},
		{"pwsh.exe -NoLogo -v", false},
		{`"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -Version`, false},
		{"cmd /c pwsh -Version", false},
		{"powershell -NoProfile -Version 5.1", true},
		{"pwsh -? -Command -", true},
		// A parameter's value is not a script argument.
		{"powershell -NoProfile -ExecutionPolicy Bypass", true},
		{"powershell -ep Bypass -WindowStyle Hidden", true},
		{"pwsh -WorkingDirectory C:/TEST111", true},
		{"powershell -ExecutionPolicy Bypass build.ps1", false},
		{"python --version -", true},
		{"bash --version -s", true},
		{"PowerShell.exe -Help", false},
		{"cmd /c python --version", false},
		// Only the first command of a pipeline inherits the session's stdin.
		{"echo x | powershell -Command -", false},
		{"echo Write-Output ok | powershell -Command -", false},
		{`type a.txt | cmd /c "python -"`, false},
		{"powershell -Command - | more", true},
		{"whoami && echo x | python -", false},
		{"cd x && powershell -Command -", true},
		{"whoami; python -", true},
		{"false || node", true},
		{"cmd /c python", true},
	} {
		if got := ReadsStdinScript(c.command); got != c.want {
			t.Errorf("ReadsStdinScript(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

// The classifier sees the same normalised program: a command wrapped by
// powershell.exe or a full path to cmd.exe is judged as it would be
// without the spelling, not passed as an unknown program.
func TestR150_ClassifyNormalisesProgramPath(t *testing.T) {
	for _, c := range []struct{ spelled, plain string }{
		{`powershell.exe -Command "Remove-Item -Recurse -Force C:\Data"`, `powershell -Command "Remove-Item -Recurse -Force C:\Data"`},
		{`"C:\Windows\System32\cmd.exe" /c rm -rf /var/lib/postgresql`, `cmd /c rm -rf /var/lib/postgresql`},
		{`C:\Windows\System32\sc.exe stop sshd`, `sc stop sshd`},
	} {
		plain := Classify(c.plain)
		if plain.Level == Green {
			t.Fatalf("premise: Classify(%q) is green", c.plain)
		}
		if got := Classify(c.spelled); got.Level != plain.Level {
			t.Errorf("Classify(%q) = %s, want %s like %q", c.spelled, got.Level, plain.Level, c.plain)
		}
	}
	if got := normalizeProgramPart(`"C:\Program Files\PowerShell\7\pwsh.exe" -Command -`); !strings.HasPrefix(got, "pwsh -Command -") {
		t.Errorf("normalizeProgramPart = %q", got)
	}
}
