package risk

// A second canary set for IAMT-352.
//
// The first one found three misses, and the repair had to fix the
// PARSING, not the three lines. That can only be verified by shapes
// nobody named to the repair: if it added three special cases,
// everything here falls apart.
//
// The second set matters just as much. A repair that widens the target
// search easily turns greedier than needed: "-Name sshd" appears not
// only in Stop-Service but also in Get-Service, and "sudo" in front of
// more than rm. A rule that, after the repair, paints reads is worse
// than a rule that missed writes: the agent will stop mid-investigation
// and the machine's owner will switch the check off entirely.

import "testing"

// TestCanary2_ParserNotSpecialCases — shapes that were in
// neither the rule table nor the earlier reviews covered.
func TestCanary2_ParserNotSpecialCases(t *testing.T) {
	cases := []struct {
		cmd  string
		want Level
		why  string
	}{
		// A flag between the action and the target — a different flag, a different action.
		{`systemctl stop --no-block ssh`, Red, "a flag nobody spoke about"},
		{`systemctl --no-pager disable sshd`, Red, "a flag before the action"},
		{`sudo systemctl mask sshd`, Red, "masking our own door under sudo"},

		// The target as a named parameter — other parameter names.
		{`Stop-Service -DisplayName "OpenSSH SSH Server" -Force`, Red, "the target through -DisplayName"},
		{`Stop-Service -Name:sshd`, Red, "a parameter through a colon"},
		{`Stop-Process -Name sshd -Force`, Red, "killing a process by name"},

		// sudo and its neighbours, with different insertions between it and the command.
		{`sudo -u root rm -rf /var/lib/mysql`, Red, "sudo with the -u flag"},
		{`sudo env DEBIAN_FRONTEND=noninteractive rm -rf /var/lib/postgresql`, Red, "sudo env before the command"},
		{`doas rm -rf /srv/www`, Red, "doas instead of sudo"},
		{`sudo dd if=/dev/zero of=/dev/nvme0n1`, Red, "wiping a disk under sudo"},

		// Compound — the red part hides in the second half under sudo.
		{`df -h && sudo rm -rf /var/lib/mysql`, Red, "red in the second part under sudo"},
	}
	for _, c := range cases {
		if v := Classify(c.cmd); v.Level != c.want {
			t.Errorf("%q: level %s, wanted %s (%s); rule %q — it looks like the three named lines were fixed, not the parsing",
				c.cmd, v.Level, c.want, c.why, v.Rule)
		}
	}
}

// TestCanary2_FixDidNotGetGreedy — the same mechanisms, but
// in harmless use. Everything here must stay green.
func TestCanary2_FixDidNotGetGreedy(t *testing.T) {
	quiet := []string{
		// -Name on reading commands: the name of a critical service means
		// nothing by itself; what matters is the action taken on it.
		`Get-Service -Name sshd`,
		`Get-Service -DisplayName "OpenSSH SSH Server"`,
		`Get-Process -Name sshd`,
		`Get-Service -Name sshd | Select-Object Status,StartType`,

		// Reading service state, including our own.
		`systemctl status sshd`,
		`systemctl is-enabled sshd`,
		`systemctl show sshd --property=ActiveState`,
		`systemctl list-units --type=service --state=running`,
		`journalctl -u sshd --since "10 min ago" --no-pager`,
		`sc.exe qc sshd`,

		// sudo in front of something perfectly harmless.
		`sudo systemctl status nginx`,
		`sudo journalctl -u nginx --no-pager | tail -50`,
		`sudo cat /etc/ssh/sshd_config`,
		`sudo ls -la /var/log`,
		`sudo -l`,

		// A red-list word inside a string, not as an operation.
		`grep -r "rm -rf" /home/deploy/scripts`,
		`echo "systemctl stop sshd"`,
		`git log --oneline --grep="drop table"`,
		`cat /etc/cron.d/backup`,
	}
	for _, cmd := range quiet {
		if v := Classify(cmd); v.Level != Green {
			t.Errorf("the repair got greedy: %q received %s by rule %q (%s) — this is a read, not an action; a false alarm here costs more than a miss, because it is what gets the whole check switched off",
				cmd, v.Level, v.Rule, v.Reason)
		}
	}
}
