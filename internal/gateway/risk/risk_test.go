package risk

import (
	"testing"
)

// ─────────────── Red rules — table pairs (red trigger + safe neighbour) ───────────────

func TestRules_RedTable(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Level
		rule string // non-empty → must be matched
	}{
		// rm recursive outside temp vs inside temp
		{"rm-recursive-outside-temp/var", "rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"rm-recursive-outside-temp/etc", "rm -rf /etc/nginx", Red, "rm-recursive-outside-temp"},
		{"rm-recursive-outside-temp/usr", "rm -rf /usr/local/foo", Red, "rm-recursive-outside-temp"},
		{"rm-recursive-inside-temp/tmpdir", "rm -rf /tmp/build", Green, "rm-recursive-inside-temp"},
		{"rm-recursive-inside-temp/vartmp", "rm -rf /var/tmp/build", Green, "rm-recursive-inside-temp"},
		{"rm-recursive-inside-temp/nm", "rm -rf ./node_modules", Green, "rm-recursive-inside-temp"},
		{"rm-recursive-root/slash", "rm -rf /", Red, "rm-recursive-root"},
		{"rm-recursive-root/tild", "rm -rf ~", Red, "rm-recursive-root"},

		// Remove-Item PowerShell equivalent
		{"ri-recursive-outside", "Remove-Item -Recurse -Force C:\\Users\\me\\Documents", Red, "remove-item-recursive-outside-temp"},
		{"ri-recursive-inside", "Remove-Item -Recurse -Force -Path C:\\Temp\\foo", Green, "remove-item-recursive-inside-temp"},

		// Disk format / partition
		{"mkfs", "mkfs /dev/sda1", Red, "disk-format"},
		{"mkfs-ext4", "mkfs.ext4 /dev/sdb1", Red, "disk-format"},
		{"fdisk", "fdisk /dev/sda", Red, "disk-partition"},
		{"diskpart", "diskpart", Red, "disk-partition"},
		{"format", "format c:", Red, "format-volume"},

		// dd of=/dev/sd*
		{"dd-of-sda", "dd if=/dev/zero of=/dev/sda bs=1M", Red, "dd-block-device"},
		{"dd-of-nvme", "dd if=/dev/zero of=/dev/nvme0n1 bs=1M", Red, "dd-block-device"},

		// redirect to /dev/sda
		{"redirect-sd", "echo x > /dev/sda", Red, "redirect-block-device"},
		{"redirect-nvme", "ls >/dev/nvme0n1", Red, "redirect-block-device"},

		// fork bomb
		{"fork-bomb", ":(){ :|:& };:", Red, "fork-bomb"},
		{"fork-bomb-spaced", ":() { : | : & } ; :", Red, "fork-bomb"},

		// iptables / netsh
		{"iptables-flush-f", "iptables -F", Red, "iptables-flush"},
		{"iptables-flush-x", "iptables -X", Red, "iptables-flush"},
		{"netsh-advfirewall-reset", "netsh advfirewall reset", Red, "netsh-advfirewall-reset"},

		// ssh service stop — multiple mechanisms
		{"stop-sshd-systemctl", "systemctl stop sshd", Red, "ssh-or-tunnel-service-action"},
		{"disable-sshd-systemctl", "systemctl disable sshd", Red, "ssh-or-tunnel-service-action"},
		{"stop-ssh-pkill", "pkill sshd", Red, "ssh-or-tunnel-service-action"},
		{"stop-sshd-stop-service", "Stop-Service sshd", Red, "ssh-or-tunnel-service-action"},
		{"stop-iamtunnel-net", "net stop iamtunnel", Red, "ssh-or-tunnel-service-action"},
		{"stop-iamtunnel-ag", "systemctl stop iamtunnel-agent", Red, "ssh-or-tunnel-service-action"},
		{"del-iamtunnel-sc", `sc.exe delete iamtunnel-svc`, Red, "ssh-or-tunnel-service-action"},
		{"kill-ssh-taskkill", `taskkill /F /IM sshd.exe`, Red, "ssh-or-tunnel-service-action"},
		{"kill-ssh-stop-process", "Stop-Process -Name sshd -Force", Red, "ssh-or-tunnel-service-action"},
		{"restart-sshd-yellow", "Restart-Service sshd", Yellow, "service-action-other"},

		// FIX-1 retry 1 — flag between verb and target.
		{"disable-sshd-with-flag", "systemctl disable --now sshd", Red, "ssh-or-tunnel-service-action"},
		{"disable-sshd-with-force", "systemctl disable -f sshd", Red, "ssh-or-tunnel-service-action"},
		{"stop-iamtunnel-with-now", "systemctl stop iamtunnel-agent --now", Red, "ssh-or-tunnel-service-action"},
		// FIX-1 retry 2 — target passed as a named parameter.
		{"stop-ssh-name-param", "Stop-Service -Name sshd -Force", Red, "ssh-or-tunnel-service-action"},
		{"stop-ssh-name-colon", "Stop-Service -Name:sshd", Red, "ssh-or-tunnel-service-action"},
		{"stop-iamtunnel-name-param", "Stop-Service -Name iamtunnel-agent", Red, "ssh-or-tunnel-service-action"},
		{"restart-ssh-name", "Restart-Service -Name sshd", Yellow, "service-action-other"},
		{"stop-process-id-pid", "Stop-Process -Id 1234", Yellow, "process-kill"},

		// FIX-1 retry 3 — destructive command under a privilege elevator.
		{"sudo-rm-destructive", "sudo rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"doas-rm-destructive", "doas rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"sudo-rm-root", "sudo rm -rf /", Red, "rm-recursive-root"},
		{"sudo-rm-with-user", "sudo -u postgres rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"sudo-rm-with-login", "sudo -i rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"sudo-rm-with-env", "sudo env FOO=1 rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"sudo-stop-sshd", "sudo systemctl stop sshd", Red, "ssh-or-tunnel-service-action"},
		{"sudo-shutdown", "sudo shutdown -h now", Red, "shutdown-reboot"},
		{"sudo-rm-non-destructive", "sudo rm -i file.txt", Yellow, "rm-non-recursive"},
		{"sudo-stop-nginx", "sudo systemctl stop nginx", Yellow, "service-action-other"},

		// user deletion
		{"userdel", "userdel -r alice", Red, "user-delete"},
		{"deluser", "deluser alice", Red, "user-delete"},
		{"remove-local-user", "Remove-LocalUser -Name alice", Red, "user-delete"},
		{"net-user-delete", `net user alice /delete`, Red, "user-delete"},

		// SQL
		{"sql-drop-database", "psql -c 'DROP DATABASE mydb'", Red, "sql-drop-truncate"},
		{"sql-drop-table", `mysql -e "DROP TABLE orders"`, Red, "sql-drop-truncate"},
		{"sql-truncate", `psql -c "TRUNCATE TABLE sessions"`, Red, "sql-drop-truncate"},

		// shutdown
		{"shutdown", "shutdown -h now", Red, "shutdown-reboot"},
		{"reboot", "reboot", Red, "shutdown-reboot"},
		{"halt", "halt", Red, "shutdown-reboot"},
		{"poweroff", "poweroff", Red, "shutdown-reboot"},
		{"restart-computer", "Restart-Computer -Force", Red, "shutdown-reboot"},
		{"stop-computer", "Stop-Computer -Force", Red, "shutdown-reboot"},

		// wipe free space
		{"cipher-wipe", "cipher /w C:\\Temp", Red, "cipher-wipe"},
		{"sdelete", "sdelete -p 1 C:\\Users\\alice", Red, "sdelete-wipe"},

		// chmod -R 777 /, chown -R /  only those exact forms
		{"chmod-r-777-root", "chmod -R 777 /", Red, "chmod-recursive-root"},
		{"chown-r-root", "chown -R alice /", Red, "chown-recursive-root"},

		// FIX-2 retry 1 — global flags before the verb.
		{"systemctl-global-flag-then-verb", "systemctl --no-pager disable sshd", Red, "ssh-or-tunnel-service-action"},
		{"systemctl-global-flag-then-verb-quiet", "systemctl --no-pager --quiet disable --now sshd", Red, "ssh-or-tunnel-service-action"},
		{"sc-global-flag-then-verb", "sc.exe --no-scm-query delete sshd", Red, "ssh-or-tunnel-service-action"},
		{"net-global-flag-then-verb", "net --no-cancel stop sshd", Red, "ssh-or-tunnel-service-action"},

		// FIX-2 retry 2 — target via -DisplayName or other non-Name
		// parameters. The display name "OpenSSH SSH Server" carries
		// the SSH signal in its substring, so isCriticalService
		// returns true and Red fires.
		{"stop-ssh-display-name", "Stop-Service -DisplayName \"OpenSSH SSH Server\" -Force", Red, "ssh-or-tunnel-service-action"},
		{"stop-iamtunnel-display-name", "Stop-Service -DisplayName \"IAMTunnel Agent\" -Force", Red, "ssh-or-tunnel-service-action"},
		{"stop-ssh-id-pid", "Stop-Process -Id 1234 -Force", Yellow, "process-kill"},

		// FIX-2 retry 3 — keyword inside read argument.
		// `git log --grep="DROP TABLE"` is read; the keyword is
		// inside the grep pattern, not a database operation.
		{"git-log-grep-drop-table", `git log --oneline --grep="drop table"`, Green, ""},
		{"git-log-grep-drop-uppercase", `git log --oneline --grep="DROP TABLE"`, Green, ""},
		{"echo-sql-quoted", `echo "DROP TABLE foo"`, Green, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.cmd)
			if got.Level != c.want {
				t.Errorf("Classify(%q) = level=%s rule=%q; want level=%s",
					c.cmd, got.Level, got.Rule, c.want)
				return
			}
			if c.rule != "" {
				if got.Rule != c.rule {
					t.Errorf("Classify(%q) rule=%q, want %q", c.cmd, got.Rule, c.rule)
				}
				if !got.Matched {
					t.Errorf("Classify(%q) matched=false, want true", c.cmd)
				}
			}
		})
	}
}

// ─────────────── Yellow rules — table pairs (yellow trigger + safe neighbour) ───────────────

func TestRules_YellowTable(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Level
		rule string
	}{
		// rm non-recursive
		{"rm-single", "rm -i some.txt", Yellow, "rm-non-recursive"},
		{"del-single", "del file.txt", Yellow, "rm-non-recursive"},
		{"remove-item-noforce", "Remove-Item file.txt", Yellow, "rm-non-recursive"},

		// service stop other (not sshd/ssh/iamtunnel)
		{"stop-nginx-systemctl", "systemctl stop nginx", Yellow, "service-action-other"},
		{"stop-w32time", "net stop W32Time", Yellow, "service-action-other"},
		{"disable-firewall", "sc.exe config MpsSvc start= disabled", Yellow, "service-action-other"},
		{"restart-nginx", "Restart-Service nginx", Yellow, "service-action-other"},
		{"stop-nginx-stop-service", "Stop-Service nginx", Yellow, "service-action-other"},

		// registry HKLM
		{"reg-add-hklm", `reg add HKLM\Software\Foo /v Bar /t REG_SZ /d "1"`, Yellow, "registry-machinelocal-write"},
		{"reg-delete-hklm", `reg delete HKLM\System\CurrentControlSet\Services\MyService`, Yellow, "registry-machinelocal-write"},
		{"set-itemproperty-hklm", `Set-ItemProperty -Path "HKLM:\\Software\\Foo" -Name "Bar" -Value "1"`, Yellow, "registry-machinelocal-write"},

		// network settings
		{"netsh-yellow", "netsh interface ip set address name=\"Ethernet0\" static 10.0.0.2", Yellow, "netsh-network-setting"},
		{"netsh-ipv4-reset", "netsh interface ipv4 reset", Yellow, "netsh-network-setting"},
		{"new-fw-rule", "New-NetFirewallRule -DisplayName foo -Direction Inbound -Action Block", Yellow, "powershell-firewall"},
		{"set-fw-profile", "Set-NetFirewallProfile -All -Enabled False", Yellow, "powershell-firewall"},
		{"route-add", "route add 10.0.0.0/24 192.168.1.1", Yellow, "route-table"},
		{"route-delete", "route delete 10.0.0.0/24", Yellow, "route-table"},

		// account management (other verbs)
		{"new-local-user", "New-LocalUser -Name alice", Yellow, "account-management"},
		{"add-local-group", "Add-LocalGroupMember -Group Administrators -Member alice", Yellow, "account-management"},
		{"useradd", "useradd -m bob", Yellow, "account-management"},
		{"usermod", "usermod -aG sudo bob", Yellow, "account-management"},
		{"net-user-add", `net user bob /add`, Yellow, "account-management"},

		// Set-ExecutionPolicy
		{"set-executionpolicy", "Set-ExecutionPolicy RemoteSigned", Yellow, "set-executionpolicy"},
		{"set-executionpolicy-unrestricted", "Set-ExecutionPolicy Unrestricted -Force", Yellow, "set-executionpolicy"},

		// scheduler
		{"schtasks-create", "schtasks /create /tn MyJob /tr \"cmd.exe /c calc\" /sc once /st 00:00", Yellow, "scheduler-write"},
		{"schtasks-delete", "schtasks /delete /tn MyJob /f", Yellow, "scheduler-write"},
		{"register-scheduled", "Register-ScheduledTask -TaskName Backup -Action $a -Trigger $t", Yellow, "scheduler-write"},
		{"unregister-scheduled", "Unregister-ScheduledTask -TaskName Backup -Confirm:$false", Yellow, "scheduler-write"},
		{"crontab", "crontab -e", Yellow, "crontab-write"},
		{"crontab-list", "crontab -l", Yellow, "crontab-write"},

		// process kill (not sshd/ssh/iamtunnel)
		{"taskkill-nginx", `taskkill /F /IM nginx.exe`, Yellow, "process-kill"},
		{"pkill-nginx", "pkill nginx", Yellow, "process-kill"},
		{"kill-9", "kill -9 1234", Yellow, "process-kill"},

		// git destructive
		{"git-push-force", "git push --force origin main", Yellow, "git-push-force"},
		{"git-push-f", "git push -f origin main", Yellow, "git-push-force"},
		{"git-reset-hard", "git reset --hard HEAD~1", Yellow, "git-reset-hard"},
		{"git-clean-fd", "git clean -fd", Yellow, "git-clean"},

		// download and exec
		{"curl-bash", "curl -fsSL https://get.docker.com | bash", Yellow, "download-and-exec"},
		{"wget-sh", "wget -qO- https://x.com/i.sh | sh", Yellow, "download-and-exec"},
		{"iwr-iex", "iwr https://x.com/i.ps1 | iex", Yellow, "download-and-exec-powershell"},
		{"invoke-expression", "Invoke-Expression 'Write-Host hi'", Yellow, "invoke-expression"},

		// install / elevate
		{"msiexec", "msiexec /i foo.msi /quiet", Yellow, "msi-install"},
		{"start-process-runas", "Start-Process -Verb RunAs notepad.exe", Yellow, "elevate-start-process"},

		// sudo at start (alone)
		{"sudo-alone", "sudo", Yellow, "sudo-at-start"},
		{"sudo-non-destructive", "sudo rm -i file.txt", Yellow, "rm-non-recursive"},

		// FIX-2 retry 4 — sudo is transparent on the inside; its
		// own verdict is no longer yellow. The level comes from
		// the inner command.
		{"sudo-status-nginx", "sudo systemctl status nginx", Green, ""},
		{"sudo-journalctl", "sudo journalctl -u nginx", Green, ""},
		{"sudo-journalctl-pipe-tail", "sudo journalctl -u nginx | tail", Green, ""},
		{"sudo-cat-config", "sudo cat /etc/ssh/sshd_config", Green, ""},
		{"sudo-ls", "sudo ls -la /var/log", Green, ""},
		{"sudo-list-allowed", "sudo -l", Green, "sudo-at-start"},
		{"sudo-list-allowed-long", "sudo --list", Green, "sudo-at-start"},
		{"sudo-version-cap", "sudo -V", Green, "sudo-at-start"},
		{"sudo-version-long", "sudo --version", Green, "sudo-at-start"},
		{"sudo-help", "sudo --help", Green, "sudo-at-start"},
		{"sudo-list-help-stacked", "sudo cat /etc/sudoers -l -h", Green, ""},

		// FIX-2 bare-shell forms — yellow because the next
		// commands in the same session run as root with no
		// further inspection.
		{"sudo-bare", "sudo", Yellow, "sudo-at-start"},
		{"sudo-interactive-shell", "sudo -i", Yellow, "sudo-at-start"},
		{"sudo-shell", "sudo -s", Yellow, "sudo-at-start"},
		{"sudo-login", "sudo --login", Yellow, "sudo-at-start"},
		{"sudo-bash", "sudo bash", Yellow, "sudo-at-start"},
		{"sudo-sh", "sudo sh", Yellow, "sudo-at-start"},
		{"sudo-su", "sudo su", Yellow, "sudo-at-start"},
		{"doas-bare", "doas", Yellow, "sudo-at-start"},

		// system dir write
		{"outfile-c-windows", `Out-File -FilePath "C:\\Windows\\System32\\drivers\\etc\\hosts" -InputObject "x"`, Yellow, "system-dir-write"},
		{"setcontent-etc", `Set-Content -Path "/etc/nginx/nginx.conf" -Value "x"`, Yellow, "system-dir-write"},
		{"echo-gt-etc", `echo "x" > /etc/nginx/nginx.conf`, Yellow, "system-dir-write"},
		{"copy-item-programfiles", `Copy-Item my.dll "C:\\Program Files\\Foo\\my.dll"`, Yellow, "system-dir-write"},
		{"tee-usr", `echo y | tee -a /var/log/syslog`, Yellow, "system-dir-write"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.cmd)
			if got.Level != c.want {
				t.Errorf("Classify(%q) = level=%s rule=%q; want level=%s",
					c.cmd, got.Level, got.Rule, c.want)
				return
			}
			if c.rule != "" {
				if got.Rule != c.rule {
					t.Errorf("Classify(%q) rule=%q, want %q", c.cmd, got.Rule, c.rule)
				}
				if !got.Matched {
					t.Errorf("Classify(%q) matched=false, want true", c.cmd)
				}
			}
		})
	}
}

// ─────────────── Green recognized (matched, rule non-empty) ───────────────

func TestRules_GreenRecognized(t *testing.T) {
	cases := []struct {
		name   string
		cmd    string
		ruleFn func(string) (Verdict, bool) // quick smoke check on the rule
	}{
		{"rm-rf-tmp-build", "rm -rf /tmp/build", ruleRMDangerous},
		{"rm-rf-tmp-foo", "rm -rf /tmp/foo", ruleRMDangerous},
		{"rm-rf-vartmp", "rm -rf /var/tmp/build", ruleRMDangerous},
		{"rm-rf-node_modules", "rm -rf ./node_modules", ruleRMDangerous},
		{"rm-rf-target", "rm -rf ./target", ruleRMDangerous},
		{"rm-rf-bin", "rm -rf ./bin", ruleRMDangerous},
		{"rm-rf-temp-env", `rm -rf $env:TEMP\\foo`, ruleRMDangerous},
		{"ri-temp", `Remove-Item -Recurse -Force -Path C:\\Temp\\x`, ruleRemoveItemDangerous},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Direct on the rule function.
			v, ok := c.ruleFn(c.cmd)
			if !ok || v.Level != Green || !v.Matched || v.Rule == "" {
				t.Errorf("%s: rule direct = (%+v, %v); want Green+matched+rule non-empty", c.name, v, ok)
			}
			// And via the public Classify entry point — Matched=true must survive.
			got := Classify(c.cmd)
			if got.Level != Green || !got.Matched || got.Rule == "" {
				t.Errorf("%s: Classify = %+v; want Green+matched+rule non-empty", c.name, got)
			}
		})
	}
}

// ─────────────── Reconnaissance — 30+ ordinary commands must be green+unmatched ───────────────

func TestReconnaissance_AlwaysGreenUnmatched(t *testing.T) {
	recon := []string{
		// Shell — Windows side
		"Get-Service",
		"Get-Service -Name BITS",
		"Get-Process",
		"Get-Process | Where-Object {$_.CPU -gt 100}",
		"Get-EventLog -Newest 50 -LogName Application",
		"Get-WinEvent -LogName System -MaxEvents 20",
		"Get-ChildItem -Path C:\\Users",
		"Get-Item C:\\Windows\\System32\\drivers\\etc\\hosts",
		"Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts",
		"Test-Path C:\\Windows",
		"Get-Location",
		"Get-Help Get-Process",
		"Select-Object -First 5",
		"Format-Table -AutoSize",
		"Format-List",
		"Where-Object {$_.Length -gt 0}",
		// Shell — Linux/macOS side
		"systemctl status nginx",
		"systemctl list-units --type=service",
		"journalctl -u nginx",
		"journalctl -u nginx --since \"1 hour ago\"",
		"journalctl -p err -b",
		"ls -la /var/log",
		"ls -la /etc",
		"cat /etc/hosts",
		"cat /etc/nginx/nginx.conf",
		"df -h",
		"du -sh /var/log/*",
		"free -m",
		"uptime",
		"uname -a",
		"ps aux",
		"ps aux | grep nginx",
		"netstat -an",
		"netstat -tlnp",
		"ss -tlnp",
		"grep -r error /var/log",
		"grep -i pattern /var/log/messages",
		"find / -name \"*.conf\"",
		"find . -type f -name '*.go'",
		"tail -n 100 /var/log/syslog",
		"tail -f /var/log/syslog",
		"head -n 20 /etc/passwd",
		"wc -l /var/log/syslog",
		"sort -u /etc/hosts",
		"stat /etc/hosts",
		"file /bin/bash",
		"whoami",
		"hostname",
		"date",
		"id",
		"ip a",
		"ip addr show",
		"ifconfig",
		"ping -c 3 203.0.113.8",
		"traceroute 203.0.113.8",
		"nslookup example.com",
		"dig example.com",
		"curl -sS https://example.com | head -20",
		"curl -V",
		// git hygiene
		"git status",
		"git log --oneline -n 20",
		"git log -p HEAD",
		"git diff",
		"git diff --stat",
		"git branch -a",
		"git remote -v",
		"git fetch",
		"git fetch --all",
		// Docker / containers — observation only
		"docker ps",
		"docker ps -a",
		"docker images",
		"docker logs mycontainer",
		"docker inspect mycontainer",
		"docker network ls",
		// Windows registry observation
		"reg query HKLM\\Software",
		"reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\"",
		// System info — harmless
		"systeminfo",
		"hostname",
		"ver",
		// tmux/screen just observe
		"tmux ls",
		"screen -ls",
		// Top / htop etc.
		"top -n 1",
		"htop",
	}
	for _, cmd := range recon {
		t.Run(cmd, func(t *testing.T) {
			got := Classify(cmd)
			if got.Level != Green {
				t.Errorf("recon %q: level=%s, want green (rule=%q reason=%q)",
					cmd, got.Level, got.Rule, got.Reason)
			}
			if got.Matched {
				t.Errorf("recon %q: matched=true, want false (a rule wrongly fired; rule=%q)",
					cmd, got.Rule)
			}
		})
	}
}

// ─────────────── Compound commands: worst verdict wins ───────────────

func TestCompound_WorstVerdictWins(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Level
		rule string
	}{
		{"safe-then-red", "ls && rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
		{"safe-then-red-tubular", "echo hi | rm -rf /var", Red, "rm-recursive-outside-temp"},
		{"red-then-safe", "rm -rf / || echo ignore", Red, "rm-recursive-root"},
		{"green-yellow-red", "Get-Service; echo done; pkill sshd", Red, "ssh-or-tunnel-service-action"},
		{"yellow-green", "taskkill /F /IM nginx.exe ; Get-Process", Yellow, "process-kill"},
		{"green-yellow", "Get-Process ; Set-ExecutionPolicy Bypass", Yellow, "set-executionpolicy"},
		{"two-yellows", "taskkill /IM a.exe ; pkill b", Yellow, "process-kill"},
		// `ls || rm -rf /var` — the rm is still red even though `ls` might
		// succeed and the `||` makes the rm unreachable; we classify by
		// shape, not by reachability.
		{"or-then-red", "ls || rm -rf /var/lib/postgresql", Red, "rm-recursive-outside-temp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.cmd)
			if got.Level != c.want {
				t.Errorf("Classify(%q) = level=%s rule=%q; want %s",
					c.cmd, got.Level, got.Rule, c.want)
			}
			if c.rule != "" && got.Rule != c.rule {
				t.Errorf("Classify(%q) rule=%q, want %q", c.cmd, got.Rule, c.rule)
			}
		})
	}
}

// ─────────────── Quotes inside strings don't split ───────────────

func TestSplitter_QuotesDoNotSplit(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		// Expected: single-part classifier must see them as one
		// segment with the quoted `;` / `|` / `&&` inside.
		want string
	}{
		{"double-quoted-semicolon", `echo "a; b"`, "echo"},
		{"single-quoted-ampamp", `echo 'a && b'`, "echo"},
		{"double-quoted-pipe", `echo "a | b"`, "echo"},
		{"backslash-escape", `echo \;b`, "echo"},
		{"powershell-backtick", "echo `;b", "echo"},
		// Quoted parts cannot smuggle in rm triggers if no rm is present.
		{"safe-string-with-scary-content", `echo "rm -rf /tmp/foo; shutdown -h now"`, "echo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parts := splitOnShellOperators(c.cmd)
			if len(parts) != 1 {
				t.Fatalf("splitOnShellOperators(%q) = %d parts (%v), want 1", c.cmd, len(parts), parts)
			}
			// The single part must still classify as green/unmatched — the
			// echo command body shouldn't trigger rules just because the
			// string mentions them.
			got := Classify(c.cmd)
			if got.Level != Green {
				t.Errorf("Classify(%q) = level=%s rule=%q; want green", c.cmd, got.Level, got.Rule)
			}
		})
	}
	// And a Red command with a quoted harmless string inside still is Red.
	t.Run("red-with-quoted-string", func(t *testing.T) {
		cmd := `rm -rf "weird name with spaces" /var/lib/postgresql`
		got := Classify(cmd)
		if got.Level != Red {
			t.Errorf("Classify(%q) = %s, want red", cmd, got.Level)
		}
	})
}

// ─────────────── Matched semantics — green recognized stays matched ───────────────

func TestMatched_RecognizedGreenHasTrue(t *testing.T) {
	cases := []string{
		"rm -rf /tmp/build",
		"rm -rf /tmp/foo",
		"rm -rf /var/tmp/x",
		"rm -rf ./node_modules",
		"rm -rf ./target",
		`Remove-Item -Recurse -Force C:\\Temp\\x`,
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			v := Classify(cmd)
			if v.Level != Green {
				t.Errorf("Classify(%q) = level=%s, want green", cmd, v.Level)
			}
			if !v.Matched {
				t.Errorf("Classify(%q) matched=false, want true (recognized green)", cmd)
			}
			if v.Rule == "" {
				t.Errorf("Classify(%q) rule=\"\"; want non-empty (recognized green)", cmd)
			}
		})
	}
}

func TestMatched_UnrecognizedGreenHasFalse(t *testing.T) {
	cases := []string{
		"Get-Service",
		"ls -la /tmp",
		"cat /etc/hosts",
		"git status",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			v := Classify(cmd)
			if v.Level != Green {
				t.Errorf("Classify(%q) = level=%s, want green", cmd, v.Level)
			}
			if v.Matched {
				t.Errorf("Classify(%q) matched=true, want false (unmatched green)", cmd)
			}
			if v.Rule != "" {
				t.Errorf("Classify(%q) rule=%q, want empty (unmatched green)", cmd, v.Rule)
			}
		})
	}
}

// ─────────────── Helpers — sanity check on the rule helpers themselves ───────────────

func TestHelpers_FirstWord(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"  ":                     "",
		"ls":                     "ls",
		"ls -la":                 "ls",
		"Get-Service -Name BITS": "Get-Service",
		"\tps aux":               "ps",
	}
	for in, want := range cases {
		if got := firstWord(in); got != want {
			t.Errorf("firstWord(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHelpers_Tokens(t *testing.T) {
	cases := map[string][]string{
		`rm -rf /tmp/foo`:    {"rm", "-rf", "/tmp/foo"},
		`echo "hello world"`: {"echo", "hello world"},
		`ls -la`:             {"ls", "-la"},
		`Get-Process | Where-Object {$_.CPU -gt 100}`: {"Get-Process", "|", "Where-Object", "{$_.CPU", "-gt", "100}"},
	}
	for in, want := range cases {
		got := tokens(in)
		if len(got) != len(want) {
			t.Errorf("tokens(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("tokens(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

func TestHelpers_IsTempPath(t *testing.T) {
	yes := []string{
		"/tmp/build",
		"/tmp",
		"/var/tmp/foo",
		"$env:TEMP/foo",
		"%TEMP%\\bar",
		"C:\\Temp\\foo",
		"c:/temp/foo",
		"./node_modules",
		"./build",
		"./target",
		"./bin",
		"./obj",
		"./proj/node_modules/foo",
		"./proj/build/output",
		"./proj/target/x.jar",
	}
	for _, p := range yes {
		if !isTempPath(p) {
			t.Errorf("isTempPath(%q) = false, want true", p)
		}
	}
	no := []string{
		"/var/lib/postgresql",
		"/etc/nginx",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/",
		"~",
		"C:\\Users",
		"C:\\Windows",
		"C:\\Program Files",
		"./src",
		"./main.go",
	}
	for _, p := range no {
		if isTempPath(p) {
			t.Errorf("isTempPath(%q) = true, want false", p)
		}
	}
}

func TestHelpers_IsCriticalService(t *testing.T) {
	// Substring matching for SSH / iamtunnel — see FIX-2. Display
	// names like "OpenSSH SSH Server" and "IAMTunnel Agent" need
	// to be recognised, so the matched substring is deliberately
	// broad. The cost: a contrived name starting with the
	// substring also matches.
	yes := []string{
		"sshd", "ssh", "sshd.service", "iamtunnel", "iamtunnel-agent",
		"iamtunnel_svc", "SSHD", "IAMTunnel",
		"OpenSSH SSH Server", // PowerShell DisplayName
		"IAMTunnel Agent",    // PowerShell DisplayName
		"MySshServer",        // custom name with SSH substring
		"ssh-fs",
	}
	no := []string{"nginx", "W32Time", "BITS", "foo", "mysql", "mariadb"}
	for _, s := range yes {
		if !isCriticalService(s) {
			t.Errorf("isCriticalService(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if isCriticalService(s) {
			t.Errorf("isCriticalService(%q) = true, want false", s)
		}
	}
}

func TestHelpers_DetectServiceAction(t *testing.T) {
	type expect struct {
		verb, target string
		serviceKind  string // "mgmt" or "proc" or ""
		ok           bool
	}
	cases := []struct {
		cmd     string
		want    expect
		wantAlt expect
	}{
		{"systemctl stop sshd", expect{"stop", "sshd", "mgmt", true}, expect{}},
		{"systemctl disable iamtunnel-agent", expect{"disable", "iamtunnel-agent", "mgmt", true}, expect{}},
		{"Stop-Service sshd", expect{"stop", "sshd", "mgmt", true}, expect{}},
		{"Restart-Service nginx", expect{"restart", "nginx", "mgmt", true}, expect{}},
		{"pkill nginx", expect{"kill", "nginx", "proc", true}, expect{}},
		{"pkill sshd", expect{"kill", "sshd", "proc", true}, expect{}},
		{"kill -9 sshd", expect{"kill", "sshd", "proc", true}, expect{}},
		{"kill -9 1234", expect{"kill", "1234", "proc", true}, expect{}},
		{"sc.exe delete iamtunnel-svc", expect{"delete", "iamtunnel-svc", "mgmt", true}, expect{}},
		{"net stop sshd", expect{"stop", "sshd", "mgmt", true}, expect{}},
		{"taskkill /F /IM sshd.exe", expect{"kill", "sshd", "proc", true}, expect{}},
		{"Stop-Process -Name sshd -Force", expect{"kill", "sshd", "proc", true}, expect{}},
		{"ls -la", expect{"", "", "", false}, expect{}},
	}
	for _, c := range cases {
		var verb, target string
		var kind string
		var ok1, ok2 bool
		verb, target, ok1 = detectServiceManagementAction(c.cmd)
		if ok1 {
			kind = "mgmt"
		} else {
			verb, target, ok2 = detectProcessKillAction(c.cmd)
			if ok2 {
				kind = "proc"
			}
		}
		ok := ok1 || ok2
		if verb != c.want.verb || target != c.want.target || kind != c.want.serviceKind || ok != c.want.ok {
			t.Errorf("detectService/%s(%q) = (%q, %q, %v); want (%q, %q, %q, %v)",
				kind, c.cmd, verb, target, ok,
				c.want.verb, c.want.target, c.want.serviceKind, c.want.ok)
		}
	}
}

func TestLevelString(t *testing.T) {
	if Green.String() != "green" {
		t.Errorf("Green.String() = %q", Green.String())
	}
	if Yellow.String() != "yellow" {
		t.Errorf("Yellow.String() = %q", Yellow.String())
	}
	if Red.String() != "red" {
		t.Errorf("Red.String() = %q", Red.String())
	}
}
