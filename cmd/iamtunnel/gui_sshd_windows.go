//go:build windows && !nogui

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/server"
)

// guiPrepareSSHDScript installs Windows' OpenSSH Server when the service
// is missing, sets it to start with Windows, starts it, and prints the
// service's final status - the three steps USER.md used to hand the
// owner as console commands (1.52).
const guiPrepareSSHDScript = `$ErrorActionPreference = 'Stop'
if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
(Get-Service -Name sshd).Status`

// guiPrepareSSHD is the Server tab's "Install and start OpenSSH Server".
//
// PowerShell is taken from the system folder by full path, never from PATH
// or an environment variable: this runs with administrator rights, and a
// PATH entry another account can write would decide what runs. The console stays hidden, like every
// other process the window starts. A component download can be slow on a
// cold Windows Update cache, so the wait is long but bounded.
func guiPrepareSSHD() (string, error) {
	sysDir, derr := windows.GetSystemDirectory()
	if derr != nil {
		return "", fmt.Errorf("could not find the Windows system folder: %w", derr)
	}
	ps := filepath.Join(sysDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", guiPrepareSSHDScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("installing OpenSSH Server did not finish within 15 minutes; Windows may still be downloading it - press START again in a while")
	}
	if err != nil || server.SSHDServiceState() != "running" {
		if text == "" && err != nil {
			text = err.Error()
		}
		return "", fmt.Errorf("could not install or start OpenSSH Server: %s — if this Windows cannot reach Windows Update, install OpenSSH Server from Settings → System → Optional features, or the MSI from github.com/PowerShell/Win32-OpenSSH/releases", lastLines(text, 6))
	}
	return "OpenSSH Server is installed and running, and starts with Windows. Starting the machine agent…", nil
}

// lastLines keeps the end of a PowerShell error, where the reason is,
// without the whole stack of position lines above it.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	var kept []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			kept = append(kept, l)
		}
	}
	if len(kept) > n {
		kept = kept[:n]
	}
	return strings.Join(kept, " ")
}
