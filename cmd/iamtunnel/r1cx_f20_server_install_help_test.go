package main

// R1-CX F-20: "server install" has had a Windows half since the logon
// task (server_task.go) - registered for the account the machine's
// registration is bound to, started at that account's every sign-in,
// refused until the machine is enrolled, installed from an elevated
// console - and the help described none of it. Every form of it named
// systemd and the LaunchDaemon only, promised "Runs as root on both" and
// asked for a root/sudo console, so a Windows operator went looking for
// a service that is never created and for a sudo that does not exist.
//
// The help is one text on every platform, so one test reads it for all
// three.

import (
	"strings"
	"testing"
)

func TestR1CX_F20_ServerInstallHelpDescribesEveryPlatform(t *testing.T) {
	forms := []struct {
		where string
		text  string
	}{
		{"the command list (iamtunnel help)", usageText},
		{"iamtunnel help server", serverHelp},
		{"iamtunnel server install --help", leafText["server install"]},
		{"iamtunnel server uninstall --help", leafText["server uninstall"]},
	}
	for _, f := range forms {
		for _, want := range []struct{ platform, word string }{
			{"Linux", "systemd"},
			{"macOS", "launchd"},
			{"Windows", "logon task"},
		} {
			if !strings.Contains(strings.ToLower(f.text), strings.ToLower(want.word)) {
				t.Errorf("%s does not name the %s autostart (%q): a %s operator reading it cannot tell what install puts in place there", f.where, want.platform, want.word, want.platform)
			}
		}
	}

	// The two forms that describe install in full also say who the
	// autostart runs as and what the command needs, on each platform.
	for _, f := range forms[1:3] {
		for _, want := range []struct{ fact, word string }{
			{"that Unix installs need root", "sudo"},
			{"that Windows installs need an elevated console", "Run as administrator"},
			{"that the Windows task runs as the registration's account", "account"},
			{"that the Windows task starts at sign-in", "signs in"},
			{"that Windows needs the machine enrolled first", "enrol"},
		} {
			if !strings.Contains(f.text, want.word) {
				t.Errorf("%s does not say %s (no %q in it)", f.where, want.fact, want.word)
			}
		}
		if strings.Contains(f.text, "Runs as root on both") || strings.Contains(f.text, "Needs a root/sudo console.") {
			t.Errorf("%s still claims the autostart runs as root and needs a root/sudo console everywhere - on Windows it is a logon task run as the registration's account", f.where)
		}
	}
}
