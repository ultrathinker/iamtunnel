package main

// server_launchd.go — the macOS half of `server install`/`uninstall`
// (SPEC §3.2.1; IAMT-263, the macOS twin of the systemd half from
// IAMT-249).
//
// The machine role differs from the gateway (§3.5.1) in exactly the
// same way it differed on Linux from the gateway's systemd half:
//
//   - the job runs as root, not as a service user: the door is a line
//     in <osUser-home>/.ssh/authorized_keys of another user's account
//     (root is needed to create ~/.ssh with the right owner, replace
//     the file atomically and hold door.lock in the server directory).
//     So no dscl user is created, no directories are re-owned, and the
//     plist has no UserName key — launchd then runs the job as root;
//   - KeepAlive means not "always" but "only after an unsuccessful
//     exit" (SuccessfulExit=false) — the macOS form of systemd's
//     Restart=on-failure prescribed by §3.2.1: a clean `server stop`
//     must not be undone by a restart, while a crash must be.
//
// The file is platform-neutral on purpose (like gateway_launchd.go):
// the plist render is pure and the sequences go through the same
// darwinLaunchdSetup seam, so all of it is verified with the recording
// fake on any host OS. The production implementations of the seam live
// in gateway_launchd_darwin.go, the stubs in gateway_launchd_stub.go.

const (
	// machinePlistLabel is the machine role's launchd job label. The
	// name mirrors the systemd unit iamtunnel-machine.service
	// (IAMT-249): the same role is called the same on both OSes; only
	// the spelling differs — a dot instead of a hyphen in the label.
	machinePlistLabel = "com.iamtunnel.machine"
	// machinePlistPath is SPEC §3.2.1's start-on-boot requirement; the
	// path is the same directory as the gateway's LaunchDaemon (SPEC
	// §3.5.1), with a different name.
	machinePlistPath = "/Library/LaunchDaemons/com.iamtunnel.machine.plist"
	// machineLogPath is the job's output. The /Library/Logs/iamtunnel
	// directory is shared with the gateway, the file is its own: two
	// daemons on one machine must not write the same log.
	machineLogPath = darwinLogDir + "/machine.log"
)

// machineLaunchdPlist renders the machine's plist: RunAtLoad, KeepAlive
// in the "only after an unsuccessful exit" form, NO UserName (root),
// ProgramArguments `<binary> server start --data-dir <dir>`, output to
// /Library/Logs/iamtunnel/machine.log. Values are XML-escaped by the
// shared renderLaunchdPlistDoc, whatever the data directory path is.
func machineLaunchdPlist(exePath, dataDir string) (string, error) {
	return renderLaunchdPlistDoc(launchdPlist{
		Label:                machinePlistLabel,
		UserName:             "",
		KeepAliveOnCleanExit: false,
		ExePath:              exePath,
		Args:                 []string{"server", "start", "--data-dir", dataDir},
		LogPath:              machineLogPath,
	})
}

// setupMachineLaunchd is the machine's macOS install sequence:
// root → log directory → write the plist (0644, root:wheel) → restart
// the already-loaded job (a repeat install must pick up the new
// --data-dir) → launchctl bootstrap system.
//
// What is NOT here, compared with the gateway half, and why: no dscl
// user and no chown of directories. The job runs as root (§3.2.1), and
// the machine data directory was created by root itself in
// runServerInstall with 0700 — there is nobody to hand it to as a
// "service user" and no reason to. Tests pin that the user half of the
// seam stays at zero calls.
func setupMachineLaunchd(setup darwinLaunchdSetup, exePath, dataDir string) error {
	const role = "server"
	root, err := setup.currentUserIsRoot()
	if err != nil {
		return envErrf("%s install: check the effective UID: %v", role, err)
	}
	if !root {
		return envErrf("%s install: the macOS service half (LaunchDaemon — SPEC §3.2.1) writes %s and needs root — repeat the install with sudo.", role, machinePlistPath)
	}
	if err := setup.makeLogDir(darwinLogDir); err != nil {
		return envErrf("%s install: create the log directory %s: %v — create it by hand (\"sudo mkdir -p %s\") and repeat the install.", role, darwinLogDir, err, darwinLogDir)
	}
	plist, err := machineLaunchdPlist(exePath, dataDir)
	if err != nil {
		return envErrf("%s install: render the LaunchDaemon plist: %v", role, err)
	}
	if err := setup.writePlist(machinePlistPath, []byte(plist), 0o644, 0, 0); err != nil {
		return envErrf("%s install: write the LaunchDaemon plist %s (0644, root:wheel): %v — write it by hand and run \"sudo launchctl bootstrap system %s\".", role, machinePlistPath, err, machinePlistPath)
	}
	return launchdBootstrapTail(setup, role, machinePlistLabel, machinePlistPath, machineLogPath)
}

// uninstallMachineLaunchd is the reverse of setupMachineLaunchd: the
// shared teardown tail (root → no plist — "nothing to do" → bootout →
// remove the plist). The machine data directory (machine.key, the
// enrolment record, the local journal) is not touched: a repeat
// install/server start revives the same machine, and removing the data
// remains an explicit operator decision — the same boundary as the
// systemd half (§3.2.1) and the gateway (§3.5.1).
func uninstallMachineLaunchd(setup darwinLaunchdSetup) (bool, error) {
	return launchdTeardownTail(setup, "server", "§3.2.1", machinePlistLabel, machinePlistPath)
}
