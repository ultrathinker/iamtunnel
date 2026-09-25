package config

import (
	"path/filepath"
	"strings"
)

// Dirs holds the working directories of the roles plus the default
// location of the config file. Resolution is pure: it reads only the
// passed environment map, never the disk, so it is testable and never
// creates anything (SPEC §3.1, §3.5 give the Windows client dir and the
// Linux gateway dir; the remaining values are this package's own
// decisions).
type Dirs struct {
	Client     string // person's data: key, known_hosts, machines.mine
	Server     string // machine-side data: machine.key, machine.id, events.jsonl
	Gateway    string // gateway data: state.json, events.jsonl, hostkey, recordings/
	ConfigFile string // default config file path
	// machineErr is the deferred %ProgramData% error, and since 1.4 it
	// belongs to the GATEWAY default alone: that is the only role whose
	// directory is still machine-wide on every platform.
	machineErr error
	// clientErr and serverErr are the per-user mirrors (IAMT-310): the
	// client and, since 1.4, the server directory both hang off the
	// person running the program, so both need $HOME / %LOCALAPPDATA%
	// while the gateway needs neither.
	//
	// They are SEPARATE errors, and separate from machineErr, because a
	// daemon asking for one role must not be refused over a variable
	// another role needs. A launchd/systemd gateway is never given
	// $HOME; failing it there — the way this worked before IAMT-310 —
	// refused a role that never touches a per-user directory at all.
	clientErr error
	serverErr error
}

// joinWin and joinUnix build paths with the platform's own separator
// regardless of the machine the tests run on, so both layouts are
// verified on either platform.
func joinWin(parts ...string) string {
	return strings.Join(nonEmpty(parts), `\`)
}

func joinUnix(parts ...string) string {
	return strings.Join(nonEmpty(parts), "/")
}

func nonEmpty(parts []string) []string {
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DirsFor resolves the directories for the given platform from env.
// Unknown platform values fall through to the Unix layout.
//
// It returns an error when the environment does not supply enough
// information to build absolute paths — returning a relative path is
// never acceptable because it would place secrets (private keys, state)
// in whatever the current directory happens to be (IAMT-76).
func DirsFor(goos string, env map[string]string) (Dirs, error) {
	if goos == "windows" {
		local := env["LOCALAPPDATA"]
		if local == "" {
			local = joinWin(env["USERPROFILE"], "AppData", "Local")
		}
		if !isAbsWin(local) {
			return Dirs{}, envErrorf(
				"cannot determine the client data directory: "+
					"%%LOCALAPPDATA%% is empty and %%USERPROFILE%% is empty — "+
					"set at least one of them so the path is absolute "+
					"(without them the path would be %q, which is relative and unsafe)", local)
		}
		d := Dirs{
			Client: joinWin(local, "iamtunnel"),
			// The SERVER directory is per-user since 1.4, and the change
			// is what makes several registrations on one machine
			// possible at all. It holds machine.key, machine.id,
			// enrolment.json and control.json — the identity of ONE
			// registration — and two people working on the same box are
			// two registrations, with two keys and two tunnels. Sharing
			// %ProgramData% meant the second `server start` found the
			// first one's control.json and refused with "a server is
			// already running for this machine".
			//
			// The GATEWAY directory stays machine-wide: a gateway is a
			// property of the host, runs as a service account, and has
			// never been per-person.
			Server: joinWin(local, "iamtunnel", "server"),
		}
		programData, err := WindowsProgramData(env)
		if err != nil {
			// Only the gateway default needs ProgramData now. Keep the
			// failure until a gateway default is actually requested, so
			// an explicit --data-dir never needs this variable.
			d.machineErr = err
			return d, nil
		}
		base := joinWin(programData, "iamtunnel")
		d.Gateway = joinWin(base, "gateway")
		d.ConfigFile = joinWin(base, "gateway.json")
		return d, nil
	}
	if goos == "darwin" {
		// The gateway keeps its data in the SYSTEM scope (SPEC §3.5.1):
		// /Library/Application Support/iamtunnel/gateway, root-owned 0700,
		// not the per-user Library path the client uses — the LaunchDaemon
		// (IAMT-259) runs as the _iamtunnel service user and must find the
		// state there regardless of which admin installed it. The machine
		// role's server directory is unchanged from before §3.5.1. Neither
		// needs $HOME, so both are set before $HOME is even looked at
		// (IAMT-310).
		d := Dirs{
			Gateway:    "/Library/Application Support/iamtunnel/gateway",
			ConfigFile: "/Library/Application Support/iamtunnel/gateway.json",
		}
		home := env["HOME"]
		if !isAbsUnix(home) {
			err := envErrorf(
				"cannot determine the per-user data directories: "+
					"$HOME is empty — "+
					"set it to an absolute path "+
					"(without it the path would be %q, which is relative and unsafe)",
				joinUnix(home, "Library", "Application Support", "iamtunnel"))
			d.clientErr, d.serverErr = err, err
			return d, nil
		}
		d.Client = joinUnix(home, "Library", "Application Support", "iamtunnel")
		// Per-user since 1.4, for the same reason as on Windows: the
		// server directory holds ONE registration's identity, and two
		// people on one machine are two registrations.
		d.Server = joinUnix(home, "Library", "Application Support", "iamtunnel", "server")
		return d, nil
	}
	// Gateway is a fixed absolute path here too — see the darwin branch
	// above and IAMT-310 for why that split matters. Server is not: it
	// became per-user in 1.4.
	d := Dirs{
		Gateway:    "/var/lib/iamtunnel",
		ConfigFile: "/etc/iamtunnel/gateway.json",
	}
	data := env["XDG_DATA_HOME"]
	if data == "" {
		data = joinUnix(env["HOME"], ".local", "share")
	}
	if !isAbsUnix(data) {
		err := envErrorf(
			"cannot determine the per-user data directories: "+
				"$XDG_DATA_HOME is empty and $HOME is empty — "+
				"set at least one of them so the path is absolute "+
				"(without them the path would be %q, which is relative and unsafe)", data)
		d.clientErr, d.serverErr = err, err
		return d, nil
	}
	d.Client = joinUnix(data, "iamtunnel")
	// Per-user since 1.4 (was /var/lib/iamtunnel-machine): the server
	// directory holds ONE registration's identity — machine.key,
	// machine.id, enrolment.json, control.json — and two people working
	// on the same machine are two registrations.
	d.Server = joinUnix(data, "iamtunnel", "server")
	return d, nil
}

// WindowsProgramData returns the Windows machine-data root named by env.
// It deliberately has no C:\ProgramData fallback: callers that need to
// create or open machine-owned files must refuse an empty or relative value
// rather than silently touching the real machine. DirsFor and server start
// share this rule.
func WindowsProgramData(env map[string]string) (string, error) {
	programData := env["ProgramData"]
	if !isAbsWin(programData) {
		return "", envErrorf(
			"cannot determine the machine data directory: "+
				"%%ProgramData%% is %q, not an absolute Windows path — "+
				"set %%ProgramData%% to an absolute path", programData)
	}
	return programData, nil
}

// isAbsWin reports whether p is an absolute Windows path (drive letter
// or UNC). It does NOT call filepath.IsAbs because the test process may
// run on Linux while checking the Windows layout.
func isAbsWin(p string) bool {
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return len(p) >= 2 && p[0] == '\\' && p[1] == '\\' // UNC
}

// isAbsUnix reports whether p is an absolute Unix path.
func isAbsUnix(p string) bool {
	return len(p) > 0 && p[0] == '/'
}

// RoleDir returns the data directory of one role: "client", "server" or
// "gateway". An unavailable machine default and an unknown role return "".
func (d Dirs) RoleDir(role string) string {
	dir, _ := d.RoleDirE(role)
	return dir
}

// RoleDirE is RoleDir with the deferred error for a machine default whose
// %ProgramData% is absent or relative. Client never needs ProgramData.
func (d Dirs) RoleDirE(role string) (string, error) {
	switch role {
	case "client":
		if d.clientErr != nil {
			return "", d.clientErr
		}
		return d.Client, nil
	case "server", "enrol":
		if d.serverErr != nil {
			return "", d.serverErr
		}
		return d.Server, nil
	case "gateway":
		if d.machineErr != nil {
			return "", d.machineErr
		}
		return d.Gateway, nil
	default:
		return "", nil
	}
}

// Files inside the client directory (SPEC §3.1).
func (d Dirs) ClientKey() string    { return filepath.Join(d.Client, "key") }
func (d Dirs) KnownHosts() string   { return filepath.Join(d.Client, "known_hosts") }
func (d Dirs) MachinesMine() string { return filepath.Join(d.Client, "machines.mine") }

// Files inside the server directory (SPEC §3.2: the machine keeps its
// registration material and its local watchdog audit journal).
func (d Dirs) MachineKey() string   { return filepath.Join(d.Server, "machine.key") }
func (d Dirs) MachineID() string    { return filepath.Join(d.Server, "machine.id") }
func (d Dirs) ServerEvents() string { return filepath.Join(d.Server, "events.jsonl") }

// Files inside the gateway directory (SPEC §3.5).
func (d Dirs) GatewayState() string   { return filepath.Join(d.Gateway, "state.json") }
func (d Dirs) GatewayEvents() string  { return filepath.Join(d.Gateway, "events.jsonl") }
func (d Dirs) GatewayHostKey() string { return filepath.Join(d.Gateway, "hostkey") }
func (d Dirs) Recordings() string     { return filepath.Join(d.Gateway, "recordings") }
