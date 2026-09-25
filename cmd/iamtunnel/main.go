// Command iamtunnel is one binary with four roles: client, server,
// admin and gateway (SPEC §1–§3, console surface §7.2).
//
// This is the full command shell (IAMT-73): every command of
// §7.2 and every admin verb of §3.3 is parsed and validated here, the
// configuration is merged (defaults < config file < environment <
// flags), and execution reaches the real role implementation in
// internal/* — there is no shared not-yet-implemented point left. A
// command that cannot be completed in this environment (no live Linux
// gateway host, a role internal/gateway itself does not implement yet)
// says so with its own named reason instead of a generic stub.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
)

// Injected at build time by build.ps1 (SPEC §9):
//
//	go build -ldflags "-X main.version=… -X main.gitSHA=…"
var (
	version = "dev"
	gitSHA  = "none"
)

// Exit codes: the four classes are distinguished; the
// not-implemented stub of this shell phase shares the user-error code,
// as the IAMT-9 skeleton did.
const (
	exitOK       = 0 // success, also --help and version
	exitInternal = 1 // unexpected internal failure (panic)
	exitUser     = 2 // wrong invocation or value; cancelled/unconfirmed; stub
	exitEnv      = 3 // broken environment: unparsable config file, missing source
	exitDenied   = 4 // the OS refuses access to a configured path
)

// streams carries everything the CLI talks to; run is a pure function
// of args plus streams, which is what makes the whole surface testable
// in-process.
type streams struct {
	in          io.Reader
	interactive bool // stdin is a terminal — confirmations may ask
	out, errs   io.Writer
	env         map[string]string
	checkSSHD   func(addr string) error

	// openGUI overrides the live window launcher run() reaches on
	// Windows, Linux and macOS (IAMT-262) with no arguments. nil means the
	// real one, runGUI. This is the seam a test substitutes (IAMT-157):
	// runGUI calls ui.Run, which opens a real OS window and then blocks
	// forever (app.Main() never returns — see internal/ui/gui.go), so a
	// test binary that ever reached the real runGUI without this seam
	// would hang, not fail. See
	// TestNoArgsOpensTheWindowOnWindowsLinuxOrDarwin.
	openGUI func(*streams) int

	// isElevated checks the current Windows token before a server command can
	// touch the protected OpenSSH administrators key file. osStreams supplies
	// elevate.IsElevated; tests supply a fixed observation, so they never query
	// UAC, runas, or the owner machine's token.
	isElevated func() (bool, error)
	// checkSSHDConfig is the server start pre-flight seam for the
	// "sshd -T -C user=<osUser>" check on Linux/Darwin. nil
	// means the production server.CheckSSHDConfig is called. Tests
	// supply a fixed observation so a test binary never shells out
	// to the real sshd/systemctl the platform defaults run
	// (defaultCheckSSHDConfig → sshd -T, defaultCheckSSHDService →
	// systemctl is-active).
	checkSSHDConfig func(osUser string) error
}

func main() {
	// Before anything can be printed: take back the caller's console if
	// there is one (console_windows.go). The binary is linked for the GUI
	// subsystem so that launching the window does not also open a black
	// console beside it, flashing at the left of the screen.
	attachParentConsole()

	code := exitInternal
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "iamtunnel: internal error: %v\n", r)
			}
		}()
		code = run(os.Args[1:], osStreams())
	}()
	os.Exit(code)
}

func osStreams() *streams {
	return &streams{
		in:          os.Stdin,
		interactive: stdinIsInteractive(),
		out:         os.Stdout,
		errs:        os.Stderr,
		env:         envMap(),
		isElevated:  elevate.IsElevated,
	}
}

// stdinIsInteractive reports whether a confirmation may ask a question:
// stdin is a character device, not a pipe or a file.
func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func envMap() map[string]string {
	m := make(map[string]string)
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// run parses args and answers; it returns the process exit code so tests
// can drive the whole CLI in-process.
func run(args []string, s *streams) int {
	// The window's "Restart as administrator" relaunches this exe with the
	// elevate marker in front (IAMT-224); the elevated copy ignores it.
	if len(args) > 0 && args[0] == elevate.AlreadyElevatedFlag {
		args = args[1:]
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		// Windows and Linux both have the live window behind this same
		// command path (IAMT-252); elsewhere runGUI is the usage stub.
		// A leading flag (--tab, --help/-h) belongs to the GUI launch
		// itself, not to a subcommand — no subcommand name starts with
		// "-", so this is unambiguous.
		return runGUIWithFlags(args, s)
	}
	switch args[0] {
	case "version":
		return cmdVersion(s, args[1:])
	case "help":
		return cmdHelpTopic(s, args[1:])
	case "--help", "-h":
		fmt.Fprint(s.out, usageText)
		return exitOK
	case "client":
		return cmdClient(s, args[1:])
	case "server":
		return cmdServer(s, args[1:])
	case "enrol":
		return cmdEnrol(s, args[1:])
	case "admin":
		return cmdAdmin(s, args[1:])
	case "gateway":
		return cmdGateway(s, args[1:])
	case "shot":
		return cmdShot(s, args[1:])
	case "desktop":
		return cmdDesktop(s, args[1:])
	case "selftest":
		return cmdSelftest(s, args[1:])
	default:
		fmt.Fprintf(s.errs, "iamtunnel: unknown command %q — see \"iamtunnel --help\".\n", args[0])
		return exitUser
	}
}

// guiTabNames maps --tab's accepted spellings (IAMT-256: lower-case,
// hyphen-free — "setup", not "set up") to the exact tab header string
// internal/ui.NewFrame compares FrameConfig.InitialTab against
// (case-insensitively — design.Tabs.Show uses strings.EqualFold, so any
// case of the right-hand values below would also work; these are the
// canonical spellings the flag emits). Kept as plain literals rather
// than a reference to internal/ui: this file builds on every platform,
// including the ones gui_other.go stubs out, where internal/ui does not
// build at all (its own build tag is windows/linux/darwin only).
// TestIAMT256_GUITabNamesMatchUITabConstants (iamt256_gui_tab_linux_test.go,
// built only where internal/ui exists) pins every literal here against
// internal/ui's exported Tab* constants so the two lists
// cannot drift apart unnoticed.
//
// "gateway" went missing the way the six before it did (R2, 24.09.2026):
// the Gateway tab arrived in the window (cc37298, frame.go's TabGateway)
// and config.screens — the shot dictionary — learned the name, but this
// list was not extended, and nothing failed, until the screens canary
// held the two dictionaries side by side.
var guiTabNames = map[string]string{
	"guide":    "Guide",
	"setup":    "Set up",
	"client":   "Client",
	"server":   "Server",
	"gateway":  "Gateway",
	"session":  "Session",
	"admin":    "Admin",
	"history":  "History",
	"settings": "Settings",
}

// runGUIWithFlags parses the GUI launch's own flags — --tab (IAMT-256)
// and the ordinary --help/-h every command accepts — ahead of opening
// the window. An empty args slice already opens it with neither
// (IAMT-157/252); --tab reaches the exact same path with nothing else
// changed, since it names no subcommand. IAMTUNNEL_GUI_TAB (already read
// by runGUI on Linux since IAMT-309 round 2's live-check hook) is how
// the chosen tab actually reaches FrameConfig.InitialTab — this function
// only validates and translates the flag's value into it.
func runGUIWithFlags(args []string, s *streams) int {
	fs := newFlagSet("", "")
	fs.valFlag("tab")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		fmt.Fprint(s.out, usageText)
		return exitOK
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	if raw := fs.val("tab"); raw != "" {
		tab, ok := guiTabNames[strings.ToLower(strings.TrimSpace(raw))]
		if !ok {
			return fail(s, userErrf("iamtunnel: unknown --tab value %q — allowed: setup, client, server, admin, settings.", raw))
		}
		if s.env == nil {
			s.env = map[string]string{}
		}
		s.env["IAMTUNNEL_GUI_TAB"] = tab
	}
	open := s.openGUI
	if open == nil {
		open = runGUI
	}
	return open(s)
}

func cmdVersion(s *streams, args []string) int {
	fs := newFlagSet("version", "")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		fmt.Fprint(s.out, "Usage: iamtunnel version\n\nPrint the binary version, the git sha and the platform.\n")
		return exitOK
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	fmt.Fprintf(s.out, "iamtunnel %s (git %s)\n", version, gitSHA)
	fmt.Fprintf(s.out, "platform %s/%s %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	// WHICH BUILD, always and not only when it is the unusual one:
	// two artefacts exist since IAMT-439, and a fact told by its
	// absence is a fact every older binary tells wrongly.
	fmt.Fprintf(s.out, "build %s\n", buildVariant)
	return exitOK
}

// cliError is a classified CLI failure; the code is the exit code.
type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string { return e.msg }

func userErrf(format string, a ...any) *cliError {
	return &cliError{code: exitUser, msg: fmt.Sprintf(format, a...)}
}

func envErrf(format string, a ...any) *cliError {
	return &cliError{code: exitEnv, msg: fmt.Sprintf(format, a...)}
}

func deniedErrf(format string, a ...any) *cliError {
	return &cliError{code: exitDenied, msg: fmt.Sprintf(format, a...)}
}

// fail prints an error and returns its class's exit code. Config package
// errors carry their own class; anything unknown is internal.
func fail(s *streams, err error) int {
	var ce *cliError
	var cfe *config.Error
	switch {
	case errors.As(err, &ce):
		fmt.Fprintln(s.errs, err)
		return ce.code
	case errors.As(err, &cfe):
		fmt.Fprintf(s.errs, "iamtunnel: %s\n", err)
		return int(cfe.Class)
	default:
		fmt.Fprintf(s.errs, "iamtunnel: internal error: %v\n", err)
		return exitInternal
	}
}

// cfgOpts are the common configuration flags a leaf collected.
type cfgOpts struct {
	configPath string
	dataDir    string
	port       *int
}

// loadConfig merges the configuration for the running role and resolves
// its data directory: flag beats IAMTUNNEL_DATA_DIR beats the
// client_dir/server_dir/gateway_dir config-file key beats the platform
// default (IAMT-201 — the file key used to be skipped entirely whenever
// neither flag nor env named a directory, because this function asked
// config.DirsFor for a fresh platform default instead of reading back
// what config.Load had already merged from the file).
//
// IAMT-206: loadConfig also migrates the legacy enrolment record before
// the strict settings parser ever reads the default config path. The
// migration only runs when the user did NOT name --config or
// IAMTUNNEL_CONFIG: an explicit path the operator wrote must continue
// to fail with the "unknown field host" error they typed it under, not
// silently rename their file. The choice of "before config.Load, not
// inside it" keeps config.Load a pure function (no os.Rename) and
// makes the migration easy to skip in tests that want to assert the
// strict parser still rejects the same shape.
func loadConfig(s *streams, role string, o cfgOpts) (config.Settings, string, error) {
	envOv, err := config.EnvOverride(s.env)
	if err != nil {
		return config.Settings{}, "", err
	}
	if o.configPath == "" && envOv.ConfigPath == "" {
		dirsForMigration, derr := config.DirsFor(runtime.GOOS, s.env)
		if derr == nil && dirsForMigration.ConfigFile != "" && dirsForMigration.Server != "" {
			legacyPath := dirsForMigration.ConfigFile
			enrolmentPath := filepath.Join(dirsForMigration.Server, gatewayRecordName)
			// Migration error is non-fatal here: a malformed or
			// settings-shaped file at the default config path is a real
			// error, but it is config.Load's job to name it with the
			// exact field/text. migrateLegacyGatewayRecord is a no-op
			// for anything that does not look like a legacy enrolment
			// record; for what it does match, a rename failure is rare
			// (the directory is writable — enrol wrote there) and the
			// fallback path is the same unknown-field error the user
			// would have hit without migration, with no worse outcome.
			_ = migrateLegacyGatewayRecord(legacyPath, enrolmentPath)
		}
	}
	dir := envOv.DataDir
	if o.dataDir != "" {
		dir = o.dataDir
	}
	st, err := config.Load(runtime.GOOS, s.env, config.Override{
		ConfigPath: o.configPath,
		DataDir:    dir,
		Port:       o.port,
	}, os.ReadFile)
	if err != nil {
		return st, "", err
	}
	if dir == "" {
		// No --data-dir/IAMTUNNEL_DATA_DIR: st already carries the
		// merged client_dir/server_dir/gateway_dir — a config-file key
		// if one was set, the platform default otherwise — so read the
		// role's directory back from it rather than resolving a fresh
		// platform default that would ignore the file.
		dir = st.RoleDir(role)
	}
	if dir == "" {
		// st.RoleDir came back empty: no config-file key overrode this
		// role's directory AND the platform has no usable default for it
		// (IAMT-159 — e.g. no absolute %ProgramData% for server/gateway).
		// config.Load's own validate() tolerates that (a client-only run
		// must not need %ProgramData%), so surface DirsFor's deferred
		// error here, for the role that actually needed the directory.
		dirs, err := config.DirsFor(runtime.GOOS, s.env)
		if err != nil {
			return config.Settings{}, "", envErrf("iamtunnel: %v", err)
		}
		dir, err = dirs.RoleDirE(role)
		if err != nil {
			return config.Settings{}, "", envErrf("iamtunnel: %v", err)
		}
	}
	return st, dir, nil
}

// helpWord reports whether the token asks for help at a role level.
func helpWord(a string) bool { return a == "help" || a == "--help" || a == "-h" }
