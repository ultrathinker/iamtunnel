package main

// server_task.go — the Windows half of `server install` / `server
// uninstall` (IAMT-337, release 1.4): a per-person LOGON TASK instead of
// a machine-wide service.
//
// Why a task and not a service. Until 1.4 a machine carried exactly one
// registration, so "the machine's server" was a coherent thing to install
// as a service: one identity, one data directory, one autostart. 1.4
// makes a registration a (machine, name) pair, one per person, because
// two programmers share one Windows box over Remote Desktop and each has
// his own Windows account, his own %LOCALAPPDATA% and his own door line.
// A single service cannot be any of them: it would run as one account
// against one directory, which is neither person's registration, and the
// audit trail — the whole point of naming registrations — would say the
// service did everything.
//
// A logon task is the exact shape of what is wanted. Its trigger names
// the account whose sign-in starts it, its principal names the account it
// runs as, and both are the same person. Two people on one box get two
// tasks side by side under \iamtunnel, each starting when its own owner
// signs in (including over Remote Desktop). Nothing here isolates them
// from each other — administrators on Windows are not isolated by design,
// and what was asked for is attribution, not isolation — but every line
// the product writes now names which registration wrote it.
//
// The file is platform-neutral on purpose, exactly like gateway_service.go
// and gateway_launchd.go: the seam is a struct of plain functions over
// strings, so the whole install/uninstall SEQUENCE is verified by a
// recording fake on any host OS, and the rendering of the task document
// is a pure function a test can read directly. The production
// implementation lives in server_task_windows.go (schtasks.exe) and the
// refusing stubs in server_task_other.go.

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

const (
	// logonTaskFolder is the Task Scheduler folder every registration's
	// task goes into. A folder rather than loose names at the root so an
	// administrator opening Task Scheduler on a shared box sees the
	// registrations as a group — which is the list of who has a server
	// on this machine.
	logonTaskFolder = `\iamtunnel`

	// logonTaskExecutionTimeLimit is the one setting whose DEFAULT would
	// be a defect here. A task created by `schtasks /Create /SC ONLOGON`
	// inherits ExecutionTimeLimit=P3D: Windows kills the task after
	// three days. The machine server is meant to run for as long as the
	// person is signed in, and a server that dies every third day —
	// taking its door line with it — is the kind of failure nobody
	// connects back to an install command. PT0S means no limit.
	logonTaskExecutionTimeLimit = "PT0S"
)

// logonTaskSpec is everything install tells Task Scheduler about one
// registration's autostart. A platform-neutral struct on purpose (the
// same reasoning as gatewayServiceSpec): a test pins every value without
// any access to Windows types, and the production seam renders it once.
type logonTaskSpec struct {
	// Machine is the registration's name — the name the administrator
	// chose when he minted the invitation, which since 1.4 is also the
	// machine's id on the gateway. It is what the task is named after,
	// so the task list reads as the registration list.
	Machine string
	// User is the Windows principal, DOMAIN\name — both the account
	// whose sign-in triggers the task and the account it runs as.
	User string
	// ExePath is the binary that ran install: the task must keep
	// running the same build from the same place, not whatever is on
	// PATH at sign-in time.
	ExePath string
	// DataDir is the person's own server directory (%LOCALAPPDATA%
	// since 1.4). Passed explicitly rather than left to the default so
	// the task keeps working if the default ever moves.
	DataDir string
}

// logonTaskSetup is the seam: every call this feature makes into Windows,
// as plain functions over strings. Same convention as systemdSetup,
// darwinLaunchdSetup and windowsServiceSetup — production value
// windowsTasks, test value a recorder.
type logonTaskSetup struct {
	// createTask registers (or replaces) the named task from a task
	// document. Replacing is deliberate: install must be repeatable,
	// and an operator who runs it again after moving the binary means
	// "make the task match what I have now".
	createTask func(name, document string) error
	// taskExists answers whether the named task is registered. Used by
	// uninstall to tell "removed it" from "there was nothing to remove"
	// — the same distinction the systemd and launchd halves make.
	taskExists func(name string) (bool, error)
	// deleteTask removes the named task. Only called when taskExists
	// said yes, so a failure here is a real failure.
	deleteTask func(name string) error
	// runTask starts the task now, without waiting for the next sign-in.
	// This is the `enable --now` half of the Unix install: an operator
	// who just installed autostart expects the server to be up when the
	// command returns, not after he signs out and back in.
	runTask func(name string) error
}

// logonTaskName is the full Task Scheduler path of a registration's task.
//
// The registration name is safe here without any escaping and that is
// not luck: state.ValidateName admits only [a-z0-9][a-z0-9._-]{0,31},
// which contains none of the characters Task Scheduler forbids in a name
// (\ / : * ? " < > |) and no whitespace. A test pins that, because the
// day somebody widens the name grammar is the day this needs escaping.
func logonTaskName(machine string) string {
	return logonTaskFolder + `\` + machine
}

// logonTaskArgs is the command line the task runs: `server start` with
// the person's own data directory named explicitly — see the DataDir
// field for why.
func logonTaskArgs(dataDir string) []string {
	return []string{"server", "start", "--data-dir", dataDir}
}

// logonTaskDocument renders the Task Scheduler XML. A pure function on
// purpose, like machineUnitFile: a test asserts every directive without
// running anything, and an operator can read the result against what
// Task Scheduler shows him.
//
// The settings that matter, and why each is not the default:
//
//   - ExecutionTimeLimit PT0S — see logonTaskExecutionTimeLimit. The
//     default P3D kills a healthy server on the third day.
//   - StopIfGoingOnBatteries / DisallowStartIfOnBatteries false — both
//     default to TRUE, which on a laptop means the server stops the
//     moment the machine is unplugged. A tunnel that disappears when
//     somebody pulls a power cable is not a tunnel.
//   - StopOnIdleEnd false — the default stops the task when the machine
//     stops being idle, which is exactly backwards for a server.
//   - DisallowStartOnRemoteAppSession false — the sessions this product
//     is built for arrive over Remote Desktop.
//   - MultipleInstancesPolicy IgnoreNew — one server per registration.
//     If the person already started one by hand, the task's own start is
//     dropped rather than racing it.
//   - RestartOnFailure 3 × 1 min — the task-level equivalent of the
//     unit's Restart=on-failure. A clean exit (`server stop`) is NOT a
//     failure and is not restarted; a crash is.
//   - RunLevel HighestAvailable with LogonType InteractiveToken — the
//     server writes the door line into
//     %ProgramData%\ssh\administrators_authorized_keys, which needs the
//     account's administrator token. InteractiveToken means no password
//     is stored anywhere: the task borrows the session's own token when
//     the person signs in. On an account that is NOT an administrator
//     the task still runs, with whatever it has, and `server start`
//     refuses with its usual elevation text — which is the honest
//     outcome, not a silent one.
//
// The element order is the order Task Scheduler itself writes when it
// exports a task; the schema is a sequence, and a document with the
// elements in a different order can be rejected. This build of Windows 11
// accepted <Description> before <URI> when the document was tried against
// the real schtasks — but registrationInfoType's sequence puts <URI>
// first, so that acceptance was leniency, not permission, and nothing
// says another Windows version is as lenient. The order here is the
// schema's.
func logonTaskDocument(spec logonTaskSpec) string {
	args := quoteTaskArgs(logonTaskArgs(spec.DataDir))
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>` + xmlText(logonTaskName(spec.Machine)) + `</URI>
    <Description>iamtunnel machine server for the registration "` + xmlText(spec.Machine) + `" (SPEC 3.2.1). Starts when ` + xmlText(spec.User) + ` signs in.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlText(spec.User) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlText(spec.User) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>` + logonTaskExecutionTimeLimit + `</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlText(spec.ExePath) + `</Command>
      <Arguments>` + xmlText(args) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// quoteTaskArgs joins the command line the way CommandLineToArgvW reads
// it back: an argument containing a space or a quote is wrapped in
// quotes, backslashes immediately before a quote are doubled, and
// anything else is passed through. The only argument that can need any
// of this is the data directory — %LOCALAPPDATA% under an account whose
// name has a space in it — but the rule is written out in full rather
// than special-cased, because a half-rule is the kind of thing that
// silently truncates a path.
func quoteTaskArgs(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a != "" && !strings.ContainsAny(a, " \t\"") {
			parts = append(parts, a)
			continue
		}
		var b strings.Builder
		b.WriteByte('"')
		backslashes := 0
		for i := 0; i < len(a); i++ {
			switch a[i] {
			case '\\':
				backslashes++
				b.WriteByte('\\')
			case '"':
				b.WriteString(strings.Repeat(`\`, backslashes+1))
				b.WriteByte('"')
				backslashes = 0
			default:
				backslashes = 0
				b.WriteByte(a[i])
			}
		}
		b.WriteString(strings.Repeat(`\`, backslashes))
		b.WriteByte('"')
		parts = append(parts, b.String())
	}
	return strings.Join(parts, " ")
}

// xmlTextEscaper escapes a value for an XML text node. encoding/xml's own
// EscapeText writes to an io.Writer and escapes more than a text node
// needs (newlines, tabs); this is the four characters that can end an
// element or an attribute, which is all this document ever interpolates.
var xmlTextEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
)

func xmlText(s string) string { return xmlTextEscaper.Replace(s) }

// logonTaskSpecFor reads out of the enrolment record everything the task
// needs to describe one person's registration, and refuses rather than
// guess when it is not there.
//
// It refuses on three counts, and each one is a thing the task would
// otherwise get WRONG rather than merely miss:
//
//   - No enrolment record: there is no registration name to call the task
//     after and no account to bind it to. Unix can legitimately install an
//     impersonal service before anybody enrols; a personal autostart for a
//     person who does not exist yet is not a thing.
//   - A registration name that is not a name: the task path is built by
//     string concatenation (logonTaskName), and the record is an ordinary
//     file on disk. A hand-edited `..\..\Something` would register a task
//     somewhere else entirely, under a name an operator looking in
//     \iamtunnel would never find. state.ValidateName is the same grammar
//     the gateway applied when it minted the name, so a record written by
//     this product always passes.
//   - No account: the task must run as the account whose door line the
//     server maintains. The record carries it since 1.4 because the
//     gateway VERIFIED it by logging in as it. When it does not, the
//     account this command is running under is the best answer available
//     — and a defensible one, since this command already required that
//     account's administrator token to get here.
//
// That last branch is defensive, NOT an upgrade path, and the review
// of 1.4 was right to say so. A genuine 1.3 registration on
// Windows lives in %ProgramData%\iamtunnel; 1.4 resolves the server
// directory to %LOCALAPPDATA%\iamtunnel\server and never looks at the old
// place or migrates it. So an upgraded machine does not reach the
// fallback: it reads no record at all and is told to register again,
// which is the truth — 1.4 does not carry a pre-1.4 registration forward,
// and SPEC §3.2.2 and RUNBOOK §1.8 say so in as many words. The branch
// stays for the only case that can still produce an empty account: a
// record this product wrote whose osUser is missing for some other
// reason. Refusing there would be a refusal with no remedy.
func logonTaskSpecFor(s *streams, path, dir string) (logonTaskSpec, error) {
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return logonTaskSpec{}, userErrf("iamtunnel %s: this machine is not registered yet, and on Windows the autostart is named after the registration and runs as the account it is bound to — so there is nothing to name it after. Run \"iamtunnel enrol <code>\" with the code from the gateway administrator first, then this command again.", path)
		}
		return logonTaskSpec{}, err
	}
	machine := strings.TrimSpace(rec.MachineID)
	if verr := state.ValidateName(machine); verr != nil {
		return logonTaskSpec{}, userErrf("iamtunnel %s: the enrolment record in %s names this registration %q, which is not a registration name (%v) — the file has been edited or damaged. Re-register with \"iamtunnel enrol <code>\" rather than repairing it by hand.", path, dir, machine, verr)
	}
	account := strings.TrimSpace(rec.OSUser)
	if account == "" {
		account, err = currentOSUser(s.env)
		if err != nil {
			return logonTaskSpec{}, userErrf("iamtunnel %s: the enrolment record carries no Windows account (it was written before 1.4) and this account cannot be identified either: %v", path, err)
		}
	}
	bin, err := os.Executable()
	if err != nil {
		return logonTaskSpec{}, envErrf("iamtunnel %s: locate this binary for the logon task: %v", path, err)
	}
	return logonTaskSpec{Machine: machine, User: account, ExePath: bin, DataDir: dir}, nil
}

// resolveQueryRefusal decides what a refused `schtasks /Query` MEANS,
// and it exists because schtasks answers "there is no such task" and
// "I will not tell you" with the same exit code — 1 — and tells them
// apart only in a sentence that is localized, so it cannot be matched
// on. Reading exit 1 as "not registered" makes uninstall print "nothing
// to remove" on a machine where the task is still registered and still
// starts a server at every sign-in, which is the worst answer this
// command can give: the operator believes the thing is gone.
//
// The second opinion comes from the filesystem. Task Scheduler stores
// every task as a file under %SystemRoot%\System32\Tasks\<folder>\<name>,
// and os.Stat separates "not there" from "cannot look" exactly, in
// errors that carry no language. The three outcomes:
//
//   - the file is not there — the refusal really was "no such task",
//     and uninstall's "nothing to do" is true;
//   - the file IS there — schtasks refused for some other reason and
//     the task exists; say so rather than report a clean machine;
//   - the stat itself failed — neither source could answer, which is
//     also not "clean".
//
// Split out of the seam and made platform-neutral so a test can drive
// all three, since the production seam panics inside a test binary.
func resolveQueryRefusal(queryErr error, present bool, statErr error) (bool, error) {
	switch {
	case statErr != nil:
		return false, fmt.Errorf("the task list could not be read (%v) and the task's own file could not be examined either: %w", queryErr, statErr)
	case present:
		return false, fmt.Errorf("the task list refused the query (%w) although the task is registered — refusing to report that there is nothing to remove", queryErr)
	default:
		return false, nil
	}
}

// setupMachineLogonTask is the install sequence: register the task, then
// start it. Split out of runServerInstall for the same reason
// setupMachineSystemd is — the sequence is what a test checks, and it
// must be checkable without a Windows host.
func setupMachineLogonTask(setup logonTaskSetup, spec logonTaskSpec) error {
	name := logonTaskName(spec.Machine)
	if err := setup.createTask(name, logonTaskDocument(spec)); err != nil {
		return envErrf("server install: register the logon task %s: %v — register it by hand per RUNBOOK.md §1.7, or run this command from a console started with \"Run as administrator\".", name, err)
	}
	if err := setup.runTask(name); err != nil {
		return envErrf("server install: the logon task %s was registered but would not start now: %v — it will still start at the next sign-in, or start the server by hand with \"iamtunnel server start\".", name, err)
	}
	return nil
}

// removeMachineLogonTask is the uninstall sequence, and it answers the
// same two-valued question the Unix halves answer: (removed, err), where
// removed=false with err=nil means there was nothing to remove — not a
// failure. Uninstall is idempotent on every platform.
func removeMachineLogonTask(setup logonTaskSetup, machine string) (bool, error) {
	// The same grammar check install makes, and for a sharper reason.
	// Install builds a task path out of a name from a file on disk, and
	// a `..\..\Something` there would REGISTER a task somewhere else;
	// uninstall builds the same path and would DELETE what it finds
	// there. A hand-edited or corrupted enrolment record must not be
	// able to turn "remove my autostart" into "remove a task of the
	// system's" — so the check lives here, in the one function both the
	// command and any later caller go through, rather than only on the
	// install path (logonTaskSpecFor).
	if err := state.ValidateName(strings.TrimSpace(machine)); err != nil {
		return false, userErrf("iamtunnel server uninstall: the enrolment record names this registration %q, which is not a registration name (%v) — refusing to build a task path out of it. Remove the task by hand in Task Scheduler under the %s folder.", machine, err, logonTaskFolder)
	}
	name := logonTaskName(machine)
	present, err := setup.taskExists(name)
	if err != nil {
		return false, envErrf("server uninstall: look up the logon task %s: %v", name, err)
	}
	if !present {
		return false, nil
	}
	if err := setup.deleteTask(name); err != nil {
		return false, envErrf("server uninstall: remove the logon task %s: %v — remove it by hand in Task Scheduler, or with \"schtasks /Delete /TN %s /F\" from a console started with \"Run as administrator\".", name, err, name)
	}
	return true, nil
}
