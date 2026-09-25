package main

// iamt337_logon_task_test.go — the Windows per-person autostart.
//
// The subject is one sentence: two people share a Windows box over Remote
// Desktop, each has his own Windows account and his own registration, and
// each must get his own autostart — starting when HE signs in, running as
// HIM, against HIS directory, named after HIS registration. A machine
// service could do none of that, which is why there is a task instead
// (server_task.go).
//
// The tests below are of two kinds, and both are needed. The document is
// checked directly, because it is the file Windows acts on and almost
// every setting in it is a NON-default that has to be written out (a task
// created with the defaults would kill the server on the third day and
// again the moment somebody unplugged the laptop). The sequence is checked
// through the recording seam, because nothing here may touch the real Task
// Scheduler of the machine the suite runs on.

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// taskRecorder is the test value of logonTaskSetup: every call, in order,
// with its arguments, and nothing reaching Windows.
type taskRecorder struct {
	calls []string
	docs  map[string]string
	// exists is what taskExists answers per task name.
	exists map[string]bool
	// createErr/runErr/existsErr/deleteErr make one step fail, for the
	// tests that check install and uninstall stop at the failing step and
	// name it.
	createErr, runErr, existsErr, deleteErr error
}

func newTaskRecorder() *taskRecorder {
	return &taskRecorder{docs: map[string]string{}, exists: map[string]bool{}}
}

func (r *taskRecorder) setup() logonTaskSetup {
	return logonTaskSetup{
		createTask: func(name, document string) error {
			r.calls = append(r.calls, "create "+name)
			if r.createErr != nil {
				return r.createErr
			}
			r.docs[name] = document
			r.exists[name] = true
			return nil
		},
		taskExists: func(name string) (bool, error) {
			r.calls = append(r.calls, "exists "+name)
			if r.existsErr != nil {
				return false, r.existsErr
			}
			return r.exists[name], nil
		},
		deleteTask: func(name string) error {
			r.calls = append(r.calls, "delete "+name)
			if r.deleteErr != nil {
				return r.deleteErr
			}
			delete(r.exists, name)
			delete(r.docs, name)
			return nil
		},
		runTask: func(name string) error {
			r.calls = append(r.calls, "run "+name)
			return r.runErr
		},
	}
}

// withAccount substitutes the account seam for the duration of one
// test. Since 1.4 the Windows account comes from the process token, not
// from %USERNAME%/%USERDOMAIN% (cmd/iamtunnel/misc.go currentOSUser),
// precisely so that setting an environment variable cannot rewrite who
// a registration is attributed to — which also means a test can no
// longer pin it that way and pins this instead.
func withAccount(t *testing.T, principal string) {
	t.Helper()
	prev := currentUserFn
	currentUserFn = func() (*user.User, error) { return &user.User{Username: principal}, nil }
	t.Cleanup(func() { currentUserFn = prev })
}

// withFakeLogonTasks substitutes the seam for the duration of one test,
// the same way withFakeGatewayService and withFakeSystemd do for the
// other two platforms.
func withFakeLogonTasks(t *testing.T) *taskRecorder {
	t.Helper()
	rec := newTaskRecorder()
	prev := windowsTasks
	windowsTasks = rec.setup()
	t.Cleanup(func() { windowsTasks = prev })
	return rec
}

// TestIAMT337_TheTaskDocumentSaysEverythingItMustNotLeaveToDefaults.
//
// Every assertion here is a default that is WRONG for a server, and each
// one fails differently in production: a three-day time limit kills a
// healthy server on day three, a battery rule stops it when somebody
// unplugs the laptop, the idle rule stops it when the person comes back
// to the keyboard, and the RemoteApp rule refuses to start it in exactly
// the sessions this product exists for.
//
// Canary: delete any one line from logonTaskDocument's <Settings> block —
// the corresponding assertion below goes red naming the setting.
func TestIAMT337_TheTaskDocumentSaysEverythingItMustNotLeaveToDefaults(t *testing.T) {
	doc := logonTaskDocument(logonTaskSpec{
		Machine: "office-pc",
		User:    `EXAMPLE\dana`,
		ExePath: `C:\Tools\iamtunnel\iamtunnel.exe`,
		DataDir: `C:\Users\dana\AppData\Local\iamtunnel\server`,
	})

	for _, want := range []struct{ element, why string }{
		{"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", "the default P3D makes Windows kill the server on the third day"},
		{"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>", "the default true stops the server the moment the machine is unplugged"},
		{"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>", "the default true refuses to start the server on a machine running on battery"},
		{"<StopOnIdleEnd>false</StopOnIdleEnd>", "the default true stops the server when the machine stops being idle, which is backwards for a server"},
		{"<DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>", "the sessions this product is built for arrive over Remote Desktop"},
		{"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", "a second server for one registration must be dropped, not raced against the first"},
		{"<LogonType>InteractiveToken</LogonType>", "the task must borrow the session's own token — no password may be stored for it"},
		{"<RunLevel>HighestAvailable</RunLevel>", "the door line goes into administrators_authorized_keys, which needs the account's administrator token"},
	} {
		if !strings.Contains(doc, want.element) {
			t.Errorf("the task document does not carry %s — %s", want.element, want.why)
		}
	}

	// The account appears twice and both are load-bearing: the trigger
	// decides WHOSE sign-in starts it, the principal decides WHO it runs
	// as. A document with one and not the other would start somebody
	// else's server, or start nobody's.
	if n := strings.Count(doc, `EXAMPLE\dana`); n != 3 {
		t.Errorf("the account appears %d times in the task document, want 3 (the logon trigger, the principal, and the description) — the trigger decides whose sign-in starts the task and the principal decides which account it runs as", n)
	}
	if !strings.Contains(doc, `--data-dir C:\Users\dana\AppData\Local\iamtunnel\server`) {
		t.Errorf("the task command line does not name the person's own data directory:\n%s", doc)
	}
	if !strings.Contains(doc, `<Command>C:\Tools\iamtunnel\iamtunnel.exe</Command>`) {
		t.Error("the task does not run the binary that installed it — after an upgrade it would run whatever is first on %PATH% at sign-in")
	}
}

// TestIAMT337_TwoRegistrationsGetTwoTasksAndNeitherTouchesTheOther is the
// requirement itself. Dana installs, then Erik installs, on the same
// machine. Two tasks, two accounts, two directories, and Dana's is
// exactly as it was.
func TestIAMT337_TwoRegistrationsGetTwoTasksAndNeitherTouchesTheOther(t *testing.T) {
	rec := withFakeLogonTasks(t)

	dana := logonTaskSpec{Machine: "office-pc", User: `EXAMPLE\dana`, ExePath: `C:\Tools\iamtunnel.exe`, DataDir: `C:\Users\dana\AppData\Local\iamtunnel\server`}
	erik := logonTaskSpec{Machine: "lab-pc", User: `EXAMPLE\erik`, ExePath: `C:\Tools\iamtunnel.exe`, DataDir: `C:\Users\erik\AppData\Local\iamtunnel\server`}

	if err := setupMachineLogonTask(windowsTasks, dana); err != nil {
		t.Fatalf("install for dana: %v", err)
	}
	before := rec.docs[logonTaskName("office-pc")]
	if err := setupMachineLogonTask(windowsTasks, erik); err != nil {
		t.Fatalf("install for erik: %v", err)
	}

	if len(rec.docs) != 2 {
		t.Fatalf("two registrations produced %d task(s): %v — one machine must be able to carry one autostart per person", len(rec.docs), rec.calls)
	}
	if got := rec.docs[logonTaskName("office-pc")]; got != before {
		t.Error("installing Erik's autostart rewrote Dana's")
	}
	if !strings.Contains(rec.docs[logonTaskName("lab-pc")], `EXAMPLE\erik`) {
		t.Error("Erik's task does not run as Erik")
	}
	// Install is `enable --now` on every platform: the server the
	// operator just installed must be up when the command returns, not
	// after the next sign-out.
	want := []string{
		"create " + logonTaskName("office-pc"), "run " + logonTaskName("office-pc"),
		"create " + logonTaskName("lab-pc"), "run " + logonTaskName("lab-pc"),
	}
	if strings.Join(rec.calls, "; ") != strings.Join(want, "; ") {
		t.Errorf("install sequence = %v, want %v", rec.calls, want)
	}
}

// TestIAMT337_UninstallOfAnAbsentTaskIsNotAFailure — uninstall is
// idempotent on every platform, and "there was nothing to remove" must
// not reach for the delete call.
func TestIAMT337_UninstallOfAnAbsentTaskIsNotAFailure(t *testing.T) {
	rec := withFakeLogonTasks(t)

	removed, err := removeMachineLogonTask(windowsTasks, "office-pc")
	if err != nil {
		t.Fatalf("uninstall with no task registered: %v", err)
	}
	if removed {
		t.Error("uninstall reported it removed a task that was never there")
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "delete ") {
			t.Errorf("uninstall called %q although the task did not exist", c)
		}
	}
}

// TestIAMT337_UninstallDoesNotGuessWhenItCannotLook is the other half of
// the same answer, and the reason taskExists returns an error at all. A
// lookup that FAILS is not a lookup that said no: reporting "nothing to
// remove" after an access-denied would tell an operator his machine is
// clean while the task is still there, starting a server at every
// sign-in.
//
// Canary: make windowsTasks.taskExists swallow its error and answer
// false, and this goes red on "reported a clean machine".
func TestIAMT337_UninstallDoesNotGuessWhenItCannotLook(t *testing.T) {
	rec := withFakeLogonTasks(t)
	rec.existsErr = os.ErrPermission

	removed, err := removeMachineLogonTask(windowsTasks, "office-pc")
	if err == nil {
		t.Fatal("uninstall reported a clean machine although it could not read the task list — the task is still there and still starts a server at every sign-in")
	}
	if removed {
		t.Error("uninstall reported a removal it did not make")
	}
	if !strings.Contains(err.Error(), logonTaskName("office-pc")) {
		t.Errorf("the refusal does not name the task it could not look up: %v", err)
	}
}

// TestIAMT337_ADamagedRecordCannotNameATaskOutsideItsFolder.
//
// The task path is built by concatenation (logonTaskName), and its input
// comes from a JSON file on disk. A machine id of `..\..\Something`
// registers a task somewhere else entirely — under a name an operator
// looking in the \iamtunnel folder would never find, and one that could
// overwrite an unrelated scheduled task of the system's. The grammar the
// gateway applied when it minted the name is applied again on the way
// back in.
//
// Canary: drop the state.ValidateName call from logonTaskSpecFor and this
// goes red on "accepted a registration name that escapes the folder".
func TestIAMT337_ADamagedRecordCannotNameATaskOutsideItsFolder(t *testing.T) {
	dir := t.TempDir()
	seedGatewayRecordForTask(t, dir, `..\..\Microsoft\Windows\UpdateOrchestrator\Reboot`, `EXAMPLE\dana`)

	s := &streams{env: map[string]string{}}
	if _, err := logonTaskSpecFor(s, "server install", dir); err == nil {
		t.Fatal("install accepted a registration name that escapes the \\iamtunnel folder — the task would be registered under a name nobody looking for it would find, and could overwrite an unrelated system task")
	}
}

// TestIAMT337_InstallBeforeEnrolmentRefusesAndNamesTheCommandThatComesFirst.
//
// On Unix an impersonal machine service may legitimately be installed
// before anybody enrols. A PERSONAL autostart cannot: it is named after
// the registration and bound to the account the registration carries, and
// neither exists yet. The refusal has to say which command comes first,
// because this is the state a person is in the very first time they run
// the product.
func TestIAMT337_InstallBeforeEnrolmentRefusesAndNamesTheCommandThatComesFirst(t *testing.T) {
	s := &streams{env: map[string]string{}}
	_, err := logonTaskSpecFor(s, "server install", t.TempDir())
	if err == nil {
		t.Fatal("install accepted a machine that has never registered — there is no name to call the task after and no account to bind it to")
	}
	if !strings.Contains(err.Error(), "iamtunnel enrol") {
		t.Errorf("the refusal does not name the command that comes first: %v", err)
	}
}

// TestIAMT337_TheTaskRunsAsTheAccountTheGatewayVERIFIED. The record's
// osUser is not a hint: the gateway proved it by logging in as that
// account during enrolment (SPEC §3.4 step 3), and it is the account
// whose authorized_keys the door line lives in. Taking the account this
// command happens to run under instead would bind the autostart to
// whoever typed it — an administrator setting a colleague's machine up,
// for instance.
func TestIAMT337_TheTaskRunsAsTheAccountTheGatewayVerified(t *testing.T) {
	dir := t.TempDir()
	seedGatewayRecordForTask(t, dir, "lab-pc", `EXAMPLE\erik`)

	// The person typing the command is somebody else entirely.
	withAccount(t, `EXAMPLE\dana`)
	s := &streams{env: map[string]string{}}
	spec, err := logonTaskSpecFor(s, "server install", dir)
	if err != nil {
		t.Fatalf("logonTaskSpecFor: %v", err)
	}
	if spec.User != `EXAMPLE\erik` {
		t.Errorf("the task would run as %q, want EXAMPLE\\erik — the registration is bound to Erik's account and it is his authorized_keys the door line lives in", spec.User)
	}
	if spec.Machine != "lab-pc" {
		t.Errorf("the task is named after %q, want lab-pc", spec.Machine)
	}
	if spec.DataDir != dir {
		t.Errorf("the task's data directory = %q, want %q", spec.DataDir, dir)
	}
}

// TestIAMT337_ARecordFromBeforeThisReleaseFallsBackToThisAccount — a 1.3
// enrolment record carries no osUser at all, and refusing to install an
// autostart on an upgraded machine would be a worse answer than the one
// account that is certainly right: the one holding the administrator
// token this command already required.
func TestIAMT337_ARecordFromBeforeThisReleaseFallsBackToThisAccount(t *testing.T) {
	dir := t.TempDir()
	seedGatewayRecordForTask(t, dir, "office-pc", "")

	withAccount(t, `EXAMPLE\dana`)
	s := &streams{env: map[string]string{}}
	spec, err := logonTaskSpecFor(s, "server install", dir)
	if err != nil {
		t.Fatalf("logonTaskSpecFor on a pre-1.4 record: %v", err)
	}
	if spec.User != `EXAMPLE\dana` {
		t.Errorf("spec.User = %q, want EXAMPLE\\dana", spec.User)
	}
}

// TestIAMT337_ADataDirectoryWithASpaceSurvivesTheCommandLine. The data
// directory is under the person's profile, and a Windows account name
// with a space in it is ordinary. Unquoted, the task would run with
// --data-dir truncated at the space and the server would start against
// the wrong directory — or refuse with a path nobody recognizes.
func TestIAMT337_ADataDirectoryWithASpaceSurvivesTheCommandLine(t *testing.T) {
	got := quoteTaskArgs(logonTaskArgs(`C:\Users\Dana Example\AppData\Local\iamtunnel\server`))
	want := `server start --data-dir "C:\Users\Dana Example\AppData\Local\iamtunnel\server"`
	if got != want {
		t.Errorf("quoteTaskArgs = %q, want %q", got, want)
	}
}

// TestIAMT337_TheRegistrationNameGrammarIsSafeAsATaskName is the
// assumption logonTaskName rests on, pinned so that widening the grammar
// cannot quietly break it. Every character state.ValidateName admits must
// be one Task Scheduler allows in a name.
func TestIAMT337_TheRegistrationNameGrammarIsSafeAsATaskName(t *testing.T) {
	// The full admitted alphabet, in one name of the maximum length.
	name := "a0bcdefghij.klmnopqrst-uvwxyz_012"[:32]
	if got := logonTaskName(name); strings.ContainsAny(strings.TrimPrefix(got, logonTaskFolder+`\`), `\/:*?"<>|`) {
		t.Errorf("logonTaskName(%q) = %q contains a character Task Scheduler forbids in a name", name, got)
	}
}

func seedGatewayRecordForTask(t *testing.T, dir, machine, osUser string) {
	t.Helper()
	rec := gatewayRecord{Host: "gw.example.test", Port: 2222, Fingerprint: "SHA256:x", MachineID: machine, OSUser: osUser}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal the enrolment record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, gatewayRecordName), raw, 0o600); err != nil {
		t.Fatalf("seed the enrolment record: %v", err)
	}
}

// TestIAMT337_UninstallCannotBeAimedOutsideItsFolder is the install-side
// canary's twin, and the sharper of the two. Install builds a task path
// from a name in a file on disk and would REGISTER a task at it;
// uninstall builds the same path and would DELETE whatever it finds
// there. A corrupted or hand-edited enrolment record must not be able to
// turn "remove my autostart" into "remove a task of the system's".
//
// Canary: drop the state.ValidateName call from removeMachineLogonTask
// and this goes red on "aimed a delete outside its own folder".
func TestIAMT337_UninstallCannotBeAimedOutsideItsFolder(t *testing.T) {
	rec := withFakeLogonTasks(t)
	// The task the damaged name points at exists and is not ours.
	victim := `\iamtunnel\..\..\Microsoft\Windows\UpdateOrchestrator\Reboot`
	rec.exists[victim] = true

	removed, err := removeMachineLogonTask(windowsTasks, `..\..\Microsoft\Windows\UpdateOrchestrator\Reboot`)
	if err == nil {
		t.Fatal(`uninstall accepted a registration name that escapes the \iamtunnel folder — it aimed a delete outside its own folder, at whatever task happens to sit there`)
	}
	if removed {
		t.Error("uninstall reported a removal")
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "delete ") {
			t.Errorf("uninstall reached the delete call anyway: %q", c)
		}
	}
	// The empty name is the same question with the likeliest input: a
	// record whose machineId is missing altogether.
	if _, err := removeMachineLogonTask(windowsTasks, ""); err == nil {
		t.Error(`uninstall accepted an empty registration name, building the task path \iamtunnel\ out of it`)
	}
}

// TestIAMT337_AnEnvironmentVariableCannotRewriteWhoRegisters is the
// review's first finding, as a test.
//
// The account went into the enrol body from %USERNAME%/%USERDOMAIN%
// until 1.4. Those belong to whoever starts the process: `set
// USERNAME=erik` in a console, then `iamtunnel enrol`, and the gateway
// records the registration as Erik's. The gateway's own proof does not
// catch it — its probe logs in as the claimed account against
// %ProgramData%\ssh\administrators_authorized_keys, which every
// administrator on the box shares, so the login succeeds and the false
// claim is stamped "verified".
//
// That is not a theoretical hole on the machine this release is for. The
// whole reason 1.4 exists is that a line in the journal must name WHO,
// and an attribution one environment variable rewrites is not one.
//
// Canary: read the account from env again in currentOSUser's Windows
// branch and this goes red naming the account it would have reported.
func TestIAMT337_AnEnvironmentVariableCannotRewriteWhoRegisters(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the environment-variable form of the account (the USERNAME/USERDOMAIN pair) is the Windows branch of currentOSUser; the Unix branch takes the login name and $SUDO_USER, and is pinned by TestEnrolSendsTheAccountAndNotTheName")
	}
	withAccount(t, `EXAMPLE\dana`)

	// What a person who wants the journal to blame somebody else does.
	env := map[string]string{
		"USERNAME":     "erik",
		"USERDOMAIN":   "EXAMPLE",
		"COMPUTERNAME": "EXAMPLE",
	}
	got, err := currentOSUser(env)
	if err != nil {
		t.Fatalf("currentOSUser: %v", err)
	}
	if got != `EXAMPLE\dana` {
		t.Errorf("currentOSUser reported %q — the environment rewrote who this registration belongs to, and every line the gateway writes about it would name the wrong person", got)
	}
}

// TestIAMT337_ARefusedQueryIsNeverReportedAsACleanMachine is the review's
// third finding.
//
// schtasks answers "there is no such task" and "I will not tell you"
// with the same exit code, and the sentence that separates them is
// localized. Reading that code as "not registered" makes uninstall say
// "nothing to do" on a machine where the task is still there and still
// starts a server at every sign-in — the operator then believes the
// thing is gone. resolveQueryRefusal asks the filesystem for a second
// opinion and only agrees with "clean" when both sources do.
//
// Canary: make resolveQueryRefusal return (false, nil) unconditionally
// and both "still there" cases below go red.
func TestIAMT337_ARefusedQueryIsNeverReportedAsACleanMachine(t *testing.T) {
	refusal := errors.New("exit status 1: access is denied")

	t.Run("the task file is there: the refusal was not 'no such task'", func(t *testing.T) {
		present, err := resolveQueryRefusal(refusal, true, nil)
		if err == nil {
			t.Fatal("a refused query on a task that IS registered was reported as a clean machine — uninstall would print \"nothing to do\" and leave a server starting at every sign-in")
		}
		if present {
			t.Error("resolveQueryRefusal answered yes; its contract is (false, err) — the caller must not act on it")
		}
	})

	t.Run("the file could not be examined either: still not clean", func(t *testing.T) {
		if _, err := resolveQueryRefusal(refusal, false, os.ErrPermission); err == nil {
			t.Fatal("neither source could answer and the machine was reported clean anyway")
		}
	})

	t.Run("the file is genuinely absent: the refusal really was 'no such task'", func(t *testing.T) {
		present, err := resolveQueryRefusal(refusal, false, nil)
		if err != nil {
			t.Fatalf("an absent task was reported as a failure: %v — uninstall must stay idempotent", err)
		}
		if present {
			t.Error("an absent task was reported present")
		}
	})
}
