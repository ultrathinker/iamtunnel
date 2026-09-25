//go:build (windows || linux || darwin) && !nogui

package main

// The gateway, made from the window (IAMT-434).
//
// The owner, 22.09.2026: he wants to copy one .exe onto a Windows
// server, run it, press a button that says "make this a gateway", read
// the one string it prints, add that gateway on his laptop, then walk
// back to the same window, open the Server tab and press Start. Two
// Windows machines, one program, no terminal anywhere.
//
// Every piece of that already existed and none of it was reachable
// without a console. "gateway install" on Windows writes the data
// directory's ACL, creates the iamtunnel-gateway SCM service under a
// virtual service account, starts it and prints the claim string; the
// Admin tab has taken that claim string since SPEC §3.6. The hole was
// between them, and it is the same hole this product keeps growing: a
// capability that works, is reachable from a terminal, and is invisible
// to the person it is for.
//
// SO THE WINDOW RUNS THE COMMANDS THEMSELVES, not a copy of their
// logic. Each action below builds a *streams over a buffer and calls
// the very function the CLI verb calls -- runGatewayInstall,
// runGatewayStatus, cmdGatewayUninstall. A second implementation of
// "install a gateway" would be a second thing to keep correct, and the
// half that is pressed less often is the half that rots: it would be
// the last to learn about a new ACL step and the first to start lying
// about what it did.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// guiGatewayStreams is one captured run of a CLI verb: the same streams
// the console gets, pointed at a buffer.
//
// env is carried over from the live window's own environment because
// several gateway steps read it -- exeUnreachableByServiceAccount looks
// at ProgramFiles, loadConfig at IAMTUNNEL_CONFIG and
// IAMTUNNEL_DATA_DIR. A window that passed an empty environment would
// quietly install a gateway somewhere the CLI would not.
func guiGatewayStreams(env map[string]string) (*streams, *bytes.Buffer, *bytes.Buffer) {
	var out, errs bytes.Buffer
	return &streams{
		in:   strings.NewReader(""),
		out:  &out,
		errs: &errs,
		env:  env,
	}, &out, &errs
}

// guiGatewayOutcome turns a captured run into what a window says.
//
// The CLI's exit code is the verdict; the buffers are the words. stderr
// wins when the code is non-zero, because that is where every refusal in
// this program is written, and falling back to stdout would show the
// operator the progress lines of a step that did not happen.
func guiGatewayOutcome(code int, out, errs *bytes.Buffer) (string, error) {
	if code == exitOK {
		return strings.TrimSpace(out.String()), nil
	}
	msg := strings.TrimSpace(errs.String())
	if msg == "" {
		msg = strings.TrimSpace(out.String())
	}
	if msg == "" {
		msg = fmt.Sprintf("the gateway command failed with exit code %d and said nothing", code)
	}
	return "", fmt.Errorf("%s", msg)
}

// gatewayDirFromEnv resolves the gateway data directory the way the CLI
// verb behind this screen resolves it — through loadConfig, so
// IAMTUNNEL_DATA_DIR, the config file's gateway_dir key and the platform
// default all land in the same place for both halves of the screen
// (R2, 24.09.2026). config.DirsFor alone — what this screen read before —
// knows only the platform default (/var/lib/iamtunnel,
// %ProgramData%\iamtunnel\gateway), so a window launched with
// IAMTUNNEL_DATA_DIR showed facts compiled from one directory and a
// detail line from another.
func gatewayDirFromEnv(env map[string]string) (string, error) {
	s, _, _ := guiGatewayStreams(env)
	_, dir, err := loadConfig(s, "gateway", cfgOpts{})
	return dir, err
}

// guiGatewayStatus is "iamtunnel gateway status"'s own work, reshaped
// for the screen.
//
// It reads the same three things status reads -- the host key, the
// state lock and state.json -- and adds the two facts only a window
// needs: whether this copy of the program may install anything at all
// (elevation), and whether it is sitting somewhere the service account
// could never read it.
func guiGatewayStatus(env map[string]string, elevated bool) (ui.GatewayState, error) {
	var st ui.GatewayState
	st.Supported = runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	st.Elevated = elevated
	st.Platform = runtime.GOOS

	dir, derr := gatewayDirFromEnv(env)
	if derr != nil {
		return st, derr
	}
	st.DataDir = dir

	if exe, err := os.Executable(); err == nil {
		st.ExePath = exe
		st.ExeReachable = !exeUnreachableByServiceAccount(exe, env)
		st.WantedExeDir = serviceReachableExeDir(env)
	}

	// THE FACTS COME FROM THE SAME PLACES STATUS READS THEM, not from
	// the sentences status writes.
	//
	// The first version of this function decided "is there a gateway
	// here" by looking for the words "no host key" in the output. The
	// command has never printed that phrase -- it prints "host key: not
	// generated yet" -- so the test never matched and the window told
	// the owner his fresh Windows VM was "set up as a gateway, but not
	// answering", offering to remove a service that did not exist.
	//
	// The lesson is not "fix the string". Prose is written for a person
	// and is rewritten whenever a sentence reads badly; a program that
	// infers a boolean from it is a program that silently changes its
	// mind when somebody improves the wording. So: the host key file
	// says whether a gateway was ever set up here, and the state lock
	// says whether one is answering -- exactly what runGatewayStatus
	// itself consults, two lines below where it starts.
	fp, hasKey := readHostkeyFingerprint(dir)
	st.Installed = hasKey
	st.Fingerprint = fp

	// Whether the one-time admin string is still there and still in
	// date. Read from state.json, not guessed from whether the printed
	// form came out empty: a string that exists but cannot be RENDERED
	// (no address written yet) is a different fact from a string
	// somebody has used, and the screen must not merge them.
	// THREE STATES, and the same three the command draws
	// (printBootstrapStatus): still good, out of date, gone. A zero
	// deadline counts as out of date there -- state.validate refuses a
	// bootstrapPending without one, so a zero is a broken entry rather
	// than an eternal one -- and this read said the opposite for a day.
	if hasKey {
		if peek, present := peekBootstrapPending(dir); present {
			deadline := peek.Expires.Time
			if !deadline.IsZero() && time.Now().Before(deadline) {
				st.ClaimPending = true
			} else {
				st.ClaimExpired = true
			}
		}
	}

	if hasKey {
		store, oerr := state.OpenForRead(dir)
		switch {
		case errors.Is(oerr, state.ErrLockHeld):
			// Somebody else holds the exclusive lock: that somebody is
			// the running gateway. The lock IS the liveness signal --
			// no extra IPC of our own (gateway.go, runGatewayStatus).
			st.Running = true
			// And what it says about its audit journal is in the file it
			// keeps beside its data for exactly this (IAMT-451). A read
			// that fails is said, not taken for "ok".
			if h, found, herr := gateway.ReadAuditHealth(dir); herr != nil {
				st.AuditKnown, st.AuditProblem = true, "its audit state could not be read: "+herr.Error()
			} else if found {
				a := admin.GatewayAuditStatus{OK: h.OK, Since: h.Since, Error: h.Error, LostWrites: h.LostWrites}
				st.AuditKnown, st.AuditProblem = true, a.Problem()
			}
		case oerr == nil:
			store.Close()
		case errors.Is(oerr, fs.ErrNotExist):
			// Set up but never started: a host key and no state yet.
		default:
			// The one case where we know a gateway is here and cannot
			// tell whether it is answering. Saying "not running" would
			// be the unknown-rendered-as-false defect this product has
			// already paid for three times.
			st.Unknown = true
		}
		// Whether the journal holds together (IAMT-467), on every look:
		// the same check "gateway verify-journal" runs. A check that
		// could not run says so and is neither answer.
		st.JournalKnown = true
		if rep, verr := events.VerifyChain(dir); verr != nil {
			st.JournalChain = "the hash chain could not be checked: " + verr.Error()
		} else {
			st.JournalChain, st.JournalIntact, st.JournalBroken = rep.Summary(), rep.Intact(), !rep.Intact()
		}
	}

	// The printed form is kept too, verbatim, under the fields the
	// screen understands: a case the window has not learned to read is
	// still legible to the person looking at it.
	s, out, errs := guiGatewayStreams(env)
	code := cmdGatewayStatus(s, nil)
	text, err := guiGatewayOutcome(code, out, errs)
	if err != nil {
		st.Detail = err.Error()
		st.Unknown = true
		return st, nil
	}
	st.Detail = text
	// The claim string is not prose: it is one token of a fixed shape
	// that install and status both print verbatim for copying. Picking
	// it out is reading a value, not guessing at a sentence.
	st.Claim = firstTokenWithPrefix(text, "iamtunnel-claim://")
	return st, nil
}

// firstTokenWithPrefix pulls the first whitespace-delimited token that
// starts with prefix. The claim string is handed to another machine
// verbatim, so it is taken as a whole token and never reflowed.
func firstTokenWithPrefix(text, prefix string) string {
	for _, field := range strings.Fields(text) {
		if strings.HasPrefix(field, prefix) {
			return field
		}
	}
	return ""
}

// guiGatewayInstall is "iamtunnel gateway install"'s own work.
//
// host is what clients and machines dial, and it is required for the
// reason the CLI requires it: without it the claim string and every
// later connection string would carry a placeholder and be unparseable
// by the window that has to read them.
func guiGatewayInstall(env map[string]string, host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("say which address other computers will dial to reach this gateway — " +
			"its DNS name or its IP as seen from them, not \"localhost\"")
	}
	if !config.ValidHost(host) {
		return "", fmt.Errorf("%q is not a DNS name or an IP address — for example gw.example.com or 203.0.113.9", host)
	}
	if port < 1024 || port > 65535 {
		return "", fmt.Errorf("the port must be between 1024 and 65535 (the gateway runs without extra privileges, "+
			"so it cannot take a low port); got %d", port)
	}

	dir, derr := gatewayDirFromEnv(env)
	if derr != nil {
		return "", derr
	}
	s, out, errs := guiGatewayStreams(env)
	code := runGatewayInstall(s, "gateway install", dir, port, false, host, false)
	return guiGatewayOutcome(code, out, errs)
}

// guiGatewayUninstall is "iamtunnel gateway uninstall"'s own work. The
// data directory survives, as it does from the console: the host key,
// the state and the recordings are not install's to destroy.
func guiGatewayUninstall(env map[string]string) (string, error) {
	s, out, errs := guiGatewayStreams(env)
	code := cmdGatewayUninstall(s, nil)
	return guiGatewayOutcome(code, out, errs)
}

// guiGatewayCopyItself puts this executable where the service account
// can read it, and reports the new path.
//
// WHY THE WINDOW DOES THIS AT ALL. The refusal it answers is real and
// correct -- a service account cannot read C:\Users\someone\Downloads,
// so a service installed from there would fail to start, later, with an
// error about a missing file. But the person meeting it has just copied
// one .exe onto a server and pressed one button, and telling them to
// open a console and move a file is the console this whole screen
// exists to avoid.
//
// It copies rather than moves: the copy the person launched keeps
// running and keeps its window. Nothing is deleted, and an existing
// file at the destination is replaced only because that is what
// installing a newer build means.
func guiGatewayCopyItself(env map[string]string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("this step is only needed on Windows, where a service account cannot read a user profile")
	}
	dir := serviceReachableExeDir(env)
	if dir == "" {
		return "", fmt.Errorf("could not work out which drive this Windows boots from, so there is nowhere to put the program")
	}
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not resolve this program's own path: %w", err)
	}
	dst := filepath.Join(dir, filepath.Base(src))
	if strings.EqualFold(src, dst) {
		return dst, nil
	}
	// IAMT-445: the folder is made at the root of the system drive, which
	// lets every signed-in account create folders and grants it Modify
	// inside them - and the program in it is later started with an
	// administrator's token. So the folder is locked to Administrators
	// before anything is copied in, and owned by them: that takes the
	// administrator token, and without it the copy is refused rather
	// than made in a folder somebody else could reopen.
	if elevated, _ := elevate.IsElevated(); !elevated {
		return "", fmt.Errorf("putting the program in %s needs administrator rights: the folder must belong to Administrators, "+
			"or anybody who signs in to this machine could replace the program that is later started as administrator. "+
			"Use \"Restart as administrator\" at the top of this window first", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("could not create %s: %w — this needs administrator rights", dir, err)
	}
	if err := lockProgramHome(dir, ""); err != nil {
		return "", fmt.Errorf("could not lock %s to administrators: %w", dir, err)
	}
	if err := copyExecutable(src, dst); err != nil {
		return "", err
	}
	if err := lockProgramHome(dir, dst); err != nil {
		return "", fmt.Errorf("could not lock %s to administrators: %w", dst, err)
	}
	return dst, nil
}

// copyExecutable writes src over dst.
//
// Through datafile's atomic replace, not a hand-rolled one. The first
// draft of this function built its own "dst.new", and gate 16 was right
// to refuse it: the destination is a directory off the root of the
// system drive (C:\\iamtunnel), the
// writer is an ELEVATED process, and a predictable temp name in a
// directory somebody else may own is precisely how round 8 of the audit
// got an elevated write redirected into a file of the attacker's
// choosing. datafile picks a random name, creates it O_EXCL, and
// refuses a name already held by a symlink, a FIFO or a second hard
// link.
//
// The body is streamed rather than read into memory: this is an 18 MB
// executable copying itself, and WriteFileAtomicFunc exists for exactly
// the case where the bytes should never sit in the process twice.
func copyExecutable(src, dst string) error {
	in, err := datafile.Open(src, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", src, err)
	}
	defer in.Close()

	err = datafile.WriteFileAtomicFunc(dst, func(f *os.File) error {
		_, cerr := io.Copy(f, in)
		return cerr
	}, datafile.WithMode(0o755))
	if err == nil {
		return nil
	}
	// The one failure worth its own sentence. A running .exe cannot be
	// replaced on Windows, and the copy at the destination is running
	// precisely when the gateway service is up -- so the honest answer
	// is not "try harder" but "that file is in use, and swapping it
	// under a live service is not something this button should do".
	if errors.Is(err, fs.ErrPermission) || isFileInUse(err) {
		return fmt.Errorf("%s is in use — if the gateway service is running from there, "+
			"remove it on this tab first, then copy the program again", dst)
	}
	return fmt.Errorf("could not put the program in place at %s: %w — this needs administrator rights", dst, err)
}

// isFileInUse recognises the Windows sharing violation a running .exe
// answers with. On other platforms it is always false: there, replacing
// a running binary is ordinary.
func isFileInUse(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// ERROR_SHARING_VIOLATION (32) and ERROR_ACCESS_DENIED (5) are what
	// a replace of a mapped executable comes back as. Matched by text
	// rather than by syscall constant so this file stays buildable on
	// every platform the GUI targets.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "being used by another process") ||
		strings.Contains(msg, "access is denied")
}
