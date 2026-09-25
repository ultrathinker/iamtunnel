package macos

import (
	"fmt"
	"os"
)

// terminalApp is the application "open -a" names. Apple's own Terminal,
// because the session iamtunnel opens is an ordinary terminal session
// (SPEC §3.1) and Terminal.app is the one terminal guaranteed to be on
// every Mac.
const terminalApp = "Terminal.app"

// ConnectScript returns the sh(1) script Terminal.app is asked to run:
// one line, "exec <program> client connect <machine>", every word
// shell-quoted by ShellCommand.
//
// Why a script file and not `osascript -e 'tell application "Terminal" to
// do script "..."'`: with the file, the machine name never enters a
// command line that anything parses twice. The only thing handed to
// "open" is a path this program generated (argv, one element) and the
// only thing that parses the name is sh inside the script, through
// ShellQuote. AppleScript's `do script` would instead make the name part
// of an AppleScript literal — one more parser, one more escaping rule,
// and one more chance to get it subtly wrong.
//
// The file holds no secret: the program path and the machine name are
// both already on the command line that produced it, and what it does is
// what "iamtunnel client connect <machine>" does in any terminal.
//
// The first command removes the script itself (IAMT-296: before that,
// every Connect left a 0700 file behind in the temp directory, and a
// failed one left it there forever). The ordering is what makes the
// removal safe rather than racy, and it is worth spelling out:
//
//   - the shell running this file was started BY Terminal.app FROM this
//     file, so the path has already been opened by whoever runs us — the
//     deletion cannot get ahead of that, because the deletion is what the
//     first line of the already-opened file does;
//   - the shell keeps reading through its open descriptor, and the inode
//     outlives the name, so the rest of the script (the exec line) still
//     parses and runs — the classic self-deleting-script failure is a
//     shell that re-opens the PATH mid-run, which sh does not;
//   - "$0" is the path the shell was handed, i.e. the very file we wrote;
//     the quotes keep it one word and "--" keeps a leading dash in a path
//     from being read as an option. This is the one place in this package
//     that deliberately does NOT go through ShellQuote — $0 has to stay
//     expandable — and it is not attacker-controlled: we generated it.
func ConnectScript(program, machine string) string {
	return "#!/bin/sh\n" +
		"# Written by iamtunnel for the Connect button (IAMT-262, IAMT-296).\n" +
		`/bin/rm -f -- "$0"` + "\n" +
		"exec " + ShellCommand(program, "client", "connect", machine) + "\n"
}

// WriteConnectScript writes ConnectScript into a fresh file in dir ("" =
// os.TempDir()) and returns the path.
//
// os.CreateTemp picks the name (O_EXCL, so no other process can predict
// or pre-create it) and the mode is narrowed to owner-only before the
// file is handed over: the script runs with this person's rights, so
// nobody else may get in between and edit what it says.
func WriteConnectScript(dir, program, machine string) (string, error) {
	f, err := os.CreateTemp(dir, "iamtunnel-connect-*.sh")
	if err != nil {
		return "", fmt.Errorf("could not create the connect script: %w", err)
	}
	path := f.Name()
	cleanup := func(err error) (string, error) {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := f.WriteString(ConnectScript(program, machine)); err != nil {
		return cleanup(fmt.Errorf("could not write %s: %w", path, err))
	}
	// The mode is narrowed on the DESCRIPTOR, before the close — not
	// os.Chmod on the path afterwards (IAMT-332 round nine): a
	// path-based chmod re-resolves the name after the content is
	// already visible under it, so a swap of the entry between close
	// and chmod would hand the execute bit to whatever stood there
	// instead. The fd cannot be re-aimed.
	if err := f.Chmod(0o700); err != nil {
		return cleanup(fmt.Errorf("could not make %s executable: %w", path, err))
	}
	if err := f.Close(); err != nil {
		return cleanup(fmt.Errorf("could not write %s: %w", path, err))
	}
	return path, nil
}

// ConnectTerminal opens a Terminal.app window running
// "iamtunnel client connect <machine>" and returns the sentence the
// window shows on success — the macOS counterpart of the Windows
// "cmd.exe /c start" terminal (gui_windows.go's guiClientConnect), and
// the wire logic behind it is the very same "client connect" verb.
func ConnectTerminal(program, machine string) (string, error) {
	return connectTerminal("", program, machine)
}

// connectTerminal is ConnectTerminal with the temp directory made
// explicit, so a test can keep the script inside t.TempDir().
func connectTerminal(dir, program, machine string) (string, error) {
	script, err := WriteConnectScript(dir, program, machine)
	if err != nil {
		return "", err
	}
	// Terminal.app runs an executable file handed to it by "open";
	// WriteConnectScript has already made it executable.
	if err := startFn(openPath, "-a", terminalApp, script); err != nil {
		// IAMT-296: nothing was started, so nothing will ever run the
		// script's own self-removal — and the refusal used to promise the
		// person they could run the file by hand, which would have meant
		// leaving one behind for every failed Connect. Remove it here, and
		// say only what actually happened: nothing points at a file now.
		_ = os.Remove(script)
		return "", fmt.Errorf("could not open a Terminal window: %w", err)
	}
	return "Opened a terminal on " + machine + ".", nil
}
