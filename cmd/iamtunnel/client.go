package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// exitSessionLost is this file's own exit code: a session that was
// granted a real shell and then ended without a clean exit-status — the
// transport died, not the remote command. It is deliberately a plain
// local constant rather than a new entry in main.go's shared
// exitOK..exitDenied block, and 5 does not collide with any of the four
// codes that block already defines. A forwarded
// remote exit-status can coincidentally also be 5 — the same ambiguity
// ssh(1) accepts with its own reserved 255, and for the same reason: the
// alternative is inventing an out-of-band signal the protocol does not
// have.
const exitSessionLost = 5

// cmdClient is the person's role (SPEC §3.1): save the connection
// string, list allowed machines, connect.
func cmdClient(s *streams, args []string) int {
	if len(args) == 0 {
		return fail(s, userErrf(`iamtunnel client: want "connect-string <str>", "machines", "connect <machine>" or "exec <machine> -- <command>" — see "iamtunnel client --help".`))
	}
	if helpWord(args[0]) {
		return helpTopic(s, "client")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "connect-string":
		return cmdClientConnectString(s, rest)
	case "gateways":
		return cmdClientGateways(s, rest)
	case "use":
		return cmdClientUse(s, rest)
	case "forget":
		return cmdClientForget(s, rest)
	case "key":
		return cmdClientKey(s, rest)
	case "machines":
		return cmdClientMachines(s, rest)
	case "connect":
		return cmdClientConnect(s, rest)
	case "exec":
		return cmdClientExec(s, rest)
	default:
		return fail(s, userErrf("iamtunnel client: unknown subcommand %q — want %q, %q, %q, %q, %q, %q, %q or %q. See \"iamtunnel client --help\".",
			sub, "connect-string <str>", "key", "gateways", "use <name>", "forget <name>",
			"machines", "connect <machine>", "exec <machine> -- <command>"))
	}
}

func cmdClientConnectString(s *streams, args []string) int {
	const path = "client connect-string"
	fs := newFlagSet(path, "<str>")
	fs.boolFlag("replace")
	// The label this gateway is known by afterwards. Optional: left out,
	// the host names it, which is the one thing about a gateway a person
	// has certainly seen. Given, it is what "client use" takes.
	fs.valFlag("name")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	cs, err := config.ParseConnString(fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	g, err := client.SaveConnectionNamed(dir, cs, fs.val("name"), fs.has("replace"))
	if err != nil {
		return fail(s, err)
	}
	fmt.Fprintf(s.out, "iamtunnel client: saved the connection to %s:%d as %q, remembered as %q and now in use (gateway key %s).\n",
		cs.Host, cs.Port, cs.Person, g.Name, cs.Fingerprint)
	return exitOK
}

// cmdClientGateways lists what this machine remembers (IAMT-432).
//
// Everything the window can do is reachable from a terminal, and the
// other way round -- gate 15 compares the two lists and says so when
// they drift.
func cmdClientGateways(s *streams, args []string) int {
	const path = "client gateways"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// Read-only: no foreign-directory gate here — the gate stands in
	// front of WRITES (IAMT-333 P1.6), and listing what this machine
	// remembers writes nothing.
	_, dir, lerr := loadConfig(s, "client", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}
	set, err := client.LoadConnections(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(s.out, "iamtunnel client: no gateway is saved yet — run \"client connect-string <str>\" with the line your administrator gave you.")
			return exitOK
		}
		return fail(s, err)
	}
	current, _ := set.CurrentGateway()
	for _, g := range set.Gateways {
		mark := "  "
		if g.Name == current.Name {
			mark = "* "
		}
		fmt.Fprintf(s.out, "%s%s\t%s@%s\t%s\n", mark, g.Name, g.Person, g.Where(), g.Fingerprint)
	}
	fmt.Fprintf(s.out, "\n* is the one every other command acts on. Switch with \"client use <name>\".\n")
	return exitOK
}

// cmdClientUse switches to a remembered gateway.
//
// It asks nothing and dials nothing. There is no login to perform: the
// key in this directory is this machine's own, and each gateway's
// administrator already holds its public half. Switching is a pointer
// move, and anything more would be an invention of ours.
func cmdClientUse(s *streams, args []string) int {
	const path = "client use"
	fs := newFlagSet(path, "<name>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	g, err := client.SelectConnection(dir, fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	fmt.Fprintf(s.out, "iamtunnel client: now using %q — %s@%s.\n", g.Name, g.Person, g.Where())
	return exitOK
}

// cmdClientForget drops one remembered gateway.
//
// The KEY stays, and so does the person record on the gateway: a client
// can always forget, only an administrator can revoke.
func cmdClientForget(s *streams, args []string) int {
	const path = "client forget"
	fs := newFlagSet(path, "<name>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	had, err := client.ForgetGateway(dir, fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	if !had {
		return fail(s, userErrf("iamtunnel client forget: no saved gateway is called %q — run \"client gateways\" to see the names.", fs.pos[0]))
	}
	fmt.Fprintf(s.out, "iamtunnel client: forgot %q. Your key is untouched, and so is the person record on that gateway — only its administrator can take that away.\n", fs.pos[0])
	return exitOK
}

// cmdClientKey prints this machine's public key, creating the key on first
// need (R4 F-14). It is what the person hands an administrator BEFORE they
// exist on any gateway: "admin people add" needs the key, and a connection
// string is only given to a person who already exists. The window shows
// the same line on Client → Key.
func cmdClientKey(s *streams, args []string) int {
	const path = "client key"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(0); err != nil {
		return fail(s, err)
	}
	// Creating the key is a write, so it passes the foreign-data-directory
	// gate first, like every other client verb (IAMT-333; review finding R4 N-01).
	dir, lerr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if lerr != nil {
		return fail(s, lerr)
	}
	signer, err := client.EnsureKey(dir)
	if err != nil {
		return fail(s, err)
	}
	fmt.Fprint(s.out, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return exitOK
}

func cmdClientMachines(s *streams, args []string) int {
	const path = "client machines"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	cs, signer, cerr := loadClientIdentity(dir)
	if cerr != nil {
		return fail(s, cerr)
	}

	machines, err := client.Machines(context.Background(), dir, cs, signer, 0)
	if err != nil {
		return fail(s, err)
	}
	if len(machines) == 0 {
		fmt.Fprintln(s.out, "iamtunnel client machines: no machines are currently granted to you.")
		return exitOK
	}
	for _, m := range machines {
		status := "offline"
		if m.Online {
			status = "online"
		}
		until := m.Until
		if until == "" {
			until = "revoked" // an indefinite grant (IAMT-221), same word as the session banner
		}
		fmt.Fprintf(s.out, "%-20s until %-25s %s\n", m.Name, until, status)
	}
	return exitOK
}

func cmdClientConnect(s *streams, args []string) int {
	const path = "client connect"
	fs := newFlagSet(path, "<machine>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	if !config.ValidName(fs.pos[0]) {
		return fail(s, config.NameError("machine", fs.pos[0]))
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	cs, signer, cerr := loadClientIdentity(dir)
	if cerr != nil {
		return fail(s, cerr)
	}

	outcome, err := client.Connect(context.Background(), client.ConnectOptions{
		Conn:           cs,
		Machine:        fs.pos[0],
		Signer:         signer,
		KnownHostsPath: client.KnownHostsPath(dir),
		In:             s.in,
		Out:            s.out,
	})
	if err != nil {
		return fail(s, err)
	}
	switch {
	case !outcome.ShellGranted:
		fmt.Fprintln(s.errs, "iamtunnel client connect: the gateway did not grant a shell — see the line above for the reason.")
		return exitUser
	case outcome.ExitStatus == nil:
		fmt.Fprintln(s.errs, "iamtunnel client connect: the session ended without a clean exit — the connection to the gateway was lost mid-session.")
		return exitSessionLost
	default:
		return int(*outcome.ExitStatus)
	}
}

// cmdClientExec is the whole point of an exec-only grant: the only way
// it can be used at all. Unlike every other flagSet-based command here, the
// positional grammar is deliberately not fs.wantN(1) — "--" is mandatory
// (no flags are parsed after it) and fs.parse already routes
// everything past it into fs.pos untouched, so this checks fs.noMore and
// the split itself by hand instead of pretending this is an ordinary
// fixed-arity command.
func cmdClientExec(s *streams, args []string) int {
	const path = "client exec"
	fs := newFlagSet(path, "<machine> -- <command>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if !fs.noMore {
		return fail(s, userErrf(`iamtunnel client exec: missing "--" before the command — usage: iamtunnel client exec <machine> -- <command>.`))
	}
	if len(fs.pos) < 1 {
		return fail(s, userErrf("iamtunnel client exec: missing <machine> — usage: iamtunnel client exec <machine> -- <command>."))
	}
	if len(fs.pos) < 2 {
		return fail(s, userErrf("iamtunnel client exec: missing <command> after \"--\" — usage: iamtunnel client exec <machine> -- <command>."))
	}
	machine := fs.pos[0]
	// The shell that invoked us already split the command into argv
	// words; joining them back with plain spaces is the same
	// reconstruction ssh(1) itself performs on "ssh host cmd arg1 arg2"
	// (its own argv, not a quoted single string) — not byte-identical to
	// whatever the person originally typed if they relied on nested
	// quoting, but that information was already gone by the time this
	// process's own argv arrived; there is nothing further back to
	// recover it from.
	command := strings.Join(fs.pos[1:], " ")
	if !config.ValidName(machine) {
		return fail(s, config.NameError("machine", machine))
	}
	dir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	cs, signer, cerr := loadClientIdentity(dir)
	if cerr != nil {
		return fail(s, cerr)
	}

	outcome, err := client.Exec(context.Background(), client.ExecOptions{
		Conn:           cs,
		Machine:        machine,
		Command:        command,
		Signer:         signer,
		KnownHostsPath: client.KnownHostsPath(dir),
		Stdout:         s.out,
		Stderr:         s.errs,
	})
	if err != nil {
		return fail(s, err)
	}
	switch {
	case !outcome.Started:
		fmt.Fprintln(s.errs, "iamtunnel client exec: the gateway did not accept the command — see the line above for the reason.")
		return exitUser
	case outcome.ExitStatus == nil:
		fmt.Fprintln(s.errs, "iamtunnel client exec: the session ended without a clean exit — the connection to the gateway was lost mid-command.")
		return exitSessionLost
	default:
		// 126 (it passes through even for a blocked command) flows
		// through here exactly like any other exit code —
		// this function does not special-case it, since the gateway
		// already turned the blocked command into an ordinary
		// exit-status before this point.
		return int(*outcome.ExitStatus)
	}
}

// loadClientIdentity is the "machines"/"connect" prelude both share: the
// saved connection string plus the person's own key, generated on first
// use inside the client's own data directory (never ~/.ssh — see
// internal/client/keys.go).
func loadClientIdentity(dir string) (config.ConnString, ssh.Signer, error) {
	cs, err := client.LoadConnection(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.ConnString{}, nil, userErrf(`iamtunnel client: no connection string saved yet — run "iamtunnel client connect-string <str>" first.`)
		}
		return config.ConnString{}, nil, err
	}
	signer, err := client.EnsureKey(dir)
	if err != nil {
		return config.ConnString{}, nil, err
	}
	return cs, signer, nil
}
