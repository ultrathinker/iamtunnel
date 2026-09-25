package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// admin_exec.go wires "iamtunnel admin <group> <verb>" to the real
// internal/admin wire client (SPEC §3.3, PROTOCOL §6): dial the gateway
// as the person's own saved command-login identity, run exactly the one
// exec command the verb names, and render the result — a table for a
// human, the raw JSON result for --json (SPEC §7.2).

// adminFail classifies a failure from the admin wire path: a gateway-
// named refusal (PROTOCOL §1.2's error envelope, surfaced here as
// *admin.CommandError) is the CLI's own user-error class — the command
// as given cannot be completed against the gateway's current state or
// this build's feature set; anything else (dial failure, malformed
// response) is an environment problem: the gateway could not be reached
// or did not speak the protocol it promised.
func adminFail(s *streams, path string, err error) int {
	var ce *admin.CommandError
	if errors.As(err, &ce) {
		fmt.Fprintf(s.errs, "iamtunnel %s: the gateway refused: %s: %s\n", path, ce.Code, ce.Message)
		return exitUser
	}
	// A dial/network failure is sometimes already one of this CLI's own
	// classified errors (e.g. envErrf) rather than a bare wrapped error;
	// respect its class instead of always collapsing to exitEnv.
	var cliE *cliError
	if errors.As(err, &cliE) {
		fmt.Fprintf(s.errs, "iamtunnel %s: %v\n", path, err)
		return cliE.code
	}
	fmt.Fprintf(s.errs, "iamtunnel %s: %v\n", path, err)
	return exitEnv
}

func printAdminJSON(s *streams, v any) int {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(s.errs, "iamtunnel admin: could not encode JSON output: %v\n", err)
		return exitInternal
	}
	fmt.Fprintln(s.out, string(data))
	return exitOK
}

// atoiFlag reads an optional whole-number flag. Empty means "not given",
// which is not the same as zero: zero offset is a real request.
func atoiFlag(v string) (int, error) {
	if strings.TrimSpace(v) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0, userErrf("iamtunnel admin sessions history: %q must be a whole number, zero or more.", v)
	}
	return n, nil
}

// printSessionHistory renders one line per SESSION -- who was in, on
// what, from when to when, and whether anything was stopped on the way.
// Keeping the rendering separate from the wire call makes the history
// contract directly testable.
func printSessionHistory(s *streams, page admin.SessionHistoryPage) int {
	if len(page.Sessions) == 0 {
		fmt.Fprintln(s.out, "(no history)")
		return exitOK
	}
	for _, h := range page.Sessions {
		ended := h.Ended
		if ended == "" {
			ended = "-"
		}
		line := fmt.Sprintf("%-24s %-24s %-14s -> %-14s %-5s %s",
			h.Started, ended, h.Person, h.Machine, h.Kind, h.Outcome)
		if h.Risks > 0 {
			line += fmt.Sprintf("  risks=%d", h.Risks)
			if h.RiskLevel != "" {
				line += "/" + h.RiskLevel
			}
		}
		if h.Command != "" {
			line += "  " + h.Command
		}
		fmt.Fprintln(s.out, line)
	}
	// The page says where it sits in the whole, so "nothing older" and
	// "there is more, ask for it" are different sentences.
	shown := page.Offset + len(page.Sessions)
	fmt.Fprintf(s.out, "%d-%d of %d\n", page.Offset+1, shown, page.Total)
	return exitOK
}

// printGatewayStatus writes the normal gateway facts plus one compact risk
// summary. With no risk events the zero-valued summary remains one useful
// line instead of expanding into an empty table.
func printGatewayStatus(s *streams, st admin.GatewayStatusResult) int {
	fmt.Fprintf(s.out, "online=%v machines-online=%d machines-verified=%d sessions=%d server-time=%s\n",
		st.Online, st.MachinesOnline, st.MachinesVerified, st.Sessions, st.ServerTime)
	fmt.Fprintf(s.out, "risk: classifier=%s; mode=%s source=%s; last 24h yellow=%d, red=%d, blocked=%d\n", st.Risk.Classifier, st.Risk.Mode, st.Risk.Source, st.Risk.Yellow, st.Risk.Red, st.Risk.Blocked)
	if st.Risk.LatestRed != nil {
		fmt.Fprintf(s.out, "      latest red: %s %s -> %s %s\n", st.Risk.LatestRed.Time, st.Risk.LatestRed.Person, st.Risk.LatestRed.Machine, st.Risk.LatestRed.Rule)
	}
	if st.ExternalRiskKey.Present {
		fmt.Fprintf(s.out, "external-risk-key: present fingerprint=%s\n", st.ExternalRiskKey.Fingerprint)
	} else {
		fmt.Fprintln(s.out, "external-risk-key: absent")
	}
	// IAMT-451. A gateway from before 1.14 does not say, and then neither
	// does this: silence is not "ok".
	if st.Audit != nil {
		if problem := st.Audit.Problem(); problem != "" {
			fmt.Fprintf(s.out, "audit: PROBLEM: %s (journal entries lost since the gateway started: %d)\n", problem, st.Audit.LostWrites)
		} else {
			fmt.Fprintf(s.out, "audit: ok (journal entries lost since the gateway started: %d)\n", st.Audit.LostWrites)
		}
	}
	// IAMT-331. Same rule: a gateway from before this field is silent,
	// and so is this line.
	if st.Pairing != nil {
		if st.Pairing.Active {
			fmt.Fprintf(s.out, "pairing: a window is OPEN, closes itself %s\n", st.Pairing.Expires)
		} else {
			fmt.Fprintln(s.out, "pairing: no window is open")
		}
	}
	// IAMT-466. Each only when the gateway says it: one from before 1.14
	// says none of them.
	if st.Version != "" {
		fmt.Fprintf(s.out, "version: %s\n", st.Version)
	}
	switch {
	case st.DiskPercent != nil:
		fmt.Fprintf(s.out, "disk: %d%% used (the file system holding the recordings)\n", *st.DiskPercent)
	case st.DiskError != "":
		fmt.Fprintf(s.out, "disk: could not be read: %s\n", st.DiskError)
	}
	if st.Draining {
		fmt.Fprintln(s.out, "draining: the gateway is stopping - it takes nothing new and closes the live sessions shortly")
	}
	return exitOK
}

// printMachineEvidence renders the recovery facts that are present only in
// the detailed MachineView fields. ObservedSSHDHostKey is deliberately shown
// as the same fingerprint accepted by machines.rekey, never as a raw
// authorized_keys line (SPEC §4.3, PROTOCOL §6).
func printMachineEvidence(s *streams, path string, m admin.MachineView) int {
	if m.ObservedSSHDHostKey == "" {
		return exitOK
	}
	fp, err := state.ComputeFingerprint(m.ObservedSSHDHostKey)
	if err != nil {
		return fail(s, envErrf("iamtunnel %s: could not fingerprint observed SSHD host key: %v", path, err))
	}
	fmt.Fprintf(s.out, "  requested=%s verified=%s observed=%s\n", m.RequestedOSUser, m.VerifiedOSUser, fp)
	return exitOK
}

// dialAdmin opens the admin wire connection for one already-loaded
// client identity (SPEC §3.3: the admin identity is exactly the client
// identity — see admin.go's runAdminVerb). Shared by
// runAdminExec (the CLI's own "admin <group> <verb>") and the live
// window's grant/revoke actions (cmd/iamtunnel/gui_actions.go,
// IAMT-181), so the two paths dial identically and cannot drift apart.
func dialAdmin(cs config.ConnString, signer ssh.Signer) (*admin.Conn, error) {
	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", cs.Host, cs.Port), Fingerprint: cs.Fingerprint}
	conn, err := admin.Dial(peer, cs.Person, signer, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("could not reach the gateway at %s: %w", peer.Addr, err)
	}
	return conn, nil
}

// runAdminExec dials the gateway with the person's saved client
// identity (see admin.go's runAdminVerb: a deliberate reuse — an admin
// is the same person who might also be a client, so it reuses
// internal/client's saved connection string and key rather than a
// directory of its own) and runs the one command the verb names.
func runAdminExec(s *streams, path, clientDir, group, verb string, fs *flagSet) int {
	cs, signer, cerr := loadClientIdentity(clientDir)
	if cerr != nil {
		return fail(s, cerr)
	}
	conn, derr := dialAdmin(cs, signer)
	if derr != nil {
		return adminFail(s, path, derr)
	}
	defer conn.Close()

	jsonOut := fs.has("json")

	switch group + "/" + verb {

	case "people/add":
		role := fs.val("role")
		if role == "" {
			role = "user"
		}
		res, err := conn.PeopleAdd(fs.pos[0], role, []string{fs.val("key")})
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "added person %q (role %s, %d key(s)).\n", res.Name, res.Role, len(res.Keys))
		return exitOK

	case "people/rename":
		terminated, err := conn.PeopleRename(fs.pos[0], fs.pos[1])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"from": fs.pos[0], "to": fs.pos[1], "terminatedSessions": terminated})
		}
		if terminated > 0 {
			fmt.Fprintf(s.out, "renamed %q to %q; %d session(s) opened under the old name killed.\n",
				fs.pos[0], fs.pos[1], terminated)
		} else {
			fmt.Fprintf(s.out, "renamed %q to %q; no session touched.\n", fs.pos[0], fs.pos[1])
		}
		return exitOK

	case "people/remove":
		if _, err := conn.PeopleRemove(fs.pos[0]); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"removed": fs.pos[0]})
		}
		fmt.Fprintf(s.out, "removed person %q.\n", fs.pos[0])
		return exitOK

	case "people/list":
		list, err := conn.PeopleList()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"people": list})
		}
		if len(list) == 0 {
			fmt.Fprintln(s.out, "(no people)")
			return exitOK
		}
		for _, p := range list {
			fmt.Fprintf(s.out, "%-20s role=%-6s keys=%d\n", p.Name, p.Role, len(p.Keys))
		}
		return exitOK

	case "people/keys":
		switch fs.pos[0] {
		case "add":
			key, err := conn.PeopleKeysAdd(fs.pos[1], fs.pos[2])
			if err != nil {
				return adminFail(s, path, err)
			}
			if jsonOut {
				return printAdminJSON(s, key)
			}
			fmt.Fprintf(s.out, "added key %s to %q.\n", key.Fingerprint, fs.pos[1])
			return exitOK
		default: // "remove", enforced by checkPeopleKeys
			if err := conn.PeopleKeysRemove(fs.pos[1], fs.pos[2]); err != nil {
				return adminFail(s, path, err)
			}
			if jsonOut {
				return printAdminJSON(s, map[string]string{"person": fs.pos[1], "removedFingerprint": fs.pos[2]})
			}
			fmt.Fprintf(s.out, "removed key %s from %q.\n", fs.pos[2], fs.pos[1])
			return exitOK
		}

	case "people/connection-string":
		cstr, err := conn.PeopleConnectionString(fs.pos[0])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"connectionString": cstr})
		}
		fmt.Fprintln(s.out, cstr)
		return exitOK

	case "machines/enrol-code":
		// Since 1.4 the invitation carries exactly one thing: the name
		// this registration will be known by, chosen by the
		// administrator running this command (SPEC §3.4).
		//
		// It does NOT carry an OS user. That was the 1.3 fix and it
		// stands: requiring a `DOMAIN\user` that could not possibly be
		// known before an invitation could be handed out was a defect
		// seen in practice. The machine reports its own account when
		// it registers, and the gateway proves it by logging in as it.
		//
		// An invocation that still passes --os-user is REFUSED rather
		// than quietly ignored: minting a code that does not do what
		// its arguments say is how somebody registers the wrong thing
		// and finds out later.
		if fs.val("os-user") != "" {
			return fail(s, userErrf("iamtunnel admin machines enrol-code: --os-user is gone since 1.3 — "+
				"the machine reports the account it runs as when it registers, and the gateway verifies it "+
				"by logging in as that account (SPEC §3.4)."))
		}
		if len(fs.pos) != 1 {
			return fail(s, userErrf("iamtunnel admin machines enrol-code: want exactly one argument, the name for this registration — "+
				"e.g. \"office-pc\". One physical machine may hold several, one per person who works on it; the name is what "+
				"you will grant access against and revoke by."))
		}
		code, expires, err := conn.MachinesInvite(fs.pos[0])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"enrolCode": code, "expires": expires})
		}
		fmt.Fprintf(s.out, "%s\n(expires %s)\n", code, expires)
		return exitOK

	case "machines/list":
		list, pending, err := conn.MachinesList()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"machines": list, "pendingEnrolments": pending})
		}
		if len(list) == 0 && len(pending) == 0 {
			fmt.Fprintln(s.out, "(no machines)")
			return exitOK
		}
		for _, m := range list {
			online := "offline"
			if m.Online {
				online = "online"
			}
			fmt.Fprintf(s.out, "%-16s id=%-10s state=%-9s door=%-8s hostkey=%-10s osuser=%-8s %s\n",
				m.Name, m.ID, m.State, m.DoorState, m.HostKeyStatus, m.OSUserStatus, online)
			if code := printMachineEvidence(s, path, m); code != exitOK {
				return code
			}
		}
		// A pending invitation no longer knows a name or an OS user —
		// nobody has registered against it yet, and since 1.3 those facts
		// arrive only with the machine itself (SPEC §3.4). All it can
		// honestly report is that one is outstanding and when it dies.
		for _, pe := range pending {
			fmt.Fprintf(s.out, "%-16s state=invited      (invitation expires %s)\n", "-", pe.Expires)
		}
		return exitOK

	case "machines/rename":
		if err := conn.MachinesRename(fs.pos[0], fs.pos[1]); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"id": fs.pos[0], "name": fs.pos[1]})
		}
		fmt.Fprintf(s.out, "renamed machine %q to %q (the id, grants and journal still point at the same machine).\n",
			fs.pos[0], fs.pos[1])
		return exitOK

	case "machines/remove":
		if err := conn.MachinesRemove(fs.pos[0]); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"removed": fs.pos[0]})
		}
		fmt.Fprintf(s.out, "removed machine %q.\n", fs.pos[0])
		return exitOK

	case "machines/rekey":
		oldKey, newKey, err := conn.MachinesRekey(fs.pos[0], fs.val("confirm-fingerprint"))
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"id": fs.pos[0], "oldHostKey": oldKey, "newHostKey": newKey})
		}
		fmt.Fprintf(s.out, "rekeyed %q: old=%s new=%s\n", fs.pos[0], oldKey, newKey)
		return exitOK

	case "machines/verify":
		mv, err := conn.MachinesVerify(fs.pos[0])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, mv)
		}
		fmt.Fprintf(s.out, "%s: state=%s door=%s\n", mv.ID, mv.State, mv.DoorState)
		if code := printMachineEvidence(s, path, mv); code != exitOK {
			return code
		}
		return exitOK

	case "machines/set-user":
		if err := conn.MachinesSetUser(fs.pos[0], fs.pos[1]); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"id": fs.pos[0], "osUser": fs.pos[1]})
		}
		fmt.Fprintf(s.out, "set os-user of %q to %s; a fresh probe will run before the door reopens.\n", fs.pos[0], fs.pos[1])
		return exitOK

	case "grants/grant":
		g, err := conn.GrantsGrant(fs.pos[0], fs.pos[1], fs.pos[2], fs.val("cap"))
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, g)
		}
		// An indefinite grant carries an empty Until (the JSON field is
		// omitted entirely); the printed form spells the missing deadline
		// out as a word so a tired administrator cannot mistake it for a
		// typo or a default. SPEC 4.3 mandates "absence != zero time".
		if g.Until == "" {
			fmt.Fprintf(s.out, "granted %s -> %s until revoked.\n", g.Person, g.Machine)
		} else {
			fmt.Fprintf(s.out, "granted %s -> %s until %s.\n", g.Person, g.Machine, g.Until)
		}
		// IAMT-400: a scripted grant never sees the window's warning
		// (layoutShellCapabilityWarning), so the printed confirmation is
		// the only surface the honest reason reaches — same sentence,
		// branched on the caps the GATEWAY echoed back, not on the flag
		// the caller typed.
		if len(g.Caps) == 1 && g.Caps[0] == "shell" {
			fmt.Fprintf(s.out, "No safety mode applies to a shell grant: the gateway sees keystrokes here, "+
				"never a whole command to classify, so log, warn, ask and block all do nothing.\n")
		}
		return exitOK

	case "grants/set-caps":
		was, killed, err := conn.GrantsSetCaps(fs.pos[0], fs.pos[1], fs.pos[2])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"caps": []string{fs.pos[2]}, "was": was, "terminatedSessions": killed})
		}
		if was == fs.pos[2] {
			fmt.Fprintf(s.out, "%s -> %s was already %s; nothing changed.\n", fs.pos[0], fs.pos[1], was)
			return exitOK
		}
		fmt.Fprintf(s.out, "%s -> %s is now %s instead of %s (%d session(s) killed).\n",
			fs.pos[0], fs.pos[1], fs.pos[2], was, killed)
		return exitOK

	case "grants/extend":
		newUntil, was, killed, err := conn.GrantsExtend(fs.pos[0], fs.pos[1], fs.pos[2])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"until": newUntil, "was": was, "terminatedSessions": killed})
		}
		// Same two words as everywhere else a deadline is printed, so a
		// scan of past output reads the same way.
		nowWord, wasWord := newUntil, was
		if nowWord == "" {
			nowWord = "until revoked"
		}
		if wasWord == "" {
			wasWord = "until revoked"
		}
		if killed > 0 {
			fmt.Fprintf(s.out, "%s -> %s now ends %s (was %s); %d session(s) killed.\n",
				fs.pos[0], fs.pos[1], nowWord, wasWord, killed)
		} else {
			fmt.Fprintf(s.out, "%s -> %s now ends %s (was %s); no session touched.\n",
				fs.pos[0], fs.pos[1], nowWord, wasWord)
		}
		return exitOK

	case "grants/revoke":
		killed, err := conn.GrantsRevoke(fs.pos[0], fs.pos[1])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"revoked": true, "terminatedSessions": killed})
		}
		fmt.Fprintf(s.out, "revoked %s -> %s (%d session(s) killed).\n", fs.pos[0], fs.pos[1], killed)
		return exitOK

	case "grants/list":
		list, err := conn.GrantsList("", "")
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"grants": list})
		}
		if len(list) == 0 {
			fmt.Fprintln(s.out, "(no grants)")
			return exitOK
		}
		for _, g := range list {
			// Same word as in `grants grant`, so a list scan matches the
			// line printed when the grant was issued.
			if g.Until == "" {
				fmt.Fprintf(s.out, "%-16s -> %-16s until revoked\n", g.Person, g.Machine)
			} else {
				fmt.Fprintf(s.out, "%-16s -> %-16s until %s\n", g.Person, g.Machine, g.Until)
			}
		}
		return exitOK

	case "sessions/active":
		list, err := conn.SessionsActive()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"sessions": list})
		}
		if len(list) == 0 {
			fmt.Fprintln(s.out, "(no active sessions)")
			return exitOK
		}
		for _, sess := range list {
			fmt.Fprintf(s.out, "%-24s %-16s -> %-16s started %s\n", sess.ID, sess.Person, sess.Machine, sess.Started)
		}
		return exitOK

	case "sessions/history":
		// The filters the window offers are the filters the console
		// offers: a history you can only narrow from one of the two is a
		// history somebody will end up grepping by hand.
		limit, lerr := atoiFlag(fs.val("limit"))
		if lerr != nil {
			return adminFail(s, path, lerr)
		}
		offset, oerr := atoiFlag(fs.val("offset"))
		if oerr != nil {
			return adminFail(s, path, oerr)
		}
		page, err := conn.SessionsHistory(fs.val("person"), fs.val("machine"), fs.val("from"), fs.val("to"), limit, offset)
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, page)
		}
		return printSessionHistory(s, page)

	case "goal/set":
		res, err := conn.GoalSet(fs.pos[0], fs.pos[1], fs.val("goal"))
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "goal for %s -> %s set (history=%d).\n", res.Person, res.Machine, len(res.History))
		return exitOK

	case "goal/current":
		res, err := conn.GoalCurrent(fs.pos[0], fs.pos[1])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "goal for %s -> %s: %s\n", res.Person, res.Machine, res.Goal)
		return exitOK

	case "goal/history":
		res, err := conn.GoalHistory(fs.pos[0], fs.pos[1])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		if len(res.History) == 0 {
			fmt.Fprintln(s.out, "(no goal history)")
			return exitOK
		}
		for _, entry := range res.History {
			fmt.Fprintf(s.out, "%s %s\n", entry.SetAt, entry.Goal)
		}
		return exitOK

	case "goal/list":
		res, err := conn.GoalList()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		if len(res.Goals) == 0 {
			fmt.Fprintln(s.out, "(no goals set)")
			return exitOK
		}
		for _, g := range res.Goals {
			fmt.Fprintf(s.out, "%s -> %s: %s (history=%d)\n", g.Person, g.Machine, g.Goal, len(g.History))
		}
		return exitOK

	case "risk/check":
		result, err := conn.RiskCheckWithGoal(fs.pos[0], fs.val("goal"))
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			if code := printAdminJSON(s, result); code != exitOK {
				return code
			}
		} else {
			fmt.Fprintf(s.out, "level=%s rule=%s classifier=%s goal-applied=%v reason=%s", result.Level, result.Rule, result.Classifier, result.GoalApplied, result.Reason)
			if result.ExternalError != "" {
				fmt.Fprintf(s.out, " external-error=%s", result.ExternalError)
			}
			fmt.Fprintln(s.out)
		}
		if result.Level == "green" {
			return exitOK
		}
		return exitUser

	case "risk/key":
		key, kerr := riskKeyArgument(s, fs.val("key"))
		if kerr != nil {
			return fail(s, kerr)
		}
		res, err := conn.RiskKeyReplace(key)
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "classifier key replaced; fingerprint=%s\n", res.Fingerprint)
		return exitOK

	case "sessions/tail":
		// The console watcher (IAMT-338). It writes the cast bytes to
		// stdout as they arrive and keeps asking until the gateway says
		// the session is over, so the operator's OWN terminal does the
		// escape-sequence work: a full-screen program on the far side
		// (mc, vim, htop) draws correctly here without this product
		// carrying a terminal emulator for the console at all. The
		// window needs one; a terminal does not.
		off := int64(0)
		if v := fs.val("offset"); v != "" {
			n, perr := strconv.ParseInt(v, 10, 64)
			if perr != nil || n < 0 {
				return fail(s, userErrf("iamtunnel %s: --offset %q must be a whole number of bytes, 0 or more.", path, v))
			}
			off = n
		}
		limit := int64(256 << 10)
		if v := fs.val("limit"); v != "" {
			n, perr := strconv.ParseInt(v, 10, 64)
			if perr != nil || n < 1 || n > 1<<20 {
				return fail(s, userErrf("iamtunnel %s: --limit %q must be between 1 and 1048576 bytes.", path, v))
			}
			limit = n
		}
		for {
			chunk, err := conn.SessionsTail(fs.pos[0], off, limit)
			if err != nil {
				return adminFail(s, path, err)
			}
			raw, derr := base64.StdEncoding.DecodeString(chunk.Data)
			if derr != nil {
				return fail(s, envErrf("iamtunnel %s: the gateway sent a chunk that is not base64: %v", path, derr))
			}
			if len(raw) > 0 {
				if _, werr := s.out.Write(raw); werr != nil {
					return fail(s, envErrf("iamtunnel %s: %v", path, werr))
				}
				off += int64(len(raw))
			}
			// Caught up. A live session may still be typing, so wait
			// before asking again; a finished one has nothing more to
			// give and the loop ends.
			if off >= chunk.Total {
				if !chunk.Live {
					return exitOK
				}
				time.Sleep(sessionTailPollInterval)
			}
		}

	case "sessions/kill":
		if err := conn.SessionsKill(fs.pos[0], ""); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"id": fs.pos[0], "killed": true})
		}
		fmt.Fprintf(s.out, "killed session %q.\n", fs.pos[0])
		return exitOK

	case "recordings/list":
		list, err := conn.RecordingsList("", fs.val("from"), fs.val("to"))
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"recordings": list})
		}
		if len(list) == 0 {
			fmt.Fprintln(s.out, "(no recordings)")
			return exitOK
		}
		for _, r := range list {
			fmt.Fprintf(s.out, "%-24s %-16s %-16s %s..%s  in=%d out=%d\n", r.ID, r.Machine, r.Person, r.Started, r.Ended, r.BytesIn, r.BytesOut)
		}
		return exitOK

	case "recordings/fetch":
		outDir := fs.val("out")
		if outDir == "" {
			outDir = "."
		}
		written, err := fetchRecording(conn, fs.pos[0], outDir)
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"id": fs.pos[0], "wrote": written})
		}
		for _, w := range written {
			fmt.Fprintf(s.out, "wrote %s\n", w)
		}
		return exitOK

	case "gateway/status":
		st, err := conn.GatewayStatus()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, st)
		}
		return printGatewayStatus(s, st)

	case "risk/mode":
		mode := ""
		if len(fs.pos) == 1 {
			mode = fs.pos[0]
		}
		res, err := conn.RiskMode(mode)
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "risk mode=%s source=%s changed=%v previous=%s\n", res.Mode, res.Source, res.Changed, res.Previous)
		return exitOK

	case "risk/source":
		classifier := ""
		if len(fs.pos) == 1 {
			classifier = fs.pos[0]
		}
		res, err := conn.RiskSource(classifier)
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "risk source=%s origin=%s changed=%v previous=%s\n",
			res.Classifier, res.Source, res.Changed, res.Previous)
		return exitOK

	case "risk/pending":
		held, err := conn.RiskPending()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"pending": held})
		}
		if len(held) == 0 {
			fmt.Fprintf(s.out, "nothing is held for you.\n")
			return exitOK
		}
		for _, h := range held {
			// The command whole, on its own line: this list exists so a
			// person can decide, and a truncated command is a different
			// command to decide about.
			fmt.Fprintf(s.out, "%s  %s  expires %s\n  %s\n",
				h.ApprovalID, h.Machine, h.ExpiresAt, h.Command)
		}
		return exitOK

	case "risk/deny":
		if err := conn.RiskDeny(fs.pos[0]); err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"denied": fs.pos[0]})
		}
		fmt.Fprintf(s.out, "refused %s; the command stays stopped.\n", fs.pos[0])
		return exitOK

	case "risk/approve":
		res, err := conn.RiskApprove(fs.pos[0])
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "risk approval=%s approved=%v changed=%v expires=%s\n", res.ApprovalID, res.Approved, res.Changed, res.ExpiresAt)
		return exitOK

	case "gateway/fingerprint":
		fps, err := conn.GatewayFingerprint()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"fingerprints": fps})
		}
		for _, fp := range fps {
			fmt.Fprintln(s.out, fp)
		}
		return exitOK

	case "gateway/backup":
		id, created, size, sha, err := conn.GatewayBackup()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]any{"id": id, "created": created, "size": size, "sha256": sha})
		}
		fmt.Fprintf(s.out, "backup %s created=%s size=%d sha256=%s\n", id, created, size, sha)
		return exitOK

	case "gateway/rotate-hostkey":
		oldFP, newFP, err := conn.GatewayRotateHostkey()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]string{"oldFingerprint": oldFP, "newFingerprint": newFP})
		}
		fmt.Fprintf(s.out, "rotated: old=%s new=%s\n", oldFP, newFP)
		return exitOK

	case "pairing/start":
		res, err := conn.PairingStart()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, res)
		}
		fmt.Fprintf(s.out, "pairing window open until %s.\n", res.Expires)
		// The same block "gateway pair" prints, from the same function
		// (gateway.go): the network route and the local recovery route
		// must not teach an operator two different things to copy.
		fmt.Fprint(s.out, pairingPrintout(res.Ref, res.Pin))
		return exitOK

	case "pairing/stop":
		stopped, err := conn.PairingStop()
		if err != nil {
			return adminFail(s, path, err)
		}
		if jsonOut {
			return printAdminJSON(s, map[string]bool{"stopped": stopped})
		}
		if stopped {
			fmt.Fprintln(s.out, "pairing window closed.")
		} else {
			fmt.Fprintln(s.out, "no pairing window was open.")
		}
		return exitOK

	default:
		// adminVerbs/adminGroups are the only source of (group, verb)
		// pairs that reach here (cmdAdmin already rejected anything
		// else), so this can only be reached by a verb added to the
		// table without a case here — a build-time consistency bug, not
		// a possible runtime input.
		panic(fmt.Sprintf("admin_exec: no case for %s/%s", group, verb))
	}
}

// recordingFetcher is the subset of admin.Conn fetchRecording actually
// uses. The interface exists for one reason: the tests in
// iamt209_recordings_fetch_exec_test.go drive fetchRecording with a
// canned gateway response so the canary runs without a real fixture
// or a network round trip — fetchRecording's own branching (exec vs
// terminal vs no-meta legacy) is exercised against the same shapes
// the live gateway produces, byte-for-byte. *admin.Conn satisfies
// this interface by virtue of its RecordingsFetch method.
type recordingFetcher interface {
	RecordingsFetch(id, part string, offset, limit int64) (admin.RecordingChunk, error)
}

// fetchRecording downloads the parts of one recording that are
// actually present in bounded chunks (PROTOCOL §6: "the client repeats
// the request with offset + decodedLen(data) until offset=total"),
// verifying
// each part's sha256 before writing it to outDir/<id>.<part>.
//
// The right set of parts depends on the recording's mode (PROTOCOL §8:
// terminal recordings produce .cast + .txt + .meta; exec-without-pty
// produces .exec.jsonl + .meta). The mode lives in .meta as the
// `recording_mode` field, so the function fetches .meta first, then
// uses that one read to pick the rest:
//
//   - "exec"     → .exec.jsonl + .meta
//   - "terminal" (or absent, i.e. legacy .meta without the field) →
//     .cast + .txt + .meta
//
// If the .meta fetch itself fails (legacy recordings written by builds
// before IAMT-163 carried no .meta; the gateway would surface
// E_NOT_FOUND for `part:"meta"`), we fall back to the terminal parts,
// which is exactly the behaviour the pre-IAMT-209 fetch had for every
// recording. The fallback is recorded so a test that triggers it can
// see the path it took.
//
// .meta is always written when present, regardless of the recording
// mode — operators want it for the bytes-in / bytes-out / exit-reason
// audit trail even when the bulk of the recording is one of the
// streamed parts.
func fetchRecording(conn recordingFetcher, id, outDir string) ([]string, error) {
	const chunk = 1 << 20 // 1 MiB, well under PROTOCOL's 1..1048576 limit

	// Step 1: probe the recording mode via .meta. A fetch failure
	// here means the recording has no .meta (pre-IAMT-163 legacy
	// recordings), and the safe assumption is terminal — exactly
	// what fetch used to assume for every recording before IAMT-209.
	// A .meta is a few kilobytes of JSON, the one part small enough
	// that buffering it for the probe is the simpler contract.
	metaBytes, err := probeRecordingMeta(conn, id, chunk)
	if err != nil {
		return fetchAndWriteParts(conn, id, outDir, []string{"cast", "txt"})
	}

	parts := partsForRecordingMode(detectRecordingMode(metaBytes))
	// .meta is always useful — append it as the last part so the
	// mode probe that drove the part choice is also written to disk.
	parts = append(parts, "meta")
	return fetchAndWriteParts(conn, id, outDir, parts)
}

// partsForRecordingMode maps a recording_mode value (as it appears in
// the .meta field `recording_mode`) to the part names
// recordings.fetch expects. Unknown / absent values fall through to
// the terminal set so a future recording mode added to PROTOCOL §8
// but not yet taught to this CLI degrades to "download what we know
// is there", not "download nothing".
func partsForRecordingMode(mode string) []string {
	switch mode {
	case "exec":
		return []string{"exec"}
	default:
		// "terminal" and anything else: asciicast + VT transcript.
		return []string{"cast", "txt"}
	}
}

// detectRecordingMode extracts `recording_mode` from a .meta payload.
// Empty string means either "absent" (legacy .meta before IAMT-163)
// or "terminal" — both map to the terminal parts list, so we don't
// need to tell them apart here.
func detectRecordingMode(metaData []byte) string {
	var meta struct {
		RecordingMode string `json:"recording_mode"`
	}
	_ = json.Unmarshal(metaData, &meta) // already validated by the gateway; local decode is best-effort
	return meta.RecordingMode
}

// partFilenameExt maps a gateway part name (PROTOCOL §8, what
// cmdRecordingsFetch's `part` field accepts: "cast", "txt", "exec",
// "meta") to the local file extension on disk after recordings.fetch.
//
// The gateway stores the lossless exec stream as `<base>.exec.jsonl`
// (admin_role.go:1569-1570), not as `.exec`; recordings.fetch must
// preserve that name on the way out so a downloaded directory mirrors
// exactly what was on the gateway and the audit operator can correlate
// file-by-file. Terminal-mode parts keep their
// existing names. Single source of truth — `fetchAndWriteParts` reads
// this table and nothing else decides a file name.
var partFilenameExt = map[string]string{
	"cast": ".cast",
	"txt":  ".txt",
	"exec": ".exec.jsonl",
	"meta": ".meta",
}

// fetchAndWriteParts downloads the named parts in order — each one
// streamed to disk chunk by chunk, its sha256 verified against what the
// gateway sent before the file takes its real name — and reports what
// it wrote under outDir. The shared helper exists so fetchRecording's
// three branches (terminal, exec, legacy-no-meta) all share one
// well-tested download/verify/write loop.
func fetchAndWriteParts(conn recordingFetcher, id, outDir string, parts []string) ([]string, error) {
	const chunk = 1 << 20
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, classifyPathErr(err, outDir)
	}
	var written []string
	for _, part := range parts {
		ext, ok := partFilenameExt[part]
		if !ok {
			// Defensive: every part that reaches this loop is named by
			// fetchRecording/partsForRecordingMode/the meta-probe fallback,
			// which are themselves driven by the closed set PROTOCOL §8
			// names. A missing entry here is a code bug (a new part added
			// without teaching the table), not a runtime input — surface
			// it loudly instead of silently picking a name that drifts
			// from what the gateway wrote.
			return written, fmt.Errorf("fetch: unknown recording part %q (no local filename extension; update partFilenameExt)", part)
		}
		dst := filepath.Join(outDir, id+ext)
		if err := downloadRecordingPartTo(conn, id, part, chunk, dst); err != nil {
			return written, fmt.Errorf("%s: %w", part, err)
		}
		written = append(written, dst)
	}
	return written, nil
}

// streamRecordingPart downloads one part of a recording chunk by chunk,
// writing the bytes to w as they arrive, and verifies the gateway's
// whole-part sha256 on the way (PROTOCOL §6: the client repeats the
// request with offset+decodedLen(data) until offset=total; the zero
// chunk at offset=total is how the loop ends). The previous shape
// assembled the whole part in memory before verifying — a 500 MB
// recording was 500 MB of the CLI's RAM — and nothing in the protocol
// needs that: every chunk is a slice of the same immutable finished
// file, so the hash streams next to the bytes and the mismatch fires
// before the caller does anything with the result.
func streamRecordingPart(conn recordingFetcher, id, part string, chunk int64, w io.Writer) error {
	return streamRecording(conn, id, part, chunk, w, true)
}

// probeRecordingMeta fetches the .meta part without the sha256 check:
// the bytes are a sniff, not the download — they are only decoded
// best-effort for recording_mode, and the authoritative .meta is
// downloaded and hash-verified again as the last part of
// fetchAndWriteParts. Skipping the check here keeps a lying gateway
// failing at the part that actually matters (the bulk download) instead
// of masquerading as "no .meta" and sending the fetch down the legacy
// fallback.
func probeRecordingMeta(conn recordingFetcher, id string, chunk int64) ([]byte, error) {
	var buf bytes.Buffer
	if err := streamRecording(conn, id, "meta", chunk, &buf, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// streamRecording is the chunk loop behind both: the hash streams next
// to the bytes when verify is set, and the mismatch fires before the
// caller does anything with the result.
func streamRecording(conn recordingFetcher, id, part string, chunk int64, w io.Writer, verify bool) error {
	var hasher hash.Hash
	if verify {
		hasher = sha256.New()
	}
	var offset int64
	for {
		res, err := conn.RecordingsFetch(id, part, offset, chunk)
		if err != nil {
			return err
		}
		raw, err := decodeBase64Loose(res.Data)
		if err != nil {
			return fmt.Errorf("gateway sent undecodable base64: %w", err)
		}
		if _, err := w.Write(raw); err != nil {
			return err
		}
		if hasher != nil {
			hasher.Write(raw)
		}
		offset += int64(len(raw))
		if offset >= res.Total {
			if hasher != nil {
				if got := hex.EncodeToString(hasher.Sum(nil)); got != res.SHA256 {
					return fmt.Errorf("sha256 mismatch: got %s, want %s", got, res.SHA256)
				}
			}
			return nil
		}
		if len(raw) == 0 {
			return fmt.Errorf("gateway made no progress at offset %d/%d", offset, res.Total)
		}
	}
}

// downloadRecordingPartTo streams one part of a recording into dst: the
// bytes land on disk as each chunk arrives (M-12), through
// datafile.WriteFileAtomicFunc, so a mismatch or a dropped connection
// leaves any previous file in place and removes the temporary — a
// half-verified recording never takes its real name.
func downloadRecordingPartTo(conn recordingFetcher, id, part string, chunk int64, dst string) error {
	err := datafile.WriteFileAtomicFunc(dst, func(f *os.File) error {
		return streamRecordingPart(conn, id, part, chunk, f)
	}, datafile.WithAdoptOwnerFn(adoptOwnership))
	return classifyDatafileErr(err)
}

// decodeBase64Loose accepts either padded standard base64 (what
// internal/gateway/admin_role.go's cmdRecordingsFetch actually sends,
// via base64.StdEncoding) without hard-failing on an empty string,
// which a zero-length final chunk legitimately is (PROTOCOL §6:
// "A zero-length chunk is allowed only at offset=total").
func decodeBase64Loose(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// sessionTailPollInterval is how often the console watcher asks the
// gateway for more of a live session. It is a poll and not a stream
// because PROTOCOL 1.2 gives one exec one JSON object; a second of lag
// is the price, and for watching somebody work it is not a price worth
// a new protocol capability. See internal/gateway/live_tail.go.
const sessionTailPollInterval = time.Second

// riskKeyArgument resolves --key, reading standard input when it is "-".
//
// A secret passed as a command-line argument is not private: it lands in
// the shell history file, and while the command runs it sits in the
// process list every other account on this machine can read. "-" exists
// so there is a way to replace the key that leaks neither, and the help
// text names it as the form to prefer.
//
// The read takes the whole stream and trims surrounding whitespace: a key
// arrives from a clipboard or a heredoc far more often than it is typed,
// and both bring a trailing newline that the gateway would otherwise
// probe as part of the key.
func riskKeyArgument(s *streams, flag string) (string, error) {
	if flag != "-" {
		return flag, nil
	}
	raw, err := io.ReadAll(s.in)
	if err != nil {
		return "", envErrf("iamtunnel admin risk key: reading the key from standard input: %v", err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", userErrf("iamtunnel admin risk key: standard input carried no key — pipe it in, e.g. \"… | iamtunnel admin risk key --key -\".")
	}
	return key, nil
}
