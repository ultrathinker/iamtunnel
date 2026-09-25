//go:build (windows || linux || darwin) && !nogui

package main

import (
	"fmt"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

// The Admin tab's half of the §3.3 verbs it did not have until 24.09.2026
// (IAMT-499): machines verify / set-user / rekey, people keys add /
// remove / connection-string, gateway fingerprint / backup /
// rotate-hostkey. Each is the same dialAdmin + admin.Conn call the CLI
// verb of the same name makes (admin_exec.go), so the window and the
// console cannot drift apart in what they send; only the sentence
// differs, because a window row has room for one.

// withAdminConn dials the gateway with this machine's saved identity and
// runs one request -- the four lines every gui action here opens with.
func withAdminConn(clientDir string, run func(*admin.Conn) (string, error)) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return run(conn.Conn)
}

func guiAdminMachineVerify(clientDir, id string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		mv, err := conn.MachinesVerify(id)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s answered the probe: %s, door %s, sshd key %s.",
			id, orWord(mv.State, "state unknown"), orWord(mv.DoorState, "closed"), orWord(mv.HostKeyStatus, "not compared yet")), nil
	})
}

func guiAdminMachineSetUser(clientDir, id, osUser string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		if err := conn.MachinesSetUser(id, osUser); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s now logs in as %s; a fresh probe runs before the door reopens.", id, osUser), nil
	})
}

func guiAdminMachineRekey(clientDir, id, confirmFingerprint string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		oldKey, newKey, err := conn.MachinesRekey(id, confirmFingerprint)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Pinned %s's new sshd key %s (was %s).", id, newKey, oldKey), nil
	})
}

func guiAdminPersonKeyAdd(clientDir, name, pubkey string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		key, err := conn.PeopleKeysAdd(name, pubkey)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Added key %s to %s.", key.Fingerprint, name), nil
	})
}

func guiAdminPersonKeyRemove(clientDir, name, fingerprint string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		if err := conn.PeopleKeysRemove(name, fingerprint); err != nil {
			return "", err
		}
		return fmt.Sprintf("Removed key %s from %s; new logins with it are refused.", fingerprint, name), nil
	})
}

func guiAdminPersonConnectionString(clientDir, name string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		return conn.PeopleConnectionString(name)
	})
}

func guiAdminGatewayFingerprint(clientDir string) ([]string, error) {
	var fps []string
	_, err := withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		var err error
		fps, err = conn.GatewayFingerprint()
		return "", err
	})
	return fps, err
}

func guiAdminGatewayBackup(clientDir string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		id, created, size, sha, err := conn.GatewayBackup()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Backup %s made %s on the gateway's disk: %d bytes, sha256 %s.", id, created, size, sha), nil
	})
}

func guiAdminGatewayRotateHostkey(clientDir string) (string, error) {
	return withAdminConn(clientDir, func(conn *admin.Conn) (string, error) {
		oldFP, newFP, err := conn.GatewayRotateHostkey()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("New host key %s (was %s). It takes effect when the gateway service restarts; after that every client and machine needs a new connection string or a new enrolment (RUNBOOK §4.3).", newFP, oldFP), nil
	})
}

// orWord is s, or the word that stands for its absence.
func orWord(s, none string) string {
	if s == "" {
		return none
	}
	return s
}
