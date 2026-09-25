package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// Machine is one entry of PROTOCOL §6 "machines.mine": exactly the fields
// the gateway sends, no more.
type Machine struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Until         string `json:"until"`
	Online        bool   `json:"online"`
	State         string `json:"state"`
	SSHDListening bool   `json:"sshdListening"`
	DoorOpen      bool   `json:"doorOpen"`
	// Caps is this person's own grant capability on this machine —
	// ["shell"] or ["exec"] (added 1.8, alongside the same
	// field in internal/gateway/admin_role.go's machineMineView): the
	// one fact a caller needs to know, before ever attempting "connect",
	// whether this machine only runs one-off commands.
	Caps []string `json:"caps"`
}

// ExecOnly reports whether Caps names exec and nothing else — the one
// question the UI actually needs answered: is Connect even worth
// offering for this machine. A grant this package has never seen a caps
// field for at all (Caps == nil, e.g. against a pre-1.8 gateway) reports
// false: the pre-1.8 behavior — offer Connect, let the gateway's own
// refusal explain if it turns out wrong — over silently hiding a
// control a person may in fact be able to use.
func (m Machine) ExecOnly() bool {
	return len(m.Caps) == 1 && m.Caps[0] == "exec"
}

type machinesMineRequest struct {
	Proto int `json:"proto"`
}

type machinesMineResult struct {
	Machines []Machine `json:"machines"`
}

// Machines runs "machines.mine" (PROTOCOL §6) as command-login ("<person>"
// alone) and returns exactly what the gateway reports: it does not filter,
// re-sort or otherwise second-guess the list, because only the gateway
// knows the live grants, online state and door state that answer
// belongs to. The gateway implements command-login and handles
// machines.mine via internal/gateway/admin_role.go cmdMachinesMine.
func Machines(ctx context.Context, dir string, cs config.ConnString, signer ssh.Signer, timeout time.Duration) ([]Machine, error) {
	client, err := dial(ctx, DialOptions{
		Conn:           cs,
		User:           cs.Person,
		Signer:         signer,
		KnownHostsPath: KnownHostsPath(dir),
		Timeout:        timeout,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := preflight(ctx, client, timeout); err != nil {
		return nil, err
	}
	env, err := execCommand(ctx, client, timeout, "machines.mine", machinesMineRequest{Proto: 1})
	if err != nil {
		return nil, err
	}
	res, err := decodeMachinesMineResult(env.Result)
	if err != nil {
		return nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway \"machines.mine\" result does not match the protocol shape: %v", err)}
	}
	return res.Machines, nil
}

// decodeMachinesMineResult decodes strictly (PROTOCOL §1.3: "any field
// not in this message's shape yields E_JSON_FIELD_UNKNOWN" is
// the rule the gateway itself applies to requests; this package holds
// the gateway's own responses to the same standard rather than silently
// tolerating a field a v1 gateway would never send).
func decodeMachinesMineResult(raw json.RawMessage) (machinesMineResult, error) {
	var res machinesMineResult
	if len(bytes.TrimSpace(raw)) == 0 {
		return res, fmt.Errorf("empty result")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return res, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return res, fmt.Errorf("trailing data after the result object")
	}
	return res, nil
}
