package gateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func iamt394ApprovalID(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "approval-id=") {
				return strings.TrimPrefix(field, "approval-id=")
			}
		}
	}
	return ""
}

func iamt394ApprovalRequest(t *testing.T, id string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"proto": 1, "approvalId": id})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func iamt394Approve(t *testing.T, f *fixture, person, id string) {
	t.Helper()
	result, cerr := f.gw.runCommand(person, "risk.approve", iamt394ApprovalRequest(t, id))
	if cerr != nil {
		t.Fatalf("risk.approve %q as %s: %s (%s)", id, person, cerr.message, cerr.code)
	}
	response, ok := result.(map[string]interface{})
	if !ok || response["approvalId"] != id || response["approved"] != true {
		t.Fatalf("risk.approve response = %#v, want approved %q", result, id)
	}
}

func iamt394RefusedRed(t *testing.T, f *fixture, command string) string {
	t.Helper()
	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "E_APPROVAL_REQUIRED")
	id := iamt394ApprovalID(stderr)
	if id == "" || !riskApprovalIDValid(id) {
		t.Fatalf("ask warning = %q, want a shape-valid approval-id", stderr)
	}
	if why := iamt353CheckNotice(stderr, "APPROVAL REQUIRED", "risk=red rule=rm-recursive-outside-temp action=ask approval-id="+id+" E_APPROVAL_REQUIRED"); why != "" {
		t.Fatalf("ask warning = %q: %s", stderr, why)
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("ask refusal exit status = %d, want 126", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ask refusal did not return exit-status 126")
	}
	return id
}

func TestIAMT394_AskRedNeverReachesMachine(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) { execSeen <- struct{}{} })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	id := iamt394RefusedRed(t, f, "rm -rf /var/lib/postgresql")
	select {
	case <-execSeen:
		t.Fatal("ask refusal reached the machine as exec")
	case <-time.After(250 * time.Millisecond):
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventRiskApproval}, Actor: f.person, Object: f.machineID})
	if err != nil {
		t.Fatalf("read risk.approval: %v", err)
	}
	if len(evs) == 0 || evs[len(evs)-1].Result != riskApprovalPending || evs[len(evs)-1].Details["approvalId"] != id {
		t.Fatalf("risk.approval events = %+v, want pending %q", evs, id)
	}
	if got := f.lastSessionDropResult(f.person, f.machineID); got != "E_APPROVAL_REQUIRED" {
		t.Fatalf("ask session.drop = %q, want E_APPROVAL_REQUIRED", got)
	}
}

func TestIAMT394_ApprovalIsExactAndOneTime(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := make(chan struct{}, 2)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	original := "rm -rf /var/lib/postgresql"
	id := iamt394RefusedRed(t, f, original)
	iamt394Approve(t, f, f.person, id)

	changedID := iamt394RefusedRed(t, f, original+" ")
	if changedID == id {
		t.Fatalf("changed command reused approval id %q", id)
	}
	select {
	case <-execSeen:
		t.Fatal("changed command consumed the approval")
	case <-time.After(250 * time.Millisecond):
	}

	client, hs := iamt353OpenExec(t, f, original)
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("approved exact command did not reach the machine")
	}
	select {
	case status := <-hs.exits:
		if status != 0 {
			t.Fatalf("approved exact command exit status = %d, want 0", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("approved exact command did not return exit-status")
	}
	_ = client.Close()

	// The approved record was consumed by the preceding exact run. A second
	// identical run must ask again and must not reach the fake sshd.
	_ = iamt394RefusedRed(t, f, original)
	select {
	case <-execSeen:
		t.Fatal("second exact run reused a one-time approval")
	case <-time.After(250 * time.Millisecond):
	}
}

func TestIAMT394_ApprovalExpires(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	id := iamt394RefusedRed(t, f, "rm -rf /var/lib/postgresql")
	f.clock.Advance(riskApprovalTTL + time.Second)

	_, cerr := f.gw.runCommand(f.person, "risk.approve", iamt394ApprovalRequest(t, id))
	if cerr == nil || cerr.code != "E_APPROVAL_NOT_FOUND" {
		t.Fatalf("expired risk.approve error = %#v, want E_APPROVAL_NOT_FOUND", cerr)
	}
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventRiskApproval}, Actor: f.person, Object: f.machineID})
	if err != nil {
		t.Fatalf("read expired risk.approval: %v", err)
	}
	if len(evs) == 0 || evs[len(evs)-1].Result != riskApprovalExpired {
		t.Fatalf("expired risk.approval events = %+v, want expired last", evs)
	}
}

func TestIAMT394_ForeignApprovalIsRejected(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	id := iamt394RefusedRed(t, f, "rm -rf /var/lib/postgresql")

	_, cerr := f.gw.runCommand("bob", "risk.approve", iamt394ApprovalRequest(t, id))
	if cerr == nil || cerr.code != "E_APPROVAL_FORBIDDEN" {
		t.Fatalf("foreign risk.approve error = %#v, want E_APPROVAL_FORBIDDEN", cerr)
	}
	// The foreign attempt did not consume or alter the pending record.
	iamt394Approve(t, f, f.person, id)
}

func TestIAMT394_YellowUnderAskBehavesWarn(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "git push --force origin main")
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "action=warn")
	if why := iamt353CheckNotice(stderr, "WARNING", "risk=yellow rule=git-push-force action=warn"); why != "" {
		t.Fatalf("yellow under ask stderr = %q: %s", stderr, why)
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("yellow under ask did not reach the machine")
	}
}

func TestIAMT394_InteractiveShellUnderAskIsNotClassified(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	if evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionRisk}, Actor: f.person, Object: f.machineID}); err != nil {
		t.Fatalf("read shell risk events: %v", err)
	} else if len(evs) != 0 {
		t.Fatalf("interactive ask shell created risk events: %+v", evs)
	}
	_ = hs.ch.Close()
}
