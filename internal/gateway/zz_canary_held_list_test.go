package gateway

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// The canary: held commands are visible, a retry does not duplicate
// entries, a refusal removes.
//
// On 21.09.2026 the maintainer asked the AI agent to copy a file, the
// gateway stopped the command, and there was nothing to approve it
// with: the id arrived only in the refusal to the agent, and looking
// at "what I have pending" was impossible in principle. The agent,
// seeing the id change on every attempt, concluded that a retry
// destroys the approval and stopped retrying -- and so the maintainer
// waited at a gate nobody was going to open.
//
// Three properties are checked together, because alone each one looks
// like it works:
//
//  1. The held one is visible through pendingRiskApprovals.
//  2. A retry of the SAME command reuses the entry: one held -- one
//     row in the list, no matter how many times the agent tries.
//  3. A refusal removes the entry at once, instead of leaving it to
//     wait out the expiry.
func TestCanary_HeldCommandsAreVisibleAndStable(t *testing.T) {
	g := &Gateway{}
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	v := risk.Verdict{Level: risk.Red, Rule: "external-classifier", Reason: "wipes a disk"}

	first := g.createRiskApproval("alice", "win-vm", "sess-1", "dd if=/dev/zero of=/dev/sda", v, now)
	held := g.pendingRiskApprovals("alice", now)
	if len(held) != 1 {
		t.Fatalf("held entries: %d, want 1 -- the list of stopped commands is empty, so the window will show nothing", len(held))
	}
	if held[0].Command != "dd if=/dev/zero of=/dev/sda" {
		t.Errorf("command in the list = %q -- the person decides by what they see, and a truncated command is a different command", held[0].Command)
	}

	// A retry half a minute later: the same person+machine+command triple.
	again := g.createRiskApproval("alice", "win-vm", "sess-2", "dd if=/dev/zero of=/dev/sda", v, now.Add(30*time.Second))
	if again.ID != first.ID {
		t.Errorf("a retry of the same command issued a NEW id (%s instead of %s): the list bloats with copies of one question, "+
			"and a careful agent concludes that retrying is not allowed", again.ID, first.ID)
	}
	if held := g.pendingRiskApprovals("alice", now.Add(30*time.Second)); len(held) != 1 {
		t.Errorf("after the retry held entries: %d, want 1", len(held))
	}

	// A different command -- its own entry.
	other := g.createRiskApproval("alice", "win-vm", "sess-3", "shutdown /s", v, now)
	if other.ID == first.ID {
		t.Error("a different command received the same id -- two different questions merged into one")
	}
	if held := g.pendingRiskApprovals("alice", now); len(held) != 2 {
		t.Errorf("held entries: %d, want 2", len(held))
	}

	// Other people's held ones are not visible.
	if held := g.pendingRiskApprovals("bob", now); len(held) != 0 {
		t.Errorf("bob sees %d of other people's stopped commands -- they contain text not meant for them", len(held))
	}

	// A refusal removes at once.
	if _, status := g.denyRiskApproval("alice", first.ID, now); status != "ok" {
		t.Fatalf("the refusal returned %q, want ok", status)
	}
	if held := g.pendingRiskApprovals("alice", now); len(held) != 1 {
		t.Errorf("after the refusal held entries: %d, want 1 -- the denied one keeps looking like it awaits a decision", len(held))
	}

	// Someone else's refusal does not go through.
	if _, status := g.denyRiskApproval("bob", other.ID, now); status != riskApprovalDenied {
		t.Errorf("bob managed to deny someone else's stopped command (status=%q)", status)
	}
}
