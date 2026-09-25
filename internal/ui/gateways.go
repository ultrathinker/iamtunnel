//go:build windows || linux || darwin

package ui

// Switching between gateways from the window (IAMT-431).
//
// The maintainer, 22.09.2026: can the client application connect to
// different gateways? It should be quick -- remembered once, so that no
// logins or passwords have to be entered again. A personal gateway for
// one's own machines, a second one at work.
//
// WHY THIS IS A SWITCH AND NOT A SETTING. Two gateways are not two
// configurations of one product. They are two separate worlds: each has
// its own machines, its own people, its own grants, its own history, and
// they share exactly one thing -- the key in this directory. Which world
// the window is looking at therefore has to be visible before anything
// else on the screen means anything, and changing it has to throw away
// every list that came from the old one.
//
// That last part is the whole risk in this feature. A window that
// switched gateways and left the previous one's machines on the screen
// would be showing a true list of the wrong world -- the same species of
// lie as the empty transcript: it looks like an answer.

import (
	"context"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// refreshGateways reloads the remembered gateways into the snapshot.
//
// Synchronous and cheap on purpose: it reads one small file on this
// machine. The Client tab calls it whenever the set can have changed,
// and nothing about it can block on a network.
func (f *Frame) refreshGateways() {
	ask := f.cfg.Actions.ClientGateways
	if ask == nil {
		return
	}
	list, current, err := ask()
	if err != nil {
		// Not said out loud: an unreadable list is reported by whatever
		// action the person actually pressed. Shouting here would put a
		// red line under a tab nobody asked anything of.
		return
	}
	f.reviseSnapshot(func(s *Snapshot) {
		s.Client.Gateways = list
		s.Client.Current = current
		s.Client.Configured = len(list) > 0
	})
}

// useGateway switches to one remembered gateway.
//
// Everything the old gateway answered is dropped in the same breath as
// the switch, not after the new lists arrive: between the press and the
// gateway's first reply there must be nothing on screen that claims to
// describe a world this window is no longer looking at.
func (f *Frame) useGateway(name string) {
	use := f.cfg.Actions.ClientUseGateway
	if use == nil {
		f.say(ctlClientGateways, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlClientGateways, "Switching.", func() (string, design.ColorKey) {
		what, err := use(name)
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.forgetTheOtherGatewaysAnswers()
		f.refreshGateways()
		f.afterGatewayChange()
		return what, design.GoodKey
	})
}

// forgetGateway drops one remembered gateway, on the SECOND press.
//
// TWO PRESSES, the way Forget on the Join card and Remove on the Admin
// rows already ask for them (23.09.2026). The first draft of this row
// had a bare ✕ that acted at once, and that is the wrong weight for what
// it does: what goes is the pinned host key fingerprint, the address and
// the person — the whole of the connection string an administrator once
// handed over. Getting it back means asking them for it again, which on
// a work gateway is a message and a wait, and if this was the last entry
// the machine is left connected to nothing at all.
//
// The ✕ is also small, sits at the end of a row, and has "Use" beside
// it: the second press is the moment to notice the row is the one under
// the one that was meant.
func (f *Frame) forgetGateway(ctl, name string) {
	if !f.confirming[ctl] {
		// One armed row at a time. A question that is no longer on
		// screen must not still be answerable: arming a second row and
		// coming back to press the first would otherwise act instantly,
		// with nothing having asked.
		f.disarmForgets()
		f.confirming[ctl] = true
		f.say(ctlClientGateways,
			"Forget “"+name+"”? Press ✕ again to confirm. The connection string for it goes too — "+
				"its address and its pinned key — and coming back needs a fresh one from that gateway's "+
				"administrator. Your own key stays, and so does your person record there.",
			design.WarnKey)
		return
	}
	f.confirming[ctl] = false
	drop := f.cfg.Actions.ClientForgetGateway
	if drop == nil {
		f.say(ctlClientGateways, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlClientGateways, "Forgetting.", func() (string, design.ColorKey) {
		what, err := drop(name)
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.forgetTheOtherGatewaysAnswers()
		f.refreshGateways()
		f.afterGatewayChange()
		return what, design.GoodKey
	})
}

// disarmForgets puts every armed ✕ back to rest.
//
// Called from the drawing goroutine only, as the whole confirming map
// is: it is arming that must be exclusive, so the one place that arms is
// the one place that clears. A forget clears its own row before it
// starts work, and the row then leaves the list, so no arming outlives
// the list it was pointed at.
func (f *Frame) disarmForgets() {
	for ctl := range f.confirming {
		if strings.HasPrefix(ctl, ctlClientGateways+"/") && strings.HasSuffix(ctl, "/forget") {
			f.confirming[ctl] = false
		}
	}
}

// forgetTheOtherGatewaysAnswers empties every list that belonged to the
// gateway being left.
//
// Each of these was fetched from one gateway and is meaningless about
// another: the machines a person may enter, the people and machines an
// administrator manages, the grants between them, the commands held for
// approval, the sessions and the history. Emptying them is not tidying
// -- a stale list here would name real machines that this person may not
// be able to reach at all, on a screen whose buttons act on the NEW
// gateway.
//
// Emptying is half of it (R1-CX F-16). The other half is the answers
// still on their way from the gateway being left: a refresh begun before
// the switch used to land after it, onto the new gateway's screen, and
// the switch's own refresh of the same list was turned away because the
// old one still held its control. So the switch also starts a new
// generation - an answer asked in an older one is dropped, and the
// refresh that was asked in it asks again, of the gateway now current -
// and cancels the requests still waiting on the old gateway.
func (f *Frame) forgetTheOtherGatewaysAnswers() {
	f.reviseSnapshot(func(s *Snapshot) {
		// Under the lock reviseSnapshot holds: every answer checks the
		// generation in that same lock before it lands, so it either
		// landed before this line or it does not land at all.
		f.gatewayGen++
		f.gatewaySwitchedAt = time.Now()
		if f.gatewayStop != nil {
			f.gatewayStop()
		}
		f.gatewayCtx, f.gatewayStop = nil, nil

		s.Client.Machines = nil
		s.Client.Held = nil
		s.Admin.People = nil
		s.Admin.Machines = nil
		s.Admin.Grants = nil
		s.Admin.ActiveSessions = nil
		s.Admin.ThisMachine = nil
		// The old gateway's safety mode and classifier key, its trouble
		// with its journal and its pairing window's PIN: answers of that
		// gateway too, and they outlived the switch (R1-CX F-16).
		s.Admin.RiskMode = RiskMode{}
		s.Admin.AuditProblem = ""
		s.Admin.Pairing = nil
		s.History = HistoryPage{}
	})
}

// gatewayNow is the generation of the gateway this window looks at, and
// the context its requests run under: cancelled at the next switch.
func (f *Frame) gatewayNow() (uint64, context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gatewayCtx == nil {
		f.gatewayCtx, f.gatewayStop = context.WithCancel(context.Background())
	}
	return f.gatewayGen, f.gatewayCtx
}

// gatewayMoved reports whether the window has switched gateways since
// generation gen.
func (f *Frame) gatewayMoved(gen uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gatewayGen != gen
}

// reviseForGateway is reviseSnapshot for an answer asked of the gateway
// of generation gen: it lands only if the window still looks at that
// gateway, and reports whether it did.
func (f *Frame) reviseForGateway(gen uint64, edit func(*Snapshot)) bool {
	landed := false
	f.reviseSnapshot(func(s *Snapshot) {
		if f.gatewayGen == gen {
			edit(s)
			landed = true
		}
	})
	return landed
}

// forCurrentGateway asks the gateway the window looks at, and lands the
// answer through the edit ask returns. When the window switched gateways
// while ask was on its way, the answer - or the error, most often the
// cancellation itself - is about the gateway it left: it is dropped, and
// the question is asked again of the gateway now current. The switch's
// own refresh of the same list was turned away because this one held its
// control, so without asking again the new gateway's list would never
// come. Each round is one switch, so this ends.
func (f *Frame) forCurrentGateway(ask func(ctx context.Context) (func(*Snapshot), error)) error {
	for {
		gen, ctx := f.gatewayNow()
		land, err := ask(ctx)
		if err != nil {
			if f.gatewayMoved(gen) {
				continue
			}
			return err
		}
		if f.reviseForGateway(gen, land) {
			return nil
		}
	}
}

// afterGatewayChange asks the new gateway for what the old one used to
// answer, so the screen fills instead of staying empty.
//
// Machines first: that is the list the Client tab is standing on. The
// admin lists follow on their own and refuse harmlessly when this person
// is not an administrator there -- which is itself a thing that can
// differ between two gateways, and another reason the two worlds cannot
// share a cached answer.
func (f *Frame) afterGatewayChange() {
	if f.cfg.Actions.Machines != nil {
		f.refreshMachines()
	}
	if f.cfg.Actions.AdminList != nil {
		f.refreshAdminLists()
	}
}

// gatewayDisplayName is what a row is labelled with. A name is always
// present by the time it reaches here (the store repairs an empty one),
// but a file edited by hand can still arrive nameless, and a blank row
// nobody can press is worse than a placeholder.
func gatewayDisplayName(g GatewayRef) string {
	if strings.TrimSpace(g.Name) != "" {
		return g.Name
	}
	if strings.TrimSpace(g.Where) != "" {
		return g.Where
	}
	return "(unnamed)"
}

// gatewayLine is the second line of a row: who you are there, and where
// "there" is.
func gatewayLine(g GatewayRef) string {
	who := strings.TrimSpace(g.Person)
	if who == "" {
		who = "—"
	}
	return who + " on " + orDash(g.Where)
}
