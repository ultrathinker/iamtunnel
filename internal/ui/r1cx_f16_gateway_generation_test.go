//go:build windows || linux || darwin

package ui

// R1-CX F-16: switching gateways emptied the old gateway's lists, but did
// not stop, or even mark, the requests still on their way from it. The
// switch's own refresh was then turned away, because the old request
// still held the control; and when the old gateway finally answered, its
// answer was written onto the new gateway's screen - home's machines
// under work's name, with Connect buttons that dial through work.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// r1cxF16World is two gateways, home and work, and which one the saved
// connections point at. home answers only once its barrier opens: the
// slow network of the finding.
type r1cxF16World struct {
	mu      sync.Mutex
	current string
	barrier chan struct{}
	// homeAsked receives the context of every request home got.
	homeAsked chan context.Context
}

func r1cxF16NewWorld() *r1cxF16World {
	return &r1cxF16World{current: "home", barrier: make(chan struct{}), homeAsked: make(chan context.Context, 16)}
}

func (w *r1cxF16World) now() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current
}

// ask answers for whichever gateway is current when it is asked. home
// ignores ctx on purpose: an action that does not honour cancellation
// must not get its late answer onto the new gateway's screen either.
func (w *r1cxF16World) ask(ctx context.Context) string {
	gw := w.now()
	if gw == "home" {
		w.homeAsked <- ctx
		<-w.barrier
	}
	return gw
}

func r1cxF16Frame(t *testing.T, w *r1cxF16World) *Frame {
	t.Helper()
	f := newBareFrame(t)
	f.cfg.Actions.ClientGateways = func() ([]GatewayRef, string, error) {
		return []GatewayRef{{Name: "home"}, {Name: "work"}}, w.now(), nil
	}
	f.cfg.Actions.ClientUseGateway = func(name string) (string, error) {
		w.mu.Lock()
		w.current = name
		w.mu.Unlock()
		return "Now using " + name + ".", nil
	}
	f.cfg.Actions.Machines = func(ctx context.Context) ([]MachineAccess, error) {
		return []MachineAccess{{Name: w.ask(ctx) + "-machine"}}, nil
	}
	f.cfg.Actions.AdminList = func(ctx context.Context) (AdminLists, error) {
		gw := w.ask(ctx)
		return AdminLists{People: []Person{{Name: gw + "-person"}}, RiskMode: RiskMode{Mode: gw + "-mode"}}, nil
	}
	f.cfg.Actions.SessionsHistory = func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
		return HistoryPage{Rows: []HistoryRow{{SessionID: w.ask(ctx) + "-session"}}, Total: 1}, nil
	}
	return f
}

// r1cxF16Next is what the very next frame will show.
func r1cxF16Next(f *Frame) Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending != nil {
		return *f.pending
	}
	return f.snap
}

func r1cxF16WaitIdle(t *testing.T, f *Frame, ctls ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, ctl := range ctls {
		for f.busy(ctl) {
			if time.Now().After(deadline) {
				t.Fatalf("%s is still busy after 10s", ctl)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// r1cxF16HomeAsked waits for home to be asked, and returns the request's
// context.
func r1cxF16HomeAsked(t *testing.T, w *r1cxF16World) context.Context {
	t.Helper()
	select {
	case ctx := <-w.homeAsked:
		return ctx
	case <-time.After(10 * time.Second):
		t.Fatal("home was never asked")
		return nil
	}
}

// r1cxF16Switch presses Use on work and waits for the switch itself.
func r1cxF16Switch(t *testing.T, f *Frame) {
	t.Helper()
	f.useGateway("work")
	r1cxF16WaitIdle(t, f, ctlClientGateways)
	if said := f.saidUnder(ctlClientGateways); said.text != "Now using work." {
		t.Fatalf("the switch said %q", said.text)
	}
}

func TestR1CX_F16_ARefreshInFlightAtTheSwitchNeverLandsOnTheNewGateway(t *testing.T) {
	rows := []struct {
		name  string
		ctl   string
		start func(f *Frame)
		shown func(s Snapshot) string
	}{
		{"machines", ctlClientRefresh, func(f *Frame) { f.refreshMachines() }, func(s Snapshot) string {
			if len(s.Client.Machines) == 0 {
				return ""
			}
			return s.Client.Machines[0].Name
		}},
		{"admin lists", ctlAdminRefresh, func(f *Frame) { f.refreshAdminLists() }, func(s Snapshot) string {
			if len(s.Admin.People) == 0 {
				return ""
			}
			return s.Admin.People[0].Name
		}},
		{"history", ctlHistory, func(f *Frame) { f.refreshHistory(0) }, func(s Snapshot) string {
			if len(s.History.Rows) == 0 {
				return ""
			}
			return s.History.Rows[0].SessionID
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			w := r1cxF16NewWorld()
			f := r1cxF16Frame(t, w)
			r.start(f)
			homeCtx := r1cxF16HomeAsked(t, w)
			r1cxF16Switch(t, f)
			stopped := homeCtx.Err() != nil
			close(w.barrier)
			r1cxF16WaitIdle(t, f, r.ctl, ctlClientRefresh, ctlAdminRefresh, ctlHistory)

			shown := r.shown(r1cxF16Next(f))
			if strings.HasPrefix(shown, "home") {
				t.Fatalf("after the switch to work the %s show %q: home's late answer landed on work's screen", r.name, shown)
			}
			if !strings.HasPrefix(shown, "work") {
				t.Fatalf("after the switch to work the %s show %q, not work's: the switch's own refresh was turned away while home's held the control, and nothing asked work again", r.name, shown)
			}
			if !stopped {
				t.Errorf("the %s request still waiting on home was not cancelled by the switch", r.name)
			}
		})
	}
}

// The status tick: it reads who this machine is and what is held for
// this person from the gateway the saved connections name at that
// moment, and can land seconds later.
func TestR1CX_F16_ATickThatLookedBeforeTheSwitchDoesNotLandAfterIt(t *testing.T) {
	w := r1cxF16NewWorld()
	close(w.barrier)
	f := r1cxF16Frame(t, w)
	looked := time.Now()
	time.Sleep(2 * time.Millisecond)
	r1cxF16Switch(t, f)
	r1cxF16WaitIdle(t, f, ctlClientRefresh, ctlAdminRefresh)

	f.ApplyLiveUpdate(LiveUpdate{
		At:            looked,
		IdentityKnown: true, Identity: &AdminIdentity{Person: "home-admin", Gateway: "home:2022"},
		HeldKnown: true, Held: []HeldCommand{{ApprovalID: "home-1", Command: "rm -rf /"}},
	})
	next := r1cxF16Next(f)
	if len(next.Client.Held) != 0 {
		t.Fatalf("a command held by home, read before the switch, is on work's screen: %+v", next.Client.Held)
	}
	if next.Admin.ThisMachine != nil {
		t.Fatalf("who this machine is on home, read before the switch, is on work's screen: %+v", *next.Admin.ThisMachine)
	}

	// A tick that looked after the switch is about work, and lands.
	f.ApplyLiveUpdate(LiveUpdate{
		At:            time.Now(),
		IdentityKnown: true, Identity: &AdminIdentity{Person: "work-admin", Gateway: "work:2022"},
		HeldKnown: true, Held: []HeldCommand{{ApprovalID: "work-1", Command: "reboot"}},
	})
	next = r1cxF16Next(f)
	if len(next.Client.Held) != 1 || next.Client.Held[0].ApprovalID != "work-1" {
		t.Fatalf("a tick that looked after the switch did not land: held %+v", next.Client.Held)
	}
	if next.Admin.ThisMachine == nil || next.Admin.ThisMachine.Person != "work-admin" {
		t.Fatalf("a tick that looked after the switch did not land: identity %+v", next.Admin.ThisMachine)
	}
}

// Actions that write their answer as state: the safety mode home
// accepted, and the pairing PIN home issued.
func TestR1CX_F16_AnAnswerFromTheOldGatewayIsNotWrittenIntoTheNewOnesState(t *testing.T) {
	w := r1cxF16NewWorld()
	f := r1cxF16Frame(t, w)
	f.cfg.Actions.AdminRiskMode = func(mode string) (RiskModeResult, error) {
		return RiskModeResult{Mode: w.ask(context.Background()) + "-" + mode, Source: "live", Changed: true}, nil
	}
	f.cfg.Actions.AdminPairingStart = func() (PairingWindow, error) {
		return PairingWindow{Pin: w.ask(context.Background()) + "-pin", Expires: time.Now().Add(time.Hour)}, nil
	}
	f.setRiskMode("strict")
	f.openPairingWindow()
	r1cxF16HomeAsked(t, w)
	r1cxF16HomeAsked(t, w)
	r1cxF16Switch(t, f)
	r1cxF16WaitIdle(t, f, ctlClientRefresh, ctlAdminRefresh)
	close(w.barrier)
	r1cxF16WaitIdle(t, f, ctlAdminRiskMode, ctlAdminPairingStart)

	next := r1cxF16Next(f)
	if strings.HasPrefix(next.Admin.RiskMode.Mode, "home") {
		t.Fatalf("the safety mode home accepted is shown as work's: %q", next.Admin.RiskMode.Mode)
	}
	if next.Admin.Pairing != nil && strings.HasPrefix(next.Admin.Pairing.Pin, "home") {
		t.Fatalf("the pairing PIN home issued is shown on work's screen: %q", next.Admin.Pairing.Pin)
	}
}
