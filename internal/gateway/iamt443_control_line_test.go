package gateway

// IAMT-443: the gateway read its machines' control channels with no rule
// at all. PROTOCOL §5.1 bounds a control line to 16 KiB, one JSON object
// per LF-terminated line, and calls an unknown field, a duplicate key or
// an object without its LF a protocol violation; the machine has held the
// gateway to that from the first day and tears the tunnel down on the
// first line that breaks it (internal/server/wire.go). The gateway ran a
// json.Decoder straight over the channel instead. It buffers a value of
// any size while it waits for the end of it, keeps the last of two
// duplicate keys, ignores fields it does not know and reads two objects on
// one line as two messages. And every request a machine made started a
// goroutine of its own, with nothing to say how many.
//
// A machine is exactly the party whose key can be lifted off a laptop.
// These tests are what one could do with it before the fix.

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// iamt443ID is a well-formed request id the gateway never issued: a
// response carrying it matches nothing pending.
const iamt443ID = "00000000-0000-4000-8000-000000000443"

// iamt443Disconnected returns the Result of the last machine.disconnected
// event for the fixture's machine, or "" while there is none.
func iamt443Disconnected(f *fixture) string {
	evs, _, err := f.log.Read(events.Filter{
		Types: []events.EventType{events.EventMachineDisconnected},
		Actor: f.machineID,
	})
	if err != nil || len(evs) == 0 {
		return ""
	}
	return evs[len(evs)-1].Result
}

// iamt443TornDown waits up to five seconds for the gateway to drop the
// machine and reports whether it did.
func iamt443TornDown(f *fixture) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if iamt443Disconnected(f) != "" {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestIAMT443_AControlLineOverTheLimitTearsTheTunnelDown(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// A well-formed response, 20 KiB long: nothing in it but its length
	// is wrong, and the length is what PROTOCOL §5.1 bounds.
	line := `{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true,"result":{"pad":"` + strings.Repeat("x", 20*1024) + `"}}` + "\n"
	if err := fm.writeControlRaw([]byte(line)); err != nil {
		t.Fatalf("write the long line: %v", err)
	}
	if !iamt443TornDown(f) {
		t.Fatalf("a %d-byte control line was read whole and the tunnel kept going; PROTOCOL §5.1 bounds a line to 16 KiB", len(line))
	}
	if got := iamt443Disconnected(f); got != "control-framing" {
		t.Errorf("the machine was dropped with reason %q, want \"control-framing\"", got)
	}
}

func TestIAMT443_AMalformedControlLineTearsTheTunnelDown(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"an unknown field", `{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true,"extra":1}`},
		{"a duplicate key", `{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true,"ok":false}`},
		{"two objects on one line", `{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true}{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true}`},
		{"another protocol version", `{"proto":2,"caps":[],"id":"` + iamt443ID + `","ok":true}`},
		{"no caps", `{"proto":1,"id":"` + iamt443ID + `","ok":true}`},
		{"an id that is not a uuid", `{"proto":1,"caps":[],"id":"not-a-uuid","ok":true}`},
		{"nesting past the limit", `{"proto":1,"caps":[],"id":"` + iamt443ID + `","ok":true,"result":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			fm := f.connectMachine(fakeMachineBehavior{})
			f.waitMachineOnline(t)

			if err := fm.writeControlRaw([]byte(tc.line + "\n")); err != nil {
				t.Fatalf("write the line: %v", err)
			}
			if !iamt443TornDown(f) {
				t.Fatalf("the gateway accepted %s on the control channel and kept the tunnel: %s", tc.name, tc.line)
			}
			if got := iamt443Disconnected(f); got != "control-protocol" {
				t.Errorf("the machine was dropped with reason %q, want \"control-protocol\"", got)
			}
		})
	}
}

// A machine's own requests are served with bounded parallelism. The
// machine here asks for something the gateway does not know - it answers
// every such request, with the op's name in the refusal - and has stopped
// reading its channel, so once the SSH window is full every answer waits.
// Before the fix each request was a goroutine of its own, and every one
// of them now waited: a machine could park as many goroutines on the
// gateway as it cared to send lines.
func TestIAMT443_AMachineCannotParkUnboundedWorkOnTheGateway(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	fm.stallControlReader()
	// Let the gateway's own start-up traffic settle before the baseline.
	time.Sleep(200 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	op := strings.Repeat("o", 10*1024)
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < 600; i++ {
			line := fmt.Sprintf(`{"proto":1,"caps":[],"id":"00000000-0000-4000-8000-%012d","op":"%s"}`+"\n", i, op)
			if fm.writeControlRaw([]byte(line)) != nil {
				return
			}
		}
	}()
	select {
	case <-sent:
	case <-time.After(3 * time.Second):
		// The gateway stopped reading: that is backpressure, and it is
		// what a bound looks like from the machine's side.
	}
	time.Sleep(200 * time.Millisecond)

	if grown := runtime.NumGoroutine() - baseline; grown > 50 {
		t.Fatalf("600 requests from one machine left %d more goroutines on the gateway; they must wait their turn, not each get one", grown)
	}
}
