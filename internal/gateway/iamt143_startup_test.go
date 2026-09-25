package gateway

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT143P2_NewRejectsZeroEnrolHMAC makes the runtime boundary explicit:
// OpenForRead is a valid read-only inspector even though it intentionally has
// no HMAC key, whereas Gateway.New is a live service and must refuse it before
// any untrusted enrol/bootstrap request can reach HashEnrolSecret.
func TestIAMT143P2_NewRejectsZeroEnrolHMAC(t *testing.T) {
	dir := t.TempDir()
	writable, err := state.Open(dir)
	if err != nil {
		t.Fatalf("open writable state: %v", err)
	}
	if err := writable.Close(); err != nil {
		t.Fatalf("close writable state: %v", err)
	}
	readOnly, err := state.OpenForRead(dir)
	if err != nil {
		t.Fatalf("OpenForRead: %v", err)
	}
	t.Cleanup(func() { _ = readOnly.Close() })

	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	for _, tc := range []struct {
		name  string
		store *state.Store
	}{
		{name: "OpenForRead", store: readOnly},
		{name: "zero Store", store: &state.Store{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, newErr := New(Config{
				Store:                     tc.store,
				Log:                       log,
				HostKey:                   genSigner(t),
				RecordingBaseDir:          filepath.Join(dir, tc.name, "recordings"),
				RecordingRotationInterval: 0,
				Now:                       time.Now,
			})
			if gw != nil {
				_ = gw.Close()
				t.Fatalf("Gateway.New returned a runtime for %s with a zero enrol HMAC key", tc.name)
			}
			if newErr == nil {
				t.Fatalf("Gateway.New accepted %s with a zero enrol HMAC key; startup must refuse before serving requests", tc.name)
			}
			if !strings.Contains(newErr.Error(), "enrol HMAC key is zero") {
				t.Fatalf("Gateway.New error %q does not name the zero enrol HMAC key", newErr)
			}
		})
	}
}
