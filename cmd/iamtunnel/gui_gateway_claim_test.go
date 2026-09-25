//go:build !nogui

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// The window and the command must answer the question "is the one-time
// first-admin line still alive" the same way.
//
// 23.09.2026, a re-review of yesterday's batch. The window reasoned:
// ClaimPending = expires.IsZero() || now.Before(expires) — that is, a
// ZERO deadline counted as eternal. The command (printBootstrapStatus)
// reasons exactly the opposite: a zero deadline is EXPIRED, and rightly
// so, because state.validate does not accept a bootstrapPending without
// a deadline at all, so zero means a broken record, not an open-ended
// one.
//
// Worse than the mismatch was a missed third case: for an EXPIRED token
// ClaimPending became false, and the card said "Already claimed" — that
// is, "someone has already become the admin of your gateway" — when in
// fact nobody had and the time had simply run out. This is the very
// defect yesterday's canary was written for: two different facts fused
// into one, and the screen picked the alarming reading.
func TestGuiGatewayStatus_TellsAnExpiredClaimFromASpentOne(t *testing.T) {
	cases := []struct {
		name        string
		expires     string
		wantPending bool
		wantExpired bool
	}{
		{"deadline in the future", time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339), true, false},
		{"deadline has passed", time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339), false, true},
		{"no deadline at all", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			env := gatewayTestEnv(dir)
			gwDir := gatewayDirWithHostKey(t, env)
			writeBootstrapPendingFixture(t, gwDir, c.expires)

			st, err := guiGatewayStatus(env, false)
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if st.ClaimPending != c.wantPending {
				t.Errorf("ClaimPending=%v but the command says \"still valid\"=%v for this deadline", st.ClaimPending, c.wantPending)
			}
			if st.ClaimExpired != c.wantExpired {
				t.Errorf("ClaimExpired=%v but the command says \"time is up\"=%v for this deadline", st.ClaimExpired, c.wantExpired)
			}
			if st.ClaimPending && st.ClaimExpired {
				t.Error("the same line is declared both still valid and expired")
			}
		})
	}
}

// And the case when there is no record at all: the line was spent (or
// never issued). Neither "still valid" nor "time is up" — and it is
// exactly this difference the card renders as "Already claimed".
func TestGuiGatewayStatus_SpentClaimIsNeitherPendingNorExpired(t *testing.T) {
	dir := t.TempDir()
	env := gatewayTestEnv(dir)
	gwDir := gatewayDirWithHostKey(t, env)
	// state.json without bootstrapPending — what a gateway whose line
	// has already been spent looks like.
	writeStateFixture(t, gwDir, `{"version":1}`)

	st, err := guiGatewayStatus(env, false)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.ClaimPending || st.ClaimExpired {
		t.Errorf("the spent line is called alive (pending=%v) or expired (expired=%v) — but it simply does not exist",
			st.ClaimPending, st.ClaimExpired)
	}
}

func gatewayDirWithHostKey(t *testing.T, env map[string]string) string {
	t.Helper()
	// The same resolution the screen itself uses (R2, 24.09.2026):
	// after the fix config.DirsFor points aside — to the platform
	// default (/var/lib/iamtunnel on POSIX — a real system path the test
	// must not touch).
	gwDir, derr := gatewayDirFromEnv(env)
	if derr != nil {
		t.Fatal(derr)
	}
	if err := os.MkdirAll(gwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrGenerateSigner(hostkeyPath(gwDir)); err != nil {
		t.Fatalf("host key: %v", err)
	}
	return gwDir
}

func writeBootstrapPendingFixture(t *testing.T, gwDir, expires string) {
	t.Helper()
	entry := `{}`
	if expires != "" {
		entry = `{"expires":"` + expires + `"}`
	}
	writeStateFixture(t, gwDir, `{"version":1,"bootstrapPending":`+entry+`}`)
}

func writeStateFixture(t *testing.T, gwDir, body string) {
	t.Helper()
	path := filepath.Join(gwDir, state.StateFileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
