package main

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
)

// limitTestView provides the live, verified state needed to reach the ACL
// cap checks.  The limits themselves deliberately come from Load followed by
// gatewayRuntimeConfig, the same configuration assembly used by gateway run.
type limitTestView struct{}

func (limitTestView) PersonExists(string) bool    { return true }
func (limitTestView) MachineExists(string) bool   { return true }
func (limitTestView) MachineVerified(string) bool { return true }
func (limitTestView) MachineOnline(string) bool   { return true }

func loadedGatewaySettings(t *testing.T) config.Settings {
	t.Helper()
	// HOME is a synthetic POSIX path, not t.TempDir(). Load is asked to
	// resolve as goos="linux", so its absolute-path check is the POSIX one:
	// a Windows temp directory does not start with "/" and is rejected as
	// relative, which failed this test on the machine the suite actually
	// runs on. Nothing here touches the disk - readFile below always says
	// "no such file" - so no real directory is needed. This is the same
	// convention the rest of internal/config's tests use.
	settings, err := config.Load("linux", map[string]string{"HOME": "/h"}, config.Override{}, func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	})
	if err != nil {
		t.Fatalf("load production gateway settings: %v", err)
	}
	return settings
}

func newLimitEngine(t *testing.T) *acl.Engine {
	t.Helper()
	cfg := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), loadedGatewaySettings(t))
	e, err := acl.NewEngine(limitTestView{}, cfg.ACLLimits)
	if err != nil {
		t.Fatalf("new ACL engine from production gateway config: %v", err)
	}
	return e
}

func addLimitGrant(t *testing.T, e *acl.Engine, person, machine string, now time.Time) {
	t.Helper()
	if err := e.AddGrant(acl.Grant{Person: person, Machine: machine, Caps: []string{"shell"}}, now); err != nil {
		t.Fatalf("add grant %s -> %s: %v", person, machine, err)
	}
}

func expectLimitDeny(t *testing.T, err error, want acl.DenyReason) {
	t.Helper()
	var deny *acl.DenyError
	if !errors.As(err, &deny) || deny.Reason != want {
		t.Fatalf("session denial = %v, want %v", err, want)
	}
}

func TestIAMT145_ProductionConfigPersonSessionLimit(t *testing.T) {
	settings := loadedGatewaySettings(t)
	cfg := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), settings)
	if got := cfg.ACLLimits.PerPerson; got != 4 {
		t.Fatalf("production ACL person limit = %d, want 4", got)
	}

	e := newLimitEngine(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	addLimitGrant(t, e, "alice", "vm1", now)
	for i := 0; i < 4; i++ {
		if _, err := e.OpenSession("alice", "vm1", now, nil); err != nil {
			t.Fatalf("open person session %d: %v", i+1, err)
		}
	}
	_, err := e.OpenSession("alice", "vm1", now, nil)
	expectLimitDeny(t, err, acl.DenyPersonSessionLimit)
}

func TestIAMT145_ProductionConfigMachineSessionLimit(t *testing.T) {
	settings := loadedGatewaySettings(t)
	cfg := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), settings)
	if got := cfg.ACLLimits.PerMachine; got != 8 {
		t.Fatalf("production ACL machine limit = %d, want 8", got)
	}

	e := newLimitEngine(t)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 8; i++ {
		person := fmt.Sprintf("person-%d", i)
		addLimitGrant(t, e, person, "vm1", now)
		if _, err := e.OpenSession(person, "vm1", now, nil); err != nil {
			t.Fatalf("open machine session %d: %v", i+1, err)
		}
	}
	addLimitGrant(t, e, "person-over-limit", "vm1", now)
	_, err := e.OpenSession("person-over-limit", "vm1", now, nil)
	expectLimitDeny(t, err, acl.DenyMachineSessionLimit)
}

func TestIAMT353_RiskActionConfigurationReachesRuntime(t *testing.T) {
	settings, err := config.Load("linux", map[string]string{"HOME": "/h"}, config.Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_action":"block","external_risk_observation_enabled":true,"external_risk_observation_key_file":"/run/observer.key"}`), nil
	})
	if err != nil {
		t.Fatalf("load risk settings: %v", err)
	}
	runtime := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), settings)
	if got := string(runtime.RiskAction); got != "block" {
		t.Fatalf("gateway RuntimeConfig risk action = %q, want block", got)
	}
	if !runtime.ExternalRiskObservationEnabled || runtime.ExternalRiskObservationKeyFile != "/run/observer.key" {
		t.Fatalf("gateway RuntimeConfig observation settings = %+v, want enabled key file", runtime)
	}
}
