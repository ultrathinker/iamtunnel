package main

// IAMT-466, the command's half: "gateway run" hands the gateway the build
// it is, so gateway.status can say it, and "admin gateway status" prints
// what the gateway now says about itself - its version, its disk, and
// whether it is stopping.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestIAMT466_TheGatewayKnowsWhichBuildItIs(t *testing.T) {
	cfg := gatewayRuntimeConfig(nil, nil, nil, t.TempDir(), loadedGatewaySettings(t))
	if cfg.Version == "" || !strings.Contains(cfg.Version, version) {
		t.Fatalf("the runtime config carries version %q, want this build's (%q)", cfg.Version, version)
	}
	if gatewayDrainTimeout <= 0 || gatewayDrainTimeout > 20*time.Second {
		t.Errorf("the drain waits %s: it has to end before launchd's default 20 s ExitTimeOut kills the service", gatewayDrainTimeout)
	}
}

func TestIAMT466_AdminGatewayStatusPrintsVersionDiskAndDraining(t *testing.T) {
	used := 41
	var out bytes.Buffer
	s := &streams{out: &out, errs: &bytes.Buffer{}, env: map[string]string{}}
	printGatewayStatus(s, admin.GatewayStatusResult{Version: "1.14 (git abc)", DiskPercent: &used, Draining: true})
	got := out.String()
	for _, want := range []string{"version: 1.14 (git abc)", "disk: 41% used", "draining: the gateway is stopping"} {
		if !strings.Contains(got, want) {
			t.Errorf("admin gateway status does not print %q:\n%s", want, got)
		}
	}

	out.Reset()
	printGatewayStatus(s, admin.GatewayStatusResult{DiskError: "statfs: no such file"})
	if got := out.String(); !strings.Contains(got, "disk: could not be read: statfs: no such file") || strings.Contains(got, "draining:") {
		t.Errorf("a gateway not stopping, with an unreadable disk, prints:\n%s", got)
	}
}
