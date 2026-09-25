package main

import "testing"

// TestCanary_B8_StatusUsesRunningServicePort is a security/reliability
// canary: a live service's declared port must win over the config default.
func TestCanary_B8_StatusUsesRunningServicePort(t *testing.T) {
	old := gatewayStatusServicePort
	t.Cleanup(func() { gatewayStatusServicePort = old })
	gatewayStatusServicePort = func() (int, error) { return 2444, nil }

	if got := statusPortForRunningService(2222, false); got != 2444 {
		t.Fatalf("running service port = %d, want 2444", got)
	}
	if got := statusPortForRunningService(2222, true); got != 2222 {
		t.Fatalf("explicit status port = %d, want 2222", got)
	}
}

func TestCanary_B8_ServicePortParsers(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want int
	}{
		{name: "systemd", text: `ExecStart=/usr/local/bin/iamtunnel gateway run --port 2444 --public-host gw.example`, want: 2444},
		{name: "windows", text: `"C:\\Program Files\\iamtunnel.exe" gateway run --port=2555 --public-host gw.example`, want: 2555},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGatewayServicePort(tc.text)
			if err != nil || got != tc.want {
				t.Fatalf("parseGatewayServicePort(%q) = %d, %v; want %d", tc.text, got, err, tc.want)
			}
		})
	}
	plist := `<key>ProgramArguments</key><array><string>iamtunnel</string><string>--port</string><string>2666</string></array>`
	if got, err := parseGatewayPlistPort(plist); err != nil || got != 2666 {
		t.Fatalf("parseGatewayPlistPort = %d, %v; want 2666", got, err)
	}
}
