package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// gatewayStatusServicePort is a read-only seam. The platform files wire it
// to the installed service declaration; tests can replace it without
// touching systemd, launchd or the Windows SCM.
var gatewayStatusServicePort = runningGatewayServicePort

// statusPortForRunningService prefers the port the running service was
// installed with. A manually started gateway has no service declaration, so
// status keeps the already-resolved config port when that read is unavailable.
func statusPortForRunningService(configPort int, explicit bool) int {
	if explicit {
		return configPort
	}
	if servicePort, err := gatewayStatusServicePort(); err == nil && servicePort > 0 {
		return servicePort
	}
	return configPort
}

// parseGatewayServicePort finds the port in a service command line. Service
// managers use both --port N and --port=N; the rest of the command line is
// deliberately opaque because the status path only needs this one value.
func parseGatewayServicePort(command string) (int, error) {
	fields := strings.Fields(command)
	for i, field := range fields {
		arg := strings.Trim(field, `"'`)
		if arg == "--port" {
			if i+1 >= len(fields) {
				return 0, fmt.Errorf("service command has --port without a value")
			}
			value := strings.Trim(fields[i+1], `"'`)
			return config.ParsePort(value, 1024)
		}
		if strings.HasPrefix(arg, "--port=") {
			return config.ParsePort(strings.TrimPrefix(arg, "--port="), 1024)
		}
	}
	return 0, fmt.Errorf("service command has no --port")
}

var gatewayPlistPortPattern = regexp.MustCompile(`(?s)<string>\s*--port\s*</string>\s*<string>\s*([^<]+?)\s*</string>`)

func parseGatewayPlistPort(plist string) (int, error) {
	m := gatewayPlistPortPattern.FindStringSubmatch(plist)
	if len(m) != 2 {
		return 0, fmt.Errorf("LaunchDaemon plist has no --port argument")
	}
	return config.ParsePort(strings.TrimSpace(m[1]), 1024)
}
