package config

// r4cx_n06_role_dir_alias_test.go — R4 review N-06.
//
// IAMT-435 refused server_dir == gateway_dir as strings: the same
// directory written two ways - Windows letter case, a trailing separator,
// a "." or ".." segment - passed, and the two roles' journals met in one
// events.jsonl after all. The comparison is now on the cleaned path, and
// case-insensitive for Windows paths (case-sensitive for POSIX ones).

import "testing"

func TestR4CXN06_TheSameDirectoryWrittenTwoWaysIsStillOneDirectory(t *testing.T) {
	for _, tc := range []struct{ goos, server, gateway string }{
		{"windows", `C:\Data\Role`, `c:\data\role\`},
		{"windows", `C:\Data\Role`, `C:/Data/Role`},
		// R4 review N-11: a relative Windows path written with "/" only.
		{"windows", "Data/Role", "data/role"},
		{"linux", "/srv/iamt/./data", "/srv/iamt/data"},
		{"linux", "/srv/iamt/x/../data", "/srv/iamt/data/"},
	} {
		s := Defaults()
		s.ClientDir, s.ServerDir, s.GatewayDir = "/c", tc.server, tc.gateway
		if err := validateFor(tc.goos, s, false, false, false); err == nil {
			t.Fatalf("R4 review N-06/N-11: on %s server_dir %q and gateway_dir %q name one directory and were accepted", tc.goos, tc.server, tc.gateway)
		}
	}
	for _, tc := range []struct{ goos, server, gateway string }{
		{"linux", "/srv/Role", "/srv/role"},
		{"darwin", `a\Role`, `a\role`},
	} {
		s := Defaults()
		s.ClientDir, s.ServerDir, s.GatewayDir = "/c", tc.server, tc.gateway
		if err := validateFor(tc.goos, s, false, false, false); err != nil {
			t.Fatalf("on %s names are case-sensitive: %q and %q are two directories: %v", tc.goos, tc.server, tc.gateway, err)
		}
	}
}
