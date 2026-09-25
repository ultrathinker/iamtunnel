// Package config is paths and settings shared by every role:
// %LOCALAPPDATA%\iamtunnel on the client, /var/lib/iamtunnel on the
// gateway, the default port 2222, and connection-string / enrol-code
// parsing with pinned fingerprints (SPEC §3.1, §3.4, §3.5). No role
// behavior and no secrets beyond what parsing requires.
package config
