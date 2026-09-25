package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
)

// Settings are the effective configuration after merging every source.
// The port is the gateway SSH port (SPEC §3.5: default 2222, flag
// --port, config file). The recording values are the SPEC §12 decisions
// (90 days, 85 % disk threshold).
type Settings struct {
	Port                           int
	PublicHost                     string
	ClientDir                      string
	ServerDir                      string
	GatewayDir                     string
	RecordingsRetentionDays        int
	RecordingsDiskStopPercent      int
	MaxSessionsPerPerson           int
	MaxSessionsPerMachine          int
	RiskAction                     string
	RiskClassifier                 string
	ExternalRiskObservationEnabled bool
	ExternalRiskObservationKeyFile string
	RecentCommandsMax              int
	RecentCommandsBudget           int
	riskClassifierExplicit         bool
}

// Defaults returns the built-in layer of the configuration.
func Defaults() Settings {
	return Settings{
		Port:                      2222,
		RecordingsRetentionDays:   90,
		RecordingsDiskStopPercent: 85,
		MaxSessionsPerPerson:      4,
		MaxSessionsPerMachine:     8,
		RiskAction:                "warn",
		RiskClassifier:            "rules",
		RecentCommandsMax:         10,
		RecentCommandsBudget:      2000,
	}
}

// Partial is one configuration layer: only the keys it sets. The config
// file decodes into it; environment variables and flags produce it.
type Partial struct {
	Port                           *int    `json:"port"`
	PublicHost                     *string `json:"public_host"`
	ClientDir                      *string `json:"client_dir"`
	ServerDir                      *string `json:"server_dir"`
	GatewayDir                     *string `json:"gateway_dir"`
	RecordingsRetentionDays        *int    `json:"recordings_retention_days"`
	RecordingsDiskStopPercent      *int    `json:"recordings_disk_stop_percent"`
	MaxSessionsPerPerson           *int    `json:"max_sessions_per_person"`
	MaxSessionsPerMachine          *int    `json:"max_sessions_per_machine"`
	RiskAction                     *string `json:"risk_action"`
	RiskClassifier                 *string `json:"risk_classifier"`
	ExternalRiskObservationEnabled *bool   `json:"external_risk_observation_enabled"`
	ExternalRiskObservationKeyFile *string `json:"external_risk_observation_key_file"`
	RecentCommandsMax              *int    `json:"recent_commands_max"`
	RecentCommandsBudget           *int    `json:"recent_commands_budget"`
}

func (p Partial) apply(s *Settings) {
	if p.Port != nil {
		s.Port = *p.Port
	}
	if p.PublicHost != nil {
		s.PublicHost = *p.PublicHost
	}
	if p.ClientDir != nil {
		s.ClientDir = *p.ClientDir
	}
	if p.ServerDir != nil {
		s.ServerDir = *p.ServerDir
	}
	if p.GatewayDir != nil {
		s.GatewayDir = *p.GatewayDir
	}
	if p.RecordingsRetentionDays != nil {
		s.RecordingsRetentionDays = *p.RecordingsRetentionDays
	}
	if p.RecordingsDiskStopPercent != nil {
		s.RecordingsDiskStopPercent = *p.RecordingsDiskStopPercent
	}
	if p.MaxSessionsPerPerson != nil {
		s.MaxSessionsPerPerson = *p.MaxSessionsPerPerson
	}
	if p.MaxSessionsPerMachine != nil {
		s.MaxSessionsPerMachine = *p.MaxSessionsPerMachine
	}
	if p.RiskAction != nil {
		s.RiskAction = *p.RiskAction
	}
	if p.RiskClassifier != nil {
		s.RiskClassifier = *p.RiskClassifier
		s.riskClassifierExplicit = true
	}
	if p.ExternalRiskObservationEnabled != nil {
		s.ExternalRiskObservationEnabled = *p.ExternalRiskObservationEnabled
	}
	if p.ExternalRiskObservationKeyFile != nil {
		s.ExternalRiskObservationKeyFile = *p.ExternalRiskObservationKeyFile
	}
	if p.RecentCommandsMax != nil {
		s.RecentCommandsMax = *p.RecentCommandsMax
	}
	if p.RecentCommandsBudget != nil {
		s.RecentCommandsBudget = *p.RecentCommandsBudget
	}
}

// configKeys is the exact set of JSON keys the config file may carry;
// anything else is a typo and must be named, not ignored.
var configKeys = []string{
	"port", "public_host", "client_dir", "server_dir", "gateway_dir",
	"recordings_retention_days", "recordings_disk_stop_percent",
	"max_sessions_per_person", "max_sessions_per_machine",
	"risk_action", "risk_classifier", "external_risk_observation_enabled", "external_risk_observation_key_file",
	"recent_commands_max", "recent_commands_budget",
}

// ParseFile decodes the config file strictly: unknown keys and wrong
// types are errors, a whitespace-only file means "no settings".
func ParseFile(data []byte) (Partial, error) {
	var p Partial
	if len(bytes.TrimSpace(data)) == 0 {
		return p, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "unknown field "); i >= 0 {
			return p, envErrorf("config file: %s — allowed keys are: %s",
				strings.TrimPrefix(msg[i:], "json: "),
				strings.Join(configKeys, ", "))
		}
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return p, envErrorf("config file: key %q must be %s, not %q",
				typeErr.Field, jsonKindName(typeErr.Type.String()), msg)
		}
		return p, envErrorf("config file does not parse as one JSON object: %v — fix or remove the file, or point --config/IAMTUNNEL_CONFIG at a good one", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return p, envErrorf("config file must contain exactly one JSON object — remove any trailing text")
	}
	return p, nil
}

func jsonKindName(goType string) string {
	switch goType {
	case "int":
		return "a whole number"
	case "string":
		return "a string"
	default:
		return goType
	}
}

// EnvOverride reads the environment layer: IAMTUNNEL_CONFIG,
// IAMTUNNEL_DATA_DIR and IAMTUNNEL_PORT.
func EnvOverride(env map[string]string) (Override, error) {
	var o Override
	o.ConfigPath = env["IAMTUNNEL_CONFIG"]
	o.DataDir = env["IAMTUNNEL_DATA_DIR"]
	if v := env["IAMTUNNEL_PORT"]; v != "" {
		p, err := ParsePort(v, 1)
		if err != nil {
			return o, userErrorf("environment IAMTUNNEL_PORT=%q is not a valid port number from 1 to 65535 — fix or remove the variable", v)
		}
		o.Port = &p
	}
	return o, nil
}

// Override is the strongest configuration layer (environment merged with
// command-line flags; the flag of a kind always beats its variable).
type Override struct {
	Port       *int
	DataDir    string // applies to the role being run
	ConfigPath string // path of the config file itself
}

// Load builds the effective configuration. Precedence — one rule for
// every key, strongest last applied:
//
//	built-in defaults < config file < environment < command-line flags.
//
// goos and env are injected so the function is pure and testable;
// readFile is normally os.ReadFile. A missing config file is fine unless
// the caller named the path explicitly (--config / IAMTUNNEL_CONFIG) —
// then it is an error, not a silent fallback.
func Load(goos string, env map[string]string, flags Override, readFile func(string) ([]byte, error)) (Settings, error) {
	dirs, err := DirsFor(goos, env)
	if err != nil {
		return Settings{}, err
	}
	s := Defaults()
	s.ClientDir, s.ServerDir, s.GatewayDir = dirs.Client, dirs.Server, dirs.Gateway

	envOv, err := EnvOverride(env)
	if err != nil {
		return s, err
	}

	// Which file to read: flag > IAMTUNNEL_CONFIG > platform default.
	path := dirs.ConfigFile
	explicit := false
	switch {
	case flags.ConfigPath != "":
		path, explicit = flags.ConfigPath, true
	case envOv.ConfigPath != "":
		path, explicit = envOv.ConfigPath, true
	}

	// Without a machine default, there is no default config-file location
	// either. An explicit config path still works; otherwise its absent layer
	// is equivalent to the usual missing default file.
	if path != "" {
		data, err := readFile(path)
		switch {
		case err == nil:
			file, perr := ParseFile(data)
			if perr != nil {
				return s, envErrorf("%s: %v", path, perr)
			}
			file.apply(&s)
		case errors.Is(err, os.ErrNotExist) && !explicit:
			// No file layer — defaults stand.
		case errors.Is(err, os.ErrNotExist):
			return s, userErrorf("config file %s does not exist — create it or stop naming it with --config/IAMTUNNEL_CONFIG", path)
		case os.IsPermission(err):
			return s, deniedErrorf("config file %s cannot be read: %v — fix the file permissions or point --config/IAMTUNNEL_CONFIG at a readable file", path, err)
		default:
			return s, envErrorf("config file %s cannot be read: %v", path, err)
		}
	}

	envOv.applySettings(&s)
	flags.applySettings(&s)
	// Keep the old opt-in meaningful for configurations that have not yet
	// selected a classifier source. An explicit risk_classifier always wins.
	if !s.riskClassifierExplicit && s.ExternalRiskObservationEnabled {
		s.RiskClassifier = "both"
	}

	if err := validateFor(goos, s, dirs.machineErr != nil, dirs.clientErr != nil, dirs.serverErr != nil); err != nil {
		return s, err
	}
	return s, nil
}

func (o Override) applySettings(s *Settings) {
	if o.Port != nil {
		s.Port = *o.Port
	}
	// o.DataDir is role-scoped: the role runner replaces its own
	// directory with it, so it is deliberately not merged here.
}

// validate checks the merged settings. Values that a stronger source
// overrode never reach here, so only the surviving ones must be sane.
func validate(s Settings, allowMissingGatewayDir, allowMissingClientDir, allowMissingServerDir bool) error {
	return validateFor("", s, allowMissingGatewayDir, allowMissingClientDir, allowMissingServerDir)
}

// validateFor is validate for the platform Load resolved: it decides how two
// role directories are compared (R4 review N-11). "" means this host's.
func validateFor(goos string, s Settings, allowMissingGatewayDir, allowMissingClientDir, allowMissingServerDir bool) error {
	// The port is the gateway's listen port; SPEC §3.5 runs the systemd
	// unit without extra capabilities, so ports below 1024 are rejected.
	if s.Port < 1024 || s.Port > 65535 {
		return userErrorf("gateway port %d is out of range 1024..65535 (SPEC §3.5 runs the gateway without extra capabilities) — fix --port, IAMTUNNEL_PORT or the config file", s.Port)
	}
	// public_host is optional at the settings layer (gateway install
	// requires it as a flag, but gateway run can take it from the config
	// file or the flag). When present, it must satisfy the §3.1 host
	// grammar — same rule that parses it back in connection strings.
	if s.PublicHost != "" && !ValidHost(s.PublicHost) {
		return userErrorf("public_host %q is not a valid hostname or IP address (SPEC §3.1 host grammar) — fix the config file or --public-host", s.PublicHost)
	}
	// IAMT-310, widened in 1.4: each role directory is exempt exactly
	// when the environment could not supply ITS variable. A launchd or
	// systemd gateway is never given $HOME and never asks for a per-user
	// directory, so an unresolved ClientDir or ServerDir must not fail a
	// run that never needed either; equally, a client-only run with no
	// %ProgramData% must not fail over the gateway directory (IAMT-159).
	//
	// The three are separate because the roles are: since 1.4 the server
	// directory is per-user like the client's, while the gateway's stays
	// machine-wide, and one missing variable must not refuse a role that
	// does not read it.
	if (!allowMissingClientDir && s.ClientDir == "") ||
		(!allowMissingServerDir && s.ServerDir == "") ||
		(!allowMissingGatewayDir && s.GatewayDir == "") {
		return userErrorf("a role data directory resolved to an empty string — check --data-dir/IAMTUNNEL_DATA_DIR and the client_dir/server_dir/gateway_dir config keys")
	}
	// IAMT-435: the machine (server) role and the gateway role sharing one
	// directory is not a layout preference — each appends to events.jsonl
	// there (Dirs.ServerEvents and Dirs.GatewayEvents) in its own format,
	// so the second role to write corrupts the first one's audit journal.
	// The platform defaults can never collide (the server directory is
	// per-user since 1.4, the gateway's is machine-wide); only explicit
	// config keys can name one directory for both, and that is refused
	// here rather than left to interleave two journals at runtime. An
	// unresolved (allowed-missing) directory is "", and "" is not a
	// collision — nothing is shared because neither role has a directory.
	if s.ServerDir != "" && sameRoleDir(goos, s.ServerDir, s.GatewayDir) {
		return userErrorf("server_dir and gateway_dir both name %q — the machine role and the gateway role would append their two different events.jsonl journals into one file and corrupt each other's audit trail — give the roles different directories in the config file", s.ServerDir)
	}
	if s.RecordingsRetentionDays < 1 || s.RecordingsRetentionDays > 36500 {
		return userErrorf("recordings_retention_days %d is out of range 1..36500 — fix the config file", s.RecordingsRetentionDays)
	}
	if s.RecordingsDiskStopPercent < 1 || s.RecordingsDiskStopPercent > 99 {
		return userErrorf("recordings_disk_stop_percent %d is out of range 1..99 — fix the config file", s.RecordingsDiskStopPercent)
	}
	if s.MaxSessionsPerPerson < 1 {
		return userErrorf("max_sessions_per_person %d must be at least 1 — fix the config file", s.MaxSessionsPerPerson)
	}
	if s.MaxSessionsPerMachine < 1 {
		return userErrorf("max_sessions_per_machine %d must be at least 1 — fix the config file", s.MaxSessionsPerMachine)
	}
	if s.RiskAction != "" && s.RiskAction != "log" && s.RiskAction != "warn" && s.RiskAction != "ask" && s.RiskAction != "block" {
		return userErrorf("risk_action %q must be log, warn, ask or block — fix the config file", s.RiskAction)
	}
	switch s.RiskClassifier {
	case "rules":
	case "ai", "both":
		if strings.TrimSpace(s.ExternalRiskObservationKeyFile) == "" {
			return userErrorf("external_risk_observation_key_file is required when risk_classifier is %q — set it to a readable API-key file", s.RiskClassifier)
		}
	default:
		return userErrorf("risk_classifier %q must be rules, ai or both — fix the config file", s.RiskClassifier)
	}
	if s.RecentCommandsMax < 1 || s.RecentCommandsMax > 20 {
		return userErrorf("recent_commands_max %d is out of range 1..20 — fix the config file", s.RecentCommandsMax)
	}
	if s.RecentCommandsBudget < 1 || s.RecentCommandsBudget > 100000 {
		return userErrorf("recent_commands_budget %d is out of range 1..100000 — fix the config file", s.RecentCommandsBudget)
	}
	return nil
}

// RoleDir returns the effective data directory of one role — "client",
// "server", "gateway", or "enrol" (an alias for "server": the enrol step
// writes into the machine's server-role directory, same as
// config.Dirs.RoleDirE) — after Load has merged defaults, the config
// file's client_dir/server_dir/gateway_dir keys, and IAMTUNNEL_PORT/flag
// overrides for the fields Load merges itself. An unknown role, or a
// role Load could not resolve a platform default for (IAMT-159: no
// absolute %ProgramData% and no config-file override), returns "" —
// callers that need a directory always got a hard error out of Load or
// out of their own flag/IAMTUNNEL_DATA_DIR handling before reaching here
// (IAMT-201).
func (s Settings) RoleDir(role string) string {
	switch role {
	case "client":
		return s.ClientDir
	case "server", "enrol":
		return s.ServerDir
	case "gateway":
		return s.GatewayDir
	default:
		return ""
	}
}

// FormatConfigHelp returns the platform-resolved path lines used by
// "iamtunnel help config".
func FormatConfigHelp(goos string, env map[string]string) string {
	d, err := DirsFor(goos, env)
	if err != nil {
		return fmt.Sprintf("  (cannot determine paths: %v)\n", err)
	}
	// IAMT-310: Client can be deferred (clientErr) even when Server and
	// Gateway resolved fine — show the reason instead of a blank path.
	client := d.Client
	if client == "" {
		if _, cerr := d.RoleDirE("client"); cerr != nil {
			client = fmt.Sprintf("(cannot determine: %v)", cerr)
		}
	}
	return fmt.Sprintf("  config file   %s\n  client data   %s\n  server data   %s\n  gateway data  %s\n",
		d.ConfigFile, client, d.Server, d.Gateway)
}

// sameRoleDir reports whether two role directories name one directory as
// written (R4 review N-06): the text compared after cleaning, so a trailing
// separator, "." and ".." segments do not make one directory two - and on
// Windows (the platform Load resolved for, not the look of the string:
// R4 review N-11) neither do the letter case and the separator style. On
// other platforms names are case-sensitive and a backslash is a character.
// Two names that reach one directory through a link are a filesystem fact
// this check, which reads no disk, cannot see.
func sameRoleDir(goos, a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return roleDirKey(goos, a) == roleDirKey(goos, b)
}

func roleDirKey(goos, dir string) string {
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos == "windows" {
		dir = strings.ToLower(strings.ReplaceAll(dir, `\`, "/"))
	}
	return path.Clean(dir)
}
