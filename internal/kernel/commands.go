package kernel

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"aries.local/aries/internal/store"
)

type CommandField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

type CommandDefinition struct {
	Path       string         `json:"path"`
	Summary    string         `json:"summary"`
	Usage      string         `json:"usage"`
	Arguments  []CommandField `json:"arguments,omitempty"`
	Flags      []CommandField `json:"flags,omitempty"`
	Permission string         `json:"permission"`
	LocalOnly  bool           `json:"local_only,omitempty"`
	Examples   []string       `json:"examples,omitempty"`
}

type commandRequest struct {
	Argv  []string                   `json:"argv"`
	Flags map[string]json.RawMessage `json:"flags,omitempty"`
}

type commandResult struct {
	Status    string   `json:"status"`
	Summary   string   `json:"summary"`
	Data      any      `json:"data,omitempty"`
	Warnings  []string `json:"warnings"`
	RequestID string   `json:"request_id"`
}

type completionRequest struct {
	Words          []string `json:"words"`
	CursorPosition int      `json:"cursor_position"`
}
type completionCandidate struct {
	Value       string `json:"value"`
	Display     string `json:"display"`
	Description string `json:"description"`
}

var commandRegistry = []CommandDefinition{
	{Path: "status", Summary: "Show node health and listener status", Usage: "status", Permission: "admin:read"},
	{Path: "config show", Summary: "Show effective non-secret configuration", Usage: "config show", Permission: "admin:read"},
	{Path: "config validate", Summary: "Validate the effective configuration", Usage: "config validate", Permission: "admin:read"},
	{Path: "config set", Summary: "Set one supported configuration field", Usage: "config set --key <field> --value <typed-value>", Flags: []CommandField{{Name: "key", Type: "string", Required: true, Description: "Writable config field name"}, {Name: "value", Type: "typed-json", Required: true, Description: "Field value encoded as a JSON scalar"}}, Permission: "admin:write"},
	{Path: "token create", Summary: "Create a protected local admin token file", Usage: "token create --out <path> [--show]", Flags: []CommandField{{Name: "out", Type: "path", Required: true, Description: "Destination token file path", Sensitive: true}, {Name: "show", Type: "boolean", Required: false, Description: "Print generated token material locally"}}, Permission: "admin:local", LocalOnly: true},
	{Path: "token rotate", Summary: "Replace a protected local admin token file", Usage: "token rotate --out <path> [--show]", Flags: []CommandField{{Name: "out", Type: "path", Required: true, Description: "Destination token file path", Sensitive: true}, {Name: "show", Type: "boolean", Required: false, Description: "Print generated token material locally"}}, Permission: "admin:local", LocalOnly: true},
	{Path: "groups list", Summary: "List local authoritative groups", Usage: "groups list", Permission: "admin:read"},
	{Path: "groups inspect", Summary: "Inspect a group and its members", Usage: "groups inspect <group-id>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}}, Permission: "admin:read"},
	{Path: "members list", Summary: "List active members of a group", Usage: "members list <group-id>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}}, Permission: "admin:read"},
	{Path: "members revoke", Summary: "Revoke one device's membership and queue key rotation", Usage: "members revoke <group-id> <device-id>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}, {Name: "device-id", Type: "string", Required: true, Description: "Device identity to revoke"}}, Permission: "admin:group-write"},
	{Path: "members role", Summary: "Set a member role to admin or member", Usage: "members role <group-id> <device-id> --role <admin|member>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}, {Name: "device-id", Type: "string", Required: true, Description: "Active member identity"}}, Flags: []CommandField{{Name: "role", Type: "string", Required: true, Description: "admin or member"}}, Permission: "admin:group-write"},
	{Path: "invites list", Summary: "List invitation status without disclosing codes", Usage: "invites list <group-id>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}}, Permission: "admin:read"},
	{Path: "invites revoke", Summary: "Revoke one invitation", Usage: "invites revoke <group-id> <invite-code>", Arguments: []CommandField{{Name: "group-id", Type: "string", Required: true, Description: "Local group identifier"}, {Name: "invite-code", Type: "string", Required: true, Description: "Invitation code provided by the operator", Sensitive: true}}, Permission: "admin:group-write"},
	{Path: "storage status", Summary: "Show logical payload storage use and quota", Usage: "storage status", Permission: "admin:read"},
	{Path: "server shutdown", Summary: "Flush durable state and stop the server", Usage: "server shutdown", Permission: "admin:shutdown"},
	{Path: "help", Summary: "Show help for a registered command", Usage: "help [command...]", Permission: "admin:read"},
}

func (s *Server) registerCommandRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/commands", s.adminAuth(http.HandlerFunc(s.listCommands)))
	mux.Handle("GET /api/v1/admin/commands/help", s.adminAuth(http.HandlerFunc(s.commandHelp)))
	mux.Handle("POST /api/v1/admin/commands/complete", s.adminAuth(http.HandlerFunc(s.completeCommand)))
	mux.Handle("POST /api/v1/admin/commands/execute", s.adminAuth(http.HandlerFunc(s.executeCommand)))
}

func (s *Server) listCommands(w http.ResponseWriter, r *http.Request) {
	items := make([]CommandDefinition, len(commandRegistry))
	copy(items, commandRegistry)
	writeJSON(w, 200, map[string]any{"api_version": APIVersion, "items": items})
}

func (s *Server) commandHelp(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		path = "help"
	}
	for _, definition := range commandRegistry {
		if definition.Path == path {
			writeJSON(w, 200, map[string]any{"command": definition, "help": definition.Summary})
			return
		}
	}
	writeError(w, r, 404, "command_not_found", "no registered command matches the requested path")
}

func (s *Server) completeCommand(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	var req completionRequest
	if err = decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "completion request is invalid")
		return
	}
	if req.CursorPosition < 0 || req.CursorPosition > len(req.Words) {
		writeError(w, r, 400, "invalid_cursor", "cursor_position is outside the token list")
		return
	}
	words := append([]string(nil), req.Words[:req.CursorPosition]...)
	prefix := ""
	if req.CursorPosition < len(req.Words) {
		prefix = req.Words[req.CursorPosition]
	}
	candidates := s.commandCandidates(words, prefix)
	writeJSON(w, 200, map[string]any{"candidates": candidates})
}

func (s *Server) commandCandidates(words []string, prefix string) []completionCandidate {
	uniq := map[string]string{}
	add := func(value, description string) {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			uniq[value] = description
		}
	}
	if len(words) == 0 {
		for _, d := range commandRegistry {
			part := strings.Fields(d.Path)[0]
			add(part, "command")
		}
	}
	if len(words) == 1 {
		root := words[0]
		for _, d := range commandRegistry {
			parts := strings.Fields(d.Path)
			if len(parts) > 1 && parts[0] == root {
				add(parts[1], d.Summary)
			}
		}
	}
	if len(words) == 2 && words[0] == "config" {
		add("show", "Show non-secret configuration")
		add("set", "Set one field")
		add("validate", "Validate configuration")
	}
	if len(words) == 2 && words[0] == "token" {
		add("create", "Create and install a token")
		add("rotate", "Rotate the token")
	}
	if len(words) == 2 && words[0] == "groups" {
		add("list", "List groups")
		add("inspect", "Inspect one group")
	}
	if len(words) == 2 && words[0] == "members" {
		add("list", "List members")
		add("revoke", "Revoke membership")
		add("role", "Change a member role")
	}
	if len(words) == 2 && words[0] == "invites" {
		add("list", "List invitation status")
		add("revoke", "Revoke an invitation")
	}
	if len(words) == 2 && words[0] == "storage" {
		add("status", "Show storage status")
	}
	if len(words) == 2 && words[0] == "server" {
		add("shutdown", "Stop the server")
	}
	if len(words) == 2 && words[0] == "config" && words[1] == "set" {
		for _, name := range configFieldNames {
			add(name, "configuration field")
		}
	}
	if len(words) == 3 && (words[0] == "groups" && words[1] == "inspect" || words[0] == "members" || words[0] == "invites") {
		_ = s.store.View(func(st store.State) error {
			for id := range st.Groups {
				add(id, "group id")
			}
			return nil
		})
	}
	values := make([]completionCandidate, 0, len(uniq))
	for value, description := range uniq {
		values = append(values, completionCandidate{Value: value, Display: value, Description: description})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Value < values[j].Value })
	return values
}

var configFieldNames = []string{"public_listen", "admin_listen", "data_dir", "admin_token_file", "max_storage_bytes", "allow_insecure_loopback", "peer_relay_enabled", "file_storage_enabled", "group_quota_bytes", "quota_bytes_per_member", "max_file_bytes", "max_file_ttl_seconds", "heartbeat_interval_seconds", "heartbeat_timeout_seconds"}

// checkAdminIdempotency is called while commandMu is held. It returns ok=false
// after writing an error; replayed=true means the original response was sent.
func (s *Server) checkAdminIdempotency(w http.ResponseWriter, r *http.Request, operation string, body []byte) (key string, replayed, ok bool) {
	key = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(key) < 8 || len(key) > 128 {
		writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key must contain 8 to 128 characters")
		return "", false, false
	}
	var old store.Idempotent
	var exists bool
	err := s.store.View(func(st store.State) error {
		old, exists = st.Idempotency["admin-rest\x00"+operation+"\x00"+key]
		return nil
	})
	if err != nil {
		writeError(w, r, 500, "storage_unavailable", "state store unavailable")
		return "", false, false
	}
	if exists {
		if old.Fingerprint != fingerprint(operation, body) {
			writeError(w, r, 409, "idempotency_conflict", "Idempotency-Key was already used with a different request")
			return "", false, false
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(old.Status)
		_, _ = w.Write(append(old.Body, '\n'))
		return key, true, true
	}
	return key, false, true
}

func (s *Server) rememberAdminIdempotency(key, operation string, body []byte, status int, response []byte) error {
	return s.store.Update(func(st *store.State) error {
		st.Idempotency["admin-rest\x00"+operation+"\x00"+key] = store.Idempotent{Fingerprint: fingerprint(operation, body), Status: status, Body: append([]byte(nil), response...)}
		return nil
	})
}

func (s *Server) executeCommand(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	var req commandRequest
	if err = decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "command request must contain structured argv and flags")
		return
	}
	if len(req.Argv) == 0 || len(req.Argv) > 8 {
		writeError(w, r, 400, "invalid_argv", "argv must contain one to eight command/argument tokens")
		return
	}
	for _, part := range req.Argv {
		if strings.TrimSpace(part) == "" {
			writeError(w, r, 400, "invalid_argv", "argv tokens must be non-empty")
			return
		}
	}
	if commandIsLocalOnly(req.Argv) {
		writeError(w, r, http.StatusForbidden, "command_local_only", "this command is available only in a local management frontend")
		return
	}
	if durableCommand(req.Argv) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if len(key) < 8 || len(key) > 128 {
			writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key must contain 8 to 128 characters")
			return
		}
		s.commandMu.Lock()
		defer s.commandMu.Unlock()
		finger := fingerprint("admin.command.execute", body)
		var old store.Idempotent
		var exists bool
		if err := s.store.View(func(st store.State) error { old, exists = st.Idempotency["admin-command\x00"+key]; return nil }); err != nil {
			writeError(w, r, 500, "storage_unavailable", "state store unavailable")
			return
		}
		if exists {
			if old.Fingerprint != finger {
				writeError(w, r, 409, "idempotency_conflict", "Idempotency-Key was already used with a different request")
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(old.Status)
			_, _ = w.Write(append(old.Body, '\n'))
			return
		}
		result, dispatchErr := s.dispatchCommand(req, r.Header.Get("X-Request-ID"))
		if dispatchErr != nil {
			status, code, message := httpError(dispatchErr)
			writeError(w, r, status, code, message)
			return
		}
		response, err := json.Marshal(result)
		if err != nil {
			writeError(w, r, 500, "internal_error", "command result could not be encoded")
			return
		}
		if err = s.store.Update(func(st *store.State) error {
			st.Idempotency["admin-command\x00"+key] = store.Idempotent{Fingerprint: finger, Status: 200, Body: response}
			return nil
		}); err != nil {
			writeError(w, r, 500, "storage_unavailable", "command ran but idempotency result could not be committed")
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write(append(response, '\n'))
		if strings.Join(req.Argv, " ") == "server shutdown" {
			_ = s.store.Close()
			if s.shutdown != nil {
				go s.shutdown()
			}
		}
		return
	}
	result, apiErr := s.dispatchCommand(req, r.Header.Get("X-Request-ID"))
	if apiErr != nil {
		status, code, message := httpError(apiErr)
		writeError(w, r, status, code, message)
		return
	}
	writeJSON(w, 200, result)
}

func commandIsLocalOnly(argv []string) bool {
	path := strings.Join(argv[:min(2, len(argv))], " ")
	for _, definition := range commandRegistry {
		if definition.Path == path {
			return definition.LocalOnly
		}
	}
	return false
}

func durableCommand(argv []string) bool {
	path := strings.Join(argv[:min(2, len(argv))], " ")
	switch path {
	case "config set", "members revoke", "members role", "invites revoke", "server shutdown":
		return true
	}
	return false
}

func (s *Server) dispatchCommand(req commandRequest, requestID string) (commandResult, error) {
	argv := req.Argv
	path := strings.Join(argv[:min(2, len(argv))], " ")
	if argv[0] == "help" {
		path = "help"
	}
	flags := req.Flags
	if flags == nil {
		flags = map[string]json.RawMessage{}
	}
	noFlags := func() error {
		if len(flags) > 0 {
			return fail(400, "unknown_flag", "this command does not accept flags")
		}
		return nil
	}
	result := commandResult{Status: "ok", Warnings: []string{}, RequestID: requestID}
	switch path {
	case "status":
		if len(argv) != 1 {
			return result, fail(400, "invalid_arguments", "status takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		result.Summary = "Node status"
		result.Data = s.statusData()
	case "config show":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "config show takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		result.Summary = "Effective configuration"
		result.Data = s.configSnapshot()
	case "config validate":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "config validate takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		if err := s.configSnapshot().Validate(); err != nil {
			return result, fail(400, "invalid_config", err.Error())
		}
		result.Summary = "Configuration is valid"
		result.Data = map[string]any{"valid": true}
	case "config set":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "config set expects --key and --value flags")
		}
		key, err := requiredString(flags, "key")
		if err != nil {
			return result, err
		}
		raw, ok := flags["value"]
		if !ok {
			return result, fail(400, "missing_flag", "--value is required")
		}
		for name := range flags {
			if name != "key" && name != "value" {
				return result, fail(400, "unknown_flag", "unknown config set flag")
			}
		}
		oldConfig := s.configSnapshot()
		cfg := oldConfig
		if err = setConfigField(&cfg, key, raw); err != nil {
			return result, err
		}
		cfg = resolveConfigPaths(cfg, s.configPath)
		if err = s.persistConfig(cfg); err != nil {
			return result, fail(500, "config_write_failed", "could not persist configuration")
		}
		if restartRequired(oldConfig, cfg) {
			result.Warnings = append(result.Warnings, "listener, data directory, and token path changes require a process restart")
		}
		result.Summary = "Configuration updated"
		result.Data = map[string]any{"config": cfg, "restart_required": restartRequired(oldConfig, cfg)}
	case "groups list":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "groups list takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		result.Summary = "Local groups"
		result.Data = s.groupsData()
	case "groups inspect":
		if len(argv) != 3 {
			return result, fail(400, "invalid_arguments", "groups inspect requires a group id")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		data, err := s.groupData(argv[2])
		if err != nil {
			return result, err
		}
		result.Summary = "Group details"
		result.Data = data
	case "members list":
		if len(argv) != 3 {
			return result, fail(400, "invalid_arguments", "members list requires a group id")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		data, err := s.membersData(argv[2])
		if err != nil {
			return result, err
		}
		result.Summary = "Active group members"
		result.Data = data
	case "members revoke":
		if len(argv) != 4 {
			return result, fail(400, "invalid_arguments", "members revoke requires group id and device id")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		data, err := s.adminRevoke(argv[2], argv[3])
		if err != nil {
			return result, err
		}
		result.Summary = "Membership revoked and rotation queued"
		result.Data = data
	case "members role":
		if len(argv) != 4 {
			return result, fail(400, "invalid_arguments", "members role requires group id and device id")
		}
		role, err := requiredString(flags, "role")
		if err != nil {
			return result, err
		}
		for name := range flags {
			if name != "role" {
				return result, fail(400, "unknown_flag", "unknown members role flag")
			}
		}
		data, err := s.adminSetRole(argv[2], argv[3], role)
		if err != nil {
			return result, err
		}
		result.Summary = "Member role changed"
		result.Data = data
	case "invites list":
		if len(argv) != 3 {
			return result, fail(400, "invalid_arguments", "invites list requires a group id")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		data, err := s.invitesData(argv[2])
		if err != nil {
			return result, err
		}
		result.Summary = "Invitation status (codes redacted)"
		result.Data = data
	case "invites revoke":
		if len(argv) != 4 {
			return result, fail(400, "invalid_arguments", "invites revoke requires group id and invitation code")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		data, err := s.adminRevokeInvite(argv[2], argv[3])
		if err != nil {
			return result, err
		}
		result.Summary = "Invitation revoked"
		result.Data = data
	case "storage status":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "storage status takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		result.Summary = "Storage status"
		result.Data = s.storageData()
	case "server shutdown":
		if len(argv) != 2 {
			return result, fail(400, "invalid_arguments", "server shutdown takes no arguments")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		result.Status = "shutting_down"
		result.Summary = "Server shutdown scheduled"
		result.Data = map[string]any{"status": "shutting_down"}
	case "help":
		if len(argv) > 3 {
			return result, fail(400, "invalid_arguments", "help accepts at most a two-token command path")
		}
		if err := noFlags(); err != nil {
			return result, err
		}
		path := strings.Join(argv[1:], " ")
		if path == "" {
			path = "help"
		}
		for _, d := range commandRegistry {
			if d.Path == path {
				result.Summary = d.Summary
				result.Data = d
				return result, nil
			}
		}
		return result, fail(404, "command_not_found", "no registered command matches the requested path")
	default:
		return result, fail(400, "command_not_found", "command is not registered; query /commands for supported commands")
	}
	return result, nil
}

func requiredString(flags map[string]json.RawMessage, name string) (string, error) {
	raw, ok := flags[name]
	if !ok {
		return "", fail(400, "missing_flag", "required flag --"+name+" is missing")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
		return "", fail(400, "invalid_flag", "flag --"+name+" must be a non-empty string")
	}
	return value, nil
}

func setConfigField(c *Config, key string, raw json.RawMessage) error {
	switch key {
	case "public_listen", "admin_listen", "data_dir", "admin_token_file":
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fail(400, "invalid_flag", "value for "+key+" must be a string")
		}
		switch key {
		case "public_listen":
			c.PublicListen = v
		case "admin_listen":
			c.AdminListen = v
		case "data_dir":
			c.DataDir = v
		case "admin_token_file":
			c.AdminTokenFile = v
		}
	case "max_storage_bytes", "group_quota_bytes", "quota_bytes_per_member", "max_file_bytes", "max_file_ttl_seconds", "heartbeat_interval_seconds", "heartbeat_timeout_seconds":
		var v int64
		if err := json.Unmarshal(raw, &v); err != nil {
			return fail(400, "invalid_flag", key+" must be an integer")
		}
		switch key {
		case "max_storage_bytes":
			c.MaxStorageBytes = v
		case "group_quota_bytes":
			c.GroupQuotaBytes = v
		case "quota_bytes_per_member":
			c.QuotaBytesPerMember = v
		case "max_file_bytes":
			c.MaxFileBytes = v
		case "max_file_ttl_seconds":
			c.MaxFileTTLSeconds = v
		case "heartbeat_interval_seconds":
			c.HeartbeatIntervalSeconds = v
		case "heartbeat_timeout_seconds":
			c.HeartbeatTimeoutSeconds = v
		}
	case "file_storage_enabled":
		if err := json.Unmarshal(raw, &c.FileStorageEnabled); err != nil {
			return fail(400, "invalid_flag", "file_storage_enabled must be a boolean")
		}
	case "allow_insecure_loopback":
		if err := json.Unmarshal(raw, &c.AllowInsecureLoopback); err != nil {
			return fail(400, "invalid_flag", "allow_insecure_loopback must be a boolean")
		}
	case "peer_relay_enabled":
		if err := json.Unmarshal(raw, &c.PeerRelayEnabled); err != nil {
			return fail(400, "invalid_flag", "peer_relay_enabled must be a boolean")
		}
	default:
		return fail(400, "unknown_config_field", "configuration field is not writable")
	}
	if err := c.Validate(); err != nil {
		return fail(400, "invalid_config", err.Error())
	}
	return nil
}

func resolveConfigPaths(c Config, configPath string) Config {
	c.DataDir = resolveConfigPath(configPath, c.DataDir)
	c.AdminTokenFile = resolveConfigPath(configPath, c.AdminTokenFile)
	return c
}

func restartRequired(old, next Config) bool {
	return old.PublicListen != next.PublicListen || old.AdminListen != next.AdminListen || old.DataDir != next.DataDir || old.AdminTokenFile != next.AdminTokenFile
}

func configRestartResponse(c Config) map[string]any {
	return map[string]any{"schema_version": c.SchemaVersion, "public_listen": c.PublicListen, "admin_listen": c.AdminListen, "data_dir": c.DataDir, "admin_token_file": c.AdminTokenFile, "max_storage_bytes": c.MaxStorageBytes, "allow_insecure_loopback": c.AllowInsecureLoopback, "peer_relay_enabled": c.PeerRelayEnabled, "file_storage_enabled": c.FileStorageEnabled, "group_quota_bytes": c.GroupQuotaBytes, "quota_bytes_per_member": c.QuotaBytesPerMember, "max_file_bytes": c.MaxFileBytes, "max_file_ttl_seconds": c.MaxFileTTLSeconds, "heartbeat_interval_seconds": c.HeartbeatIntervalSeconds, "heartbeat_timeout_seconds": c.HeartbeatTimeoutSeconds, "restart_required": true}
}

func (s *Server) persistConfig(c Config) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if err := writeConfigAtomic(s.configPath, c); err != nil {
		return err
	}
	s.config = c
	return nil
}

func (s *Server) statusData() map[string]any {
	data := map[string]any{}
	_ = s.store.View(func(st store.State) error {
		pending := 0
		for _, g := range st.Groups {
			for _, e := range g.Events {
				if e.CompletedAt == "" {
					pending++
				}
			}
		}
		data = map[string]any{"api_version": APIVersion, "node_id": st.NodeID, "server_code": st.ServerCode, "uptime_seconds": int64(time.Since(s.startedAt).Seconds()), "started_at": s.startedAt.Format(time.RFC3339Nano), "public_listener": map[string]any{"address": s.publicAddr, "state": "listening"}, "admin_listener": map[string]any{"address": s.adminAddr, "state": "listening"}, "connected_devices": nil, "connected_devices_state": "not_supported", "pending_control_events": pending}
		return nil
	})
	peerState := "disabled"
	if s.configSnapshot().PeerRelayEnabled {
		peerState = "not_implemented"
	}
	data["storage_state"] = s.storageState()
	data["peer_relay_state"] = peerState
	return data
}

func (s *Server) storageState() string {
	if err := s.store.View(func(store.State) error { return nil }); err != nil {
		return "unavailable"
	}
	info, err := os.Stat(s.store.Path())
	if err != nil || !info.Mode().IsRegular() {
		return "degraded"
	}
	nonceInfo, err := os.Stat(s.store.Path() + ".nonces")
	if err != nil || !nonceInfo.Mode().IsRegular() {
		return "degraded"
	}
	root := s.fileRoot()
	if _, err := os.ReadDir(root); err != nil && !os.IsNotExist(err) {
		return "degraded"
	}
	return "available"
}

func (s *Server) groupsData() []map[string]any {
	items := []map[string]any{}
	_ = s.store.View(func(st store.State) error {
		for _, g := range st.Groups {
			count := 0
			for _, m := range g.Members {
				if m.Active {
					count++
				}
			}
			items = append(items, map[string]any{"id": g.ID, "name": g.Name, "authority_node": g.AuthorityNode, "member_count": count, "generation": g.Generation, "created_at": g.CreatedAt})
		}
		sort.Slice(items, func(i, j int) bool { return items[i]["id"].(string) < items[j]["id"].(string) })
		return nil
	})
	return items
}

func (s *Server) groupData(group string) (any, error) {
	var data any
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		members := []store.Member{}
		for _, m := range g.Members {
			if m.Active {
				members = append(members, m)
			}
		}
		sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
		data = map[string]any{"id": g.ID, "name": g.Name, "authority_node": g.AuthorityNode, "creator_id": g.CreatorID, "approval_policy": g.Policy, "generation": g.Generation, "members": members, "pending_control_events": pendingEvents(g)}
		return nil
	})
	return data, err
}
func (s *Server) membersData(group string) (any, error) {
	var members []store.Member
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		for _, m := range g.Members {
			if m.Active {
				members = append(members, m)
			}
		}
		sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
		return nil
	})
	return map[string]any{"items": members}, err
}
func pendingEvents(g store.Group) int {
	n := 0
	for _, e := range g.Events {
		if e.CompletedAt == "" {
			n++
		}
	}
	return n
}

func (s *Server) adminRevoke(group, device string) (any, error) {
	var result any
	err := s.store.Update(func(st *store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return fail(404, "member_not_found", "active member not found")
		}
		if device == g.CreatorID {
			return fail(409, "creator_transfer_required", "creator role must be transferred before revocation")
		}
		member.Active = false
		g.Members[device] = member
		removeApprovalSlot(st, group, device)
		event, err := queueMembershipEvent(&g, device, "member_revoked")
		if err != nil {
			return err
		}
		st.Groups[group] = g
		result = map[string]any{"group_id": group, "device_id": device, "status": "revoked", "control_event_id": event.ID, "required_generation": event.RequiredEpoch}
		return nil
	})
	return result, err
}
func (s *Server) adminSetRole(group, device, role string) (any, error) {
	if role != "admin" && role != "member" {
		return nil, fail(400, "invalid_role", "role must be admin or member")
	}
	var result any
	err := s.store.Update(func(st *store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return fail(404, "member_not_found", "active member not found")
		}
		if device == g.CreatorID {
			return fail(409, "creator_transfer_required", "creator role must be transferred separately")
		}
		member.Role = role
		g.Members[device] = member
		st.Groups[group] = g
		result = map[string]any{"group_id": group, "device_id": device, "role": role}
		return nil
	})
	return result, err
}
func (s *Server) invitesData(group string) (any, error) {
	items := []map[string]any{}
	err := s.store.View(func(st store.State) error {
		if _, ok := st.Groups[group]; !ok {
			return fail(404, "group_not_found", "group not found")
		}
		for _, inv := range st.Invites {
			if inv.GroupID == group {
				items = append(items, map[string]any{"code": "[redacted]", "creator_id": inv.CreatorID, "expires_at": inv.ExpiresAt, "revoked": inv.Revoked})
			}
		}
		return nil
	})
	return map[string]any{"items": items}, err
}
func (s *Server) adminRevokeInvite(group, code string) (any, error) {
	var result any
	err := s.store.Update(func(st *store.State) error {
		inv, ok := st.Invites[code]
		if !ok || inv.GroupID != group {
			return fail(404, "invite_not_found", "invite not found")
		}
		inv.Revoked = true
		st.Invites[code] = inv
		result = map[string]any{"group_id": group, "status": "revoked"}
		return nil
	})
	return result, err
}
func (s *Server) storageData() map[string]any {
	stats := s.fileStorageStats()
	config := s.configSnapshot()
	return map[string]any{"used_bytes": stats.UsedBytes, "blob_bytes": stats.BlobBytes, "quota_bytes": config.MaxStorageBytes, "file_count": stats.FileCount, "pending_uploads": stats.PendingUploads, "tombstone_count": stats.Tombstones, "evictions": stats.Evictions, "file_storage_enabled": config.FileStorageEnabled, "group_quota_bytes": config.GroupQuotaBytes, "quota_bytes_per_member": config.QuotaBytesPerMember, "state": s.storageState()}
}
