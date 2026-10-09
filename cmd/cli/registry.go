package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"aries.local/aries/internal/client"
)

const metadataVersion = 1

var metadataName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
var secretLike = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)
var pathLike = regexp.MustCompile(`(?i)([a-z]:\\|\\\\[^\\/ ]+|/(?:[^ /]+/)+[^ ]*)`)

// Builtin command metadata provides useful local help and offline completion.
// Server-owned handlers remain authoritative for all remote operations.
var builtinRegistry = client.Registry{APIVersion: "v1", Items: []client.CommandDefinition{
	{Path: "status", Summary: "Show node health and listener status", Usage: "status", Permission: "admin:read"},
	{Path: "config show", Summary: "Show effective non-secret configuration", Usage: "config show", Permission: "admin:read"},
	{Path: "config validate", Summary: "Validate the effective configuration", Usage: "config validate", Permission: "admin:read"},
	{Path: "config set", Summary: "Set one supported configuration field", Usage: "config set --key <field> --value <typed-value>", Flags: []client.CommandField{{Name: "key", Type: "string", Required: true, Description: "Writable config field name"}, {Name: "value", Type: "typed-json", Required: true, Description: "Field value encoded as a JSON scalar"}}, Permission: "admin:write"},
	{Path: "token create", Summary: "Create a protected local admin token file", Usage: "token create --out <path> [--show]", Flags: []client.CommandField{{Name: "out", Type: "path", Required: true, Description: "Destination token file path", Sensitive: true}, {Name: "show", Type: "boolean", Description: "Print the token once locally"}}, LocalOnly: true},
	{Path: "token rotate", Summary: "Replace a protected local admin token file", Usage: "token rotate --out <path> [--show]", Flags: []client.CommandField{{Name: "out", Type: "path", Required: true, Description: "Destination token file path", Sensitive: true}, {Name: "show", Type: "boolean", Description: "Print the token once locally"}}, LocalOnly: true},
	{Path: "groups list", Summary: "List local authoritative groups", Usage: "groups list", Permission: "admin:read"},
	{Path: "groups inspect", Summary: "Inspect a group and its members", Usage: "groups inspect <group-id>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}}, Permission: "admin:read"},
	{Path: "members list", Summary: "List active members of a group", Usage: "members list <group-id>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}}, Permission: "admin:read"},
	{Path: "members revoke", Summary: "Revoke one device membership and queue key rotation", Usage: "members revoke <group-id> <device-id>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}, {Name: "device-id", Type: "string", Required: true}}, Permission: "admin:group-write"},
	{Path: "members role", Summary: "Set a member role", Usage: "members role <group-id> <device-id> --role <admin|member>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}, {Name: "device-id", Type: "string", Required: true}}, Flags: []client.CommandField{{Name: "role", Type: "string", Required: true}}, Permission: "admin:group-write"},
	{Path: "invites list", Summary: "List invitation status without disclosing codes", Usage: "invites list <group-id>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}}, Permission: "admin:read"},
	{Path: "invites revoke", Summary: "Revoke an invitation", Usage: "invites revoke <group-id> <invite-code>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}, {Name: "invite-code", Type: "string", Required: true, Sensitive: true}}, Permission: "admin:group-write"},
	{Path: "storage status", Summary: "Show storage use and quota", Usage: "storage status", Permission: "admin:read"},
	{Path: "server shutdown", Summary: "Flush durable state and stop the server", Usage: "server shutdown", Permission: "admin:shutdown"},
	{Path: "help", Summary: "Show help for a registered command", Usage: "help [command...]"},
}}

type cachedRegistry struct {
	Version  int             `json:"metadata_version"`
	Registry client.Registry `json:"registry"`
	SavedAt  time.Time       `json:"saved_at"`
}

func defaultCachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return filepath.Join(os.TempDir(), "ariesctl", "commands.json")
	}
	return filepath.Join(dir, "Aries", "commands.json")
}

func loadRegistry(o options, allowOffline bool, stderr io.Writer) (client.Registry, error) {
	if o.endpoint != "" && o.token != "" {
		api, err := connect(o)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
			registry, fetchErr := api.Commands(ctx)
			cancel()
			if fetchErr == nil && validRegistry(registry) {
				registry = withLocalCommands(sanitizeRegistry(registry))
				_ = saveRegistry(o.cache, registry)
				return registry, nil
			}
			if !allowOffline {
				if fetchErr != nil {
					return client.Registry{}, fetchErr
				}
				return client.Registry{}, errors.New("server returned invalid command metadata")
			}
			if fetchErr != nil {
				fmt.Fprintf(stderr, "warning: command registry unavailable; using safe offline metadata: %v\n", fetchErr)
			}
		} else if !allowOffline {
			return client.Registry{}, err
		}
	} else if !allowOffline {
		return client.Registry{}, usageError("--endpoint and --token-file are required")
	}
	if registry, ok := readRegistry(o.cache); ok {
		return withLocalCommands(registry), nil
	}
	return cloneRegistry(builtinRegistry), nil
}

func validRegistry(r client.Registry) bool {
	if r.APIVersion == "" || len(r.Items) == 0 || len(r.Items) > 256 {
		return false
	}
	for _, d := range r.Items {
		parts := strings.Fields(d.Path)
		if len(parts) == 0 || len(parts) > 3 {
			return false
		}
		for _, part := range parts {
			if !metadataName.MatchString(part) {
				return false
			}
		}
		for _, f := range append(append([]client.CommandField{}, d.Arguments...), d.Flags...) {
			if !metadataName.MatchString(f.Name) || len(f.Description) > 1024 {
				return false
			}
		}
	}
	return true
}

func sanitizeRegistry(r client.Registry) client.Registry {
	r = cloneRegistry(r)
	for i := range r.Items {
		d := &r.Items[i]
		d.Examples = nil
		for j := range d.Arguments {
			if d.Arguments[j].Sensitive {
				d.Arguments[j].Description = "sensitive value"
			} else {
				d.Arguments[j].Description = safeMetadataText(d.Arguments[j].Description)
			}
		}
		for j := range d.Flags {
			if d.Flags[j].Sensitive {
				d.Flags[j].Description = "sensitive value"
			} else {
				d.Flags[j].Description = safeMetadataText(d.Flags[j].Description)
			}
		}
		d.Summary = safeMetadataText(d.Summary)
		d.Usage = safeMetadataText(d.Usage)
		d.Examples = nil
	}
	return r
}

func safeMetadataText(s string) string {
	if len(s) > 512 || secretLike.MatchString(s) || pathLike.MatchString(s) {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return -1
		}
		return r
	}, s)
}

func withLocalCommands(r client.Registry) client.Registry {
	for _, local := range builtinRegistry.Items {
		if local.Path == "token create" || local.Path == "token rotate" {
			replaced := false
			for i := range r.Items {
				if r.Items[i].Path == local.Path {
					r.Items[i] = local
					replaced = true
				}
			}
			if !replaced {
				r.Items = append(r.Items, local)
			}
		}
	}
	return r
}

func cloneRegistry(r client.Registry) client.Registry {
	b, _ := json.Marshal(r)
	var clone client.Registry
	_ = json.Unmarshal(b, &clone)
	return clone
}

func saveRegistry(path string, r client.Registry) error {
	if path == "" {
		return errors.New("cache path is empty")
	}
	data, err := json.MarshalIndent(cachedRegistry{metadataVersion, sanitizeRegistry(r), time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0600)
}

func atomicWriteFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace a symlink")
	}
	f, err := os.CreateTemp(dir, ".aries-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = client.RestrictFile(tmp)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readRegistry(path string) (client.Registry, bool) {
	var cache cachedRegistry
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, &cache) != nil || cache.Version != metadataVersion || !validRegistry(cache.Registry) {
		return client.Registry{}, false
	}
	return sanitizeRegistry(cache.Registry), true
}

func showHelp(o options, r client.Registry, path []string, out io.Writer) error {
	joined := strings.Join(path, " ")
	if joined != "" {
		if d, ok := findCommand(r, joined); ok {
			if o.endpoint != "" && o.token != "" {
				if api, err := connect(o); err == nil {
					ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
					remote, e := api.CommandHelp(ctx, joined)
					cancel()
					if e == nil && remote.Path == joined {
						d = sanitizeRegistry(client.Registry{APIVersion: "v1", Items: []client.CommandDefinition{remote}}).Items[0]
					}
				}
			}
			printDefinition(out, d)
			return nil
		}
		return usageError("no command metadata for " + strconv.Quote(joined))
	}
	fmt.Fprintln(out, "Aries server management commands")
	for _, d := range r.Items {
		if d.Path == "help" {
			continue
		}
		fmt.Fprintf(out, "  %-22s %s\n", d.Path, d.Summary)
	}
	fmt.Fprintln(out, "\nUse `ariesctl help <command>` for usage. Global options: --endpoint, --token-file, --timeout, --cache.")
	return nil
}

func findCommand(r client.Registry, path string) (client.CommandDefinition, bool) {
	for _, d := range r.Items {
		if d.Path == path {
			return d, true
		}
	}
	return client.CommandDefinition{}, false
}
func printDefinition(w io.Writer, d client.CommandDefinition) {
	fmt.Fprintf(w, "%s\n\n%s\nUsage: %s\n", d.Path, d.Summary, d.Usage)
	if d.Permission != "" {
		fmt.Fprintf(w, "Permission: %s\n", d.Permission)
	}
	for _, f := range d.Flags {
		required := ""
		if f.Required {
			required = " (required)"
		}
		fmt.Fprintf(w, "  --%-18s %s%s\n", f.Name, f.Description, required)
	}
	for _, a := range d.Arguments {
		required := ""
		if a.Required {
			required = " (required)"
		}
		fmt.Fprintf(w, "  <%s> %s%s\n", a.Name, a.Description, required)
	}
}

func candidatesOffline(r client.Registry, words []string) []client.Candidate {
	prefix := ""
	if len(words) > 0 {
		prefix = words[len(words)-1]
		words = words[:len(words)-1]
	}
	seen := map[string]bool{}
	var out []client.Candidate
	add := func(value, desc string) {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) && !seen[value] {
			seen[value] = true
			out = append(out, client.Candidate{Value: value, Display: value, Description: desc})
		}
	}
	if len(words) == 0 {
		for _, d := range r.Items {
			root := strings.Fields(d.Path)[0]
			add(root, "command")
		}
	} else {
		joined := strings.Join(words, " ")
		for _, d := range r.Items {
			parts := strings.Fields(d.Path)
			if len(parts) > len(words) && strings.Join(parts[:len(words)], " ") == joined {
				add(parts[len(words)], d.Summary)
			}
			if d.Path == joined {
				for _, f := range d.Flags {
					add("--"+f.Name, f.Description)
				}
				if strings.HasPrefix(prefix, "--") {
					for _, f := range d.Flags {
						add("--"+f.Name, f.Description)
					}
				}
			}
		}
	}
	if len(words) >= 2 && words[0] == "config" && words[1] == "set" && (len(words) == 2 || len(words) == 3 && words[2] == "--key") {
		for _, k := range []string{"public_listen", "admin_listen", "data_dir", "admin_token_file", "max_storage_bytes", "allow_insecure_loopback", "peer_relay_enabled"} {
			add(k, "writable configuration field")
		}
	}
	if len(words) >= 3 && words[0] == "config" && words[1] == "set" {
		field := ""
		if len(words) >= 4 && words[2] == "--key" {
			field = words[3]
		}
		if len(words) >= 3 && words[2] == "--value" {
			field = ""
		}
		if len(words) == 3 && words[2] == "--value" {
			field = ""
		}
		for i := 0; i+1 < len(words); i++ {
			if words[i] == "--key" {
				field = words[i+1]
			}
		}
		if field == "allow_insecure_loopback" || field == "peer_relay_enabled" || field == "file_storage_enabled" {
			add("true", "boolean value")
			add("false", "boolean value")
		}
		if field == "group_quota_bytes" || field == "quota_bytes_per_member" || field == "max_file_bytes" || field == "max_file_ttl_seconds" {
			add("0", "integer value; zero disables the limit where applicable")
		}
	}
	if len(words) >= 5 && words[0] == "members" && words[1] == "role" && words[len(words)-1] == "--role" {
		add("admin", "member administrator")
		add("member", "ordinary member")
	}
	if len(words) >= 3 && words[0] == "members" && words[1] == "role" && words[len(words)-2] == "--role" {
		add("admin", "member administrator")
		add("member", "ordinary member")
	}
	return out
}

func runCompletion(o options, args []string, out io.Writer) error {
	jsonOnly := true
	if len(args) > 0 && args[0] == "--values" {
		args = args[1:]
		jsonOnly = false
	}
	words := args
	registry, ok := readRegistry(o.cache)
	if !ok {
		registry = cloneRegistry(builtinRegistry)
	}
	registry = withLocalCommands(registry)
	var candidates []client.Candidate
	if sensitiveCompletion(registry, words) {
		candidates = []client.Candidate{}
	} else if o.endpoint != "" && o.token != "" {
		if api, e := connect(o); e == nil {
			timeout := o.timeout
			if timeout > 400*time.Millisecond {
				timeout = 400 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			remote, fetchErr := api.Complete(ctx, words, len(words)-1)
			cancel()
			if fetchErr == nil {
				candidates = remote
			}
		}
	}
	if candidates == nil {
		candidates = candidatesOffline(registry, words)
	}
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if safeCompletionValue(candidate.Value) {
			candidate.Display = safeMetadataText(candidate.Display)
			candidate.Description = safeMetadataText(candidate.Description)
			filtered = append(filtered, candidate)
		}
	}
	candidates = filtered
	if !jsonOnly {
		for _, candidate := range candidates {
			fmt.Fprintln(out, candidate.Value)
		}
		return nil
	}
	b, err := json.Marshal(candidates)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

func safeCompletionValue(value string) bool {
	if len(value) == 0 || len(value) > 256 || strings.ContainsAny(value, "\r\n\t/:\\") || secretLike.MatchString(value) {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-", r)) {
			return false
		}
	}
	return true
}

func sensitiveCompletion(r client.Registry, words []string) bool {
	if len(words) == 0 {
		return false
	}
	before := words[:len(words)-1]
	var def *client.CommandDefinition
	var pathLen int
	for i := range r.Items {
		d := &r.Items[i]
		parts := strings.Fields(d.Path)
		if len(before) >= len(parts) && strings.Join(before[:len(parts)], " ") == d.Path && len(parts) > pathLen {
			def = d
			pathLen = len(parts)
		}
	}
	if def == nil {
		return false
	}
	args := before[pathLen:]
	pos := 0
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			name, _, has := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
			for _, field := range def.Flags {
				if field.Name == name && field.Sensitive {
					return true
				}
			}
			if !has && i+1 < len(args) {
				i++
			}
			continue
		}
		pos++
	}
	return pos < len(def.Arguments) && def.Arguments[pos].Sensitive
}

func installCompletion(args []string, out io.Writer) error {
	if len(args) != 1 {
		return usageError("usage: ariesctl completion install <powershell|bash|zsh>")
	}
	shell := strings.ToLower(args[0])
	script, profile, err := completionFiles(shell)
	if err != nil {
		return err
	}
	dir := filepath.Dir(script)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = atomicWriteFile(script, []byte(completionScript(shell)), 0600); err != nil {
		return err
	}
	line := completionProfileLine(shell, script)
	if err = appendProfileOnce(profile, line); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed Aries completion for %s. Restart the shell or source %s.\n", shell, profile)
	return nil
}

func completionFiles(shell string) (string, string, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	script := filepath.Join(config, "Aries", "completions", "ariesctl."+shell)
	switch shell {
	case "powershell":
		profile := os.Getenv("PROFILE")
		if profile == "" {
			profile = filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")
		}
		return script, profile, nil
	case "bash":
		return script, filepath.Join(home, ".bashrc"), nil
	case "zsh":
		return script, filepath.Join(home, ".zshrc"), nil
	default:
		return "", "", usageError("completion shell must be powershell, bash, or zsh")
	}
}

func completionProfileLine(shell, script string) string {
	switch shell {
	case "powershell":
		return ". '" + strings.ReplaceAll(script, "'", "''") + "'"
	default:
		return "source '" + strings.ReplaceAll(script, "'", "'\\''") + "'"
	}
}

func appendProfileOnce(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if strings.Contains(string(old), "# ariesctl completion") {
		return nil
	}
	contents := strings.TrimRight(string(old), "\r\n") + "\n# ariesctl completion\n" + line + "\n"
	mode := fs.FileMode(0600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm() & 0600
		if mode == 0 {
			mode = 0600
		}
	}
	return atomicWriteFile(path, []byte(contents), mode)
}

func completionScript(shell string) string {
	switch shell {
	case "bash":
		return "_ariesctl_complete() { local words=(\"${COMP_WORDS[@]:1}\"); COMPREPLY=( $(ariesctl __complete-values \"${words[@]}\" 2>/dev/null) ); }; complete -F _ariesctl_complete ariesctl\n"
	case "zsh":
		return "_ariesctl_complete() { local -a vals; vals=(${(f)\"$(ariesctl __complete-values \"${words[@]:2}\" 2>/dev/null)\"}); compadd -- $vals }; compdef _ariesctl_complete ariesctl\n"
	case "powershell":
		return "Register-ArgumentCompleter -Native -CommandName ariesctl -ScriptBlock { param($wordToComplete,$commandAst,$cursorPosition) $words=@($commandAst.ToString() -split '\\s+' | Select-Object -Skip 1); & ariesctl __complete-values @words 2>$null | ForEach-Object { if ($_ -like \"$wordToComplete*\") { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',$_) } } }\n"
	default:
		return ""
	}
}

var _ = json.Valid
