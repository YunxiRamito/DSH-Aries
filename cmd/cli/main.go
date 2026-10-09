// ariesctl is the server-management front end to the Aries command registry.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aries.local/aries/internal/client"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string    { return e.err.Error() }
func (e *exitError) Unwrap() error    { return e.err }
func usageError(message string) error { return &exitError{2, errors.New(message)} }

type options struct {
	endpoint, token, cache string
	language               string
	timeout                time.Duration
}

func run(args []string, stdout, stderr io.Writer) int {
	err := executeCLI(args, os.Stdin, stdout, stderr)
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "error:", err)
	return exitCode(err)
}

func exitCode(err error) int {
	var usage *exitError
	if errors.As(err, &usage) {
		return usage.code
	}
	var input *client.InputError
	if errors.As(err, &input) {
		return 2
	}
	var connection *client.ConnectionError
	if errors.As(err, &connection) {
		return 4
	}
	var api *client.APIError
	if errors.As(err, &api) {
		if api.Status == 401 || api.Status == 403 {
			return 3
		}
		if api.Status >= 500 {
			return 5
		}
		if api.Status == 400 || api.Status == 422 {
			return 2
		}
	}
	return 1
}

func parseOptions(args []string) (options, []string, error) {
	o := options{endpoint: defaultEndpoint(), token: defaultTokenFile(), language: os.Getenv("ARIES_LANGUAGE"), timeout: client.DefaultTimeout, cache: defaultCachePath()}
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		name, value, has := strings.Cut(arg, "=")
		if name != "--endpoint" && name != "--token-file" && name != "--timeout" && name != "--cache" && name != "--language" && name != "--lang" {
			rest = append(rest, arg)
			continue
		}
		if !has {
			i++
			if i >= len(args) {
				return o, nil, usageError(name + " requires a value")
			}
			value = args[i]
		}
		switch name {
		case "--endpoint":
			o.endpoint = value
		case "--token-file":
			o.token = value
		case "--cache":
			o.cache = value
		case "--timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return o, nil, usageError("--timeout must be a positive duration")
			}
			o.timeout = d
		case "--language", "--lang":
			language, err := normalizeLanguage(value)
			if err != nil {
				return o, nil, usageError(err.Error())
			}
			o.language = string(language)
		}
	}
	return o, rest, nil
}

func defaultEndpoint() string {
	if endpoint := strings.TrimSpace(os.Getenv("ARIES_ENDPOINT")); endpoint != "" {
		return endpoint
	}
	return "http://127.0.0.1:7788"
}

// defaultTokenFile gives local deployments a zero-argument path while still
// keeping the token itself out of arguments, logs, and preferences. We prefer
// an existing file; when none exists we return the executable's conventional
// location so the resulting error points at the actionable path.
func defaultTokenFile() string {
	if token := strings.TrimSpace(os.Getenv("ARIES_TOKEN_FILE")); token != "" {
		return token
	}
	candidates := make([]string, 0, 8)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "secrets", "admin.token"), filepath.Join(cwd, "admin.token"))
	}
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates = append(candidates, filepath.Join(dir, "secrets", "admin.token"), filepath.Join(dir, "admin.token"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, "DSH-Aries", "secrets", "admin.token"), filepath.Join(home, ".config", "Aries", "admin.token"))
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return filepath.Join("secrets", "admin.token")
}

func connect(o options) (*client.Client, error) {
	if o.endpoint == "" || o.token == "" {
		return nil, usageError("--endpoint and --token-file are required (or ARIES_ENDPOINT and ARIES_TOKEN_FILE)")
	}
	return client.New(o.endpoint, o.token, o.timeout)
}

func executeCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	o, words, err := parseOptions(args)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		// The interactive terminal is the primary CLI experience. Keep `ui` as
		// an explicit alias, while a bare `ariesctl` opens the same menu.
		return runUI(o, stdin, stdout, stderr)
	}
	if words[0] == "ui" {
		if len(words) > 1 && (words[1] == "--help" || words[1] == "-h") {
			fmt.Fprintln(stdout, "Usage: ariesctl [global options] ui")
			fmt.Fprintln(stdout, "Start the interactive bilingual terminal interface.")
			return nil
		}
		if len(words) > 1 {
			return usageError("ui takes no command arguments")
		}
		return runUI(o, stdin, stdout, stderr)
	}
	if words[0] == "__complete" {
		return runCompletion(o, words[1:], stdout)
	}
	if words[0] == "__complete-values" {
		return runCompletion(o, append([]string{"--values"}, words[1:]...), stdout)
	}
	if words[0] == "completion" {
		return installCompletion(words[1:], stdout)
	}
	if words[0] == "token" {
		return runToken(words[1:], stdout)
	}
	if words[0] == "--help" || words[0] == "-h" {
		words = []string{"help"}
	}
	for i, w := range words {
		if w == "--help" || w == "-h" {
			words = append([]string{"help"}, words[:i]...)
			break
		}
	}
	registry, err := loadRegistry(o, words[0] == "help", stderr)
	if err != nil {
		return err
	}
	if words[0] == "commands" {
		b, _ := json.Marshal(registry)
		return writePrettyJSON(stdout, b)
	}
	if words[0] == "help" {
		return showHelp(o, registry, words[1:], stdout)
	}
	// Retain storage as a short alias while directing it to the canonical command.
	if len(words) == 1 && words[0] == "storage" {
		words = append(words, "status")
	}
	request, err := parseCommand(registry, words)
	if err != nil {
		return err
	}
	api, err := connect(o)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	key, err := newIdempotencyKey()
	if err != nil {
		return err
	}
	result, err := api.Execute(ctx, request, key)
	if err != nil {
		return err
	}
	return writePrettyJSON(stdout, result)
}

func parseCommand(registry client.Registry, words []string) (client.CommandRequest, error) {
	var definition *client.CommandDefinition
	for i := range registry.Items {
		d := &registry.Items[i]
		path := strings.Fields(d.Path)
		if len(words) >= len(path) && strings.Join(words[:len(path)], " ") == d.Path {
			if definition == nil || len(path) > len(strings.Fields(definition.Path)) {
				definition = d
			}
		}
	}
	if definition == nil {
		return client.CommandRequest{}, usageError("unknown command; run `ariesctl help` or `ariesctl commands`")
	}
	if definition.LocalOnly {
		return client.CommandRequest{}, usageError("this command must run locally")
	}
	path := strings.Fields(definition.Path)
	request := client.CommandRequest{Argv: append([]string(nil), path...), Flags: map[string]json.RawMessage{}}
	tokens := words[len(path):]
	// The documented shorthand config set <key> <value> maps to canonical typed flags.
	if definition.Path == "config set" && len(tokens) == 2 && !strings.HasPrefix(tokens[0], "--") {
		tokens = []string{"--key", tokens[0], "--value", tokens[1]}
	}
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if !strings.HasPrefix(token, "--") {
			request.Argv = append(request.Argv, token)
			continue
		}
		name, value, has := strings.Cut(strings.TrimPrefix(token, "--"), "=")
		var field *client.CommandField
		for j := range definition.Flags {
			if definition.Flags[j].Name == name {
				field = &definition.Flags[j]
				break
			}
		}
		if field == nil {
			return request, usageError("unknown flag --" + name + "; run `ariesctl help " + definition.Path + "`")
		}
		if _, exists := request.Flags[name]; exists {
			return request, usageError("duplicate flag --" + name)
		}
		if !has {
			i++
			if i >= len(tokens) {
				return request, usageError("--" + name + " requires a value")
			}
			value = tokens[i]
		}
		encoded, err := encodeFlag(field.Type, value)
		if err != nil {
			return request, usageError("--" + name + ": " + err.Error())
		}
		if name == "role" && value != "admin" && value != "member" {
			return request, usageError("--role must be admin or member")
		}
		request.Flags[name] = encoded
	}
	for _, f := range definition.Flags {
		if f.Required {
			if _, ok := request.Flags[f.Name]; !ok {
				return request, usageError("required flag --" + f.Name + " is missing")
			}
		}
	}
	if len(request.Argv)-len(path) > len(definition.Arguments) {
		return request, usageError("too many arguments; usage: " + definition.Usage)
	}
	for i, field := range definition.Arguments {
		if field.Required && i >= len(request.Argv)-len(path) {
			return request, usageError("missing <" + field.Name + ">; usage: " + definition.Usage)
		}
	}
	return request, nil
}

func encodeFlag(kind, value string) (json.RawMessage, error) {
	switch kind {
	case "typed-json":
		if json.Valid([]byte(value)) {
			var scalar any
			_ = json.Unmarshal([]byte(value), &scalar)
			switch scalar.(type) {
			case map[string]any, []any, nil:
				return nil, errors.New("requires a JSON string, number, or boolean")
			default:
				return []byte(value), nil
			}
		}
		return json.Marshal(value)
	case "integer", "int":
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, errors.New("requires an integer")
		}
		return []byte(strconv.FormatInt(v, 10)), nil
	case "boolean", "bool":
		v, err := strconv.ParseBool(value)
		if err != nil {
			return nil, errors.New("requires true or false")
		}
		return []byte(strconv.FormatBool(v)), nil
	default:
		return json.Marshal(value)
	}
}

func runToken(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(stdout, "Usage: ariesctl token create|rotate --out <path> [--show]")
		return nil
	}
	if args[0] != "create" && args[0] != "rotate" {
		return usageError("token expects create or rotate")
	}
	var path string
	var show bool
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--out":
			i++
			if i >= len(args) {
				return usageError("--out requires a path")
			}
			path = args[i]
		case "--show":
			show = true
		default:
			return usageError("unknown token option")
		}
	}
	if path == "" {
		return usageError("token command requires --out <path>")
	}
	var token string
	var err error
	if args[0] == "rotate" {
		token, err = client.RotateTokenFile(path)
	} else {
		token, err = client.CreateTokenFile(path)
	}
	if err != nil {
		return err
	}
	if show {
		_, err = fmt.Fprintln(stdout, token)
	} else {
		_, err = fmt.Fprintf(stdout, "Protected admin token written to %s. Secret not displayed.\n", path)
	}
	if args[0] == "rotate" {
		fmt.Fprintln(stdout, "This only replaces the local file. Arrange secure delivery to the server and restart it as required; remote token rotation is not performed.")
	}
	return err
}

func newIdempotencyKey() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}
func writePrettyJSON(w io.Writer, raw json.RawMessage) error {
	var b bytes.Buffer
	if err := json.Indent(&b, raw, "", "  "); err != nil {
		return err
	}
	_, err := io.WriteString(w, b.String()+"\n")
	return err
}
