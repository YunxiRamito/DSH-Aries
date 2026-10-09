package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aries.local/aries/internal/client"
)

func TestCanonicalCommandIsDiscoveredAndExecutedAsStructuredArgv(t *testing.T) {
	var gotRegistry, gotExecute bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cli-test-token" {
			t.Error("missing bearer auth")
		}
		switch r.URL.Path {
		case "/api/v1/admin/commands":
			gotRegistry = true
			if r.Method != http.MethodGet {
				t.Errorf("registry method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(client.Registry{APIVersion: "v1", Items: []client.CommandDefinition{{Path: "config set", Summary: "Set config", Usage: "config set --key <key> --value <value>", Flags: []client.CommandField{{Name: "key", Type: "string", Required: true}, {Name: "value", Type: "typed-json", Required: true}}, Permission: "admin:write"}}})
		case "/api/v1/admin/commands/execute":
			gotExecute = true
			if r.Method != http.MethodPost {
				t.Errorf("execute method=%s", r.Method)
			}
			if len(r.Header.Get("Idempotency-Key")) < 8 {
				t.Error("missing Idempotency-Key")
			}
			var request client.CommandRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if strings.Join(request.Argv, " ") != "config set" {
				t.Errorf("argv=%v", request.Argv)
			}
			if string(request.Flags["key"]) != "\"max_storage_bytes\"" || string(request.Flags["value"]) != "2048" {
				t.Errorf("flags=%s", mustJSON(request.Flags))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "summary": "Configuration updated", "warnings": []string{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenPath, []byte("cli-test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "commands.json")
	var stdout, stderr strings.Builder
	args := []string{"--endpoint", server.URL, "--token-file", tokenPath, "--cache", cache, "config", "set", "max_storage_bytes", "2048"}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !gotRegistry || !gotExecute {
		t.Fatalf("registry=%v execute=%v", gotRegistry, gotExecute)
	}
	if !strings.Contains(stdout.String(), "Configuration updated") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if _, ok := readRegistry(cache); !ok {
		t.Fatal("safe registry cache was not written")
	}
}

func TestLocalHelpAndOfflineCompletionUseCachedSafeMetadata(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "commands.json")
	r := client.Registry{APIVersion: "v1", Items: []client.CommandDefinition{
		{Path: "invites revoke", Summary: "Revoke invitation", Usage: "invites revoke <group-id> <invite-code>", Arguments: []client.CommandField{{Name: "group-id", Type: "string", Required: true}, {Name: "invite-code", Type: "string", Required: true, Sensitive: true}}, Permission: "admin:group-write", Examples: []string{"invites revoke secret-code"}},
		{Path: "config show", Summary: "Show config", Usage: "config show"},
	}}
	if err := saveRegistry(cache, r); err != nil {
		t.Fatal(err)
	}
	o := options{cache: cache}
	loaded, ok := readRegistry(cache)
	if !ok {
		t.Fatal("registry cache rejected")
	}
	if loaded.Items[0].Examples != nil || loaded.Items[0].Arguments[1].Description != "sensitive value" {
		t.Fatalf("unsafe metadata survived sanitization: %#v", loaded.Items[0])
	}
	var help strings.Builder
	if err := showHelp(o, loaded, []string{"config", "show"}, &help); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(help.String(), "config show") {
		t.Fatalf("help=%q", help.String())
	}
	var completion strings.Builder
	if err := runCompletion(o, []string{"in"}, &completion); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(completion.String(), "invites") {
		t.Fatalf("completion=%q", completion.String())
	}
	var sensitive strings.Builder
	if err := runCompletion(o, []string{"invites", "revoke", "group-1", ""}, &sensitive); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(sensitive.String()) != "[]" {
		t.Fatalf("sensitive completion leaked candidate: %q", sensitive.String())
	}
}

func TestTokenCreateAndRotateAreLocalOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	var stdout, stderr strings.Builder
	if code := run([]string{"token", "create", "--out", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("create exit=%d stderr=%q", code, stderr.String())
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"token", "rotate", "--out", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("rotate exit=%d stderr=%q", code, stderr.String())
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(first)) == strings.TrimSpace(string(second)) {
		t.Fatal("rotation did not replace token")
	}
	if strings.Contains(stdout.String(), strings.TrimSpace(string(second))) {
		t.Fatal("secret printed without --show")
	}
	if !strings.Contains(stdout.String(), "only replaces the local file") {
		t.Fatalf("expected local-only guidance, got %q", stdout.String())
	}
}

func TestCompletionScriptsAndProfileInstallAreIdempotent(t *testing.T) {
	for _, shell := range []string{"powershell", "bash", "zsh"} {
		if script := completionScript(shell); !strings.Contains(script, "ariesctl __complete-values") {
			t.Errorf("%s script missing local completion call", shell)
		}
	}
	profile := filepath.Join(t.TempDir(), "profile")
	line := completionProfileLine("bash", "/tmp/a path/completion.sh")
	if err := appendProfileOnce(profile, line); err != nil {
		t.Fatal(err)
	}
	if err := appendProfileOnce(profile, line); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), "# ariesctl completion") != 1 {
		t.Fatalf("profile is not idempotent: %q", b)
	}
}

func TestCommandFlagValidationAndSafeCompletionValues(t *testing.T) {
	r := builtinRegistry
	if _, err := parseCommand(r, []string{"members", "role", "g", "d", "--role", "root"}); err == nil {
		t.Fatal("invalid role should be rejected from canonical usage metadata")
	}
	for _, unsafe := range []string{"bad value", "secret\nnext", "token/path\\x", strings.Repeat("A", 300)} {
		if safeCompletionValue(unsafe) {
			t.Errorf("accepted unsafe candidate %q", unsafe)
		}
	}
}

func TestConnectionDefaultsUseLoopbackAndProtectedTokenPath(t *testing.T) {
	t.Setenv("ARIES_ENDPOINT", "")
	t.Setenv("ARIES_TOKEN_FILE", "")
	o, words, err := parseOptions([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	if o.endpoint != "http://127.0.0.1:7788" {
		t.Fatalf("default endpoint=%q", o.endpoint)
	}
	if o.token == "" || !strings.Contains(strings.ToLower(filepath.ToSlash(o.token)), "admin.token") {
		t.Fatalf("default token path=%q", o.token)
	}
	if len(words) != 1 || words[0] != "status" {
		t.Fatalf("words=%v", words)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
