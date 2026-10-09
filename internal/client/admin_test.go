package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseEndpointRequiresTLSOutsideLoopback(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		wantErr  bool
	}{
		{"https://admin.example:8788", false},
		{"http://127.0.0.1:8788", false},
		{"http://[::1]:8788", false},
		{"http://admin.example:8788", true},
		{"https://user:pass@admin.example", true},
		{"https://admin.example/api/v1/admin", true},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			_, err := parseEndpoint(tc.endpoint)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseEndpoint() error = %v; wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestTokenFileSecureCreateReadAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "admin.token")
	generated, err := CreateTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) < 43 {
		t.Fatalf("token length = %d, expected at least 256 bits encoded", len(generated))
	}
	read, err := ReadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if read != generated {
		t.Fatal("read token does not match generated token")
	}
	if _, err := CreateTokenFile(path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("creating over an existing token should fail safely, got %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("token file permissions = %o, expected owner-only", info.Mode().Perm())
	}
}

func TestReadTokenRejectsInsecureUnixPermissions(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix permission bits are not ACLs on Windows")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("ReadToken error = %v; want insecure permission error", err)
	}
}

func TestClientGetUsesBearerAndParsesAPIErrorWithoutLeakingToken(t *testing.T) {
	const token = "unique-secret-token-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/api/v1/admin/status" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"bad ` + token + `\u001b[31mred ` + token + `","request_id":"req-1"}}`))
	}))
	defer server.Close()

	api, err := NewWithToken(server.URL, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Get(context.Background(), "/api/v1/admin/status")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v; want APIError", err)
	}
	if apiErr.Status != http.StatusUnauthorized || apiErr.Code != "unauthorized" || apiErr.RequestID != "req-1" {
		t.Fatalf("unexpected API error: %#v", apiErr)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("API error exposed the bearer token")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatal("API error preserved terminal control characters")
	}
}

func TestClientRequestRejectsUnsafePathsAndBadJSON(t *testing.T) {
	api, err := NewWithToken("http://127.0.0.1:8080", "token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "https://evil.example/"); err == nil {
		t.Fatal("absolute path should be rejected")
	}
	if _, err := api.Put(context.Background(), "/api/v1/admin/config", json.RawMessage("{"), "idempotency-key-1"); err == nil {
		t.Fatal("invalid JSON should be rejected")
	}
}

func TestClientTimeoutHasStableConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	api, err := NewWithToken(server.URL, "token", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Get(context.Background(), "/api/v1/admin/status")
	var connection *ConnectionError
	if !errors.As(err, &connection) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v; want useful timeout ConnectionError", err)
	}
}

func TestCreateTokenDoesNotExposeSecretInFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateTokenFile(filepath.Join(path, "..", "a-directory")); err == nil {
		t.Fatal("expected existing target to fail")
	}
}
