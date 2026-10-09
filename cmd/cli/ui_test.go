package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"aries.local/aries/internal/client"
	"aries.local/aries/internal/kernel"
)

func TestMainMenuRendersStatusAndExitDoesNotStopService(t *testing.T) {
	shutdownCalled := false
	tokenPath := filepath.Join(t.TempDir(), "admin.token")
	token, err := client.CreateTokenFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("authorization header missing")
		}
		switch r.URL.Path {
		case "/api/v1/admin/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node_id": "node-test", "server_code": "ABCD", "uptime_seconds": 91,
				"public_listener":   map[string]any{"address": "127.0.0.1:8787"},
				"admin_listener":    map[string]any{"address": "127.0.0.1:8788"},
				"connected_devices": nil, "storage_state": "available",
			})
		case "/api/v1/admin/commands/execute":
			shutdownCalled = true
			http.Error(w, "unexpected stop", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	o := options{endpoint: server.URL, token: tokenPath, timeout: time.Second}
	var output, errorsOut strings.Builder
	if err := runMainMenu(o, uiPreferences{Core: "online"}, "", langEnglish, bufio.NewReader(strings.NewReader("7\n")), &output, &errorsOut); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Aries Service Control", "node-test", "ABCD", "127.0.0.1:8787", "Exit CLI (service stays in background)"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("menu output missing %q:\n%s", expected, output.String())
		}
	}
	if shutdownCalled {
		t.Fatal("exiting the CLI must not stop the background service")
	}
	if errorsOut.Len() != 0 {
		t.Fatalf("unexpected menu error: %s", errorsOut.String())
	}
}

func writeTokenForUITest(t *testing.T, path string) string {
	t.Helper()
	if _, err := client.CreateTokenFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirstDeploymentCreatesProtectedLocalCoreConfig(t *testing.T) {
	root := filepath.Join(t.TempDir(), "node")
	files, err := createDeploymentFiles(root, "127.0.0.1:8787", "127.0.0.1:8788")
	if err != nil {
		t.Fatal(err)
	}
	config, err := kernel.LoadConfig(files.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.AdminListen != "127.0.0.1:8788" || !config.AllowInsecureLoopback {
		t.Fatalf("unexpected local admin configuration: %#v", config)
	}
	if _, err := client.ReadToken(files.tokenPath); err != nil {
		t.Fatalf("generated token is not protected/readable: %v", err)
	}
	if endpoint, tokenPath, err := localConnection(files.configPath); err != nil || endpoint != "http://127.0.0.1:8788" || tokenPath != files.tokenPath {
		t.Fatalf("local connection = %q %q, %v", endpoint, tokenPath, err)
	}
}

func TestOnlineCoreRequiresAnAdminTokenFile(t *testing.T) {
	reader := strings.NewReader("https://relay.example:8788\nmissing-token-file\n")
	_, _, err := selectOnlineCore(uiPreferences{}, options{timeout: time.Second}, bufio.NewReader(reader), io.Discard, langEnglish)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing admin token file error, got %v", err)
	}
}

func TestSettingsCoverContractAndParseTypedValues(t *testing.T) {
	want := []string{"public_listen", "admin_listen", "data_dir", "admin_token_file", "max_storage_bytes", "allow_insecure_loopback", "peer_relay_enabled", "file_storage_enabled", "group_quota_bytes", "quota_bytes_per_member", "max_file_bytes", "max_file_ttl_seconds"}
	if len(uiSettings) != len(want) {
		t.Fatalf("settings count=%d, want %d", len(uiSettings), len(want))
	}
	for i, key := range want {
		if uiSettings[i].Key != key {
			t.Errorf("setting[%d]=%s, want %s", i, uiSettings[i].Key, key)
		}
	}
	for _, test := range []struct{ kind, value, want string }{
		{"integer", "1024", "1024"}, {"boolean", "true", "true"}, {"string", "127.0.0.1:8788", `"127.0.0.1:8788"`},
	} {
		got, err := typedSettingValue(test.kind, test.value)
		if err != nil || string(got) != test.want {
			t.Errorf("typedSettingValue(%q, %q) = %s, %v; want %s", test.kind, test.value, got, err, test.want)
		}
	}
	if _, err := typedSettingValue("integer", "-1"); err == nil {
		t.Fatal("negative quota value should be rejected")
	}
}

func TestByteSettingsFormatAsDecimalGBWithoutScientificNotation(t *testing.T) {
	for _, test := range []struct {
		bytes int64
		want  string
	}{
		{0, "0 GB"},
		{268435456, "0.25 GB"},
		{1073741824, "1 GB"},
		{1610612736, "1.5 GB"},
		{10737418240, "10 GB"},
	} {
		if got := formatBytesGB(test.bytes, langChinese); got != test.want {
			t.Errorf("formatBytesGB(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
	for _, raw := range []string{"1073741824", "268435456", "10737418240"} {
		field := settingInfo{Key: "max_storage_bytes", Kind: "integer"}
		got := formatSettingValue(field, json.RawMessage(raw), langChinese)
		if strings.ContainsAny(got, "eE") {
			t.Errorf("formatSettingValue(%s) used scientific notation: %q", raw, got)
		}
	}
	field := settingInfo{Key: "max_storage_bytes", Kind: "integer"}
	for _, test := range []struct {
		input string
		want  string
	}{
		{"1.5", "1610612736"},
		{"0.25 GB", "268435456"},
		{"10", "10737418240"},
	} {
		got, err := parseSettingInput(field, test.input)
		if err != nil || string(got) != test.want {
			t.Errorf("parseSettingInput(%q) = %s, %v; want %s", test.input, got, err, test.want)
		}
	}
	if got := settingInputDefault(field, json.RawMessage("268435456")); got != "0.25" {
		t.Errorf("byte setting edit default = %q, want 0.25 GB value", got)
	}
	if _, err := parseSettingInput(field, "-0.5"); err == nil {
		t.Fatal("negative GB value should be rejected")
	}
	for _, original := range []int64{1, 2, 3, 123456789, 268435456, 1073741824, 9223372036854775807} {
		input := settingInputDefault(field, json.RawMessage(strconv.FormatInt(original, 10)))
		parsed, err := parseSettingInput(field, input)
		if err != nil || string(parsed) != strconv.FormatInt(original, 10) {
			t.Errorf("byte setting round-trip %d through %q = %s, %v", original, input, parsed, err)
		}
	}
}
