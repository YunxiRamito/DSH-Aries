package kernel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aries.local/aries/internal/store"
)

type testNode struct {
	s          *Server
	st         *store.Store
	cfg        Config
	configPath string
}
type testDevice struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestNode(t *testing.T) testNode {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("x", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	cfg := Config{SchemaVersion: 1, PublicListen: "127.0.0.1:8787", AdminListen: "127.0.0.1:8788", DataDir: dir, AdminTokenFile: tokenPath, MaxStorageBytes: 1024 * 1024, AllowInsecureLoopback: true, PeerRelayEnabled: false, FileStorageEnabled: true, GroupQuotaBytes: 1024 * 1024, MaxFileBytes: 256 * 1024 * 1024, MaxFileTTLSeconds: 30 * 24 * 60 * 60}
	st, err := store.Open(filepath.Join(dir, "state.json"), "node_0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, configPath, st)
	if err != nil {
		t.Fatal(err)
	}
	return testNode{s: s, st: st, cfg: cfg, configPath: configPath}
}

func (n testNode) close(t *testing.T) {
	t.Helper()
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
}

func (n testNode) request(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:54321"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	if strings.HasPrefix(path, "/api/v1/admin/") || path == "/healthz" {
		n.s.AdminHandler().ServeHTTP(w, r)
	} else {
		n.s.PublicHandler().ServeHTTP(w, r)
	}
	return w
}

func (n testNode) enroll(t *testing.T) testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubEncoded := base64.RawURLEncoding.EncodeToString(pub)
	body, _ := json.Marshal(map[string]string{"public_key": pubEncoded})
	w := n.request(http.MethodPost, "/api/v1/public/devices/challenge", body, nil)
	if w.Code != 200 {
		t.Fatalf("challenge failed: %d %s", w.Code, w.Body)
	}
	challengeResp := map[string]any{}
	if err = json.Unmarshal(w.Body.Bytes(), &challengeResp); err != nil {
		t.Fatal(err)
	}
	challengeID := challengeResp["challenge_id"].(string)
	nonce := challengeResp["nonce"].(string)
	canonical := []byte("enroll\n" + challengeID + "\n" + nonce + "\n" + pubEncoded)
	sig := ed25519.Sign(priv, canonical)
	enrollBody, _ := json.Marshal(map[string]string{"challenge_id": challengeID, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	w = n.request(http.MethodPost, "/api/v1/public/devices/enroll", enrollBody, map[string]string{"Idempotency-Key": "enroll-key-" + challengeID})
	if w.Code != 201 {
		t.Fatalf("enroll failed: %d %s", w.Code, w.Body)
	}
	var response map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return testDevice{id: response["device_id"].(string), pub: pub, priv: priv}
}

func (n testNode) signedRequest(t *testing.T, d testDevice, method, path string, body []byte, idem string) *httptest.ResponseRecorder {
	t.Helper()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce, err := randomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{method, path, timestamp, nonce, idem, base64.RawURLEncoding.EncodeToString(sum[:])}, "\n")
	sig := ed25519.Sign(d.priv, []byte(canonical))
	return n.request(method, path, body, map[string]string{"X-Device-ID": d.id, "X-Device-Timestamp": timestamp, "X-Device-Nonce": nonce, "X-Device-Signature": base64.RawURLEncoding.EncodeToString(sig), "Idempotency-Key": idem})
}

func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %s: %v", w.Body, err)
	}
	return result
}

func TestAdminAuthConfigRedactionAndStatusContract(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	w := n.request(http.MethodGet, "/healthz", nil, nil)
	if w.Code != 200 {
		t.Fatalf("health status %d", w.Code)
	}
	w = n.request(http.MethodGet, "/api/v1/admin/status", nil, nil)
	if w.Code != 401 {
		t.Fatalf("unauthenticated status got %d", w.Code)
	}
	secret := strings.Repeat("x", 64)
	w = n.request(http.MethodGet, "/api/v1/admin/config", nil, map[string]string{"Authorization": "Bearer " + secret})
	if w.Code != 200 {
		t.Fatalf("config status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("admin token leaked through config response")
	}
	var cfg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema_version", "public_listen", "admin_listen", "data_dir", "admin_token_file", "max_storage_bytes", "allow_insecure_loopback", "peer_relay_enabled", "file_storage_enabled", "group_quota_bytes", "quota_bytes_per_member", "max_file_bytes", "max_file_ttl_seconds", "heartbeat_interval_seconds", "heartbeat_timeout_seconds"} {
		if _, ok := cfg[field]; !ok {
			t.Errorf("config missing %s", field)
		}
	}
	w = n.request(http.MethodGet, "/api/v1/admin/status", nil, map[string]string{"Authorization": "Bearer " + secret})
	if w.Code != 200 {
		t.Fatalf("status status %d", w.Code)
	}
	status := decodeMap(t, w)
	for _, field := range []string{"api_version", "node_id", "uptime_seconds", "started_at", "public_listener", "admin_listener", "connected_devices", "pending_control_events", "storage_state"} {
		if _, ok := status[field]; !ok {
			t.Errorf("status missing %s", field)
		}
	}
}

func TestDeviceEnrollmentMembershipRevocationAndRotationSurviveRestart(t *testing.T) {
	n := newTestNode(t)
	a := n.enroll(t)
	b := n.enroll(t)
	groupBody := []byte(`{"name":"test","approval_policy":"creator"}`)
	w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups", groupBody, "group-create-0001")
	if w.Code != 201 {
		t.Fatalf("create group: %d %s", w.Code, w.Body)
	}
	created := decodeMap(t, w)
	group := created["group_id"].(string)
	invite := created["invite_code"].(string)
	// Replaying the same durable request returns its original result without
	// creating another group, even though the per-request signing nonce changes.
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups", groupBody, "group-create-0001")
	if w.Code != 201 {
		t.Fatalf("idempotent replay: %d %s", w.Code, w.Body)
	}
	if decodeMap(t, w)["group_id"] != group {
		t.Fatal("idempotent replay changed result")
	}
	applyBody := []byte(`{}`)
	w = n.signedRequest(t, b, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", applyBody, "application-create-0001")
	if w.Code != 201 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	appID := decodeMap(t, w)["application_id"].(string)
	approvalBody := []byte(`{"approve":true}`)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+group+"/applications/"+appID+"/approvals", approvalBody, "approval-000001")
	if w.Code != 200 {
		t.Fatalf("approval: %d %s", w.Code, w.Body)
	}
	deliveryBody := []byte(`{"envelope":"ZW5jcnlwdGVkLWtleS1lbmdlbG9wZQ"}`)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+group+"/applications/"+appID+"/key-delivery", deliveryBody, "delivery-000001")
	if w.Code != 201 {
		t.Fatalf("key delivery: %d %s", w.Code, w.Body)
	}
	messageCiphertext := "c2VjcmV0LW1lc3NhZ2UtY2lwaGVydGV4dA"
	messageBody := []byte(fmt.Sprintf(`{"epoch":1,"ciphertext":%q}`, messageCiphertext))
	w = n.signedRequest(t, b, http.MethodPost, "/api/v1/public/groups/"+group+"/messages", messageBody, "message-000001")
	if w.Code != 201 {
		t.Fatalf("message: %d %s", w.Code, w.Body)
	}
	var storedCiphertext string
	if err := n.st.View(func(st store.State) error { storedCiphertext = st.Messages[group][0].Ciphertext; return nil }); err != nil {
		t.Fatal(err)
	}
	if storedCiphertext != messageCiphertext {
		t.Fatal("opaque ciphertext was modified")
	}
	if strings.Contains(storedCiphertext, "secret-message") {
		t.Fatal("test ciphertext unexpectedly contains plaintext")
	}
	leaveBody := []byte(`{}`)
	w = n.signedRequest(t, b, http.MethodPost, "/api/v1/public/groups/"+group+"/leave", leaveBody, "leave-0000001")
	if w.Code != 202 {
		t.Fatalf("leave: %d %s", w.Code, w.Body)
	}
	leave := decodeMap(t, w)
	eventID := leave["control_event_id"].(string)
	// Persisted pending events are not tied to online connections or file quota.
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(n.st.Path(), "ignored")
	if err != nil {
		t.Fatal(err)
	}
	var eventCount int
	if err = reopened.View(func(st store.State) error { eventCount = len(st.Groups[group].Events); return nil }); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("pending leave event lost on restart: %d", eventCount)
	}
	server, err := New(n.cfg, n.configPath, reopened)
	if err != nil {
		t.Fatal(err)
	}
	n.st = reopened
	n.s = server
	// The leaving device retains its device identity but cannot use old group authorization.
	w = n.signedRequest(t, b, http.MethodPost, "/api/v1/public/groups/"+group+"/messages", messageBody, "message-0000002")
	if w.Code != 403 {
		t.Fatalf("revoked member was not rejected: %d %s", w.Code, w.Body)
	}
	rotationBody := []byte(`{"epoch":2,"envelopes":{}}`)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+group+"/rotations/"+eventID, rotationBody, "rotate-0000001")
	if w.Code != 200 {
		t.Fatalf("rotation: %d %s", w.Code, w.Body)
	}
	oldBody := []byte(`{"epoch":1,"ciphertext":"b2xkLWtleS1jaXBoZXI"}`)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+group+"/messages", oldBody, "message-old-key1")
	if w.Code != 409 {
		t.Fatalf("stale generation accepted: %d %s", w.Code, w.Body)
	}
	newBody := []byte(`{"epoch":2,"ciphertext":"bmV3LWtleS1jaXBoZXI"}`)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+group+"/messages", newBody, "message-new-key1")
	if w.Code != 201 {
		t.Fatalf("new generation rejected: %d %s", w.Code, w.Body)
	}
	n.close(t)
}

func TestChallengeRateLimitAndInvalidProof(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(pub)
	body, _ := json.Marshal(map[string]string{"public_key": encoded})
	for i := 0; i < 8; i++ {
		w := n.request(http.MethodPost, "/api/v1/public/devices/challenge", body, nil)
		if w.Code != 200 {
			t.Fatalf("challenge %d: %d %s", i, w.Code, w.Body)
		}
	}
	w := n.request(http.MethodPost, "/api/v1/public/devices/challenge", body, nil)
	if w.Code != 429 {
		t.Fatalf("expected bounded rate limit, got %d %s", w.Code, w.Body)
	}
	w = n.request(http.MethodPost, "/api/v1/public/devices/enroll", []byte(`{"challenge_id":"missing","signature":"invalid"}`), map[string]string{"Idempotency-Key": "invalid-enroll-01"})
	if w.Code != 401 {
		t.Fatalf("invalid challenge accepted: %d", w.Code)
	}
}

func TestApplicationListAndPublicKeyBoundaries(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a := n.enroll(t)
	b := n.enroll(t)
	c := n.enroll(t)
	if err := n.st.Update(func(st *store.State) error {
		st.Groups["grp_apps"] = store.Group{ID: "grp_apps", Name: "apps", AuthorityNode: st.NodeID, CreatorID: a.id, Policy: "creator", CreatedAt: "2026-10-11T00:00:00Z", Generation: 1, Members: map[string]store.Member{
			a.id: {DeviceID: a.id, Role: "creator", Active: true, JoinedAt: "2026-10-11T00:00:00Z"},
			b.id: {DeviceID: b.id, Role: "member", Active: true, JoinedAt: "2026-10-11T00:00:00Z"},
		}, Rotations: map[string]store.Rotation{}}
		st.Groups["grp_other"] = store.Group{ID: "grp_other", Name: "other", AuthorityNode: st.NodeID, CreatorID: c.id, Policy: "creator", CreatedAt: "2026-10-11T00:00:00Z", Generation: 1, Members: map[string]store.Member{
			c.id: {DeviceID: c.id, Role: "creator", Active: true, JoinedAt: "2026-10-11T00:00:00Z"},
		}, Rotations: map[string]store.Rotation{}}
		st.Applications["app_0001"] = store.Application{ID: "app_0001", GroupID: "grp_apps", DeviceID: c.id, Status: "pending_approval", CreatedAt: "2026-10-11T00:00:01Z", UpdatedAt: "2026-10-11T00:00:01Z", Approvals: map[string]bool{a.id: false}}
		st.Applications["app_0002"] = store.Application{ID: "app_0002", GroupID: "grp_apps", DeviceID: b.id, Status: "awaiting_key", CreatedAt: "2026-10-11T00:00:02Z", UpdatedAt: "2026-10-11T00:00:02Z", Approvals: map[string]bool{a.id: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if w := n.request(http.MethodGet, "/api/v1/public/groups/grp_apps/applications", nil, nil); w.Code != 401 {
		t.Fatalf("anonymous application list status: %d %s", w.Code, w.Body)
	}
	path := "/api/v1/public/groups/grp_apps/applications?limit=1"
	w := n.signedRequest(t, a, http.MethodGet, path, nil, "application-list-1")
	if w.Code != 200 {
		t.Fatalf("application list: %d %s", w.Code, w.Body)
	}
	first := decodeMap(t, w)
	items := first["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["application_id"] != "app_0001" {
		t.Fatalf("unexpected first application page: %#v", first)
	}
	item := items[0].(map[string]any)
	if item["public_key"] != base64.RawURLEncoding.EncodeToString(c.pub) || item["status"] != "pending_approval" {
		t.Fatalf("application identity/status mismatch: %#v", item)
	}
	cursor := first["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("application list did not return a next cursor")
	}
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/grp_apps/applications?limit=1&cursor="+url.QueryEscape(cursor), nil, "application-list-2")
	if w.Code != 200 {
		t.Fatalf("application list cursor: %d %s", w.Code, w.Body)
	}
	second := decodeMap(t, w)["items"].([]any)
	if len(second) != 1 || second[0].(map[string]any)["application_id"] != "app_0002" {
		t.Fatalf("unexpected second application page: %#v", second)
	}
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/grp_apps/applications/app_0001", nil, "application-detail-1")
	if w.Code != 200 {
		t.Fatalf("application detail: %d %s", w.Code, w.Body)
	}
	detail := decodeMap(t, w)
	if detail["public_key"] != base64.RawURLEncoding.EncodeToString(c.pub) || detail["created_at"] != "2026-10-11T00:00:01Z" {
		t.Fatalf("application detail identity mismatch: %#v", detail)
	}
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/grp_apps/members", nil, "member-list-public-key")
	if w.Code != 200 {
		t.Fatalf("member list: %d %s", w.Code, w.Body)
	}
	members := decodeMap(t, w)["items"].([]any)
	keys := map[string]string{}
	for _, raw := range members {
		m := raw.(map[string]any)
		keys[m["device_id"].(string)] = m["public_key"].(string)
	}
	if keys[a.id] != base64.RawURLEncoding.EncodeToString(a.pub) || keys[b.id] != base64.RawURLEncoding.EncodeToString(b.pub) {
		t.Fatalf("member public keys do not match registered identities: %#v", keys)
	}
	if w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/grp_other/applications", nil, "cross-group-application-list"); w.Code != 403 {
		t.Fatalf("cross-group application list was not forbidden: %d %s", w.Code, w.Body)
	}
	if w = n.signedRequest(t, a, http.MethodDelete, "/api/v1/public/groups/grp_apps/members/"+b.id, []byte("{}"), "revoke-for-application-boundary"); w.Code != 202 {
		t.Fatalf("revoke member: %d %s", w.Code, w.Body)
	}
	if w = n.signedRequest(t, b, http.MethodGet, "/api/v1/public/groups/grp_apps/applications", nil, "revoked-application-list"); w.Code != 403 {
		t.Fatalf("revoked member application list was not forbidden: %d %s", w.Code, w.Body)
	}
}

func TestAdminConfigRejectsUnknownFieldsWithoutChangingConfig(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	secret := strings.Repeat("x", 64)
	body := []byte(`{"schema_version":1,"public_listen":"127.0.0.1:1","admin_listen":"127.0.0.1:2","data_dir":".","admin_token_file":"token","max_storage_bytes":0,"allow_insecure_loopback":true,"peer_relay_enabled":false,"token":"leak"}`)
	w := n.request(http.MethodPut, "/api/v1/admin/config", body, map[string]string{"Authorization": "Bearer " + secret})
	if w.Code != 400 {
		t.Fatalf("unknown config field accepted: %d %s", w.Code, w.Body)
	}
	if n.s.config.PublicListen != "127.0.0.1:8787" {
		t.Fatal("invalid config changed effective config")
	}
}

func TestTLSRequiredOffLoopback(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "203.0.113.4:50000"
	w := httptest.NewRecorder()
	n.s.PublicHandler().ServeHTTP(w, req)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("remote HTTP was not blocked: %d", w.Code)
	}
}

func TestNodeIdentityIsNotDerivedFromAdminToken(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	var got string
	if err := n.st.View(func(st store.State) error { got = st.NodeID; return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "node_") || strings.Contains(got, hex.EncodeToString([]byte(strings.Repeat("x", 64)))) {
		t.Fatalf("unexpected node identity: %s", got)
	}
}

func TestServerCodeIsStableAndUsedForInvitePrefix(t *testing.T) {
	n := newTestNode(t)
	device := n.enroll(t)
	body := []byte(`{"name":"code test","approval_policy":"creator"}`)
	w := n.signedRequest(t, device, http.MethodPost, "/api/v1/public/groups", body, "server-code-group-01")
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", w.Code, w.Body)
	}
	response := decodeMap(t, w)
	code, ok := response["invite_code"].(string)
	if !ok || len(code) != 11 || code[4] != '-' {
		t.Fatalf("invite code has invalid server-code form: %#v", response["invite_code"])
	}
	var storedCode, nodeIdentity string
	if err := n.st.View(func(st store.State) error { storedCode, nodeIdentity = st.ServerCode, st.NodeID; return nil }); err != nil {
		t.Fatal(err)
	}
	if code[:4] != storedCode || len(storedCode) != 4 {
		t.Fatalf("invite prefix must use persisted four-character server code: code=%q server_code=%q node_id=%q", code, storedCode, nodeIdentity)
	}
	nodeInfo := n.request(http.MethodGet, "/api/v1/public/node", nil, nil)
	if nodeInfo.Code != http.StatusOK {
		t.Fatalf("public node info failed: %d %s", nodeInfo.Code, nodeInfo.Body)
	}
	info := decodeMap(t, nodeInfo)
	if info["node_id"] != nodeIdentity || info["server_code"] != storedCode {
		t.Fatalf("public node info mismatch: %#v", info)
	}
	statePath := n.st.Path()
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(statePath, "different-startup-node")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(func(st store.State) error {
		if st.ServerCode != storedCode || st.NodeID != nodeIdentity {
			t.Fatalf("node identities changed after reopen: code=%q node=%q", st.ServerCode, st.NodeID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceNonceReplaySurvivesServerRestart(t *testing.T) {
	n := newTestNode(t)
	device := n.enroll(t)
	body := []byte(`{"name":"nonce test","approval_policy":"creator"}`)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce, err := randomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	idem := "persistent-nonce-01"
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{http.MethodPost, "/api/v1/public/groups", timestamp, nonce, idem, base64.RawURLEncoding.EncodeToString(sum[:])}, "\n")
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(device.priv, []byte(canonical)))
	headers := map[string]string{"X-Device-ID": device.id, "X-Device-Timestamp": timestamp, "X-Device-Nonce": nonce, "X-Device-Signature": signature, "Idempotency-Key": idem}
	first := n.request(http.MethodPost, "/api/v1/public/groups", body, headers)
	if first.Code != http.StatusCreated {
		t.Fatalf("first signed request failed: %d %s", first.Code, first.Body)
	}
	statePath := n.st.Path()
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(statePath, "ignored-restart-node")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(n.cfg, n.configPath, reopened)
	if err != nil {
		t.Fatal(err)
	}
	replay := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/groups", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	restarted.PublicHandler().ServeHTTP(replay, req)
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), "replayed_device_proof") {
		t.Fatalf("nonce replay was accepted after restart: %d %s", replay.Code, replay.Body)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminStatusReportsUnsupportedAndConfiguredStatesHonestly(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	status := n.s.statusData()
	if status["connected_devices"] != nil || status["connected_devices_state"] != "not_supported" {
		t.Fatalf("connected-device count should be explicitly unknown without session tracking: %#v", status)
	}
	if status["storage_state"] != "available" || status["peer_relay_state"] != "disabled" {
		t.Fatalf("unexpected operational state: %#v", status)
	}
	n.cfg.PeerRelayEnabled = true
	n.s.replaceConfig(n.cfg)
	if got := n.s.statusData()["peer_relay_state"]; got != "not_implemented" {
		t.Fatalf("enabled peer relay must be reported as unimplemented: %v", got)
	}
	if got := n.s.storageData()["state"]; got != "available" {
		t.Fatalf("storage endpoint state should use a live check: %v", got)
	}
}

func TestAdminCommandRegistryHelpCompletionAndStructuredExecution(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	token := strings.Repeat("x", 64)
	admin := map[string]string{"Authorization": "Bearer " + token}
	w := n.request(http.MethodGet, "/api/v1/admin/commands", nil, admin)
	if w.Code != 200 {
		t.Fatalf("registry status %d: %s", w.Code, w.Body)
	}
	var registry struct {
		Items []CommandDefinition `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &registry); err != nil {
		t.Fatal(err)
	}
	localOnly := map[string]bool{}
	for _, cmd := range registry.Items {
		if cmd.Path == "token create" || cmd.Path == "token rotate" {
			localOnly[cmd.Path] = cmd.LocalOnly
		}
	}
	if !localOnly["token create"] || !localOnly["token rotate"] {
		t.Fatal("token create and rotation must be advertised as local_only")
	}
	w = n.request(http.MethodGet, "/api/v1/admin/commands/help?path=groups%20list", nil, admin)
	if w.Code != 200 {
		t.Fatalf("help status %d", w.Code)
	}
	w = n.request(http.MethodPost, "/api/v1/admin/commands/complete", []byte(`{"words":["config","set"],"cursor_position":2}`), admin)
	if w.Code != 200 {
		t.Fatalf("completion status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("completion leaked admin token")
	}
	if !strings.Contains(w.Body.String(), "max_storage_bytes") {
		t.Fatal("config key completion is missing")
	}
	w = n.request(http.MethodPost, "/api/v1/admin/commands/execute", []byte(`{"argv":["status"],"flags":{}}`), admin)
	if w.Code != 200 {
		t.Fatalf("structured status command: %d %s", w.Code, w.Body)
	}
	var result commandResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" || result.RequestID == "" {
		t.Fatalf("invalid command result: %#v", result)
	}
	w = n.request(http.MethodPost, "/api/v1/admin/commands/execute", []byte(`{"argv":["shell","whoami"]}`), admin)
	if w.Code != 400 {
		t.Fatalf("arbitrary command accepted: %d", w.Code)
	}
	for _, action := range []string{"create", "rotate"} {
		w = n.request(http.MethodPost, "/api/v1/admin/commands/execute", []byte(`{"argv":["token","`+action+`"]}`), admin)
		if w.Code != 403 || strings.Contains(w.Body.String(), "token\"") {
			t.Fatalf("local token action %s was exposed over API: %d %s", action, w.Code, w.Body)
		}
	}
}

func TestConfigSetResolvesRelativePathsAndReportsRestartRequirement(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	token := strings.Repeat("x", 64)
	admin := map[string]string{"Authorization": "Bearer " + token, "Idempotency-Key": "config-update-001"}
	w := n.request(http.MethodPost, "/api/v1/admin/commands/execute", []byte(`{"argv":["config","set"],"flags":{"key":"data_dir","value":"./new-data"}}`), admin)
	if w.Code != http.StatusOK {
		t.Fatalf("config set status %d: %s", w.Code, w.Body)
	}
	var result struct {
		Data struct {
			Config          Config `json:"config"`
			RestartRequired bool   `json:"restart_required"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(filepath.Dir(n.configPath), "new-data")
	if result.Data.Config.DataDir != wantDir || !result.Data.RestartRequired {
		t.Fatalf("config set should persist an effective path and request restart: got %#v want data_dir %q", result.Data, wantDir)
	}
}
