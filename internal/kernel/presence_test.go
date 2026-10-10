package kernel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aries.local/aries/internal/store"
)

func presenceGroup(t *testing.T) (testNode, testDevice, testDevice, string) {
	t.Helper()
	n := newTestNode(t)
	a, b := n.enroll(t), n.enroll(t)
	w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"presence","approval_policy":"creator"}`), "presence-group-0001")
	if w.Code != http.StatusCreated {
		n.close(t)
		t.Fatalf("create group: %d %s", w.Code, w.Body)
	}
	group := decodeMap(t, w)["group_id"].(string)
	if err := n.st.Update(func(st *store.State) error {
		g := st.Groups[group]
		g.Members[b.id] = store.Member{DeviceID: b.id, Role: "member", Active: true, JoinedAt: time.Now().UTC().Format(time.RFC3339)}
		st.Groups[group] = g
		return nil
	}); err != nil {
		n.close(t)
		t.Fatal(err)
	}
	return n, a, b, group
}

func presenceItems(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.Items
}

func TestDeviceHeartbeatAndGroupPresence(t *testing.T) {
	n, a, b, group := presenceGroup(t)
	defer n.close(t)

	w := n.request(http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{}`), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous heartbeat: %d %s", w.Code, w.Body)
	}

	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"client_version":"launcher/1"}`), "heartbeat-a-0001")
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body)
	}
	var heartbeat map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &heartbeat); err != nil {
		t.Fatal(err)
	}
	if heartbeat["device_id"] != a.id || heartbeat["online"] != true || heartbeat["client_version"] != "launcher/1" {
		t.Fatalf("unexpected heartbeat response: %#v", heartbeat)
	}

	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "presence-a-0001")
	if w.Code != http.StatusOK {
		t.Fatalf("presence: %d %s", w.Code, w.Body)
	}
	items := presenceItems(t, w)
	if len(items) != 2 {
		t.Fatalf("presence is not complete: %#v", items)
	}
	var aItem, bItem map[string]any
	for _, item := range items {
		switch item["device_id"] {
		case a.id:
			aItem = item
		case b.id:
			bItem = item
		}
	}
	if aItem == nil || bItem == nil || aItem["online"] != true || bItem["online"] != false || aItem["client_version"] != "launcher/1" {
		t.Fatalf("unexpected presence: %#v", items)
	}

	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"client_version":""}`), "heartbeat-a-0002")
	if w.Code != http.StatusOK {
		t.Fatalf("empty client version heartbeat: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"client_version":"`+strings.Repeat("x", 65)+`"}`), "heartbeat-a-0003")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized client version accepted: %d %s", w.Code, w.Body)
	}
}

func TestGroupPresenceExpiresAndRevocationIsImmediate(t *testing.T) {
	n, a, b, group := presenceGroup(t)
	defer n.close(t)
	n.s.config.HeartbeatIntervalSeconds = 1
	n.s.config.HeartbeatTimeoutSeconds = 1

	for _, d := range []testDevice{a, b} {
		w := n.signedRequest(t, d, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{}`), "heartbeat-expire-"+d.id)
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %s: %d %s", d.id, w.Code, w.Body)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	w := n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "presence-expire-0001")
	if w.Code != http.StatusOK {
		t.Fatalf("expired presence: %d %s", w.Code, w.Body)
	}
	for _, item := range presenceItems(t, w) {
		if item["online"] != false {
			t.Fatalf("expired device reported online: %#v", item)
		}
	}

	w = n.signedRequest(t, a, http.MethodDelete, "/api/v1/public/groups/"+group+"/members/"+b.id, []byte(`{}`), "revoke-presence-0001")
	if w.Code != http.StatusAccepted {
		t.Fatalf("revoke member: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, b, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "presence-revoked-0001")
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked member could read presence: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "presence-revoked-0002")
	if w.Code != http.StatusOK || len(presenceItems(t, w)) != 1 {
		t.Fatalf("revoked member remained in presence: %d %s", w.Code, w.Body)
	}
}

func TestGroupPresenceDoesNotSurviveRestartOrCrossGroupAccess(t *testing.T) {
	n, a, b, group := presenceGroup(t)
	w := n.signedRequest(t, b, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"other","approval_policy":"creator"}`), "presence-other-0001")
	if w.Code != http.StatusCreated {
		t.Fatalf("create second group: %d %s", w.Code, w.Body)
	}
	other := decodeMap(t, w)["group_id"].(string)
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+other+"/presence", nil, "presence-cross-group-1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-group presence access: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{}`), "heartbeat-restart-0001")
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat before restart: %d %s", w.Code, w.Body)
	}
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(n.st.Path(), "ignored")
	if err != nil {
		t.Fatal(err)
	}
	n.st = reopened
	n.s, err = New(n.cfg, n.configPath, reopened)
	if err != nil {
		t.Fatal(err)
	}
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "presence-after-restart")
	if w.Code != http.StatusOK {
		t.Fatalf("presence after restart: %d %s", w.Code, w.Body)
	}
	for _, item := range presenceItems(t, w) {
		if item["online"] != false {
			t.Fatalf("historical heartbeat survived restart: %#v", item)
		}
	}
}
