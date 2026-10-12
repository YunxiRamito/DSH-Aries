package kernel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"aries.local/aries/internal/store"
)

func heartbeatName(t *testing.T, n testNode, d testDevice, name string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"device_name": name})
	if err != nil {
		t.Fatal(err)
	}
	w := n.signedRequest(t, d, http.MethodPost, "/api/v1/public/devices/heartbeat", body, "")
	if w.Code != http.StatusOK || decodeMap(t, w)["device_name"] != strings.TrimSpace(name) {
		t.Fatalf("name heartbeat: %d %s", w.Code, w.Body)
	}
}

func TestDeviceNameRoundTripPersistenceAndIdentity(t *testing.T) {
	n, a, b, group := presenceGroup(t)
	defer func() { n.close(t) }()
	heartbeatName(t, n, a, "  我的电脑 🖥️  ")
	heartbeatName(t, n, b, "OPPO Find X8")
	path := "/api/v1/public/groups/" + group + "/members"
	checkMembers := func() {
		t.Helper()
		w := n.signedRequest(t, a, http.MethodGet, path, nil, "")
		if w.Code != http.StatusOK {
			t.Fatalf("members: %d %s", w.Code, w.Body)
		}
		items := decodeMap(t, w)["items"].([]any)
		if len(items) != 2 {
			t.Fatalf("expected both members: %s", w.Body)
		}
		want := map[string]string{a.id: "我的电脑 🖥️", b.id: "OPPO Find X8"}
		keys := map[string]string{a.id: base64.RawURLEncoding.EncodeToString(a.pub), b.id: base64.RawURLEncoding.EncodeToString(b.pub)}
		for _, raw := range items {
			item := raw.(map[string]any)
			id := item["device_id"].(string)
			if item["device_name"] != want[id] || item["public_key"] != keys[id] {
				t.Fatalf("name changed identity or did not round trip: %#v", item)
			}
		}
	}
	checkMembers()
	// Enrollment of the original registered key retains the existing name and
	// the unchanged enrollment-proof canonical form.
	encoded := base64.RawURLEncoding.EncodeToString(a.pub)
	challengeBody, _ := json.Marshal(map[string]string{"public_key": encoded})
	w := n.request(http.MethodPost, "/api/v1/public/devices/challenge", challengeBody, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("re-enrollment challenge: %d %s", w.Code, w.Body)
	}
	challenge := decodeMap(t, w)
	challengeID, nonce := challenge["challenge_id"].(string), challenge["nonce"].(string)
	signature := ed25519.Sign(a.priv, []byte("enroll\n"+challengeID+"\n"+nonce+"\n"+encoded))
	enrollBody, _ := json.Marshal(map[string]string{"challenge_id": challengeID, "signature": base64.RawURLEncoding.EncodeToString(signature)})
	w = n.request(http.MethodPost, "/api/v1/public/devices/enroll", enrollBody, map[string]string{"Idempotency-Key": "named-reenrollment-" + challengeID})
	if w.Code != http.StatusOK || decodeMap(t, w)["device_id"] != a.id {
		t.Fatalf("re-enrollment changed identity: %d %s", w.Code, w.Body)
	}
	checkMembers()
	// A repeated value or an old heartbeat must not rewrite the snapshot.
	snapshotPath := n.st.Path()
	marker := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(snapshotPath, marker, marker); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"client_version":"old-client/1"}`, `{"device_name":null}`, `{"device_name":"我的电脑 🖥️"}`} {
		w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(body), "")
		if w.Code != http.StatusOK || decodeMap(t, w)["device_name"] != "我的电脑 🖥️" {
			t.Fatalf("old/repeated heartbeat lost name: %d %s", w.Code, w.Body)
		}
	}
	after, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || !info.ModTime().Equal(marker) {
		t.Fatal("omitted or unchanged device_name rewrote the durable snapshot")
	}
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	n.st, err = store.Open(snapshotPath, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	n.s, err = New(n.cfg, n.configPath, n.st)
	if err != nil {
		t.Fatal(err)
	}
	checkMembers() // The same device signatures work after restoring names.
	w = n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/"+group+"/presence", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("presence after restart: %d %s", w.Code, w.Body)
	}
	for _, item := range presenceItems(t, w) {
		if item["online"] != false {
			t.Fatalf("persistent display name resurrected heartbeat: %#v", item)
		}
	}
}

func TestDeviceNameFailedCommitDoesNotRefreshPresence(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a := n.enroll(t)
	heartbeatName(t, n, a, "Original")
	n.s.presenceMu.Lock()
	before := n.s.presence[a.id]
	n.s.presenceMu.Unlock()
	// Keep the nonce log writable while obstructing only snapshot replacement.
	path, backup := n.st.Path(), n.st.Path()+".test-backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(path)
		if err := os.Rename(backup, path); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"device_name":"Uncommitted","client_version":"failed-version"}`), "")
	if w.Code != http.StatusInternalServerError || decodeMap(t, w)["error"].(map[string]any)["code"] != "storage_unavailable" {
		t.Fatalf("failed durable rename response: %d %s", w.Code, w.Body)
	}
	n.s.presenceMu.Lock()
	after := n.s.presence[a.id]
	n.s.presenceMu.Unlock()
	if before != after {
		t.Fatalf("failed durable name update refreshed presence: before=%#v after=%#v", before, after)
	}
	if err := n.st.View(func(st store.State) error {
		if st.Devices[a.id].DeviceName != "Original" {
			t.Fatal("failed durable rename was published")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceNameValidationDoesNotPolluteStoredIdentity(t *testing.T) {
	n, a, b, _ := presenceGroup(t)
	defer n.close(t)
	heartbeatName(t, n, a, "Original")
	for i, name := range []string{"", "   ", strings.Repeat("界", 129), "bad\nname", "bad\tname", "bad\x00name", "bad\u0085name", "bad\u007fname", "\nOriginal\n"} {
		body, _ := json.Marshal(map[string]string{"device_name": name})
		w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/devices/heartbeat", body, "")
		if w.Code != http.StatusBadRequest || decodeMap(t, w)["error"].(map[string]any)["code"] != "invalid_device_name" {
			t.Fatalf("invalid name %d accepted or wrong error: %d %s", i, w.Code, w.Body)
		}
	}
	// The claimed identity cannot authorize a change with another device's key.
	impersonator := b
	impersonator.id = a.id
	w := n.signedRequest(t, impersonator, http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"device_name":"Impersonated"}`), "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("forged name heartbeat: %d %s", w.Code, w.Body)
	}
	w = n.request(http.MethodPost, "/api/v1/public/devices/heartbeat", []byte(`{"device_name":"Anonymous"}`), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous name heartbeat: %d %s", w.Code, w.Body)
	}
	if err := n.st.View(func(st store.State) error {
		d := st.Devices[a.id]
		if d.DeviceName != "Original" || d.ID != a.id || d.PublicKey != base64.RawURLEncoding.EncodeToString(a.pub) {
			t.Fatalf("invalid or unauthorized name update polluted identity: %#v", d)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	heartbeatName(t, n, a, strings.Repeat("界", 128)) // Unicode characters, not bytes.
	heartbeatName(t, n, a, "OPPO Find X8")
	info := decodeMap(t, n.request(http.MethodGet, "/api/v1/public/node", nil, nil))
	capabilities := map[string]bool{}
	for _, raw := range info["capabilities"].([]any) {
		capabilities[raw.(string)] = true
	}
	for _, name := range []string{"device_name", "group_applications", "device_public_key", "device_presence", "group_file_cache_cleanup"} {
		if !capabilities[name] {
			t.Errorf("node does not advertise %s: %#v", name, info)
		}
	}
}

func TestPairingApplicationsNamesApprovalRejectionAndKeyAcknowledgement(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b, c, outsider := n.enroll(t), n.enroll(t), n.enroll(t), n.enroll(t)
	heartbeatName(t, n, b, "OPPO Find X8")
	heartbeatName(t, n, c, "另一台手机")
	w := n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"pairing","approval_policy":"creator"}`), "name-pairing-group")
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", w.Code, w.Body)
	}
	created := decodeMap(t, w)
	group, invite := created["group_id"].(string), created["invite_code"].(string)
	base := "/api/v1/public/groups/" + group
	for _, suffix := range []string{"/applications", "/members"} {
		w = n.request(http.MethodGet, base+suffix, nil, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous could read %s: %d %s", suffix, w.Code, w.Body)
		}
	}
	w = n.signedRequest(t, a, http.MethodGet, base+"/applications", nil, "")
	if w.Code != http.StatusOK || len(decodeMap(t, w)["items"].([]any)) != 0 {
		t.Fatalf("empty application list is not usable: %d %s", w.Code, w.Body)
	}
	apply := func(d testDevice, key string) string {
		t.Helper()
		w := n.signedRequest(t, d, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", []byte(`{}`), key)
		if w.Code != http.StatusCreated {
			t.Fatalf("apply: %d %s", w.Code, w.Body)
		}
		return decodeMap(t, w)["application_id"].(string)
	}
	appB, appC := apply(b, "name-pairing-apply-b"), apply(c, "name-pairing-apply-c")
	w = n.signedRequest(t, outsider, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"other","approval_policy":"creator"}`), "name-pairing-other-group")
	if w.Code != http.StatusCreated {
		t.Fatalf("other group: %d %s", w.Code, w.Body)
	}
	otherBase := "/api/v1/public/groups/" + decodeMap(t, w)["group_id"].(string)
	for _, suffix := range []string{"/applications", "/members"} {
		w = n.signedRequest(t, a, http.MethodGet, otherBase+suffix, nil, "")
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-group read %s: %d %s", suffix, w.Code, w.Body)
		}
	}
	w = n.signedRequest(t, outsider, http.MethodGet, otherBase+"/applications/"+appB, nil, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-group application id leaked detail: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, outsider, http.MethodGet, base+"/applications/"+appB, nil, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("outsider application detail: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, a, http.MethodGet, base+"/applications", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list real applications: %d %s", w.Code, w.Body)
	}
	items := decodeMap(t, w)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected both pending applications: %s", w.Body)
	}
	for _, raw := range items {
		item := raw.(map[string]any)
		wantName, wantKey := "OPPO Find X8", base64.RawURLEncoding.EncodeToString(b.pub)
		if item["device_id"] == c.id {
			wantName, wantKey = "另一台手机", base64.RawURLEncoding.EncodeToString(c.pub)
		}
		if item["device_name"] != wantName || item["public_key"] != wantKey {
			t.Fatalf("application name/identity mismatch: %#v", item)
		}
	}
	for _, d := range []testDevice{b, outsider} {
		for _, suffix := range []string{"/applications", "/members"} {
			w = n.signedRequest(t, d, http.MethodGet, base+suffix, nil, "")
			if w.Code != http.StatusForbidden {
				t.Fatalf("nonmember could read %s: %d %s", suffix, w.Code, w.Body)
			}
		}
	}
	w = n.signedRequest(t, b, http.MethodGet, base+"/applications/"+appB, nil, "")
	if w.Code != http.StatusOK || decodeMap(t, w)["device_name"] != "OPPO Find X8" {
		t.Fatalf("owner cannot read named application: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, outsider, http.MethodPost, base+"/applications/"+appB+"/approvals", []byte(`{"approve":true}`), "name-pairing-unauthorized")
	if w.Code != http.StatusForbidden {
		t.Fatalf("outsider approved application: %d %s", w.Code, w.Body)
	}
	for _, action := range []struct{ app, body, status string }{{appB, `{"approve":true}`, "awaiting_key"}, {appC, `{"approve":false}`, "rejected"}} {
		w = n.signedRequest(t, a, http.MethodPost, base+"/applications/"+action.app+"/approvals", []byte(action.body), "name-pairing-approve-"+action.app)
		if w.Code != http.StatusOK || decodeMap(t, w)["status"] != action.status {
			t.Fatalf("approval/rejection: %d %s", w.Code, w.Body)
		}
	}
	const envelope = "ZW5jcnlwdGVkLWtleS1lbmdlbG9wZQ"
	for i, app := range []string{appC, appB} {
		w = n.signedRequest(t, a, http.MethodPost, base+"/applications/"+app+"/key-delivery", []byte(fmt.Sprintf(`{"envelope":%q}`, envelope)), "name-pairing-delivery-"+app)
		want := http.StatusCreated
		if i == 0 {
			want = http.StatusConflict
		}
		if w.Code != want {
			t.Fatalf("key delivery: %d %s", w.Code, w.Body)
		}
	}
	w = n.signedRequest(t, b, http.MethodGet, base+"/key-deliveries", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("key poll: %d %s", w.Code, w.Body)
	}
	deliveries := decodeMap(t, w)["items"].([]any)
	if len(deliveries) != 1 || deliveries[0].(map[string]any)["envelope"] != envelope {
		t.Fatalf("opaque key envelope was lost or altered: %s", w.Body)
	}
	delivery := deliveries[0].(map[string]any)["id"].(string)
	ackPath := base + "/key-deliveries/" + delivery + "/ack"
	w = n.signedRequest(t, a, http.MethodPost, ackPath, []byte(`{}`), "name-pairing-wrong-ack")
	if w.Code != http.StatusForbidden {
		t.Fatalf("sender acknowledged recipient key: %d %s", w.Code, w.Body)
	}
	for i := 0; i < 2; i++ {
		w = n.signedRequest(t, b, http.MethodPost, ackPath, []byte(`{}`), "name-pairing-ack")
		if w.Code != http.StatusOK || decodeMap(t, w)["status"] != "acknowledged" {
			t.Fatalf("key acknowledgement/replay: %d %s", w.Code, w.Body)
		}
	}
	w = n.signedRequest(t, b, http.MethodGet, base+"/key-deliveries", nil, "")
	if w.Code != http.StatusOK || len(decodeMap(t, w)["items"].([]any)) != 0 {
		t.Fatalf("acknowledged envelope remained pending: %d %s", w.Code, w.Body)
	}
	// Generic groups still admit a third member after a rejected application.
	appC = apply(c, "name-pairing-reapply-c")
	for _, step := range []struct {
		suffix, body, key string
		status            int
	}{
		{"/approvals", `{"approve":true}`, "name-pairing-reapprove", http.StatusOK},
		{"/key-delivery", fmt.Sprintf(`{"envelope":%q}`, envelope), "name-pairing-redeliver", http.StatusCreated},
	} {
		w = n.signedRequest(t, a, http.MethodPost, base+"/applications/"+appC+step.suffix, []byte(step.body), step.key)
		if w.Code != step.status {
			t.Fatalf("third member: %d %s", w.Code, w.Body)
		}
	}
	w = n.signedRequest(t, a, http.MethodGet, base+"/members", nil, "")
	if w.Code != http.StatusOK || len(decodeMap(t, w)["items"].([]any)) != 3 {
		t.Fatalf("generic group rejected third member: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, a, http.MethodDelete, base+"/members/"+b.id, []byte(`{}`), "name-pairing-revoke-b")
	if w.Code != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	for _, suffix := range []string{"/applications", "/applications/" + appC, "/members", "/key-deliveries"} {
		w = n.signedRequest(t, b, http.MethodGet, base+suffix, nil, "")
		if w.Code != http.StatusForbidden {
			t.Fatalf("revoked member could read %s: %d %s", suffix, w.Code, w.Body)
		}
	}
}
