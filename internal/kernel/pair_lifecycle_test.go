package kernel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"aries.local/aries/internal/store"
)

func lifecycleGroup(t *testing.T, n testNode, creator testDevice, key string) (string, string) {
	t.Helper()
	w := n.signedRequest(t, creator, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"lifecycle","approval_policy":"creator"}`), key)
	lifecycleHTTP(t, w, http.StatusCreated, "")
	v := decodeMap(t, w)
	return v["group_id"].(string), v["invite_code"].(string)
}

// These fixtures exercise registration, approval and opaque delivery over the
// actual signed public handler. No device identity or membership is fabricated.
func lifecycleJoin(t *testing.T, n testNode, creator, recipient testDevice, group, invite, key string) (string, string) {
	t.Helper()
	w := n.signedRequest(t, recipient, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", []byte(`{}`), key+"-apply")
	lifecycleHTTP(t, w, http.StatusCreated, "")
	app := decodeMap(t, w)["application_id"].(string)
	base := "/api/v1/public/groups/" + group + "/applications/" + app
	w = n.signedRequest(t, creator, http.MethodPost, base+"/approvals", []byte(`{"approve":true}`), key+"-approve")
	lifecycleHTTP(t, w, http.StatusOK, "")
	w = n.signedRequest(t, creator, http.MethodPost, base+"/key-delivery", []byte(`{"envelope":"ZW5jcnlwdGVkLWtleS1lbmdlbG9wZQ"}`), key+"-delivery")
	lifecycleHTTP(t, w, http.StatusCreated, "")
	w = n.signedRequest(t, recipient, http.MethodGet, "/api/v1/public/groups/"+group+"/key-deliveries", nil, "")
	lifecycleHTTP(t, w, http.StatusOK, "")
	for _, raw := range decodeMap(t, w)["items"].([]any) {
		item := raw.(map[string]any)
		if item["recipient_id"] == recipient.id {
			return app, item["id"].(string)
		}
	}
	t.Fatal("new recipient did not receive the opaque envelope")
	return "", ""
}

func lifecycleHTTP(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("response status want %d got %d: %s", status, w.Code, w.Body)
	}
	if code != "" && decodeMap(t, w)["error"].(map[string]any)["code"] != code {
		t.Fatalf("expected error %q: %s", code, w.Body)
	}
}

func lifecycleRestart(t *testing.T, n *testNode) {
	t.Helper()
	path := n.st.Path()
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	n.st, err = store.Open(path, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	n.s, err = New(n.cfg, n.configPath, n.st)
	if err != nil {
		t.Fatal(err)
	}
}

func lifecycleRead(t *testing.T, n testNode, d testDevice, path string) map[string]any {
	t.Helper()
	w := n.signedRequest(t, d, http.MethodGet, path, nil, "")
	lifecycleHTTP(t, w, http.StatusOK, "")
	return decodeMap(t, w)
}

func lifecycleConfirmation(t *testing.T, v map[string]any, status, delivery, recipient string, epoch uint64) string {
	t.Helper()
	if v["key_confirmation_status"] != status || v["key_delivery_id"] != delivery || v["key_recipient_id"] != recipient || v["key_epoch"] != float64(epoch) {
		t.Fatalf("incorrect confirmation binding: %#v", v)
	}
	confirmed, _ := v["confirmed_at"].(string)
	if status == "acknowledged" {
		if ts, err := time.Parse(time.RFC3339Nano, confirmed); err != nil || ts.Location() != time.UTC {
			t.Fatalf("confirmation lacks valid UTC server time: %#v", v)
		}
	} else if confirmed != "" {
		t.Fatalf("unconfirmed/revoked key exposes confirmed_at: %#v", v)
	}
	if _, ok := v["envelope"]; ok {
		t.Fatal("confirmation metadata leaked the opaque envelope")
	}
	return confirmed
}

func TestKeyConfirmationRecipientAckObservableAndDurable(t *testing.T) {
	n := newTestNode(t)
	defer func() { n.close(t) }()
	a, b, outsider := n.enroll(t), n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "confirmation-group")
	app, delivery := lifecycleJoin(t, n, a, b, group, invite, "confirmation-join")
	base := "/api/v1/public/groups/" + group
	detail := base + "/applications/" + app
	for _, d := range []testDevice{a, b} {
		v := lifecycleRead(t, n, d, detail)
		if v["status"] != "approved" {
			t.Fatal("confirmation changed the established application status")
		}
		lifecycleConfirmation(t, v, "awaiting_ack", delivery, b.id, 1)
	}
	lifecycleHTTP(t, n.request(http.MethodGet, detail, nil, nil), http.StatusUnauthorized, "")
	lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodGet, detail, nil, ""), http.StatusForbidden, "")
	ack := base + "/key-deliveries/" + delivery + "/ack"
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, ack, []byte(`{}`), "confirmation-wrong-ack"), http.StatusForbidden, "delivery_recipient_mismatch")
	lifecycleConfirmation(t, lifecycleRead(t, n, a, detail), "awaiting_ack", delivery, b.id, 1)
	w := n.signedRequest(t, b, http.MethodPost, ack, []byte(`{}`), "confirmation-real-ack")
	lifecycleHTTP(t, w, http.StatusOK, "")
	confirmed := lifecycleConfirmation(t, lifecycleRead(t, n, a, detail), "acknowledged", delivery, b.id, 1)
	if decodeMap(t, w)["acknowledged_at"] != confirmed {
		t.Fatal("sender view does not reflect persisted recipient acknowledgement time")
	}
	for _, key := range []string{"confirmation-real-ack", "confirmation-second-key"} {
		w = n.signedRequest(t, b, http.MethodPost, ack, []byte(`{}`), key)
		lifecycleHTTP(t, w, http.StatusOK, "")
		if decodeMap(t, w)["acknowledged_at"] != confirmed {
			t.Fatal("repeat acknowledgement changed the first confirmation time")
		}
	}
	lifecycleRestart(t, &n)
	if lifecycleConfirmation(t, lifecycleRead(t, n, a, detail), "acknowledged", delivery, b.id, 1) != confirmed {
		t.Fatal("confirmation timestamp changed across restart")
	}
	for _, raw := range lifecycleRead(t, n, a, base+"/members")["items"].([]any) {
		v := raw.(map[string]any)
		if v["device_id"] == b.id {
			if lifecycleConfirmation(t, v, "acknowledged", delivery, b.id, 1) != confirmed {
				t.Fatal("member list does not expose application confirmation")
			}
		}
	}
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodDelete, base+"/members/"+b.id, []byte(`{}`), "confirmation-revoke"), http.StatusAccepted, "")
	lifecycleConfirmation(t, lifecycleRead(t, n, a, detail), "revoked", delivery, b.id, 1)
	// Existing application owners retain their own application-detail access;
	// that display permission must never preserve a trusted confirmation.
	lifecycleConfirmation(t, lifecycleRead(t, n, b, detail), "revoked", delivery, b.id, 1)
}

func TestKeyConfirmationLegacyBindingsFailClosed(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b := n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "legacy-confirmation-group")
	app, delivery := lifecycleJoin(t, n, a, b, group, invite, "legacy-confirmation-join")
	base := "/api/v1/public/groups/" + group
	lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "legacy-confirmation-ack"), http.StatusOK, "")
	// Simulate a pre-capability snapshot: no join binding, only its original
	// acknowledged bool. A server must not guess a trusted confirmation from it.
	if err := n.st.Update(func(st *store.State) error {
		appValue := st.Applications[app]
		appValue.KeyDeliveryID = ""
		st.Applications[app] = appValue
		g := st.Groups[group]
		m := g.Members[b.id]
		m.KeyDeliveryID = ""
		g.Members[b.id] = m
		st.Groups[group] = g
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []map[string]any{lifecycleRead(t, n, a, base+"/applications/"+app), lifecycleRead(t, n, b, base+"/applications/"+app)} {
		if v["key_confirmation_status"] != "unknown" || v["confirmed_at"] != nil || v["key_delivery_id"] != nil {
			t.Fatalf("legacy snapshot guessed confirmed identity: %#v", v)
		}
	}
	for _, raw := range lifecycleRead(t, n, a, base+"/members")["items"].([]any) {
		if v := raw.(map[string]any); v["key_confirmation_status"] != "unknown" || v["confirmed_at"] != nil {
			t.Fatalf("legacy member guessed confirmed identity: %#v", v)
		}
	}
}

func TestKeyConfirmationFailedCommitRemainsAwaitingAck(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b := n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "failed-confirmation-group")
	app, delivery := lifecycleJoin(t, n, a, b, group, invite, "failed-confirmation-join")
	base := "/api/v1/public/groups/" + group
	restore := lifecycleBlockSnapshot(t, n)
	w := n.signedRequest(t, b, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "failed-confirmation-ack")
	lifecycleHTTP(t, w, http.StatusInternalServerError, "storage_unavailable")
	lifecycleConfirmation(t, lifecycleRead(t, n, a, base+"/applications/"+app), "awaiting_ack", delivery, b.id, 1)
	restore()
	lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "failed-confirmation-ack"), http.StatusOK, "")
	lifecycleConfirmation(t, lifecycleRead(t, n, a, base+"/applications/"+app), "acknowledged", delivery, b.id, 1)
}

func lifecycleBlockSnapshot(t *testing.T, n testNode) func() {
	t.Helper()
	path, backup := n.st.Path(), n.st.Path()+".lifecycle-backup"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		_ = os.Rename(backup, path)
		t.Fatal(err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
			if err := os.Rename(backup, path); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

func TestUnpairBothRolesBeforeAndAfterAckAndDurableReplay(t *testing.T) {
	for _, initiator := range []string{"creator", "member"} {
		for _, acknowledged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ack=%t", initiator, acknowledged), func(t *testing.T) {
				n := newTestNode(t)
				defer func() { n.close(t) }()
				a, b, outsider := n.enroll(t), n.enroll(t), n.enroll(t)
				group, invite := lifecycleGroup(t, n, a, "unpair-role-group")
				_, delivery := lifecycleJoin(t, n, a, b, group, invite, "unpair-role-join")
				base := "/api/v1/public/groups/" + group
				if acknowledged {
					lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "unpair-role-ack"), http.StatusOK, "")
				}
				caller := a
				if initiator == "member" {
					caller = b
				}
				headers := lifecycleHeaders(t, caller, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-role-operation")
				w := n.request(http.MethodPost, base+"/unpair", []byte(`{}`), headers)
				lifecycleHTTP(t, w, http.StatusOK, "")
				original := w.Body.String()
				if got := decodeMap(t, w); got["group_id"] != group || got["device_id"] != caller.id || got["status"] != "unpaired" || len(got) != 3 {
					t.Fatalf("unpair success is not exact caller-bound contract: %#v", got)
				}
				for restart := 0; restart < 2; restart++ {
					lifecycleHTTP(t, n.request(http.MethodPost, base+"/unpair", []byte(`{}`), headers), http.StatusConflict, "replayed_device_proof")
					w = n.signedRequest(t, caller, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-role-operation")
					lifecycleHTTP(t, w, http.StatusOK, "")
					if w.Body.String() != original {
						t.Fatal("lost-response retry changed the committed result")
					}
					lifecycleHTTP(t, n.signedRequest(t, caller, http.MethodPost, base+"/unpair", []byte(`{"other":true}`), "unpair-role-operation"), http.StatusConflict, "idempotency_conflict")
					for _, d := range []testDevice{a, b} {
						v := lifecycleRead(t, n, d, base+"/pairing-status")
						if v["group_id"] != group || v["device_id"] != d.id || v["status"] != "unpaired" || v["unpaired_at"] == nil {
							t.Fatalf("offline peer cannot observe a specific terminal state: %#v", v)
						}
					}
					lifecycleRestart(t, &n)
				}
				lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodGet, base+"/pairing-status", nil, ""), http.StatusForbidden, "membership_required")
				lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-role-operation"), http.StatusForbidden, "membership_required")
				// The other original member can independently confirm an already
				// closed pair, even without the initiator's operation key.
				w = n.signedRequest(t, b, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-peer-confirm")
				lifecycleHTTP(t, w, http.StatusOK, "")
				if decodeMap(t, w)["device_id"] != b.id {
					t.Fatal("peer replay was bound to the wrong caller")
				}
			})
		}
	}
}

func TestUnpairRejectsNonPairAndUnauthorizedRequests(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b, c, outsider := n.enroll(t), n.enroll(t), n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "unpair-boundary-group")
	base := "/api/v1/public/groups/" + group
	lifecycleHTTP(t, n.request(http.MethodPost, base+"/unpair", []byte(`{}`), nil), http.StatusUnauthorized, "")
	lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-outsider"), http.StatusForbidden, "membership_required")
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-single-member"), http.StatusConflict, "pair_not_two_devices")
	w := n.signedRequest(t, b, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", []byte(`{}`), "unpair-only-pending")
	lifecycleHTTP(t, w, http.StatusCreated, "")
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-pending-member"), http.StatusConflict, "pair_not_two_devices")
	lifecycleJoin(t, n, a, b, group, invite, "unpair-boundary-b")
	lifecycleJoin(t, n, a, c, group, invite, "unpair-boundary-c")
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-multi-member"), http.StatusConflict, "pair_not_two_devices")
	if len(lifecycleRead(t, n, a, base+"/members")["items"].([]any)) != 3 {
		t.Fatal("rejected unpair destroyed the generic multi-member group")
	}
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodDelete, base+"/members/"+c.id, []byte(`{}`), "unpair-boundary-revoke"), http.StatusAccepted, "")
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-revoked-member"), http.StatusForbidden, "membership_required")
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodGet, base+"/pairing-status", nil, ""), http.StatusForbidden, "membership_required")
	other, _ := lifecycleGroup(t, n, outsider, "unpair-boundary-other")
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+other+"/unpair", []byte(`{}`), "unpair-cross-group"), http.StatusForbidden, "membership_required")
	for i, body := range []string{"", "null", "[]", `{"unexpected":1}`, "{} {}"} {
		lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/unpair", []byte(body), fmt.Sprintf("unpair-invalid-%d", i)), http.StatusBadRequest, "invalid_request")
	}
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/unpair", []byte(`{}`), ""), http.StatusBadRequest, "idempotency_key_required")
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodGet, "/api/v1/public/groups/grp_unknown/pairing-status", nil, ""), http.StatusNotFound, "group_not_found")
}

func lifecycleFile(t *testing.T, n testNode, sender, recipient testDevice, group, key string, payload []byte, complete bool) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	body := mustJSON(t, map[string]any{"epoch": 1, "encrypted_metadata": "YQ", "size_bytes": len(payload), "chunk_size_bytes": len(payload), "sha256": hex.EncodeToString(sum[:]), "ttl_seconds": 3600, "targets": []string{recipient.id}})
	w := n.signedFileRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+group+"/file-transfers", body, key+"-create")
	lifecycleHTTP(t, w, http.StatusCreated, "")
	id := decodeMap(t, w)["file_id"].(string)
	if complete {
		uploadAndComplete(t, n, sender, key, group+"/"+id, payload, len(payload))
	}
	return id
}

func lifecycleSnapshot(t *testing.T, n testNode) []byte {
	t.Helper()
	var result []byte
	if err := n.st.View(func(st store.State) error {
		var err error
		result, err = json.Marshal(st)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestUnpairCommitFailureIsAtomicAcrossMetadataFilesAndPresence(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b := n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "unpair-failure-group")
	lifecycleJoin(t, n, a, b, group, invite, "unpair-failure-join")
	heartbeatName(t, n, a, "Persistent PC")
	heartbeatName(t, n, b, "Persistent Phone")
	file := lifecycleFile(t, n, a, b, group, "unpair-failure-file", []byte("opaque ciphertext"), true)
	base := "/api/v1/public/groups/" + group
	before := lifecycleSnapshot(t, n)
	presence := lifecycleRead(t, n, a, base+"/presence")
	restore := lifecycleBlockSnapshot(t, n)
	w := n.signedRequest(t, b, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-failure-operation")
	lifecycleHTTP(t, w, http.StatusInternalServerError, "storage_unavailable")
	if !bytes.Equal(before, lifecycleSnapshot(t, n)) {
		t.Fatal("failed unpair commit published a partial state or idempotency result")
	}
	if !reflect.DeepEqual(presence, lifecycleRead(t, n, a, base+"/presence")) {
		t.Fatal("failed unpair commit changed presence")
	}
	if payload, err := os.ReadFile(n.s.fileBlobPath(file)); err != nil || string(payload) != "opaque ciphertext" {
		t.Fatalf("failed unpair physically deleted live ciphertext: %q %v", payload, err)
	}
	restore()
	lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/unpair", []byte(`{}`), "unpair-failure-operation"), http.StatusOK, "")
}

func TestGroupClosureRevokesOnlyTargetGroupAndRetainsRetryableTombstones(t *testing.T) {
	for _, operation := range []string{"unpair", "close"} {
		t.Run(operation, func(t *testing.T) {
			n := newTestNode(t)
			defer n.close(t)
			a, b, c := n.enroll(t), n.enroll(t), n.enroll(t)
			group, invite := lifecycleGroup(t, n, a, "unpair-scope-group")
			app, delivery := lifecycleJoin(t, n, a, b, group, invite, "unpair-scope-join")
			if operation == "close" {
				d := n.enroll(t)
				lifecycleJoin(t, n, a, d, group, invite, "close-scope-third")
			}
			base := "/api/v1/public/groups/" + group
			upload := lifecycleFile(t, n, a, b, group, "unpair-scope-upload", []byte("upload bytes"), false)
			available := lifecycleFile(t, n, b, a, group, "unpair-scope-available", []byte("available bytes"), true)
			// Retain an artifact the first physical cleanup cannot remove. Metadata
			// closure must commit independently, and a later cleanup must retry it.
			blocked := n.s.fileBlobPath(available)
			if err := os.Remove(blocked); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocked, "obstruction"), []byte("blocked"), 0600); err != nil {
				t.Fatal(err)
			}
			other, otherInvite := lifecycleGroup(t, n, a, "unpair-scope-other")
			lifecycleJoin(t, n, a, b, other, otherInvite, "unpair-scope-other-join")
			otherFile := lifecycleFile(t, n, a, b, other, "unpair-scope-other-file", []byte("other ciphertext"), true)
			heartbeatName(t, n, a, "我的电脑")
			heartbeatName(t, n, b, "手机")
			w := n.signedRequest(t, c, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", []byte(`{}`), "unpair-scope-pending")
			lifecycleHTTP(t, w, http.StatusCreated, "")
			pending := decodeMap(t, w)["application_id"].(string)
			lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/messages", []byte(`{"epoch":1,"ciphertext":"b3BhcXVl"}`), "unpair-scope-message"), http.StatusCreated, "")
			// Include both a pending target-group rotation and an unrelated pending
			// event to verify closure never requires clients to rotate a deleted pair.
			if err := n.st.Update(func(st *store.State) error {
				g := st.Groups[group]
				g.Events = append(g.Events, store.ControlEvent{ID: "evt_target", Type: "member_left", RequiredEpoch: 2})
				st.Groups[group] = g
				g = st.Groups[other]
				g.Events = append(g.Events, store.ControlEvent{ID: "evt_other", Type: "member_left", RequiredEpoch: 2})
				st.Groups[other] = g
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			otherBase := "/api/v1/public/groups/" + other
			otherMembers := lifecycleRead(t, n, a, otherBase+"/members")
			otherPresence := lifecycleRead(t, n, b, otherBase+"/presence")
			var beforeGroup store.Group
			var beforeFile store.File
			var beforeDevices map[string]store.Device
			if err := n.st.View(func(st store.State) error {
				beforeGroup, beforeFile, beforeDevices = st.Groups[other], st.Files[otherFile], st.Devices
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			caller := b
			if operation == "close" {
				caller = a
			}
			lifecycleHTTP(t, n.signedRequest(t, caller, http.MethodPost, base+"/"+operation, []byte(`{}`), "unpair-scope-operation"), http.StatusOK, "")
			if err := n.st.View(func(st store.State) error {
				if _, exists := st.Groups[group]; exists || len(st.Messages[group]) != 0 || len(st.KeyDeliveries[group]) != 0 {
					t.Fatal("unpair retained old group authorization, messages or deliveries")
				}
				for _, inv := range st.Invites {
					if inv.GroupID == group && !inv.Revoked {
						t.Fatal("unpair left a live invitation")
					}
				}
				for _, app := range st.Applications {
					if app.GroupID == group {
						t.Fatal("unpair left old application state")
					}
				}
				for _, id := range []string{upload, available} {
					if st.Files[id].Status != "tombstone" || st.Files[id].GroupID != group {
						t.Fatalf("unpair lost durable file tombstone: %#v", st.Files[id])
					}
				}
				if !reflect.DeepEqual(beforeGroup, st.Groups[other]) || !reflect.DeepEqual(beforeFile, st.Files[otherFile]) || !reflect.DeepEqual(beforeDevices, st.Devices) {
					t.Fatal("unpair mutated other group control events, files or global device identities")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(otherMembers, lifecycleRead(t, n, a, otherBase+"/members")) || !reflect.DeepEqual(otherPresence, lifecycleRead(t, n, b, otherBase+"/presence")) {
				t.Fatal("unpair changed other-group members, device names or presence")
			}
			if payload, err := os.ReadFile(n.s.fileBlobPath(otherFile)); err != nil || string(payload) != "other ciphertext" {
				t.Fatalf("unpair removed other group's physical ciphertext: %v", err)
			}
			for _, d := range []testDevice{a, b} {
				for _, suffix := range []string{"/members", "/messages", "/events", "/key-deliveries", "/applications/" + app, "/applications/" + pending, "/presence"} {
					code := "group_not_found"
					if strings.HasPrefix(suffix, "/applications/") {
						code = "application_not_found"
					}
					lifecycleHTTP(t, n.signedRequest(t, d, http.MethodGet, base+suffix, nil, ""), http.StatusNotFound, code)
				}
				lifecycleHTTP(t, n.signedFileRequest(t, d, http.MethodGet, base+"/file-transfers/"+available+"/chunks/0", nil, ""), http.StatusNotFound, "group_not_found")
				lifecycleHTTP(t, n.signedFileRequest(t, d, http.MethodPost, base+"/file-transfers/"+available+"/ack", []byte(`{}`), "unpair-old-file-ack-"+d.id), http.StatusNotFound, "group_not_found")
			}
			lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, "/api/v1/public/invites/"+invite+"/applications", []byte(`{}`), "unpair-old-invite"), http.StatusNotFound, "invite_expired")
			lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/applications/"+app+"/key-delivery", []byte(`{"envelope":"YQ"}`), "unpair-old-delivery"), http.StatusNotFound, "group_not_found")
			lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "unpair-old-key-ack"), http.StatusNotFound, "group_not_found")
			lifecycleHTTP(t, n.signedFileRequest(t, a, http.MethodPost, base+"/file-transfers/"+upload+"/complete", []byte(`{}`), "unpair-old-complete"), http.StatusNotFound, "group_not_found")
			n.s.fileLock().Lock()
			n.s.cleanupFiles(time.Now().UTC())
			n.s.fileLock().Unlock()
			if _, err := os.Stat(blocked); err != nil {
				t.Fatalf("obstruction fixture did not retain pending cleanup: %v", err)
			}
			if err := os.Remove(filepath.Join(blocked, "obstruction")); err != nil {
				t.Fatal(err)
			}
			n.s.fileLock().Lock()
			n.s.cleanupFiles(time.Now().UTC())
			n.s.fileLock().Unlock()
			if _, err := os.Stat(blocked); !os.IsNotExist(err) {
				t.Fatalf("physical cleanup did not retry after obstruction cleared: %v", err)
			}
		})
	}
}

// Prepare signatures before launching concurrent requests, so goroutines only
// execute actual handlers and report their responses to the parent test.
func lifecycleHeaders(t *testing.T, d testDevice, method, path string, body []byte, idem string) map[string]string {
	t.Helper()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce, err := randomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{method, path, timestamp, nonce, idem, base64.RawURLEncoding.EncodeToString(sum[:])}, "\n")
	return map[string]string{"X-Device-ID": d.id, "X-Device-Timestamp": timestamp, "X-Device-Nonce": nonce, "X-Device-Signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(d.priv, []byte(canonical))), "Idempotency-Key": idem}
}

func TestGroupClosureConcurrentFileWritesCannotResurrectClosedGroup(t *testing.T) {
	for _, phase := range []string{"unpair-upload", "unpair-complete", "close-upload", "close-complete"} {
		t.Run(phase, func(t *testing.T) {
			for iteration := 0; iteration < 4; iteration++ {
				n := newTestNode(t)
				a, b := n.enroll(t), n.enroll(t)
				group, invite := lifecycleGroup(t, n, a, "unpair-race-group")
				lifecycleJoin(t, n, a, b, group, invite, "unpair-race-join")
				operation, caller := "unpair", b
				if strings.HasPrefix(phase, "close-") {
					operation, caller = "close", a
					c := n.enroll(t)
					lifecycleJoin(t, n, a, c, group, invite, "close-race-third")
				}
				payload := []byte("racing opaque file")
				id := lifecycleFile(t, n, a, b, group, "unpair-race-file", payload, false)
				base := "/api/v1/public/groups/" + group
				method, path, body := http.MethodPut, base+"/file-transfers/"+id+"/chunks/0", payload
				if strings.HasSuffix(phase, "-complete") {
					lifecycleHTTP(t, n.signedFileRequest(t, a, method, path, body, "unpair-race-upload"), http.StatusOK, "")
					method, path, body = http.MethodPost, base+"/file-transfers/"+id+"/complete", []byte(`{}`)
				}
				unpairHeaders := lifecycleHeaders(t, caller, http.MethodPost, base+"/"+operation, []byte(`{}`), "unpair-race-operation")
				fileHeaders := lifecycleHeaders(t, a, method, path, body, "unpair-race-write")
				start := make(chan struct{})
				unpairResult, fileResult := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
				go func() {
					<-start
					unpairResult <- n.request(http.MethodPost, base+"/"+operation, []byte(`{}`), unpairHeaders)
				}()
				go func() { <-start; fileResult <- n.request(method, path, body, fileHeaders) }()
				close(start)
				lifecycleHTTP(t, <-unpairResult, http.StatusOK, "")
				w := <-fileResult
				if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
					t.Fatalf("file write did not serialize before/after unpair: %d %s", w.Code, w.Body)
				}
				if err := n.st.View(func(st store.State) error {
					if _, exists := st.Groups[group]; exists || st.Files[id].Status != "tombstone" {
						t.Fatal("racing file write resurrected an unpaired group/file")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				lifecycleHTTP(t, n.signedFileRequest(t, a, http.MethodGet, base+"/file-transfers/"+id+"/chunks/0", nil, ""), http.StatusNotFound, "group_not_found")
				n.close(t)
			}
		})
	}
}

func TestGenericCreatorDisconnectTransfersAtomicallyAndRotationRestoresConfirmation(t *testing.T) {
	n := newTestNode(t)
	defer func() { n.close(t) }()
	a, b, c, outsider := n.enroll(t), n.enroll(t), n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "generic-disconnect-group")
	lifecycleJoin(t, n, a, b, group, invite, "generic-disconnect-b")
	appC, oldDelivery := lifecycleJoin(t, n, a, c, group, invite, "generic-disconnect-c")
	base := "/api/v1/public/groups/" + group
	path := base + "/disconnect"
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, path, []byte(`{}`), "generic-missing-successor"), http.StatusConflict, "creator_transfer_required")
	for _, successor := range []string{a.id, outsider.id, "dev_unknown"} {
		body := mustJSON(t, map[string]string{"transfer_creator_to": successor})
		lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, path, body, "generic-invalid-"+successor), http.StatusBadRequest, "invalid_successor")
	}
	transfer := mustJSON(t, map[string]string{"transfer_creator_to": b.id})
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, path, transfer, "generic-member-transfer"), http.StatusBadRequest, "invalid_request")
	lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodPost, path, []byte(`{}`), "generic-outsider-disconnect"), http.StatusForbidden, "membership_required")
	w := n.signedRequest(t, a, http.MethodPost, path, transfer, "generic-creator-disconnect")
	lifecycleHTTP(t, w, http.StatusAccepted, "")
	committed := w.Body.String()
	v := decodeMap(t, w)
	if v["status"] != "left" || v["group_id"] != group || v["device_id"] != a.id || v["creator_id"] != b.id || v["required_generation"] != float64(2) {
		t.Fatalf("creator transfer and disconnect did not return the committed lifecycle: %#v", v)
	}
	event := v["control_event_id"].(string)
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodGet, base+"/members", nil, ""), http.StatusForbidden, "membership_required")
	checkRemaining := func() {
		t.Helper()
		items := lifecycleRead(t, n, b, base+"/members")["items"].([]any)
		if len(items) != 2 {
			t.Fatalf("creator disconnect unexpectedly closed the multi-member group: %#v", items)
		}
		for _, raw := range items {
			item := raw.(map[string]any)
			if item["device_id"] == b.id && item["role"] != "creator" {
				t.Fatal("successor was not creator in the same durable commit")
			}
			if item["device_id"] == c.id {
				lifecycleConfirmation(t, item, "revoked", oldDelivery, c.id, 1)
			}
		}
		if v := lifecycleRead(t, n, a, base+"/membership-status"); v["status"] != "left" || v["changed_at"] == nil {
			t.Fatalf("disconnected creator has no durable scoped receipt: %#v", v)
		}
	}
	checkRemaining()
	lifecycleRestart(t, &n)
	checkRemaining()
	w = n.signedRequest(t, a, http.MethodPost, path, transfer, "generic-creator-disconnect")
	lifecycleHTTP(t, w, http.StatusAccepted, "")
	if w.Body.String() != committed {
		t.Fatal("restart retry lost the committed transfer-and-disconnect response")
	}
	w = n.signedRequest(t, a, http.MethodPost, path, []byte(`{}`), "generic-new-key-confirm-left")
	lifecycleHTTP(t, w, http.StatusOK, "")
	if decodeMap(t, w)["status"] != "left" {
		t.Fatal("new key did not confirm the caller's terminal departure")
	}
	rotation := mustJSON(t, map[string]any{"epoch": 2, "envelopes": map[string]string{c.id: "YQ"}})
	lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/rotations/"+event, rotation, "generic-rotation-commit"), http.StatusOK, "")
	var delivery string
	for _, raw := range lifecycleRead(t, n, c, base+"/key-deliveries")["items"].([]any) {
		item := raw.(map[string]any)
		if item["epoch"] == float64(2) {
			delivery = item["id"].(string)
		}
	}
	if delivery == "" {
		t.Fatal("rotation did not produce a recipient-bound delivery")
	}
	readCurrent := func() map[string]any {
		t.Helper()
		for _, raw := range lifecycleRead(t, n, b, base+"/members")["items"].([]any) {
			item := raw.(map[string]any)
			if item["device_id"] == c.id {
				return item
			}
		}
		t.Fatal("rotation dropped the remaining recipient")
		return nil
	}
	lifecycleConfirmation(t, readCurrent(), "awaiting_ack", delivery, c.id, 2)
	lifecycleConfirmation(t, lifecycleRead(t, n, b, base+"/applications/"+appC), "revoked", oldDelivery, c.id, 1)
	// An acknowledgement of a superseded key may not confirm the new epoch.
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/key-deliveries/"+oldDelivery+"/ack", []byte(`{}`), "generic-old-key-ack"), http.StatusOK, "")
	lifecycleConfirmation(t, readCurrent(), "awaiting_ack", delivery, c.id, 2)
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/key-deliveries/"+delivery+"/ack", []byte(`{}`), "generic-current-key-ack"), http.StatusOK, "")
	confirmed := lifecycleConfirmation(t, readCurrent(), "acknowledged", delivery, c.id, 2)
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/messages", []byte(`{"epoch":2,"ciphertext":"b3BhcXVl"}`), "generic-rotated-message"), http.StatusCreated, "")
	lifecycleRestart(t, &n)
	if lifecycleConfirmation(t, readCurrent(), "acknowledged", delivery, c.id, 2) != confirmed {
		t.Fatal("current rotated key confirmation did not survive restart")
	}
	if err := n.st.View(func(st store.State) error {
		g := st.Groups[group]
		if len(g.Events) != 1 || g.Events[0].ID != event || g.Events[0].CompletedAt == "" || g.Generation != 2 {
			t.Fatalf("rotation did not retain and finish the generic control event: %#v", g.Events)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGenericDisconnectAndCloseCommitFailuresRetainCreatorAndFiles(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b := n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "generic-atomic-group")
	lifecycleJoin(t, n, a, b, group, invite, "generic-atomic-join")
	file := lifecycleFile(t, n, a, b, group, "generic-atomic-file", []byte("atomic ciphertext"), true)
	base := "/api/v1/public/groups/" + group
	before := lifecycleSnapshot(t, n)
	restore := lifecycleBlockSnapshot(t, n)
	for _, operation := range []struct{ suffix, body, key string }{
		{"/disconnect", string(mustJSON(t, map[string]string{"transfer_creator_to": b.id})), "generic-atomic-disconnect"},
		{"/close", `{}`, "generic-atomic-close"},
	} {
		lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+operation.suffix, []byte(operation.body), operation.key), http.StatusInternalServerError, "storage_unavailable")
		if !bytes.Equal(before, lifecycleSnapshot(t, n)) {
			t.Fatalf("failed %s changed group roles, membership, files or receipts", operation.suffix)
		}
		if payload, err := os.ReadFile(n.s.fileBlobPath(file)); err != nil || string(payload) != "atomic ciphertext" {
			t.Fatalf("failed %s removed a live physical file: %v", operation.suffix, err)
		}
	}
	restore()
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{}`), "generic-atomic-close"), http.StatusOK, "")
}

func TestGenericCloseCreatorOnlyAndTerminalReceiptsSurviveRestart(t *testing.T) {
	for _, memberCount := range []int{1, 3} {
		t.Run(fmt.Sprint(memberCount), func(t *testing.T) {
			n := newTestNode(t)
			defer func() { n.close(t) }()
			a, b, c, outsider := n.enroll(t), n.enroll(t), n.enroll(t), n.enroll(t)
			group, invite := lifecycleGroup(t, n, a, "generic-close-group")
			base := "/api/v1/public/groups/" + group
			participants := []testDevice{a}
			if memberCount == 3 {
				lifecycleJoin(t, n, a, b, group, invite, "generic-close-b")
				lifecycleJoin(t, n, a, c, group, invite, "generic-close-c")
				participants = append(participants, b, c)
				lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-member"), http.StatusForbidden, "creator_required")
				lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPut, base+"/members/"+b.id+"/role", []byte(`{"role":"admin"}`), "generic-close-admin-role"), http.StatusOK, "")
				lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-admin"), http.StatusForbidden, "creator_required")
			}
			lifecycleHTTP(t, n.request(http.MethodPost, base+"/close", []byte(`{}`), nil), http.StatusUnauthorized, "")
			lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-outsider"), http.StatusForbidden, "membership_required")
			w := n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-operation")
			lifecycleHTTP(t, w, http.StatusOK, "")
			original := w.Body.String()
			if v := decodeMap(t, w); v["group_id"] != group || v["device_id"] != a.id || v["status"] != "group_closed" || len(v) != 3 {
				t.Fatalf("creator close did not return exact terminal confirmation: %#v", v)
			}
			for _, d := range participants {
				v := lifecycleRead(t, n, d, base+"/membership-status")
				if v["device_id"] != d.id || v["group_id"] != group || v["status"] != "group_closed" || v["changed_at"] == nil {
					t.Fatalf("closed group's former active member lacks terminal receipt: %#v", v)
				}
			}
			lifecycleRestart(t, &n)
			w = n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-operation")
			lifecycleHTTP(t, w, http.StatusOK, "")
			if w.Body.String() != original {
				t.Fatal("close result did not survive restart/lost response")
			}
			lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{"changed":1}`), "generic-close-operation"), http.StatusConflict, "idempotency_conflict")
			lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-new-key"), http.StatusOK, "")
			if memberCount == 3 {
				lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/close", []byte(`{}`), "generic-close-admin-new-key"), http.StatusForbidden, "creator_required")
			}
			lifecycleHTTP(t, n.signedRequest(t, outsider, http.MethodGet, base+"/membership-status", nil, ""), http.StatusForbidden, "membership_required")
		})
	}
}

func TestGenericSingleMemberDisconnectAndStaleRetryCannotAffectNewGroup(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	a, b := n.enroll(t), n.enroll(t)
	old, _ := lifecycleGroup(t, n, a, "generic-single-group")
	oldBase := "/api/v1/public/groups/" + old
	transfer := mustJSON(t, map[string]string{"transfer_creator_to": b.id})
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, oldBase+"/disconnect", transfer, "generic-single-transfer"), http.StatusBadRequest, "invalid_request")
	w := n.signedRequest(t, a, http.MethodPost, oldBase+"/disconnect", []byte(`{}`), "generic-single-disconnect")
	lifecycleHTTP(t, w, http.StatusOK, "")
	if decodeMap(t, w)["status"] != "group_closed" {
		t.Fatal("last-member disconnect did not explicitly close the group")
	}
	original := w.Body.String()
	current, invite := lifecycleGroup(t, n, a, "generic-new-group")
	lifecycleJoin(t, n, a, b, current, invite, "generic-new-join")
	for _, key := range []string{"generic-single-disconnect", "generic-single-confirm"} {
		w = n.signedRequest(t, a, http.MethodPost, oldBase+"/disconnect", []byte(`{}`), key)
		lifecycleHTTP(t, w, http.StatusOK, "")
		if w.Body.String() != original {
			t.Fatal("stale last-member disconnect did not remain scoped to old group")
		}
	}
	if len(lifecycleRead(t, n, a, "/api/v1/public/groups/"+current+"/members")["items"].([]any)) != 2 {
		t.Fatal("stale retry closed or revoked the caller's new group")
	}
	if v := lifecycleRead(t, n, a, oldBase+"/membership-status"); v["status"] != "group_closed" {
		t.Fatalf("stale group's terminal status changed after new pairing: %#v", v)
	}
}

func TestGenericDepartureReceiptsAreNotOverwrittenByLaterGroupClose(t *testing.T) {
	n := newTestNode(t)
	defer func() { n.close(t) }()
	a, b, c := n.enroll(t), n.enroll(t), n.enroll(t)
	group, invite := lifecycleGroup(t, n, a, "generic-terminal-group")
	lifecycleJoin(t, n, a, b, group, invite, "generic-terminal-b")
	lifecycleJoin(t, n, a, c, group, invite, "generic-terminal-c")
	base := "/api/v1/public/groups/" + group
	w := n.signedRequest(t, b, http.MethodPost, base+"/disconnect", []byte(`{}`), "generic-member-disconnect")
	lifecycleHTTP(t, w, http.StatusAccepted, "")
	if v := decodeMap(t, w); v["status"] != "left" || v["creator_id"] != a.id || v["required_generation"] != float64(2) {
		t.Fatalf("ordinary member departure corrupted the remaining group: %#v", v)
	}
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodDelete, base+"/members/"+c.id, []byte(`{}`), "generic-terminal-revoke"), http.StatusAccepted, "")
	left := lifecycleRead(t, n, b, base+"/membership-status")
	revoked := lifecycleRead(t, n, c, base+"/membership-status")
	if left["status"] != "left" || revoked["status"] != "revoked" {
		t.Fatalf("self-disconnect and revocation are conflated: left=%#v revoked=%#v", left, revoked)
	}
	if err := n.st.View(func(st store.State) error {
		g := st.Groups[group]
		if len(g.Events) != 2 || g.CreatorID != a.id || !g.Members[a.id].Active {
			t.Fatal("generic departure discarded the remaining group's pending control events")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	lifecycleHTTP(t, n.signedRequest(t, a, http.MethodPost, base+"/close", []byte(`{}`), "generic-terminal-close"), http.StatusOK, "")
	lifecycleRestart(t, &n)
	if !reflect.DeepEqual(left, lifecycleRead(t, n, b, base+"/membership-status")) || !reflect.DeepEqual(revoked, lifecycleRead(t, n, c, base+"/membership-status")) {
		t.Fatal("later group close or restart overwrote earlier device-specific departure reasons")
	}
	lifecycleHTTP(t, n.signedRequest(t, b, http.MethodPost, base+"/disconnect", []byte(`{}`), "generic-left-retry-new-key"), http.StatusOK, "")
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/disconnect", []byte(`{}`), "generic-revoked-retry-new-key"), http.StatusForbidden, "membership_required")
	lifecycleHTTP(t, n.signedRequest(t, c, http.MethodPost, base+"/close", []byte(`{}`), "generic-revoked-close"), http.StatusForbidden, "creator_required")
}
