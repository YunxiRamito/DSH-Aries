package kernel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestInviteRotationExplicitScopeAndReplay(t *testing.T) {
	n, a, b, group := presenceGroup(t)
	defer n.close(t)
	c := n.enroll(t)
	base := "/api/v1/public/groups/" + group
	create := func(d testDevice, key string) string {
		t.Helper()
		w := n.signedRequest(t, d, http.MethodPost, base+"/invites", []byte(`{}`), key)
		if w.Code != 201 {
			t.Fatalf("create invitation: %d %s", w.Code, w.Body)
		}
		return decodeMap(t, w)["invite_code"].(string)
	}
	codeA, codeB := create(a, "rotate-creator-invite"), create(b, "rotate-peer-invite")
	body, _ := json.Marshal(map[string]string{"replace_code": codeA})
	w := n.signedRequest(t, b, http.MethodPost, base+"/invites/rotate", body, "rotate-peer-forbidden")
	if w.Code != 403 {
		t.Fatalf("ordinary member replaced another issuer's invite: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, c, http.MethodPost, base+"/invites/rotate", body, "rotate-outsider-forbidden")
	if w.Code != 403 {
		t.Fatalf("outsider rotated invite: %d %s", w.Code, w.Body)
	}
	w = n.request(http.MethodPost, base+"/invites/rotate", body, nil)
	if w.Code != 401 {
		t.Fatalf("anonymous rotated invite: %d", w.Code)
	}
	w = n.signedRequest(t, a, http.MethodPost, base+"/invites/rotate", body, "rotate-creator-key")
	if w.Code != 201 {
		t.Fatalf("rotate: %d %s", w.Code, w.Body)
	}
	response := append([]byte(nil), w.Body.Bytes()...)
	newCode := decodeMap(t, w)["invite_code"].(string)
	if newCode == codeA || decodeMap(t, w)["replaced_invite_code"] != codeA {
		t.Fatal("rotation did not bind selected old code")
	}
	for code, expected := range map[string]int{codeA: 404, codeB: 200, newCode: 200} {
		w = n.request(http.MethodGet, "/api/v1/public/invites/"+code, nil, nil)
		if w.Code != expected {
			t.Fatalf("invitation scope %d", w.Code)
		}
	}
	w = n.signedRequest(t, c, http.MethodPost, "/api/v1/public/invites/"+codeA+"/applications", []byte(`{}`), "rotate-old-code-apply")
	if w.Code != 404 {
		t.Fatalf("old code still grants applications: %d", w.Code)
	}
	w = n.signedRequest(t, a, http.MethodPost, base+"/invites/rotate", body, "rotate-creator-key")
	if w.Code != 201 || !bytes.Equal(response, w.Body.Bytes()) {
		t.Fatal("rotation replay changed result")
	}
	otherBody, _ := json.Marshal(map[string]string{"replace_code": codeB})
	w = n.signedRequest(t, a, http.MethodPost, base+"/invites/rotate", otherBody, "rotate-creator-key")
	if w.Code != 409 {
		t.Fatal("different-body replay accepted")
	}
	w = n.signedRequest(t, a, http.MethodPost, base+"/invites/rotate", body, "rotate-creator-new-key")
	if w.Code != 409 {
		t.Fatal("already replaced code produced second replacement")
	}
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups", []byte(`{"name":"another group","approval_policy":"creator"}`), "rotate-another-group")
	if w.Code != 201 {
		t.Fatalf("other group: %d", w.Code)
	}
	other := decodeMap(t, w)["group_id"].(string)
	w = n.signedRequest(t, a, http.MethodPost, "/api/v1/public/groups/"+other+"/invites/rotate", otherBody, "rotate-cross-group-code")
	if w.Code != 404 {
		t.Fatal("cross group invitation replacement accepted")
	}
}

func TestInviteRotationCommitFailurePreservesOldCode(t *testing.T) {
	n, a, _, group := presenceGroup(t)
	defer n.close(t)
	base := "/api/v1/public/groups/" + group
	w := n.signedRequest(t, a, http.MethodPost, base+"/invites", []byte(`{}`), "rotate-failure-create")
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	code := decodeMap(t, w)["invite_code"].(string)
	snapshot := n.st.Path()
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(snapshot, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(snapshot); _ = os.WriteFile(snapshot, data, 0600) }()
	body, _ := json.Marshal(map[string]string{"replace_code": code})
	w = n.signedRequest(t, a, http.MethodPost, base+"/invites/rotate", body, "rotate-failed-commit")
	if w.Code != 500 {
		t.Fatalf("expected atomic commit failure, got %d %s", w.Code, w.Body)
	}
	w = n.request(http.MethodGet, "/api/v1/public/invites/"+code, nil, nil)
	if w.Code != 200 {
		t.Fatal("failed commit revoked original invitation")
	}
}
