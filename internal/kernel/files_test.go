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
	"strings"
	"testing"
	"time"

	"aries.local/aries/internal/store"
)

func (n testNode) signedFileRequest(t *testing.T, d testDevice, method, path string, body []byte, idem string) *httptest.ResponseRecorder {
	t.Helper()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce, err := randomToken(24)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{method, path, timestamp, nonce, idem, base64.RawURLEncoding.EncodeToString(sum[:])}, "\n")
	sig := ed25519.Sign(d.priv, []byte(canonical))
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Device-ID", d.id)
	req.Header.Set("X-Device-Timestamp", timestamp)
	req.Header.Set("X-Device-Nonce", nonce)
	req.Header.Set("X-Device-Signature", base64.RawURLEncoding.EncodeToString(sig))
	req.Header.Set("Idempotency-Key", idem)
	w := httptest.NewRecorder()
	n.s.FileHandler().ServeHTTP(w, req)
	return w
}

func createTransferFixture(t *testing.T, n testNode, targets []string, size int64, chunkSize int64, payload []byte, ttl int64) (testDevice, string) {
	t.Helper()
	n.s.config.FileStorageEnabled = true
	sender := n.enroll(t)
	groupBody := []byte(`{"name":"file test","approval_policy":"creator"}`)
	w := n.signedRequest(t, sender, http.MethodPost, "/api/v1/public/groups", groupBody, "file-group-create-0001")
	if w.Code != 201 {
		t.Fatalf("create group: %d %s", w.Code, w.Body)
	}
	groupID := decodeMap(t, w)["group_id"].(string)
	for _, target := range targets {
		if err := n.st.Update(func(st *store.State) error {
			g := st.Groups[groupID]
			g.Members[target] = store.Member{DeviceID: target, Role: "member", Active: true, JoinedAt: time.Now().UTC().Format(time.RFC3339)}
			st.Groups[groupID] = g
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	checksum := sha256.Sum256(payload)
	descriptor, _ := json.Marshal(map[string]any{"epoch": 1, "encrypted_metadata": "YQ", "size_bytes": size, "chunk_size_bytes": chunkSize, "sha256": hex.EncodeToString(checksum[:]), "ttl_seconds": ttl, "targets": targets})
	w = n.signedFileRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+groupID+"/file-transfers", descriptor, "file-transfer-create-0001")
	if w.Code != 201 {
		t.Fatalf("create transfer: %d %s", w.Code, w.Body)
	}
	return sender, groupID + "/" + decodeMap(t, w)["file_id"].(string)
}

func uploadAndComplete(t *testing.T, n testNode, sender testDevice, key, groupAndFile string, payload []byte, chunkSize int) {
	t.Helper()
	parts := strings.SplitN(groupAndFile, "/", 2)
	for i, start := 0, 0; start < len(payload); i, start = i+1, start+chunkSize {
		end := start + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		path := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/chunks/" + fmt.Sprint(i)
		w := n.signedFileRequest(t, sender, http.MethodPut, path, payload[start:end], fmt.Sprintf("file-chunk-%s-%d", key, i))
		if w.Code != 200 {
			t.Fatalf("upload chunk %d: %d %s", i, w.Code, w.Body)
		}
	}
	w := n.signedFileRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/file-transfers/"+parts[1]+"/complete", []byte("{}"), "file-complete-"+key)
	if w.Code != 200 {
		t.Fatalf("complete transfer: %d %s", w.Code, w.Body)
	}
}

func TestResumableFileTransferDownloadAckAndCleanup(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	payload := []byte("opaque encrypted bytes")
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 5, payload, 3600)
	fileParts := strings.SplitN(groupAndFile, "/", 2)
	// Repeating an already committed identical chunk is an idempotent resume.
	chunkPath := "/api/v1/public/groups/" + fileParts[0] + "/file-transfers/" + fileParts[1] + "/chunks/0"
	w := n.signedFileRequest(t, sender, http.MethodPut, chunkPath, payload[:5], "file-chunk-resume-000")
	if w.Code != 200 {
		t.Fatalf("resume chunk: %d %s", w.Code, w.Body)
	}
	for i, start := 1, 5; start < len(payload); i, start = i+1, start+5 {
		end := start + 5
		if end > len(payload) {
			end = len(payload)
		}
		path := "/api/v1/public/groups/" + fileParts[0] + "/file-transfers/" + fileParts[1] + "/chunks/" + fmt.Sprint(i)
		w = n.signedFileRequest(t, sender, http.MethodPut, path, payload[start:end], fmt.Sprintf("file-chunk-resume-%03d", i))
		if w.Code != 200 {
			t.Fatalf("upload chunk %d: %d %s", i, w.Code, w.Body)
		}
	}
	w = n.signedFileRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+fileParts[0]+"/file-transfers/"+fileParts[1]+"/complete", []byte("{}"), "file-complete-resume-0001")
	if w.Code != 200 {
		t.Fatalf("complete transfer: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(n.s.fileRoot(), "uploads", fileParts[1])); !os.IsNotExist(err) {
		t.Fatalf("available transfer should discard upload chunks after metadata commit, stat err=%v", err)
	}
	for i, start := 0, 0; start < len(payload); i, start = i+1, start+5 {
		end := start + 5
		if end > len(payload) {
			end = len(payload)
		}
		path := "/api/v1/public/groups/" + fileParts[0] + "/file-transfers/" + fileParts[1] + "/chunks/" + fmt.Sprint(i)
		w = n.signedFileRequest(t, target, http.MethodGet, path, nil, fmt.Sprintf("file-download-%03d", i))
		if w.Code != 200 || string(w.Body.Bytes()) != string(payload[start:end]) {
			t.Fatalf("download chunk %d: %d %q", i, w.Code, w.Body.Bytes())
		}
	}
	w = n.signedFileRequest(t, target, http.MethodPost, "/api/v1/public/groups/"+fileParts[0]+"/file-transfers/"+fileParts[1]+"/ack", []byte("{}"), "file-ack-00000001")
	ack := decodeMap(t, w)
	if w.Code != 200 || ack["status"] != "acknowledged" || ack["cleanup_pending"] != true {
		t.Fatalf("acknowledgement: %d %s", w.Code, w.Body)
	}
	w = n.signedFileRequest(t, target, http.MethodGet, "/api/v1/public/groups/"+fileParts[0]+"/file-transfers/"+fileParts[1]+"/chunks/0", nil, "file-after-clean-0001")
	if w.Code != 410 || !strings.Contains(w.Body.String(), "fresh copy") {
		t.Fatalf("expected explicit no-copy tombstone: %d %s", w.Code, w.Body)
	}
	_, err := os.Stat(n.s.fileBlobPath(fileParts[1]))
	if !os.IsNotExist(err) {
		t.Fatalf("blob should be removed after all-target ack, stat=%v", err)
	}
	stateBytes, err := os.ReadFile(n.st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateBytes), string(payload)) {
		t.Fatal("ciphertext payload was embedded in JSON state")
	}
}

func TestAvailableFileAckReportsNonFinalCleanupState(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	first := n.enroll(t)
	second := n.enroll(t)
	payload := []byte("shared ciphertext")
	sender, groupAndFile := createTransferFixture(t, n, []string{first.id, second.id}, int64(len(payload)), 6, payload, 3600)
	uploadAndComplete(t, n, sender, "ack-pending", groupAndFile, payload, 6)
	parts := strings.SplitN(groupAndFile, "/", 2)
	path := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/ack"
	w := n.signedFileRequest(t, first, http.MethodPost, path, []byte("{}"), "file-ack-first-target-001")
	ack := decodeMap(t, w)
	if w.Code != 200 || ack["cleanup_pending"] != false {
		t.Fatalf("non-final acknowledgement must not claim cleanup is pending: %d %s", w.Code, w.Body)
	}
	if err := n.st.View(func(st store.State) error {
		if st.Files[parts[1]].Status != "available" {
			t.Fatalf("file should remain available until every target acknowledges: %#v", st.Files[parts[1]])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptOrMissingDownloadChunkIsTombstonedBeforeResponse(t *testing.T) {
	for _, mode := range []string{"missing", "truncated", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			n := newTestNode(t)
			defer n.close(t)
			target := n.enroll(t)
			payload := []byte("opaque ciphertext split into chunks")
			sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 8, payload, 3600)
			uploadAndComplete(t, n, sender, "bad-"+mode, groupAndFile, payload, 8)
			parts := strings.SplitN(groupAndFile, "/", 2)
			blobPath := n.s.fileBlobPath(parts[1])
			switch mode {
			case "missing":
				if err := os.Remove(blobPath); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(blobPath, payload[:3], 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				corrupt := append([]byte(nil), payload...)
				corrupt[0] ^= 0xff
				if err := os.WriteFile(blobPath, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/chunks/0"
			w := n.signedFileRequest(t, target, http.MethodGet, path, nil, "file-corrupt-fetch-"+mode)
			if w.Code != http.StatusGone || strings.Contains(w.Body.String(), string(payload[:8])) {
				t.Fatalf("unavailable chunk must return 410 without ciphertext bytes: %d %q", w.Code, w.Body.Bytes())
			}
			if err := n.st.View(func(st store.State) error {
				f := st.Files[parts[1]]
				if f.Status != "tombstone" || f.TombstoneReason != "corrupt_no_copy" {
					t.Fatalf("corrupt payload must be tombstoned before response: %#v", f)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
				t.Fatalf("unavailable blob should be cleaned, stat err=%v", err)
			}
		})
	}
}

func TestIncompleteUploadResumesAfterServerRestart(t *testing.T) {
	n := newTestNode(t)
	target := n.enroll(t)
	payload := []byte("durable ciphertext across restart")
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 7, payload, 3600)
	parts := strings.SplitN(groupAndFile, "/", 2)
	first := payload[:7]
	chunkPath := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/chunks/0"
	w := n.signedFileRequest(t, sender, http.MethodPut, chunkPath, first, "file-chunk-before-restart-0001")
	if w.Code != 200 {
		t.Fatalf("upload first chunk: %d %s", w.Code, w.Body)
	}
	if err := n.st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(n.st.Path(), "ignored-node")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(n.cfg, n.configPath, st)
	if err != nil {
		t.Fatal(err)
	}
	restartedNode := testNode{s: restarted, st: st, cfg: n.cfg, configPath: n.configPath}
	defer restartedNode.close(t)
	uploadAndComplete(t, restartedNode, sender, "restart", groupAndFile, payload, 7)
	if _, err := os.Stat(restarted.fileBlobPath(parts[1])); err != nil {
		t.Fatalf("completed blob did not survive restart: %v", err)
	}
}

func TestCompleteRetryResyncsMatchingBlobAndRemovesUploadChunks(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	payload := []byte("blob rename committed before metadata")
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 7, payload, 3600)
	parts := strings.SplitN(groupAndFile, "/", 2)
	for i, start := 0, 0; start < len(payload); i, start = i+1, start+7 {
		end := start + 7
		if end > len(payload) {
			end = len(payload)
		}
		path := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/chunks/" + fmt.Sprint(i)
		w := n.signedFileRequest(t, sender, http.MethodPut, path, payload[start:end], fmt.Sprintf("file-crash-chunk-%d", i))
		if w.Code != http.StatusOK {
			t.Fatalf("upload chunk %d: %d %s", i, w.Code, w.Body)
		}
	}
	var f store.File
	if err := n.st.View(func(st store.State) error { f = st.Files[parts[1]]; return nil }); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the durable blob rename but before the state commit.
	n.s.fileLock().Lock()
	err := n.s.assembleFile(f)
	n.s.fileLock().Unlock()
	if err != nil {
		t.Fatalf("pre-commit assembly: %v", err)
	}
	if _, err := os.Stat(filepath.Join(n.s.fileRoot(), "uploads", parts[1])); err != nil {
		t.Fatalf("chunks should remain until metadata is committed: %v", err)
	}
	completePath := "/api/v1/public/groups/" + parts[0] + "/file-transfers/" + parts[1] + "/complete"
	w := n.signedFileRequest(t, sender, http.MethodPost, completePath, []byte("{}"), "file-crash-complete-0001")
	if w.Code != http.StatusOK {
		t.Fatalf("complete retry: %d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(n.s.fileRoot(), "uploads", parts[1])); !os.IsNotExist(err) {
		t.Fatalf("committed transfer should remove chunks: %v", err)
	}
}

func TestCleanupRemovesOnlyControlledCrashTempFiles(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, 8, 4, []byte("12345678"), 3600)
	_ = sender
	parts := strings.SplitN(groupAndFile, "/", 2)
	blobDir := filepath.Dir(n.s.fileBlobPath(parts[1]))
	uploadDir := filepath.Join(n.s.fileRoot(), "uploads", parts[1])
	for _, dir := range []string{blobDir, uploadDir} {
		if err := n.s.ensureFileDirectory(dir); err != nil {
			t.Fatal(err)
		}
	}
	blobTemp := filepath.Join(blobDir, ".blob-crash.tmp")
	chunkTemp := filepath.Join(uploadDir, ".chunk-crash.tmp")
	for _, path := range []string{blobTemp, chunkTemp} {
		if err := os.WriteFile(path, []byte("partial temp"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	n.s.fileLock().Lock()
	n.s.cleanupFiles(time.Now().UTC())
	n.s.fileLock().Unlock()
	for _, path := range []string{blobTemp, chunkTemp} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("controlled crash temp was not cleaned: %s, err=%v", path, err)
		}
	}
}

func TestRemovingSenderTombstonesUploadsButPreservesCompletedFiles(t *testing.T) {
	for _, operation := range []string{"leave", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			n := newTestNode(t)
			defer n.close(t)
			target := n.enroll(t)
			pendingPayload := []byte("pending ciphertext")
			sender, pendingGroupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(pendingPayload)), 6, pendingPayload, 3600)
			pendingParts := strings.SplitN(pendingGroupAndFile, "/", 2)

			completedPayload := []byte("completed ciphertext")
			completedHash := sha256.Sum256(completedPayload)
			descriptor, _ := json.Marshal(map[string]any{
				"epoch": 1, "encrypted_metadata": "YQ", "size_bytes": len(completedPayload),
				"chunk_size_bytes": 7, "sha256": hex.EncodeToString(completedHash[:]),
				"ttl_seconds": 3600, "targets": []string{target.id},
			})
			createPath := "/api/v1/public/groups/" + pendingParts[0] + "/file-transfers"
			w := n.signedFileRequest(t, sender, http.MethodPost, createPath, descriptor, "sender-removal-completed-create")
			if w.Code != http.StatusCreated {
				t.Fatalf("create completed transfer: %d %s", w.Code, w.Body)
			}
			completedID := decodeMap(t, w)["file_id"].(string)
			completedGroupAndFile := pendingParts[0] + "/" + completedID
			uploadAndComplete(t, n, sender, "sender-removal-completed", completedGroupAndFile, completedPayload, 7)

			creatorPath := "/api/v1/public/groups/" + pendingParts[0] + "/creator"
			creatorBody, _ := json.Marshal(map[string]string{"new_creator_id": target.id})
			w = n.signedRequest(t, sender, http.MethodPost, creatorPath, creatorBody, "sender-removal-transfer-creator")
			if w.Code != http.StatusOK {
				t.Fatalf("transfer creator: %d %s", w.Code, w.Body)
			}
			if operation == "leave" {
				path := "/api/v1/public/groups/" + pendingParts[0] + "/leave"
				w = n.signedRequest(t, sender, http.MethodPost, path, []byte("{}"), "sender-removal-leave")
			} else {
				path := "/api/v1/public/groups/" + pendingParts[0] + "/members/" + sender.id
				w = n.signedRequest(t, target, http.MethodDelete, path, []byte("{}"), "sender-removal-revoke")
			}
			if w.Code != http.StatusAccepted {
				t.Fatalf("remove sender: %d %s", w.Code, w.Body)
			}
			if err := n.st.View(func(st store.State) error {
				pending := st.Files[pendingParts[1]]
				completed := st.Files[completedID]
				if pending.Status != "tombstone" || pending.TombstoneReason != "sender_left_no_copy" {
					t.Fatalf("sender removal must tombstone its upload: %#v", pending)
				}
				if completed.Status != "available" {
					t.Fatalf("sender removal must preserve completed files: %#v", completed)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			fetchPath := "/api/v1/public/groups/" + pendingParts[0] + "/file-transfers/" + completedID + "/chunks/0"
			w = n.signedFileRequest(t, target, http.MethodGet, fetchPath, nil, "sender-removal-fetch-completed")
			if w.Code != http.StatusOK || string(w.Body.Bytes()) != string(completedPayload[:7]) {
				t.Fatalf("remaining member should still fetch completed file: %d %q", w.Code, w.Body.Bytes())
			}
		})
	}
}

func TestQuotaEvictionReturnsNoCopyAndTargetsCanBeRemoved(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	n.s.config.MaxStorageBytes = 0
	n.s.config.GroupQuotaBytes = 12
	target := n.enroll(t)
	payload := []byte("12345678")
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 8, payload, 3600)
	uploadAndComplete(t, n, sender, "old", groupAndFile, payload, 8)
	parts := strings.SplitN(groupAndFile, "/", 2)
	secondBodyHash := sha256.Sum256(payload)
	body, _ := json.Marshal(map[string]any{"epoch": 1, "encrypted_metadata": "YQ", "size_bytes": len(payload), "chunk_size_bytes": len(payload), "sha256": hex.EncodeToString(secondBodyHash[:]), "ttl_seconds": 3600, "targets": []string{target.id}})
	w := n.signedFileRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/file-transfers", body, "file-second-create-0001")
	if w.Code != 201 || !strings.Contains(w.Body.String(), parts[1]) {
		t.Fatalf("quota eviction report missing: %d %s", w.Code, w.Body)
	}
	w = n.signedFileRequest(t, target, http.MethodGet, "/api/v1/public/groups/"+parts[0]+"/file-transfers/"+parts[1]+"/chunks/0", nil, "file-evicted-fetch-001")
	if w.Code != 410 || !strings.Contains(w.Body.String(), "fresh copy") {
		t.Fatalf("evicted file should report no copy: %d %s", w.Code, w.Body)
	}
	if err := n.st.Update(func(st *store.State) error { RemoveFileTarget(st, parts[0], target.id); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredTransferIsTombstonedAndCleaned(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	payload := []byte("ephemeral")
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 4, payload, 3600)
	uploadAndComplete(t, n, sender, "ttl", groupAndFile, payload, 4)
	parts := strings.SplitN(groupAndFile, "/", 2)
	if err := n.st.Update(func(st *store.State) error {
		f := st.Files[parts[1]]
		f.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		st.Files[parts[1]] = f
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := n.signedFileRequest(t, target, http.MethodGet, "/api/v1/public/groups/"+parts[0]+"/file-transfers/"+parts[1]+"/chunks/0", nil, "file-expired-fetch-001")
	if w.Code != 410 {
		t.Fatalf("expired file status: %d %s", w.Code, w.Body)
	}
	if err := n.st.View(func(st store.State) error {
		if st.Files[parts[1]].TombstoneReason != "expired_no_copy" {
			t.Fatalf("wrong tombstone: %#v", st.Files[parts[1]])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRemovingLastTargetReportsNoCopy(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	payload := []byte("ciphertext")
	_, groupAndFile := createTransferFixture(t, n, []string{target.id}, int64(len(payload)), 4, payload, 3600)
	parts := strings.SplitN(groupAndFile, "/", 2)
	if err := n.st.Update(func(st *store.State) error {
		RemoveFileTarget(st, parts[0], target.id)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := n.st.View(func(st store.State) error {
		f := st.Files[parts[1]]
		if f.Status != "tombstone" || f.TombstoneReason != "no_remaining_targets" {
			t.Fatalf("last target removal must tombstone transfer: %#v", f)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	n.s.fileLock().Lock()
	n.s.cleanupFiles(time.Now().UTC())
	n.s.fileLock().Unlock()
}

func TestPublicHandlerMountsTransfersAndRetiresInlineFileAPI(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	for _, path := range []string{
		"/api/v1/public/groups/grp_test/file-transfers",
		"/api/v1/public/groups/grp_test/files",
	} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/files") {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:54321"
		w := httptest.NewRecorder()
		n.s.PublicHandler().ServeHTTP(w, r)
		if strings.HasPrefix(path, "/api/v1/public/groups/grp_test/files") {
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("legacy API should require a device proof before migration response, got %d", w.Code)
			}
			continue
		}
		if w.Code == http.StatusNotFound {
			t.Fatalf("PublicHandler did not mount transfer route %s", path)
		}
	}
	d := n.enroll(t)
	w := n.signedRequest(t, d, http.MethodPost, "/api/v1/public/groups/grp_test/files", []byte(`{}`), "legacy-files-disabled-001")
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "file_transfer_required") {
		t.Fatalf("legacy inline API should return migration response: %d %s", w.Code, w.Body)
	}
	n.s.config.FileStorageEnabled = false
	w = n.signedFileRequest(t, d, http.MethodPost, "/api/v1/public/groups/grp_test/file-transfers", []byte(`{}`), "file-storage-disabled-001")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "file_storage_disabled") {
		t.Fatalf("disabled storage must reject the new API: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, d, http.MethodPost, "/api/v1/public/groups/grp_test/files", []byte(`{}`), "legacy-storage-disabled-01")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "file_storage_disabled") {
		t.Fatalf("disabled storage must reject the legacy path too: %d %s", w.Code, w.Body)
	}
}

func TestMembershipLifecyclePrunesFileRecipientsAtomically(t *testing.T) {
	t.Run("leave", func(t *testing.T) {
		n := newTestNode(t)
		defer n.close(t)
		target := n.enroll(t)
		sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, 8, 4, []byte("12345678"), 3600)
		parts := strings.SplitN(groupAndFile, "/", 2)
		w := n.signedRequest(t, target, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/leave", []byte("{}"), "file-leave-target-0001")
		if w.Code != 202 {
			t.Fatalf("leave status %d: %s", w.Code, w.Body)
		}
		assertFileTombstone(t, n, parts[1], "no_remaining_targets")
		_ = sender
	})
	t.Run("revoke", func(t *testing.T) {
		n := newTestNode(t)
		defer n.close(t)
		target := n.enroll(t)
		sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, 8, 4, []byte("12345678"), 3600)
		parts := strings.SplitN(groupAndFile, "/", 2)
		path := "/api/v1/public/groups/" + parts[0] + "/members/" + target.id
		w := n.signedRequest(t, sender, http.MethodDelete, path, []byte("{}"), "file-revoke-target-001")
		if w.Code != 202 {
			t.Fatalf("revoke status %d: %s", w.Code, w.Body)
		}
		assertFileTombstone(t, n, parts[1], "no_remaining_targets")
	})
}

func TestGroupClosurePreservesFileTombstoneMetadata(t *testing.T) {
	n := newTestNode(t)
	defer n.close(t)
	target := n.enroll(t)
	sender, groupAndFile := createTransferFixture(t, n, []string{target.id}, 8, 4, []byte("12345678"), 3600)
	parts := strings.SplitN(groupAndFile, "/", 2)
	body, _ := json.Marshal(map[string]string{"new_creator_id": target.id})
	w := n.signedRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/creator", body, "file-transfer-creator-001")
	if w.Code != 200 {
		t.Fatalf("transfer creator: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, sender, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/leave", []byte("{}"), "file-creator-leave-0001")
	if w.Code != 202 {
		t.Fatalf("former creator leave: %d %s", w.Code, w.Body)
	}
	w = n.signedRequest(t, target, http.MethodPost, "/api/v1/public/groups/"+parts[0]+"/leave", []byte("{}"), "file-last-member-leave-001")
	if w.Code != 200 {
		t.Fatalf("last member leave: %d %s", w.Code, w.Body)
	}
	if err := n.st.View(func(st store.State) error {
		if _, ok := st.Groups[parts[0]]; ok {
			t.Fatal("closed group remains in state")
		}
		f, ok := st.Files[parts[1]]
		if !ok || f.Status != "tombstone" || f.TombstoneReason != "group_deleted_no_copy" {
			t.Fatalf("group close did not preserve file tombstone: %#v", f)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertFileTombstone(t *testing.T, n testNode, fileID, reason string) {
	t.Helper()
	if err := n.st.View(func(st store.State) error {
		f := st.Files[fileID]
		if f.Status != "tombstone" || f.TombstoneReason != reason || len(f.Targets) != 0 {
			t.Fatalf("membership transition did not atomically prune targets: %#v", f)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
