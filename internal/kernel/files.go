package kernel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"aries.local/aries/internal/store"
)

const (
	defaultFileChunkBytes = int64(1 << 20)
	maxFileChunkBytes     = int64(4 << 20)
	defaultFileTTL        = 7 * 24 * time.Hour
	maxFileTTL            = 365 * 24 * time.Hour
	maxFileCleanupBatch   = 100
)

var fileRootLocks sync.Map // absolute data directory -> *sync.Mutex

type fileTransferCreateRequest struct {
	Epoch             uint64   `json:"epoch"`
	EncryptedMetadata string   `json:"encrypted_metadata"`
	SizeBytes         int64    `json:"size_bytes"`
	ChunkSizeBytes    int64    `json:"chunk_size_bytes,omitempty"`
	SHA256            string   `json:"sha256"`
	TTLSeconds        int64    `json:"ttl_seconds,omitempty"`
	Targets           []string `json:"targets,omitempty"`
}

type FileStorageStats struct {
	UsedBytes      int64 `json:"used_bytes"`
	BlobBytes      int64 `json:"blob_bytes"`
	FileCount      int   `json:"file_count"`
	PendingUploads int   `json:"pending_uploads"`
	Tombstones     int   `json:"tombstones"`
	Evictions      int   `json:"evictions"`
}

type fileCacheBucket struct {
	Count int   `json:"count"`
	Bytes int64 `json:"bytes"`
}

type fileCacheStats struct {
	GroupID        string          `json:"group_id"`
	Uploading      fileCacheBucket `json:"uploading"`
	Available      fileCacheBucket `json:"available"`
	CleanupPending fileCacheBucket `json:"cleanup_pending"`
	LogicalDeleted fileCacheBucket `json:"logical_deleted"`
	PhysicalBytes  int64           `json:"physical_bytes"`
}

type fileCacheCleanupRequest struct {
	FileIDs []string `json:"file_ids"`
}

// FileHandler returns the authenticated resumable-transfer API as a standalone
// handler. PublicHandler can mount the same routes by calling registerFileRoutes.
func (s *Server) FileHandler() http.Handler {
	mux := http.NewServeMux()
	s.registerFileRoutes(mux)
	return requestIDs(s.secureTransport(mux))
}

// registerFileRoutes is the integration hook for Server.PublicHandler. Keep
// this separate so file-transfer routes can be reviewed and wired independently.
func (s *Server) registerFileRoutes(mux *http.ServeMux) {
	// Keep the former inline JSON route as a migration response only. It must
	// never invoke the snapshot-backed legacy payload handlers.
	mux.HandleFunc("POST /api/v1/public/groups/{group}/files", s.legacyInlineFilesRemoved)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/files", s.legacyInlineFilesRemoved)
	mux.HandleFunc("DELETE /api/v1/public/groups/{group}/files/{file}", s.legacyInlineFilesRemoved)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/file-transfers", s.createFileTransfer)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/file-transfers", s.listFileTransfers)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/file-transfers/cache", s.fileCacheStatsHandler)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/file-transfers/cache/cleanup", s.cleanupFileCache)
	mux.HandleFunc("PUT /api/v1/public/groups/{group}/file-transfers/{file}/chunks/{index}", s.putFileChunk)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/file-transfers/{file}/chunks/{index}", s.getFileChunk)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/file-transfers/{file}/complete", s.completeFileTransfer)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/file-transfers/{file}/ack", s.ackFileTransfer)
	mux.HandleFunc("DELETE /api/v1/public/groups/{group}/file-transfers/{file}", s.deleteFileTransfer)
}

func (s *Server) legacyInlineFilesRemoved(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.authorizedBody(w, r); !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	writeError(w, r, http.StatusGone, "file_transfer_required", "inline JSON file payloads are disabled; use the resumable /file-transfers API")
}

func (s *Server) fileRoot() string { return filepath.Join(filepath.Dir(s.store.Path()), "file-blobs") }

func (s *Server) fileLock() *sync.Mutex {
	root, _ := filepath.Abs(s.fileRoot())
	value, _ := fileRootLocks.LoadOrStore(root, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *Server) fileChunkPath(id string, index int) string {
	return filepath.Join(s.fileRoot(), "uploads", id, fmt.Sprintf("%08d.part", index))
}

func (s *Server) fileBlobPath(id string) string {
	return filepath.Join(s.fileRoot(), "blobs", id+".blob")
}

func (s *Server) ensureFileDirectory(path string) error {
	root, err := filepath.Abs(s.fileRoot())
	if err != nil {
		return err
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("file storage path escaped its root")
	}
	if err := secureFileDirectory(root); err != nil {
		return err
	}
	current := root
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := secureFileDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) requireFileStorage(w http.ResponseWriter, r *http.Request) bool {
	if s.configSnapshot().FileStorageEnabled {
		return true
	}
	writeError(w, r, 403, "file_storage_disabled", "file storage is disabled on this node")
	return false
}

func (s *Server) createFileTransfer(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	config := s.configSnapshot()
	var req fileTransferCreateRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "file transfer descriptor is invalid")
		return
	}
	if req.SizeBytes <= 0 || (config.MaxFileBytes > 0 && req.SizeBytes > config.MaxFileBytes) || (config.MaxStorageBytes > 0 && req.SizeBytes > config.MaxStorageBytes) {
		writeError(w, r, 400, "invalid_size", "size_bytes must be positive and fit the configured global quota")
		return
	}
	chunkSize := req.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = defaultFileChunkBytes
	}
	if chunkSize < 1 || chunkSize > maxFileChunkBytes {
		writeError(w, r, 400, "invalid_chunk_size", "chunk_size_bytes must be between 1 and 4194304")
		return
	}
	chunkCount64 := 1 + (req.SizeBytes-1)/chunkSize
	if chunkCount64 > 65536 {
		writeError(w, r, 400, "invalid_size", "file requires too many chunks")
		return
	}
	if _, err := decodeOpaque(req.EncryptedMetadata); err != nil {
		writeError(w, r, 400, "invalid_metadata", "encrypted_metadata must be non-empty unpadded base64url")
		return
	}
	checksum, err := decodeSHA256(req.SHA256)
	if err != nil {
		writeError(w, r, 400, "invalid_sha256", "sha256 must be 64 lowercase hexadecimal characters")
		return
	}
	ttl := defaultFileTTL
	maxTTLSeconds := int64(maxFileTTL / time.Second)
	if config.MaxFileTTLSeconds > 0 && config.MaxFileTTLSeconds < maxTTLSeconds {
		maxTTLSeconds = config.MaxFileTTLSeconds
	}
	if int64(ttl/time.Second) > maxTTLSeconds {
		ttl = time.Duration(maxTTLSeconds) * time.Second
	}
	if req.TTLSeconds != 0 {
		if req.TTLSeconds < 60 || req.TTLSeconds > maxTTLSeconds {
			writeError(w, r, 400, "invalid_ttl", "ttl_seconds is outside the configured retention limit")
			return
		}
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl < time.Minute || ttl > maxFileTTL {
		writeError(w, r, 400, "invalid_ttl", "ttl_seconds must be between 60 and 31536000")
		return
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.cleanupFiles(time.Now().UTC())
	var evicted []string
	s.mutate(w, r, device, "file_transfer.create:"+group, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		if req.Epoch != g.Generation {
			return 0, nil, fail(409, "generation_mismatch", "file uses a stale or unknown content-key generation")
		}
		if hasPendingRotation(g) {
			return 0, nil, fail(409, "rotation_required", "new content is paused until pending key rotation is completed")
		}
		targets, err := fileTargets(g, device, req.Targets)
		if err != nil {
			return 0, nil, err
		}
		if len(targets) == 0 {
			return 0, nil, fail(400, "empty_recipient_set", "at least one target recipient is required")
		}
		used := int64(0)
		groupUsed := int64(0)
		groupQuota := config.GroupQuotaBytes
		if config.QuotaBytesPerMember > 0 {
			members := int64(0)
			for _, member := range g.Members {
				if member.Active {
					members++
				}
			}
			if members > 0 && config.QuotaBytesPerMember > (1<<63-1)/members {
				groupQuota = 1<<63 - 1
			} else {
				groupQuota = members * config.QuotaBytesPerMember
			}
		}
		if groupQuota > 0 && req.SizeBytes > groupQuota {
			return 0, nil, fail(507, "group_quota_exceeded", "file is larger than the group quota")
		}
		candidates := make([]store.File, 0)
		for _, f := range st.Files {
			if f.Status == "tombstone" {
				continue
			}
			used += f.SizeBytes
			if f.GroupID == group {
				groupUsed += f.SizeBytes
			}
			if f.ChunkCount > 0 && (f.Status == "available" || f.Status == "") {
				candidates = append(candidates, f)
			}
		}
		if (config.MaxStorageBytes > 0 && used > config.MaxStorageBytes-req.SizeBytes) || (groupQuota > 0 && groupUsed > groupQuota-req.SizeBytes) {
			sort.Slice(candidates, func(i, j int) bool {
				if candidates[i].DownloadCount != candidates[j].DownloadCount {
					return candidates[i].DownloadCount < candidates[j].DownloadCount
				}
				a, b := fileEvictionTime(candidates[i]), fileEvictionTime(candidates[j])
				if !a.Equal(b) {
					return a.Before(b)
				}
				return candidates[i].CreatedAt < candidates[j].CreatedAt
			})
			for _, candidate := range candidates {
				if groupQuota > 0 && groupUsed > groupQuota-req.SizeBytes && candidate.GroupID != group {
					continue
				}
				candidate.Status = "tombstone"
				candidate.TombstoneReason = "quota_evicted_no_copy"
				st.Files[candidate.ID] = candidate
				evicted = append(evicted, candidate.ID)
				used -= candidate.SizeBytes
				if candidate.GroupID == group {
					groupUsed -= candidate.SizeBytes
				}
				if (config.MaxStorageBytes == 0 || used <= config.MaxStorageBytes-req.SizeBytes) && (groupQuota == 0 || groupUsed <= groupQuota-req.SizeBytes) {
					break
				}
			}
			if (config.MaxStorageBytes > 0 && used > config.MaxStorageBytes-req.SizeBytes) || (groupQuota > 0 && groupUsed > groupQuota-req.SizeBytes) {
				return 0, nil, fail(507, "storage_quota_exceeded", "configured global storage quota cannot fit the transfer")
			}
		}
		id, err := randomID("ft_")
		if err != nil {
			return 0, nil, err
		}
		now := time.Now().UTC()
		f := store.File{ID: id, GroupID: group, SenderID: device, Epoch: req.Epoch, EncryptedMetadata: req.EncryptedMetadata, SizeBytes: req.SizeBytes, ChunkSizeBytes: chunkSize, ChunkCount: int(chunkCount64), SHA256: hex.EncodeToString(checksum), ReceivedChunks: map[int]string{}, Targets: targets, Acknowledged: map[string]bool{}, Status: "uploading", CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(ttl).Format(time.RFC3339Nano)}
		st.Files[id] = f
		return 201, map[string]any{"file_id": id, "size_bytes": req.SizeBytes, "chunk_size_bytes": chunkSize, "chunk_count": f.ChunkCount, "expires_at": f.ExpiresAt, "targets": targets, "evicted_files": evicted}, nil
	})
	s.cleanupFiles(time.Now().UTC())
}

func decodeSHA256(v string) ([]byte, error) {
	if len(v) != 64 || strings.ToLower(v) != v {
		return nil, errors.New("invalid checksum")
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("invalid checksum")
	}
	return b, nil
}

func fileTargets(g store.Group, sender string, requested []string) ([]string, error) {
	allowed := map[string]bool{}
	for id, member := range g.Members {
		if member.Active && id != sender {
			allowed[id] = true
		}
	}
	if requested == nil {
		for id := range allowed {
			requested = append(requested, id)
		}
	}
	seen := map[string]bool{}
	for _, id := range requested {
		if !allowed[id] || seen[id] {
			return nil, fail(400, "invalid_targets", "targets must be distinct active group members other than the sender")
		}
		seen[id] = true
	}
	sort.Strings(requested)
	return requested, nil
}

func fileEvictionTime(f store.File) time.Time {
	if f.LastDownloadedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, f.LastDownloadedAt); err == nil {
			return t
		}
	}
	if f.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, f.CreatedAt); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (s *Server) transferFor(st store.State, group, id string, actor string) (store.File, error) {
	g, ok := st.Groups[group]
	if !ok {
		return store.File{}, fail(404, "group_not_found", "group not found")
	}
	member, ok := g.Members[actor]
	if !ok || !member.Active {
		return store.File{}, fail(403, "membership_required", "active group membership is required")
	}
	f, ok := st.Files[id]
	if !ok || f.GroupID != group || f.ChunkCount == 0 {
		return store.File{}, fail(404, "file_not_found", "file transfer not found")
	}
	return f, nil
}

func (s *Server) putFileChunk(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	group, id := r.PathValue("group"), r.PathValue("file")
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 {
		writeError(w, r, 400, "invalid_chunk_index", "chunk index must be a non-negative integer")
		return
	}
	if len(body) == 0 || int64(len(body)) > maxFileChunkBytes {
		writeError(w, r, 400, "invalid_chunk_size", "chunk body must contain 1 to 4194304 bytes")
		return
	}
	checksum := sha256.Sum256(body)
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	var target store.File
	err = s.store.View(func(st store.State) error {
		var e error
		target, e = s.transferFor(st, group, id, device)
		if e != nil {
			return e
		}
		if target.SenderID != device {
			return fail(403, "sender_required", "only the transfer sender may upload chunks")
		}
		if target.Status != "uploading" {
			return fail(409, "transfer_state", "transfer is not accepting chunks")
		}
		if index >= target.ChunkCount {
			return fail(400, "invalid_chunk_index", "chunk index is outside the transfer")
		}
		want := target.ChunkSizeBytes
		if index == target.ChunkCount-1 {
			want = target.SizeBytes - int64(index)*target.ChunkSizeBytes
		}
		if int64(len(body)) != want {
			return fail(400, "invalid_chunk_size", "chunk body does not match the declared chunk size")
		}
		if old := target.ReceivedChunks[index]; old != "" && old != hex.EncodeToString(checksum[:]) {
			return fail(409, "chunk_conflict", "a different chunk is already stored at this index")
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	partPath := s.fileChunkPath(id, index)
	if target.ReceivedChunks[index] == "" {
		if err := s.writeAtomic(s.fileChunkPath(id, index), body); err != nil {
			writeError(w, r, 500, "blob_write_failed", "could not durably store file chunk")
			return
		}
	} else if existing, err := os.ReadFile(partPath); err != nil || !bytes.Equal(existing, body) {
		if err := s.writeAtomic(partPath, body); err != nil {
			writeError(w, r, 500, "blob_write_failed", "could not repair a previously acknowledged file chunk")
			return
		}
	}
	bodyHash := hex.EncodeToString(checksum[:])
	s.mutate(w, r, device, fmt.Sprintf("file_transfer.chunk:%s:%d", id, index), body, func(st *store.State) (int, any, error) {
		f, err := s.transferFor(*st, group, id, device)
		if err != nil {
			return 0, nil, err
		}
		if f.SenderID != device || f.Status != "uploading" {
			return 0, nil, fail(409, "transfer_state", "transfer is not accepting chunks")
		}
		if old := f.ReceivedChunks[index]; old != "" && old != bodyHash {
			return 0, nil, fail(409, "chunk_conflict", "a different chunk is already stored at this index")
		}
		if f.ReceivedChunks == nil {
			f.ReceivedChunks = map[int]string{}
		}
		f.ReceivedChunks[index] = bodyHash
		st.Files[id] = f
		return 200, map[string]any{"file_id": id, "chunk_index": index, "sha256": bodyHash, "status": "stored"}, nil
	})
}

func (s *Server) completeFileTransfer(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		writeError(w, r, 400, "invalid_request", "complete request must be empty")
		return
	}
	group, id := r.PathValue("group"), r.PathValue("file")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	var f store.File
	err := s.store.View(func(st store.State) error {
		var e error
		f, e = s.transferFor(st, group, id, device)
		if e != nil {
			return e
		}
		if f.SenderID != device {
			return fail(403, "sender_required", "only the transfer sender may complete an upload")
		}
		if f.Status == "available" {
			return nil
		}
		if f.Status != "uploading" {
			return fail(409, "transfer_state", "transfer cannot be completed")
		}
		if len(f.ReceivedChunks) != f.ChunkCount {
			return fail(409, "chunks_missing", "all declared chunks must be uploaded before completion")
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	if f.Status == "uploading" {
		if err := s.assembleFile(f); err != nil {
			if errors.Is(err, errFileHashMismatch) {
				writeError(w, r, 422, "file_hash_mismatch", "assembled ciphertext does not match the declared sha256")
				return
			}
			writeError(w, r, 500, "blob_write_failed", "could not finalize encrypted file")
			return
		}
	}
	statusBody := body
	if len(statusBody) == 0 {
		statusBody = []byte("{}")
	}
	s.mutate(w, r, device, "file_transfer.complete:"+id, statusBody, func(st *store.State) (int, any, error) {
		current, err := s.transferFor(*st, group, id, device)
		if err != nil {
			return 0, nil, err
		}
		if current.SenderID != device {
			return 0, nil, fail(403, "sender_required", "only the transfer sender may complete an upload")
		}
		if current.Status == "available" {
			return 200, map[string]any{"file_id": id, "status": current.Status, "sha256": current.SHA256}, nil
		}
		if current.Status != "uploading" {
			return 0, nil, fail(409, "transfer_state", "transfer cannot be completed")
		}
		if len(current.ReceivedChunks) != current.ChunkCount {
			return 0, nil, fail(409, "chunks_missing", "all declared chunks must be uploaded before completion")
		}
		current.Status = "available"
		current.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		st.Files[id] = current
		return 200, map[string]any{"file_id": id, "status": current.Status, "sha256": current.SHA256}, nil
	})
	// The metadata commit makes the assembled blob authoritative. The cleanup
	// pass removes resumable chunk copies only after observing that durable state.
	s.cleanupFiles(time.Now().UTC())
}

var errFileHashMismatch = errors.New("file checksum mismatch")

func (s *Server) assembleFile(f store.File) error {
	if err := s.ensureFileDirectory(filepath.Dir(s.fileBlobPath(f.ID))); err != nil {
		return err
	}
	if existing, err := os.OpenFile(s.fileBlobPath(f.ID), os.O_RDWR, 0); err == nil {
		stat, statErr := existing.Stat()
		h := sha256.New()
		_, hashErr := io.Copy(h, existing)
		if statErr == nil && hashErr == nil && stat.Size() == f.SizeBytes && hex.EncodeToString(h.Sum(nil)) == f.SHA256 {
			// A retry may find the blob rename completed before the metadata
			// commit. Re-sync both the file and its directory before accepting it.
			if err := existing.Sync(); err != nil {
				_ = existing.Close()
				return err
			}
			if err := existing.Close(); err != nil {
				return err
			}
			return syncDir(filepath.Dir(s.fileBlobPath(f.ID)))
		}
		_ = existing.Close()
		if err := os.Remove(s.fileBlobPath(f.ID)); err != nil {
			return err
		}
	}
	out, err := os.CreateTemp(filepath.Dir(s.fileBlobPath(f.ID)), ".blob-*.tmp")
	if err != nil {
		return err
	}
	name := out.Name()
	defer func() { _ = os.Remove(name) }()
	if err = out.Chmod(0600); err != nil {
		_ = out.Close()
		return err
	}
	if err = secureFilePath(name); err != nil {
		_ = out.Close()
		return err
	}
	h := sha256.New()
	for i := 0; i < f.ChunkCount; i++ {
		part, openErr := os.Open(s.fileChunkPath(f.ID, i))
		if openErr != nil {
			_ = out.Close()
			return openErr
		}
		chunkHash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(out, h, chunkHash), part)
		closeErr := part.Close()
		if copyErr != nil {
			_ = out.Close()
			return copyErr
		}
		if closeErr != nil {
			_ = out.Close()
			return closeErr
		}
		if written != expectedFileChunkSize(f, i) {
			_ = out.Close()
			return errors.New("stored chunk has invalid size")
		}
		if hex.EncodeToString(chunkHash.Sum(nil)) != f.ReceivedChunks[i] {
			_ = out.Close()
			return errors.New("stored chunk checksum mismatch")
		}
	}
	if hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		_ = out.Close()
		return errFileHashMismatch
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.fileBlobPath(f.ID)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(s.fileBlobPath(f.ID)))
}

func expectedFileChunkSize(f store.File, index int) int64 {
	if index == f.ChunkCount-1 {
		return f.SizeBytes - int64(index)*f.ChunkSizeBytes
	}
	return f.ChunkSizeBytes
}

func (s *Server) getFileChunk(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	group, id := r.PathValue("group"), r.PathValue("file")
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 {
		writeError(w, r, 400, "invalid_chunk_index", "chunk index must be a non-negative integer")
		return
	}
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.cleanupFiles(time.Now().UTC())
	var f store.File
	err = s.store.View(func(st store.State) error {
		var e error
		f, e = s.transferFor(st, group, id, device)
		if e != nil {
			return e
		}
		if f.Status == "tombstone" {
			return fail(410, "file_unavailable", "file ciphertext has been removed; request a fresh copy from a member")
		}
		if f.Status != "available" {
			return fail(409, "file_incomplete", "file is not ready for download")
		}
		if index >= f.ChunkCount {
			return fail(404, "chunk_not_found", "chunk index is outside the file")
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	length := expectedFileChunkSize(f, index)
	offset := int64(index) * f.ChunkSizeBytes
	if f.ChunkSizeBytes <= 0 || f.ChunkSizeBytes > maxFileChunkBytes || length <= 0 || length > maxFileChunkBytes || offset < 0 || offset > f.SizeBytes || length > f.SizeBytes-offset || f.ReceivedChunks[index] == "" {
		s.respondCorruptFileChunk(w, r, id)
		return
	}
	blob, err := os.Open(s.fileBlobPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.respondCorruptFileChunk(w, r, id)
			return
		}
		writeError(w, r, 500, "blob_read_failed", "could not read encrypted file")
		return
	}
	stat, statErr := blob.Stat()
	if statErr != nil || stat.Size() != f.SizeBytes {
		_ = blob.Close()
		s.respondCorruptFileChunk(w, r, id)
		return
	}
	// Read and authenticate the complete requested chunk before writing any
	// response bytes. The descriptor caps this allocation at four MiB.
	chunk := make([]byte, int(length))
	n, readErr := io.ReadFull(io.NewSectionReader(blob, offset, length), chunk)
	closeErr := blob.Close()
	if readErr != nil || int64(n) != length || closeErr != nil {
		s.respondCorruptFileChunk(w, r, id)
		return
	}
	chunkHash := sha256.Sum256(chunk)
	if hex.EncodeToString(chunkHash[:]) != f.ReceivedChunks[index] {
		s.respondCorruptFileChunk(w, r, id)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Chunk-SHA256", f.ReceivedChunks[index])
	if _, err := w.Write(chunk); err != nil {
		return
	}
	if err := s.store.Update(func(st *store.State) error {
		current, ok := st.Files[id]
		if ok && current.Status == "available" {
			current.LastDownloadedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if current.DownloadedBy == nil {
				current.DownloadedBy = map[string]bool{}
			}
			if !current.DownloadedBy[device] {
				current.DownloadCount++
			}
			current.DownloadedBy[device] = true
			st.Files[id] = current
		}
		return nil
	}); err != nil {
		return
	}
}

func (s *Server) respondCorruptFileChunk(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.tombstoneUnavailableFile(id, "corrupt_no_copy"); err != nil {
		writeError(w, r, 500, "storage_unavailable", "could not record unavailable file state")
		return
	}
	s.cleanupFiles(time.Now().UTC())
	writeError(w, r, 410, "file_unavailable", "file ciphertext is missing or corrupt; request a fresh copy from a member")
}

func (s *Server) tombstoneUnavailableFile(id, reason string) error {
	return s.store.Update(func(st *store.State) error {
		f, ok := st.Files[id]
		if !ok || f.ChunkCount == 0 || f.Status == "tombstone" {
			return nil
		}
		f.Status = "tombstone"
		f.TombstoneReason = reason
		st.Files[id] = f
		return nil
	})
}

func targetContains(f store.File, device string) bool {
	for _, id := range f.Targets {
		if id == device {
			return true
		}
	}
	return false
}

func (s *Server) ackFileTransfer(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		writeError(w, r, 400, "invalid_request", "ack request must be empty")
		return
	}
	group, id := r.PathValue("group"), r.PathValue("file")
	if len(body) == 0 {
		body = []byte("{}")
	}
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.mutate(w, r, device, "file_transfer.ack:"+id, body, func(st *store.State) (int, any, error) {
		f, err := s.transferFor(*st, group, id, device)
		if err != nil {
			return 0, nil, err
		}
		if f.Status != "available" {
			return 0, nil, fail(409, "file_unavailable", "only an available file can be acknowledged")
		}
		if !targetContains(f, device) {
			return 0, nil, fail(403, "not_a_recipient", "device is not a target recipient for this file")
		}
		if f.Acknowledged == nil {
			f.Acknowledged = map[string]bool{}
		}
		f.Acknowledged[device] = true
		all := allFileTargetsAcknowledged(f)
		if all {
			f.Status = "tombstone"
			f.TombstoneReason = "all_targets_acknowledged"
		}
		st.Files[id] = f
		return 200, map[string]any{"file_id": id, "device_id": device, "status": "acknowledged", "cleanup_pending": all}, nil
	})
}

func allFileTargetsAcknowledged(f store.File) bool {
	if len(f.Targets) == 0 {
		return false
	}
	for _, target := range f.Targets {
		if !f.Acknowledged[target] {
			return false
		}
	}
	return true
}

func (s *Server) listFileTransfers(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	group := r.PathValue("group")
	limit := parseLimit(r, 100, 200)
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, r, 400, "invalid_cursor", "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	var items []store.File
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, f := range st.Files {
			if f.GroupID == group && f.ChunkCount > 0 {
				items = append(items, f)
			}
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt < items[j].CreatedAt })
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := append([]store.File(nil), items[offset:end]...)
	next := end
	if end == len(items) {
		next = 0
	}
	writeJSON(w, 200, map[string]any{"items": page, "next_offset": next})
}

// fileCacheStatsHandler reports the logical transfer state and the physical
// cache state for one group. It deliberately does not run the global janitor:
// a group-scoped read must not remove another group's files.
func (s *Server) fileCacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	stats := fileCacheStats{GroupID: group}
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, f := range st.Files {
			if f.GroupID != group || f.ChunkCount == 0 {
				continue
			}
			physicalBytes := s.filePhysicalBytes(f.ID)
			stats.PhysicalBytes += physicalBytes
			status := f.Status
			if status == "" {
				status = "available"
			}
			switch status {
			case "uploading":
				stats.Uploading.Count++
				stats.Uploading.Bytes += f.SizeBytes
			case "available":
				stats.Available.Count++
				stats.Available.Bytes += f.SizeBytes
			case "tombstone":
				stats.LogicalDeleted.Count++
				stats.LogicalDeleted.Bytes += f.SizeBytes
				if physicalBytes > 0 {
					stats.CleanupPending.Count++
					stats.CleanupPending.Bytes += physicalBytes
				}
			}
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	writeJSON(w, 200, stats)
}

func (s *Server) cleanupFileCache(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	var req fileCacheCleanupRequest
	if err := decodeJSON(body, &req); err != nil || len(req.FileIDs) == 0 {
		writeError(w, r, 400, "invalid_cleanup_request", "file_ids must contain at least one file id")
		return
	}
	if len(req.FileIDs) > maxFileCleanupBatch {
		writeError(w, r, 400, "cleanup_batch_too_large", fmt.Sprintf("file_ids may contain at most %d entries", maxFileCleanupBatch))
		return
	}
	seen := make(map[string]bool, len(req.FileIDs))
	for _, id := range req.FileIDs {
		if id == "" || seen[id] {
			writeError(w, r, 400, "invalid_cleanup_request", "file_ids must contain distinct non-empty ids")
			return
		}
		seen[id] = true
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(key) < 8 || len(key) > 128 {
		writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key must contain 8 to 128 characters")
		return
	}
	storageKey := idempotencyKey(device, "file_cache.cleanup:"+group, key)
	hash := fingerprint("file_cache.cleanup:"+group, body)
	var replay store.Idempotent
	replayed := false
	if err := s.store.View(func(st store.State) error {
		if old, ok := st.Idempotency[storageKey]; ok {
			if old.Fingerprint != hash {
				return errIdempotencyConflict
			}
			replay = old
			replayed = true
		}
		return nil
	}); err != nil {
		if errors.Is(err, errIdempotencyConflict) {
			writeError(w, r, 409, "idempotency_conflict", "Idempotency-Key was already used with a different request")
		} else {
			writeError(w, r, 500, "storage_unavailable", "could not read durable state")
		}
		return
	}
	if replayed {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(replay.Status)
		_, _ = w.Write(append(append([]byte(nil), replay.Body...), '\n'))
		return
	}
	var deleted, already []string
	err := s.store.Update(func(st *store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, id := range req.FileIDs {
			f, ok := st.Files[id]
			if !ok || f.GroupID != group || f.ChunkCount == 0 {
				return fail(404, "file_not_found", "file transfer not found")
			}
			if f.SenderID != device && member.Role != "creator" && member.Role != "admin" {
				return fail(403, "delete_forbidden", "only the sender or group administrator may delete this file")
			}
		}
		for _, id := range req.FileIDs {
			f := st.Files[id]
			if f.Status == "tombstone" {
				already = append(already, id)
				continue
			}
			f.Status = "tombstone"
			f.TombstoneReason = "deleted_by_member"
			st.Files[id] = f
			deleted = append(deleted, id)
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	// The metadata transition is durable before physical removal begins. The
	// targeted cleanup preserves files belonging to every other group.
	s.cleanupSelectedFileArtifacts(req.FileIDs)
	pending := make([]string, 0)
	for _, id := range req.FileIDs {
		if s.filePhysicalBytes(id) > 0 {
			pending = append(pending, id)
		}
	}
	responseValue := map[string]any{
		"group_id":                  group,
		"requested":                 len(req.FileIDs),
		"logical_deleted":           deleted,
		"already_deleted":           already,
		"cleanup_pending":           pending,
		"physical_cleanup_complete": len(pending) == 0,
	}
	response, err := json.Marshal(responseValue)
	if err != nil {
		writeError(w, r, 500, "internal_error", "could not encode cleanup response")
		return
	}
	if err := s.store.Update(func(st *store.State) error {
		if old, ok := st.Idempotency[storageKey]; ok {
			if old.Fingerprint != hash {
				return errIdempotencyConflict
			}
			return nil
		}
		st.Idempotency[storageKey] = store.Idempotent{Fingerprint: hash, Status: 200, Body: response}
		return nil
	}); err != nil {
		if errors.Is(err, errIdempotencyConflict) {
			writeError(w, r, 409, "idempotency_conflict", "Idempotency-Key was already used with a different request")
		} else {
			writeError(w, r, 500, "storage_unavailable", "cleanup committed but idempotency result could not be recorded")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(append(response, '\n'))
}

func (s *Server) filePhysicalBytes(id string) int64 {
	var total int64
	add := func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		if !info.IsDir() {
			total += info.Size()
			return
		}
		_ = filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if info, err := entry.Info(); err == nil {
				total += info.Size()
			}
			return nil
		})
	}
	add(s.fileBlobPath(id))
	add(filepath.Join(s.fileRoot(), "uploads", id))
	return total
}

func (s *Server) cleanupSelectedFileArtifacts(ids []string) {
	for _, id := range ids {
		_ = os.Remove(s.fileBlobPath(id))
		_ = os.RemoveAll(filepath.Join(s.fileRoot(), "uploads", id))
	}
}

func (s *Server) deleteFileTransfer(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if !s.requireFileStorage(w, r) {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		writeError(w, r, 400, "invalid_request", "delete request must be empty")
		return
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	group, id := r.PathValue("group"), r.PathValue("file")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.mutate(w, r, device, "file_transfer.delete:"+id, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		f, ok := st.Files[id]
		if !ok || f.GroupID != group || f.ChunkCount == 0 {
			return 0, nil, fail(404, "file_not_found", "file transfer not found")
		}
		if f.SenderID != device && m.Role != "creator" && m.Role != "admin" {
			return 0, nil, fail(403, "delete_forbidden", "only the sender or group administrator may delete this file")
		}
		f.Status = "tombstone"
		f.TombstoneReason = "deleted_by_member"
		st.Files[id] = f
		return 200, map[string]any{"file_id": id, "status": "deleted"}, nil
	})
	s.cleanupFiles(time.Now().UTC())
}

// RemoveFileTarget is intended to be called from the same durable membership
// transition that removes a device. It prevents departed devices from holding
// file delivery open. Physical cleanup runs on the next file request or janitor.
func RemoveFileTarget(st *store.State, group, device string) {
	for id, f := range st.Files {
		if f.GroupID != group || f.ChunkCount == 0 {
			continue
		}
		if f.SenderID == device && f.Status == "uploading" {
			f.Status = "tombstone"
			f.TombstoneReason = "sender_left_no_copy"
			st.Files[id] = f
			continue
		}
		for i, target := range f.Targets {
			if target == device {
				f.Targets = append(f.Targets[:i], f.Targets[i+1:]...)
				break
			}
		}
		delete(f.Acknowledged, device)
		if len(f.Targets) == 0 && (f.Status == "available" || f.Status == "uploading") {
			f.Status = "tombstone"
			f.TombstoneReason = "no_remaining_targets"
		} else if f.Status == "available" && allFileTargetsAcknowledged(f) {
			f.Status = "tombstone"
			f.TombstoneReason = "all_targets_acknowledged"
		}
		st.Files[id] = f
	}
}

// TombstoneGroupFiles must be called before deleting a group's state. The
// cleanup pass removes the physical blobs after the durable membership/group
// transaction commits.
func TombstoneGroupFiles(st *store.State, group string) {
	for id, f := range st.Files {
		if f.GroupID != group || f.ChunkCount == 0 {
			continue
		}
		f.Status = "tombstone"
		f.TombstoneReason = "group_deleted_no_copy"
		st.Files[id] = f
	}
}

// FileCleanupLoop should be started once by the server process to enforce TTL
// while idle. Cleanup also runs opportunistically on every transfer request.
func (s *Server) FileCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.fileLock().Lock()
		s.cleanupFiles(time.Now().UTC())
		s.fileLock().Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) cleanupFiles(now time.Time) {
	var remove []string
	var removeUploads []string
	active := map[string]bool{}
	if err := s.store.Update(func(st *store.State) error {
		for id, f := range st.Files {
			if f.ChunkCount == 0 {
				if f.Ciphertext != "" {
					// Remove inline ciphertext left by an older snapshot-backed API.
					// Keep a durable marker so clients can request a fresh copy.
					f.Ciphertext = ""
					f.Status = "tombstone"
					f.TombstoneReason = "legacy_inline_removed_no_copy"
					st.Files[id] = f
				}
				continue
			}
			if f.Status != "tombstone" && f.ExpiresAt != "" {
				if expires, err := time.Parse(time.RFC3339Nano, f.ExpiresAt); err == nil && !now.Before(expires) {
					f.Status = "tombstone"
					f.TombstoneReason = "expired_no_copy"
					st.Files[id] = f
				}
			}
			if f.Status == "tombstone" {
				remove = append(remove, id)
			} else if f.ChunkCount > 0 {
				active[id] = true
				if f.Status == "available" {
					removeUploads = append(removeUploads, id)
				}
			}
		}
		return nil
	}); err != nil {
		return
	}
	for _, id := range removeUploads {
		uploadDir := filepath.Join(s.fileRoot(), "uploads", id)
		if err := os.RemoveAll(uploadDir); err == nil {
			_ = syncDir(filepath.Dir(uploadDir))
		}
	}
	for _, id := range remove {
		_ = os.Remove(s.fileBlobPath(id))
		_ = os.RemoveAll(filepath.Join(s.fileRoot(), "uploads", id))
	}
	s.cleanupOrphanBlobs(active)
	s.cleanupStaleFileTemps()
}

func (s *Server) cleanupOrphanBlobs(active map[string]bool) {
	blobsDir := filepath.Join(s.fileRoot(), "blobs")
	if entries, err := os.ReadDir(blobsDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() && strings.HasSuffix(name, ".blob") && !active[strings.TrimSuffix(name, ".blob")] {
				_ = os.Remove(filepath.Join(blobsDir, name))
			}
		}
	}
	uploadsDir := filepath.Join(s.fileRoot(), "uploads")
	if entries, err := os.ReadDir(uploadsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && !active[entry.Name()] {
				_ = os.RemoveAll(filepath.Join(uploadsDir, entry.Name()))
			}
		}
	}
}

// cleanupStaleFileTemps removes only temporary names created by this package.
// Callers hold fileLock so no active upload or assembly can own these paths.
func (s *Server) cleanupStaleFileTemps() {
	blobsDir := filepath.Join(s.fileRoot(), "blobs")
	cleanupNamedTemps(blobsDir, ".blob-")

	uploadsDir := filepath.Join(s.fileRoot(), "uploads")
	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			cleanupNamedTemps(filepath.Join(uploadsDir, entry.Name()), ".chunk-")
		}
	}
}

func cleanupNamedTemps(dir, prefix string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		if info, err := entry.Info(); err == nil && info.Mode().IsRegular() {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func (s *Server) fileStorageStats() FileStorageStats {
	stats := FileStorageStats{}
	_ = s.store.View(func(st store.State) error {
		for _, f := range st.Files {
			if f.Status == "tombstone" {
				stats.Tombstones++
				if f.TombstoneReason == "quota_evicted_no_copy" {
					stats.Evictions++
				}
				continue
			}
			if f.ChunkCount == 0 {
				// Pre-transfer legacy records remain in older snapshots and count
				// against logical quota until explicitly migrated/removed.
				stats.UsedBytes += f.SizeBytes
				stats.FileCount++
				continue
			}
			stats.UsedBytes += f.SizeBytes
			stats.FileCount++
			if f.Status == "uploading" {
				stats.PendingUploads++
			}
		}
		return nil
	})
	var total int64
	var visit func(string)
	visit = func(path string) {
		entries, err := os.ReadDir(path)
		if err != nil {
			return
		}
		for _, entry := range entries {
			child := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				visit(child)
				continue
			}
			if info, err := entry.Info(); err == nil {
				total += info.Size()
			}
		}
	}
	visit(s.fileRoot())
	stats.BlobBytes = total
	return stats
}

func (s *Server) writeAtomic(path string, data []byte) error {
	if err := s.ensureFileDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return syncExistingFileAndDir(path)
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".chunk-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = secureFilePath(tmp)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	keep = true
	return syncDir(filepath.Dir(path))
}

func syncExistingFileAndDir(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
