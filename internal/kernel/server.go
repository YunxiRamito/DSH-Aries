package kernel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aries.local/aries/internal/store"
)

const APIVersion = "v1"
const maxRequestBytes = 4 << 20
const challengeLifetime = 2 * time.Minute
const deviceProofWindow = 5 * time.Minute
const maxDeviceNonces = 100000

var BuildVersion = "dev"

type Server struct {
	store      *store.Store
	configMu   sync.RWMutex
	config     Config
	configPath string
	tokenHash  [32]byte
	startedAt  time.Time
	publicAddr string
	adminAddr  string
	shutdown   func()

	mu             sync.Mutex
	challenges     map[string]challenge
	challengeRates map[string]challengeRate
	commandMu      sync.Mutex
	presenceMu     sync.Mutex
	presence       map[string]presenceRecord
}

type challenge struct {
	DeviceID   string
	PublicKey  []byte
	Nonce      []byte
	ExpiresAt  time.Time
	Enrollment bool
}

type challengeRate struct {
	WindowStart time.Time
	Count       int
}

func New(config Config, configPath string, st *store.Store) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	token, err := os.ReadFile(config.AdminTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read admin token file: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) < 32 {
		return nil, errors.New("admin token must contain at least 32 bytes")
	}
	if err := st.View(func(store.State) error { return nil }); err != nil {
		return nil, err
	}
	h := sha256.Sum256(token)
	return &Server{store: st, config: config, configPath: configPath, tokenHash: h, startedAt: time.Now().UTC(), publicAddr: config.PublicListen, adminAddr: config.AdminListen, challenges: map[string]challenge{}, challengeRates: map[string]challengeRate{}, presence: map[string]presenceRecord{}}, nil
}

func (s *Server) configSnapshot() Config {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config
}

func (s *Server) replaceConfig(config Config) {
	s.configMu.Lock()
	s.config = config
	s.configMu.Unlock()
}

func (s *Server) SetShutdown(fn func()) { s.shutdown = fn }

func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/v1/public/node", s.publicNodeInfo)
	mux.HandleFunc("POST /api/v1/public/devices/challenge", s.deviceChallenge)
	mux.HandleFunc("POST /api/v1/public/devices/enroll", s.deviceEnroll)
	mux.HandleFunc("POST /api/v1/public/devices/heartbeat", s.deviceHeartbeat)
	mux.HandleFunc("POST /api/v1/public/groups", s.createGroup)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/invites", s.createInvite)
	mux.HandleFunc("GET /api/v1/public/invites/{code}", s.inviteInfo)
	mux.HandleFunc("POST /api/v1/public/invites/{code}/applications", s.applyInvite)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/applications", s.applicationList)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/applications/{application}", s.applicationStatus)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/applications/{application}/approvals", s.approveApplication)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/applications/{application}/key-delivery", s.deliverJoinKey)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/events", s.groupEvents)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/leave", s.leaveGroup)
	mux.HandleFunc("PUT /api/v1/public/groups/{group}/members/{member}/role", s.setMemberRole)
	mux.HandleFunc("DELETE /api/v1/public/groups/{group}/members/{member}", s.revokeMember)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/creator", s.transferCreator)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/members", s.memberList)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/presence", s.groupPresence)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/rotations/{event}", s.completeRotation)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/key-deliveries", s.keyDeliveries)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/key-deliveries/{delivery}/ack", s.ackKeyDelivery)
	mux.HandleFunc("POST /api/v1/public/groups/{group}/messages", s.postMessage)
	mux.HandleFunc("GET /api/v1/public/groups/{group}/messages", s.listMessages)
	s.registerFileRoutes(mux)
	return requestIDs(s.secureTransport(mux))
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /api/v1/admin/status", s.adminAuth(http.HandlerFunc(s.adminStatus)))
	mux.Handle("GET /api/v1/admin/config", s.adminAuth(http.HandlerFunc(s.adminConfig)))
	mux.Handle("PUT /api/v1/admin/config", s.adminAuth(http.HandlerFunc(s.putAdminConfig)))
	mux.Handle("GET /api/v1/admin/groups", s.adminAuth(http.HandlerFunc(s.adminGroups)))
	mux.Handle("GET /api/v1/admin/storage", s.adminAuth(http.HandlerFunc(s.adminStorage)))
	mux.Handle("POST /api/v1/admin/shutdown", s.adminAuth(http.HandlerFunc(s.adminShutdown)))
	s.registerCommandRoutes(mux)
	return requestIDs(s.secureTransport(mux))
}

// Remote cleartext HTTP is rejected. When explicitly enabled, loopback HTTP is
// useful for local development and for TLS-terminating reverse proxies bound
// to loopback; forwarded headers are never trusted for this decision.
func (s *Server) secureTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip := net.ParseIP(host)
			if !s.configSnapshot().AllowInsecureLoopback || err != nil || ip == nil || !ip.IsLoopback() {
				writeError(w, r, http.StatusUpgradeRequired, "tls_required", "TLS is required for non-loopback connections")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		got := sha256.Sum256([]byte(parts[1]))
		if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "api_version": APIVersion, "build_version": BuildVersion, "started_at": s.startedAt.Format(time.RFC3339Nano)})
}

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.statusData())
}

func (s *Server) adminConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.configSnapshot())
}

func (s *Server) putAdminConfig(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	key, replayed, ok := s.checkAdminIdempotency(w, r, "admin.config.put", b)
	if !ok {
		return
	}
	if replayed {
		return
	}
	// Preserve defaults for fields introduced by newer config schema revisions.
	c := DefaultConfig()
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		writeError(w, r, 400, "invalid_config", err.Error())
		return
	}
	if err = ensureEOF(dec); err != nil {
		writeError(w, r, 400, "invalid_config", err.Error())
		return
	}
	if err = c.Validate(); err != nil {
		writeError(w, r, 400, "invalid_config", err.Error())
		return
	}
	// Relative data and token paths in the API document resolve against the
	// current config directory, matching startup and command-dispatch behavior.
	c = resolveConfigPaths(c, s.configPath)
	oldConfig := s.configSnapshot()
	if err = s.persistConfig(c); err != nil {
		writeError(w, r, 500, "config_write_failed", "could not persist configuration")
		return
	}
	var response any = c
	if restartRequired(oldConfig, c) {
		// These fields are durable and visible now; listener/store/token changes
		// require a process restart to take effect in this single-process slice.
		response = map[string]any{"schema_version": c.SchemaVersion, "public_listen": c.PublicListen, "admin_listen": c.AdminListen, "data_dir": c.DataDir, "admin_token_file": c.AdminTokenFile, "max_storage_bytes": c.MaxStorageBytes, "allow_insecure_loopback": c.AllowInsecureLoopback, "peer_relay_enabled": c.PeerRelayEnabled, "file_storage_enabled": c.FileStorageEnabled, "group_quota_bytes": c.GroupQuotaBytes, "quota_bytes_per_member": c.QuotaBytesPerMember, "max_file_bytes": c.MaxFileBytes, "max_file_ttl_seconds": c.MaxFileTTLSeconds, "heartbeat_interval_seconds": c.HeartbeatIntervalSeconds, "heartbeat_timeout_seconds": c.HeartbeatTimeoutSeconds, "restart_required": true}
	}
	encoded, _ := json.Marshal(response)
	if err := s.rememberAdminIdempotency(key, "admin.config.put", b, 200, encoded); err != nil {
		writeError(w, r, 500, "storage_unavailable", "configuration saved but idempotency result could not be committed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(append(encoded, '\n'))
}

func (s *Server) adminGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.groupsData()})
}

func (s *Server) adminStorage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.storageData())
}

func (s *Server) adminShutdown(w http.ResponseWriter, r *http.Request) {
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	b, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	key, replayed, ok := s.checkAdminIdempotency(w, r, "admin.shutdown", b)
	if !ok {
		return
	}
	if replayed {
		return
	}
	response := []byte(`{"status":"shutting_down"}`)
	if err := s.rememberAdminIdempotency(key, "admin.shutdown", b, 202, response); err != nil {
		writeError(w, r, 500, "storage_unavailable", "could not persist shutdown request")
		return
	}
	if err := s.store.Close(); err != nil {
		writeError(w, r, 500, "flush_failed", "could not flush durable state")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(202)
	_, _ = w.Write(append(response, '\n'))
	if s.shutdown != nil {
		go s.shutdown()
	}
}

func (s *Server) nodeID() string {
	var id string
	_ = s.store.View(func(st store.State) error { id = st.NodeID; return nil })
	return id
}

func resolveConfigPath(configPath, value string) string {
	if value == "" {
		return value
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(configPath), value))
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(b) > maxRequestBytes {
		return nil, errors.New("request body is invalid or too large")
	}
	return b, nil
}

func requestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := randomToken(12)
		if err != nil {
			id = "unavailable"
		}
		w.Header().Set("X-Request-ID", id)
		r2 := r.Clone(r.Context())
		r2.Header = r.Header.Clone()
		r2.Header.Set("X-Request-ID", id)
		next.ServeHTTP(w, r2)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = "unavailable"
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": id}})
}

func decodeJSON(body []byte, dst any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return ensureEOF(dec)
}

func decodeOpaque(value string) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("ciphertext must be non-empty unpadded base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) == 0 {
		return nil, errors.New("ciphertext must be non-empty unpadded base64url")
	}
	return b, nil
}

func fingerprint(scope string, body []byte) string {
	h := sha256.Sum256(append([]byte(scope+"\n"), body...))
	return hex.EncodeToString(h[:])
}

func idempotencyKey(device, operation, key string) string {
	return device + "\x00" + operation + "\x00" + key
}

func (s *Server) mutate(w http.ResponseWriter, r *http.Request, device, operation string, body []byte, fn func(*store.State) (int, any, error)) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(key) < 8 || len(key) > 128 {
		writeError(w, r, 400, "idempotency_key_required", "Idempotency-Key must contain 8 to 128 characters")
		return
	}
	storageKey := idempotencyKey(device, operation, key)
	hash := fingerprint(operation, body)
	var status int
	var response json.RawMessage
	err := s.store.Update(func(st *store.State) error {
		if old, ok := st.Idempotency[storageKey]; ok {
			if old.Fingerprint != hash {
				return errIdempotencyConflict
			}
			status = old.Status
			response = append([]byte(nil), old.Body...)
			return nil
		}
		var value any
		var actionErr error
		status, value, actionErr = fn(st)
		if actionErr != nil {
			return actionErr
		}
		var encodeErr error
		response, encodeErr = json.Marshal(value)
		if encodeErr != nil {
			return encodeErr
		}
		st.Idempotency[storageKey] = store.Idempotent{Fingerprint: hash, Status: status, Body: response}
		return nil
	})
	if errors.Is(err, errIdempotencyConflict) {
		writeError(w, r, 409, "idempotency_conflict", "Idempotency-Key was already used with a different request")
		return
	}
	if err != nil {
		var ae apiError
		if errors.As(err, &ae) {
			writeError(w, r, ae.status, ae.code, ae.message)
			return
		}
		writeError(w, r, 500, "storage_unavailable", "could not commit durable state")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(response, '\n'))
}

var errIdempotencyConflict = errors.New("idempotency conflict")

type apiError struct {
	status        int
	code, message string
}

func (e apiError) Error() string { return e.message }
func httpError(err error) (int, string, string) {
	var e apiError
	if errors.As(err, &e) {
		return e.status, e.code, e.message
	}
	return 500, "internal_error", "request could not be completed"
}
func fail(status int, code, message string) error {
	return apiError{status: status, code: code, message: message}
}

func (s *Server) deviceProof(r *http.Request, body []byte) (string, error) {
	deviceID := r.Header.Get("X-Device-ID")
	timestamp := r.Header.Get("X-Device-Timestamp")
	nonce := r.Header.Get("X-Device-Nonce")
	signature := r.Header.Get("X-Device-Signature")
	if deviceID == "" || timestamp == "" || nonce == "" || signature == "" {
		return "", fail(401, "device_proof_required", "device proof headers are required")
	}
	tm, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(tm) > deviceProofWindow || time.Until(tm) > deviceProofWindow {
		return "", fail(401, "device_proof_expired", "device proof timestamp is invalid or expired")
	}
	if len(nonce) < 12 || len(nonce) > 128 {
		return "", fail(401, "invalid_device_proof", "device nonce is invalid")
	}
	var pub []byte
	err = s.store.View(func(st store.State) error {
		d, ok := st.Devices[deviceID]
		if !ok {
			return errors.New("unknown device")
		}
		decoded, e := base64.RawURLEncoding.DecodeString(d.PublicKey)
		if e != nil {
			return e
		}
		pub = decoded
		return nil
	})
	if err != nil {
		return "", fail(401, "unknown_device", "device identity is not registered")
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fail(401, "invalid_device_proof", "device signature is invalid")
	}
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{r.Method, r.URL.RequestURI(), timestamp, nonce, r.Header.Get("Idempotency-Key"), base64.RawURLEncoding.EncodeToString(bodyHash[:])}, "\n")
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(canonical), sig) {
		return "", fail(401, "invalid_device_proof", "device signature is invalid")
	}
	now := time.Now().UTC()
	cacheKey := deviceNonceKey(deviceID, nonce)
	err = s.store.AcceptDeviceNonce(cacheKey, tm.Add(deviceProofWindow).UnixNano(), now.UnixNano(), maxDeviceNonces)
	if errors.Is(err, store.ErrNonceReplay) {
		return "", fail(409, "replayed_device_proof", "device proof nonce was already used")
	}
	if errors.Is(err, store.ErrNonceCapacity) {
		return "", fail(503, "device_proof_capacity", "device proof verification is temporarily at capacity")
	}
	if err != nil {
		return "", fail(503, "device_proof_storage", "device proof could not be durably recorded")
	}
	return deviceID, nil
}

func deviceNonceKey(deviceID, nonce string) string {
	return fingerprint("device-proof-nonce:"+deviceID, []byte(nonce))
}

func (s *Server) authenticated(w http.ResponseWriter, r *http.Request, body []byte) (string, bool) {
	id, err := s.deviceProof(r, body)
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return "", false
	}
	return id, true
}
