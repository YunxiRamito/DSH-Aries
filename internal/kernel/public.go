package kernel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"aries.local/aries/internal/store"
)

type challengeRequest struct {
	DeviceID  string `json:"device_id,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}
type enrollRequest struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}
type createGroupRequest struct {
	Name           string `json:"name"`
	ApprovalPolicy string `json:"approval_policy"`
}
type createInviteRequest struct{}
type applyRequest struct{}
type approvalRequest struct {
	Approve bool `json:"approve"`
}

type roleRequest struct {
	Role string `json:"role"`
}
type creatorTransferRequest struct {
	NewCreatorID string `json:"new_creator_id"`
}
type envelopeRequest struct {
	Envelope string `json:"envelope"`
}
type rotationRequest struct {
	Epoch     uint64            `json:"epoch"`
	Envelopes map[string]string `json:"envelopes"`
}
type messageRequest struct {
	Epoch      uint64 `json:"epoch"`
	Ciphertext string `json:"ciphertext"`
}
type fileRequest struct {
	Epoch             uint64 `json:"epoch"`
	EncryptedMetadata string `json:"encrypted_metadata"`
	Ciphertext        string `json:"ciphertext"`
	SizeBytes         int64  `json:"size_bytes"`
}

func (s *Server) publicNodeInfo(w http.ResponseWriter, r *http.Request) {
	var nodeID, serverCode string
	if err := s.store.View(func(st store.State) error {
		nodeID, serverCode = st.NodeID, st.ServerCode
		return nil
	}); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "storage_unavailable", "node identity is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"node_id": nodeID, "server_code": serverCode, "api_version": APIVersion})
}

func (s *Server) deviceChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	var req challengeRequest
	if err = decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "challenge request is invalid")
		return
	}
	var pub []byte
	deviceID := req.DeviceID
	enrollment := req.PublicKey != ""
	if enrollment {
		if req.DeviceID != "" {
			writeError(w, r, 400, "invalid_request", "specify device_id or public_key")
			return
		}
		pub, err = base64.RawURLEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			writeError(w, r, 400, "invalid_public_key", "public_key must be an Ed25519 public key in unpadded base64url")
			return
		}
	} else if deviceID == "" {
		writeError(w, r, 400, "invalid_request", "device_id or public_key is required")
		return
	} else {
		err = s.store.View(func(st store.State) error {
			d, ok := st.Devices[deviceID]
			if !ok {
				return errors.New("unknown device")
			}
			pub, _ = base64.RawURLEncoding.DecodeString(d.PublicKey)
			return nil
		})
		if err != nil {
			writeError(w, r, 404, "unknown_device", "device identity is not registered")
			return
		}
	}
	id, err := randomID("ch_")
	if err != nil {
		writeError(w, r, 500, "internal_error", "could not create challenge")
		return
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		writeError(w, r, 500, "internal_error", "could not create challenge")
		return
	}
	s.mu.Lock()
	now := time.Now().UTC()
	for key, value := range s.challenges {
		if now.After(value.ExpiresAt) {
			delete(s.challenges, key)
		}
	}
	for key, rate := range s.challengeRates {
		if now.Sub(rate.WindowStart) >= time.Minute {
			delete(s.challengeRates, key)
		}
	}
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	rate, known := s.challengeRates[remoteHost]
	if !known && len(s.challengeRates) >= 4096 {
		s.mu.Unlock()
		writeError(w, r, 503, "challenge_capacity", "challenge service is temporarily at capacity")
		return
	}
	if !known || now.Sub(rate.WindowStart) >= time.Minute {
		rate = challengeRate{WindowStart: now, Count: 0}
	}
	if rate.Count >= 8 {
		s.mu.Unlock()
		writeError(w, r, 429, "challenge_rate_limited", "too many challenges from this network address")
		return
	}
	if len(s.challenges) >= 4096 {
		s.mu.Unlock()
		writeError(w, r, 503, "challenge_capacity", "challenge service is temporarily at capacity")
		return
	}
	rate.Count++
	s.challengeRates[remoteHost] = rate
	s.challenges[id] = challenge{DeviceID: deviceID, PublicKey: pub, Nonce: nonce, ExpiresAt: now.Add(challengeLifetime), Enrollment: enrollment}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"challenge_id": id, "nonce": base64.RawURLEncoding.EncodeToString(nonce), "expires_at": now.Add(challengeLifetime).Format(time.RFC3339)})
}

func (s *Server) deviceEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return
	}
	var req enrollRequest
	if err = decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "enrollment request is invalid")
		return
	}
	s.mu.Lock()
	ch, ok := s.challenges[req.ChallengeID]
	s.mu.Unlock()
	if !ok || !ch.Enrollment || time.Now().After(ch.ExpiresAt) {
		writeError(w, r, 401, "challenge_expired", "enrollment challenge is missing or expired")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	pubEncoded := base64.RawURLEncoding.EncodeToString(ch.PublicKey)
	canonical := []byte("enroll\n" + req.ChallengeID + "\n" + base64.RawURLEncoding.EncodeToString(ch.Nonce) + "\n" + pubEncoded)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(ch.PublicKey), canonical, sig) {
		writeError(w, r, 401, "invalid_enrollment_proof", "enrollment signature is invalid")
		return
	}
	pubHash := sha256.Sum256(ch.PublicKey)
	deviceID := "dev_" + hex.EncodeToString(pubHash[:16])
	s.mutate(w, r, deviceID, "device.enroll", body, func(st *store.State) (int, any, error) {
		if current, exists := st.Devices[deviceID]; exists {
			if current.PublicKey != pubEncoded {
				return 0, nil, fail(409, "device_conflict", "device identity conflicts with an existing key")
			}
			return 200, map[string]any{"device_id": deviceID, "status": "registered"}, nil
		}
		st.Devices[deviceID] = store.Device{ID: deviceID, PublicKey: pubEncoded, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		return 201, map[string]any{"device_id": deviceID, "status": "registered"}, nil
	})
}

func (s *Server) authorizedBody(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, r, 400, "invalid_body", err.Error())
		return "", nil, false
	}
	id, ok := s.authenticated(w, r, body)
	return id, body, ok
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req createGroupRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "group request is invalid")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 120 {
		writeError(w, r, 400, "invalid_name", "group name must contain 1 to 120 characters")
		return
	}
	if !validPolicy(req.ApprovalPolicy) {
		writeError(w, r, 400, "invalid_policy", "approval_policy is invalid")
		return
	}
	s.mutate(w, r, device, "group.create", body, func(st *store.State) (int, any, error) {
		id, err := randomID("grp_")
		if err != nil {
			return 0, nil, err
		}
		now := time.Now().UTC()
		g := store.Group{ID: id, Name: req.Name, AuthorityNode: st.NodeID, CreatorID: device, Policy: req.ApprovalPolicy, CreatedAt: now.Format(time.RFC3339), Generation: 1, Members: map[string]store.Member{}, Rotations: map[string]store.Rotation{}}
		g.Members[device] = store.Member{DeviceID: device, Role: "creator", Active: true, JoinedAt: g.CreatedAt}
		code, inv, err := s.newInvite(st, id, device, req.ApprovalPolicy, now)
		if err != nil {
			return 0, nil, err
		}
		st.Groups[id] = g
		st.Invites[code] = inv
		return 201, map[string]any{"group_id": id, "authority_node": st.NodeID, "generation": g.Generation, "invite_code": code, "invite_expires_at": inv.ExpiresAt, "member": map[string]any{"device_id": device, "role": "creator"}}, nil
	})
}

func validPolicy(v string) bool {
	switch v {
	case "all", "creator", "inviter", "creator_inviter", "public":
		return true
	}
	return false
}

func (s *Server) newInvite(st *store.State, group, creator, policy string, now time.Time) (string, store.Invite, error) {
	for i := 0; i < 10; i++ {
		n := make([]byte, 4)
		if _, err := rand.Read(n); err != nil {
			return "", store.Invite{}, err
		}
		number := int(n[0])<<24 | int(n[1])<<16 | int(n[2])<<8 | int(n[3])
		digits := fmt.Sprintf("%06d", number%1000000)
		code := st.ServerCode + "-" + digits
		if _, exists := st.Invites[code]; exists {
			continue
		}
		inv := store.Invite{Code: code, GroupID: group, CreatorID: creator, Policy: policy, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(3 * time.Minute).Format(time.RFC3339)}
		return code, inv, nil
	}
	return "", store.Invite{}, fail(503, "invite_capacity", "could not allocate a unique invite code")
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req createInviteRequest
	if len(body) > 0 && decodeJSON(body, &req) != nil {
		writeError(w, r, 400, "invalid_request", "invite request is invalid")
		return
	}
	group := r.PathValue("group")
	s.mutate(w, r, device, "invite.create:"+group, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		now := time.Now().UTC()
		code, inv, err := s.newInvite(st, group, device, g.Policy, now)
		if err != nil {
			return 0, nil, err
		}
		st.Invites[code] = inv
		return 201, map[string]any{"invite_code": code, "group_id": group, "expires_at": inv.ExpiresAt}, nil
	})
}

func (s *Server) applyInvite(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req applyRequest
	if len(body) > 0 && decodeJSON(body, &req) != nil {
		writeError(w, r, 400, "invalid_request", "application request is invalid")
		return
	}
	code := r.PathValue("code")
	s.mutate(w, r, device, "invite.apply:"+code, body, func(st *store.State) (int, any, error) {
		inv, ok := st.Invites[code]
		if !ok || inv.Revoked || time.Now().After(parseTime(inv.ExpiresAt)) {
			return 0, nil, fail(404, "invite_expired", "invite code is unavailable or expired")
		}
		g, ok := st.Groups[inv.GroupID]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		if m, exists := g.Members[device]; exists && m.Active {
			return 0, nil, fail(409, "already_member", "device is already a group member")
		}
		id, err := randomID("app_")
		if err != nil {
			return 0, nil, err
		}
		approvals := map[string]bool{}
		switch inv.Policy {
		case "all":
			for memberID, m := range g.Members {
				if m.Active {
					approvals[memberID] = false
				}
			}
		case "creator":
			approvals[g.CreatorID] = false
		case "inviter":
			approvals[inv.CreatorID] = false
		case "creator_inviter":
			approvals[g.CreatorID] = false
			approvals[inv.CreatorID] = false
		}
		status := "pending_approval"
		if inv.Policy == "public" {
			status = "awaiting_key"
		}
		if len(approvals) == 0 && inv.Policy != "public" {
			status = "awaiting_key"
		}
		now := time.Now().UTC().Format(time.RFC3339)
		app := store.Application{ID: id, InviteCode: code, GroupID: g.ID, DeviceID: device, Status: status, Approvals: approvals, CreatedAt: now, UpdatedAt: now}
		st.Applications[id] = app
		return 201, map[string]any{"application_id": id, "group_id": g.ID, "status": status, "required_approvals": approvals}, nil
	})
}

func (s *Server) inviteInfo(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	err := s.store.View(func(st store.State) error {
		inv, ok := st.Invites[code]
		if !ok || inv.Revoked || time.Now().After(parseTime(inv.ExpiresAt)) {
			return fail(404, "invite_expired", "invite code is unavailable or expired")
		}
		g, ok := st.Groups[inv.GroupID]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		count := 0
		for _, member := range g.Members {
			if member.Active {
				count++
			}
		}
		writeJSON(w, 200, map[string]any{"group_id": g.ID, "group_name": g.Name, "authority_node": g.AuthorityNode, "member_count": count, "approval_policy": g.Policy, "expires_at": inv.ExpiresAt})
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
	}
}

func (s *Server) applicationStatus(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group, appID := r.PathValue("group"), r.PathValue("application")
	err := s.store.View(func(st store.State) error {
		app, ok := st.Applications[appID]
		if !ok || app.GroupID != group {
			return fail(404, "application_not_found", "application not found")
		}
		if app.DeviceID != device {
			g := st.Groups[group]
			member, ok := g.Members[device]
			if !ok || !member.Active {
				return fail(403, "membership_required", "application owner or active group membership is required")
			}
		}
		publicKey, ok := registeredDevicePublicKey(st, app.DeviceID)
		if !ok {
			return fail(500, "device_identity_missing", "application device identity is not registered")
		}
		writeJSON(w, 200, map[string]any{"application_id": app.ID, "device_id": app.DeviceID, "public_key": publicKey, "status": app.Status, "approvals": app.Approvals, "created_at": app.CreatedAt, "updated_at": app.UpdatedAt})
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
	}
}

// applicationList returns applications for an active group member. The
// default status filter deliberately excludes terminal applications so a
// launcher can poll this endpoint without receiving stale history.
func (s *Server) applicationList(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	limit := parseLimit(r, 100, 200)
	statuses, err := applicationStatusFilter(r)
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	after, err := decodeApplicationCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}

	type applicationItem struct {
		ApplicationID string `json:"application_id"`
		DeviceID      string `json:"device_id"`
		PublicKey     string `json:"public_key"`
		Status        string `json:"status"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
	}
	items := make([]applicationItem, 0)
	nextCursor := ""
	err = s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		apps := make([]store.Application, 0)
		for _, app := range st.Applications {
			if app.GroupID != group || !statuses[app.Status] || !applicationAfterCursor(app, after) {
				continue
			}
			apps = append(apps, app)
		}
		sort.Slice(apps, func(i, j int) bool {
			if apps[i].CreatedAt == apps[j].CreatedAt {
				return apps[i].ID < apps[j].ID
			}
			return apps[i].CreatedAt < apps[j].CreatedAt
		})
		hasMore := len(apps) > limit
		if len(apps) > limit {
			apps = apps[:limit]
		}
		for _, app := range apps {
			publicKey, ok := registeredDevicePublicKey(st, app.DeviceID)
			if !ok {
				return fail(500, "device_identity_missing", "application device identity is not registered")
			}
			items = append(items, applicationItem{ApplicationID: app.ID, DeviceID: app.DeviceID, PublicKey: publicKey, Status: app.Status, CreatedAt: app.CreatedAt, UpdatedAt: app.UpdatedAt})
		}
		if hasMore && len(apps) > 0 {
			last := apps[len(apps)-1]
			nextCursor = encodeApplicationCursor(last.CreatedAt, last.ID)
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": nextCursor})
}

func (s *Server) approveApplication(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req approvalRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "approval request is invalid")
		return
	}
	group, appID := r.PathValue("group"), r.PathValue("application")
	s.mutate(w, r, device, "application.approve:"+appID, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		app, ok := st.Applications[appID]
		if !ok || app.GroupID != group {
			return 0, nil, fail(404, "application_not_found", "application not found")
		}
		if app.Status != "pending_approval" {
			return 0, nil, fail(409, "application_state", "application is not awaiting approval")
		}
		actor, actorExists := g.Members[device]
		if !actorExists || !actor.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		approvalSlot := device
		if _, required := app.Approvals[device]; !required {
			if actor.Role != "admin" {
				return 0, nil, fail(403, "approval_not_required", "device is not an approver for this application")
			}
			if !req.Approve {
				for slot := range app.Approvals {
					if !app.Approvals[slot] {
						approvalSlot = slot
						break
					}
				}
			}
			if req.Approve {
				slots := make([]string, 0, len(app.Approvals))
				for slot := range app.Approvals {
					if !app.Approvals[slot] {
						slots = append(slots, slot)
					}
				}
				sort.Strings(slots)
				if len(slots) == 0 {
					return 0, nil, fail(409, "application_state", "application has no pending approval")
				}
				approvalSlot = slots[0]
			}
		}
		if !req.Approve {
			app.Status = "rejected"
		} else {
			app.Approvals[approvalSlot] = true
			all := true
			for _, approved := range app.Approvals {
				if !approved {
					all = false
				}
			}
			if all {
				app.Status = "awaiting_key"
			}
		}
		app.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		st.Applications[appID] = app
		return 200, map[string]any{"application_id": appID, "status": app.Status, "approvals": app.Approvals}, nil
	})
}

func (s *Server) deliverJoinKey(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req envelopeRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "key delivery is invalid")
		return
	}
	if _, err := decodeOpaque(req.Envelope); err != nil {
		writeError(w, r, 400, "invalid_envelope", "envelope must be non-empty unpadded base64url ciphertext")
		return
	}
	group, appID := r.PathValue("group"), r.PathValue("application")
	s.mutate(w, r, device, "application.key_delivery:"+appID, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		app, ok := st.Applications[appID]
		if !ok || app.GroupID != group {
			return 0, nil, fail(404, "application_not_found", "application not found")
		}
		if app.Status != "awaiting_key" {
			return 0, nil, fail(409, "application_state", "application is not awaiting key delivery")
		}
		g.Members[app.DeviceID] = store.Member{DeviceID: app.DeviceID, Role: "member", Active: true, JoinedAt: time.Now().UTC().Format(time.RFC3339)}
		st.Groups[group] = g
		id, _ := randomID("kd_")
		st.KeyDeliveries[group] = append(st.KeyDeliveries[group], store.KeyDelivery{ID: id, GroupID: group, SenderID: device, RecipientID: app.DeviceID, Epoch: g.Generation, Envelope: req.Envelope, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
		app.Status = "approved"
		app.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		st.Applications[appID] = app
		return 201, map[string]any{"application_id": appID, "status": "approved", "member_device_id": app.DeviceID, "generation": g.Generation}, nil
	})
}

func (s *Server) groupEvents(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeError(w, r, 400, "invalid_cursor", "after must be an unsigned event sequence")
			return
		}
		after = parsed
	}
	wait := 0
	if value := r.URL.Query().Get("wait_ms"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			writeError(w, r, 400, "invalid_wait", "wait_ms must be a non-negative integer")
			return
		}
		if parsed > 25000 {
			parsed = 25000
		}
		wait = parsed
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			writeError(w, r, 400, "invalid_limit", "limit must be a positive integer")
			return
		}
		if parsed > 200 {
			parsed = 200
		}
		limit = parsed
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Millisecond)
	for {
		items := []map[string]any{}
		next := after
		err := s.store.View(func(st store.State) error {
			g, ok := st.Groups[group]
			if !ok {
				return fail(404, "group_not_found", "group not found")
			}
			m, ok := g.Members[device]
			if !ok || !m.Active {
				return fail(403, "membership_required", "active group membership is required")
			}
			for _, e := range g.Events {
				if e.Sequence > after {
					items = append(items, map[string]any{"sequence": e.Sequence, "type": "control", "event": e})
				}
			}
			for _, msg := range st.Messages[group] {
				if msg.Sequence > after {
					items = append(items, map[string]any{"sequence": msg.Sequence, "type": "message", "message": msg})
				}
			}
			sort.Slice(items, func(i, j int) bool { return items[i]["sequence"].(uint64) < items[j]["sequence"].(uint64) })
			if len(items) > 0 {
				next = items[len(items)-1]["sequence"].(uint64)
			}
			return nil
		})
		if err != nil {
			status, code, msg := httpError(err)
			writeError(w, r, status, code, msg)
			return
		}
		if len(items) > limit {
			items = items[:limit]
			next = items[len(items)-1]["sequence"].(uint64)
		}
		if len(items) > 0 || time.Now().After(deadline) || wait == 0 {
			writeJSON(w, 200, map[string]any{"items": items, "next_cursor": strconv.FormatUint(next, 10)})
			return
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Server) leaveGroup(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		var ignored map[string]any
		if decodeJSON(body, &ignored) != nil {
			writeError(w, r, 400, "invalid_request", "leave request is invalid")
			return
		}
	}
	group := r.PathValue("group")
	s.mutate(w, r, device, "group.leave:"+group, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		others := 0
		for id, m := range g.Members {
			if id != device && m.Active {
				others++
			}
		}
		if device == g.CreatorID && others > 0 {
			return 0, nil, fail(409, "creator_transfer_required", "creator must transfer the creator role before leaving")
		}
		member.Active = false
		g.Members[device] = member
		RemoveFileTarget(st, group, device)
		if others == 0 {
			TombstoneGroupFiles(st, group)
			deleteGroupState(st, group)
			return 200, map[string]any{"group_id": group, "status": "group_closed"}, nil
		}
		removeApprovalSlot(st, group, device)
		event, err := queueMembershipEvent(&g, device, "member_left")
		if err != nil {
			return 0, nil, err
		}
		st.Groups[group] = g
		return 202, map[string]any{"group_id": group, "status": "left", "control_event_id": event.ID, "required_generation": event.RequiredEpoch}, nil
	})
}

func queueMembershipEvent(g *store.Group, device, eventType string) (store.ControlEvent, error) {
	pending := uint64(0)
	for _, event := range g.Events {
		if event.CompletedAt == "" {
			pending++
		}
	}
	id, err := randomID("evt_")
	if err != nil {
		return store.ControlEvent{}, err
	}
	g.NextSequence++
	event := store.ControlEvent{ID: id, Type: eventType, DeviceID: device, RequiredEpoch: g.Generation + pending + 1, CreatedAt: time.Now().UTC().Format(time.RFC3339), Sequence: g.NextSequence}
	g.Events = append(g.Events, event)
	return event, nil
}

func removeApprovalSlot(st *store.State, group, device string) {
	for id, app := range st.Applications {
		if app.GroupID != group || app.Status != "pending_approval" {
			continue
		}
		delete(app.Approvals, device)
		ready := true
		for _, approved := range app.Approvals {
			if !approved {
				ready = false
				break
			}
		}
		if ready {
			app.Status = "awaiting_key"
		}
		app.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		st.Applications[id] = app
	}
}

func deleteGroupState(st *store.State, group string) {
	delete(st.Groups, group)
	delete(st.Messages, group)
	delete(st.KeyDeliveries, group)
	for code, inv := range st.Invites {
		if inv.GroupID == group {
			delete(st.Invites, code)
		}
	}
	for id, app := range st.Applications {
		if app.GroupID == group {
			delete(st.Applications, id)
		}
	}
	for id, f := range st.Files {
		if f.GroupID == group {
			if f.ChunkCount > 0 {
				f.Status = "tombstone"
				f.TombstoneReason = "group_deleted_no_copy"
				st.Files[id] = f
			} else {
				delete(st.Files, id)
			}
		}
	}
}

func (s *Server) setMemberRole(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req roleRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "role request is invalid")
		return
	}
	if req.Role != "admin" && req.Role != "member" {
		writeError(w, r, 400, "invalid_role", "role must be admin or member")
		return
	}
	group, target := r.PathValue("group"), r.PathValue("member")
	s.mutate(w, r, device, "member.role:"+group+":"+target, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		actor, ok := g.Members[device]
		if !ok || !actor.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		if device != g.CreatorID {
			return 0, nil, fail(403, "creator_required", "only the group creator can appoint or remove administrators")
		}
		member, ok := g.Members[target]
		if !ok || !member.Active {
			return 0, nil, fail(404, "member_not_found", "active member not found")
		}
		if target == g.CreatorID {
			return 0, nil, fail(409, "creator_transfer_required", "creator role must be transferred separately")
		}
		member.Role = req.Role
		g.Members[target] = member
		st.Groups[group] = g
		return 200, map[string]any{"group_id": group, "device_id": target, "role": member.Role}, nil
	})
}

func (s *Server) revokeMember(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		var ignored map[string]any
		if decodeJSON(body, &ignored) != nil {
			writeError(w, r, 400, "invalid_request", "revoke request is invalid")
			return
		}
	}
	group, target := r.PathValue("group"), r.PathValue("member")
	s.mutate(w, r, device, "member.revoke:"+group+":"+target, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		actor, ok := g.Members[device]
		if !ok || !actor.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		member, ok := g.Members[target]
		if !ok || !member.Active {
			return 0, nil, fail(404, "member_not_found", "active member not found")
		}
		if target == g.CreatorID {
			return 0, nil, fail(409, "creator_transfer_required", "creator role must be transferred separately")
		}
		if device != g.CreatorID && (actor.Role != "admin" || member.Role != "member") {
			return 0, nil, fail(403, "revoke_forbidden", "group administrators may revoke ordinary members only")
		}
		member.Active = false
		g.Members[target] = member
		RemoveFileTarget(st, group, target)
		removeApprovalSlot(st, group, target)
		event, err := queueMembershipEvent(&g, target, "member_revoked")
		if err != nil {
			return 0, nil, err
		}
		st.Groups[group] = g
		return 202, map[string]any{"group_id": group, "device_id": target, "status": "revoked", "control_event_id": event.ID, "required_generation": event.RequiredEpoch}, nil
	})
}

func (s *Server) transferCreator(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req creatorTransferRequest
	if err := decodeJSON(body, &req); err != nil || req.NewCreatorID == "" {
		writeError(w, r, 400, "invalid_request", "new_creator_id is required")
		return
	}
	group := r.PathValue("group")
	s.mutate(w, r, device, "creator.transfer:"+group, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		if device != g.CreatorID {
			return 0, nil, fail(403, "creator_required", "only the current creator can transfer the creator role")
		}
		next, ok := g.Members[req.NewCreatorID]
		if !ok || !next.Active {
			return 0, nil, fail(404, "member_not_found", "new creator must be an active group member")
		}
		old := g.Members[device]
		old.Role = "member"
		g.Members[device] = old
		next.Role = "creator"
		g.Members[req.NewCreatorID] = next
		g.CreatorID = req.NewCreatorID
		st.Groups[group] = g
		return 200, map[string]any{"group_id": group, "creator_id": g.CreatorID}, nil
	})
}

func (s *Server) ackKeyDelivery(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	if len(body) > 0 && string(body) != "{}" {
		writeError(w, r, 400, "invalid_request", "acknowledgement must be empty")
		return
	}
	group, id := r.PathValue("group"), r.PathValue("delivery")
	s.mutate(w, r, device, "key_delivery.ack:"+id, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		for i, d := range st.KeyDeliveries[group] {
			if d.ID == id {
				if d.RecipientID != device {
					return 0, nil, fail(403, "delivery_recipient_mismatch", "only the intended recipient may acknowledge a key delivery")
				}
				d.Acknowledged = true
				st.KeyDeliveries[group][i] = d
				return 200, map[string]any{"delivery_id": id, "status": "acknowledged"}, nil
			}
		}
		return 0, nil, fail(404, "delivery_not_found", "key delivery not found")
	})
}

func (s *Server) memberList(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	items := []map[string]any{}
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		self, ok := g.Members[device]
		if !ok || !self.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, member := range g.Members {
			if member.Active {
				publicKey, ok := registeredDevicePublicKey(st, member.DeviceID)
				if !ok {
					return fail(500, "device_identity_missing", "member device identity is not registered")
				}
				items = append(items, map[string]any{"device_id": member.DeviceID, "public_key": publicKey, "role": member.Role, "active": member.Active, "joined_at": member.JoinedAt})
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i]["device_id"].(string) < items[j]["device_id"].(string) })
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

type applicationCursor struct {
	CreatedAt string
	ID        string
}

func registeredDevicePublicKey(st store.State, deviceID string) (string, bool) {
	device, ok := st.Devices[deviceID]
	if !ok || device.ID != deviceID || device.PublicKey == "" {
		return "", false
	}
	return device.PublicKey, true
}

func applicationStatusFilter(r *http.Request) (map[string]bool, error) {
	values := r.URL.Query()["status"]
	if len(values) == 0 {
		return map[string]bool{"pending_approval": true, "awaiting_key": true}, nil
	}
	filter := map[string]bool{}
	for _, value := range values {
		for _, status := range strings.Split(value, ",") {
			status = strings.TrimSpace(status)
			if status == "" {
				continue
			}
			if status == "all" {
				return map[string]bool{"pending_approval": true, "awaiting_key": true, "approved": true, "rejected": true}, nil
			}
			switch status {
			case "pending_approval", "awaiting_key", "approved", "rejected":
				filter[status] = true
			default:
				return nil, fail(400, "invalid_status", "status must be pending_approval, awaiting_key, approved, rejected, or all")
			}
		}
	}
	if len(filter) == 0 {
		return nil, fail(400, "invalid_status", "status must not be empty")
	}
	return filter, nil
}

func encodeApplicationCursor(createdAt, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(createdAt + "\x00" + id))
}

func decodeApplicationCursor(value string) (applicationCursor, error) {
	if value == "" {
		return applicationCursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return applicationCursor{}, fail(400, "invalid_cursor", "cursor is invalid")
	}
	parts := strings.Split(string(b), "\x00")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return applicationCursor{}, fail(400, "invalid_cursor", "cursor is invalid")
	}
	if _, err := time.Parse(time.RFC3339, parts[0]); err != nil {
		return applicationCursor{}, fail(400, "invalid_cursor", "cursor is invalid")
	}
	return applicationCursor{CreatedAt: parts[0], ID: parts[1]}, nil
}

func applicationAfterCursor(app store.Application, cursor applicationCursor) bool {
	if cursor.ID == "" {
		return true
	}
	if app.CreatedAt == cursor.CreatedAt {
		return app.ID > cursor.ID
	}
	return app.CreatedAt > cursor.CreatedAt
}

func (s *Server) completeRotation(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req rotationRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "rotation payload is invalid")
		return
	}
	for _, e := range req.Envelopes {
		if _, err := decodeOpaque(e); err != nil {
			writeError(w, r, 400, "invalid_envelope", "all envelopes must be non-empty unpadded base64url ciphertext")
			return
		}
	}
	group, eventID := r.PathValue("group"), r.PathValue("event")
	s.mutate(w, r, device, "rotation.complete:"+eventID, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, ok := g.Members[device]
		if !ok || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		var target *store.ControlEvent
		idx := -1
		for i := range g.Events {
			if g.Events[i].ID == eventID {
				target = &g.Events[i]
				idx = i
				break
			}
		}
		if target == nil {
			return 0, nil, fail(404, "event_not_found", "control event not found")
		}
		if target.CompletedAt != "" {
			return 200, map[string]any{"event_id": eventID, "status": "completed", "generation": target.RequiredEpoch}, nil
		}
		for _, e := range g.Events {
			if e.CompletedAt == "" && e.ID != eventID {
				return 0, nil, fail(409, "rotation_order", "earlier control events must be completed first")
			}
			if e.ID == eventID {
				break
			}
		}
		if req.Epoch != target.RequiredEpoch || req.Epoch <= g.Generation {
			return 0, nil, fail(409, "generation_mismatch", "rotation generation does not match the required generation")
		}
		expected := map[string]bool{}
		for id, m := range g.Members {
			if m.Active {
				if id == device {
					continue
				}
				expected[id] = true
			}
		}
		if len(req.Envelopes) != len(expected) {
			return 0, nil, fail(400, "recipient_set_mismatch", "envelopes must cover every other active member exactly once")
		}
		for id := range req.Envelopes {
			if !expected[id] {
				return 0, nil, fail(400, "recipient_set_mismatch", "envelopes must cover every other active member exactly once")
			}
		}
		now := time.Now().UTC().Format(time.RFC3339)
		target.CompletedAt = now
		g.Events[idx] = *target
		g.Generation = req.Epoch
		rotation := store.Rotation{EventID: eventID, Epoch: req.Epoch, Envelopes: req.Envelopes, CompletedAt: now}
		g.Rotations[eventID] = rotation
		for recipient, envelope := range req.Envelopes {
			id, _ := randomID("kd_")
			st.KeyDeliveries[group] = append(st.KeyDeliveries[group], store.KeyDelivery{ID: id, GroupID: group, SenderID: device, RecipientID: recipient, Epoch: req.Epoch, Envelope: envelope, CreatedAt: now})
		}
		st.Groups[group] = g
		return 200, map[string]any{"event_id": eventID, "status": "completed", "generation": g.Generation}, nil
	})
}

func (s *Server) keyDeliveries(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	items := []store.KeyDelivery{}
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, d := range st.KeyDeliveries[group] {
			if d.RecipientID == device && !d.Acknowledged {
				items = append(items, d)
			}
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) postMessage(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req messageRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, 400, "invalid_request", "message is invalid")
		return
	}
	if _, err := decodeOpaque(req.Ciphertext); err != nil {
		writeError(w, r, 400, "invalid_ciphertext", "ciphertext must be non-empty unpadded base64url")
		return
	}
	group := r.PathValue("group")
	s.mutate(w, r, device, "message.create:"+group, body, func(st *store.State) (int, any, error) {
		g, ok := st.Groups[group]
		if !ok {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		if req.Epoch != g.Generation {
			return 0, nil, fail(409, "generation_mismatch", "message uses a stale or unknown content-key generation")
		}
		if hasPendingRotation(g) {
			return 0, nil, fail(409, "rotation_required", "new content is paused until pending key rotation is completed")
		}
		id, err := randomID("msg_")
		if err != nil {
			return 0, nil, err
		}
		g.NextSequence++
		msg := store.Message{ID: id, GroupID: group, SenderID: device, Epoch: req.Epoch, Ciphertext: req.Ciphertext, CreatedAt: time.Now().UTC().Format(time.RFC3339), Sequence: g.NextSequence}
		st.Groups[group] = g
		st.Messages[group] = append(st.Messages[group], msg)
		return 201, map[string]any{"message_id": id, "generation": req.Epoch, "created_at": msg.CreatedAt}, nil
	})
}

func (s *Server) listMessages(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	items := []store.Message{}
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeError(w, r, 400, "invalid_cursor", "after must be an unsigned sequence")
			return
		}
		after = parsed
	}
	limit := parseLimit(r, 100, 200)
	err := s.store.View(func(st store.State) error {
		g, ok := st.Groups[group]
		if !ok {
			return fail(404, "group_not_found", "group not found")
		}
		m, ok := g.Members[device]
		if !ok || !m.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		for _, message := range st.Messages[group] {
			if message.Sequence > after {
				items = append(items, message)
			}
		}
		return nil
	})
	if err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	if len(items) > limit {
		items = items[:limit]
	}
	next := after
	if len(items) > 0 {
		next = items[len(items)-1].Sequence
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": strconv.FormatUint(next, 10)})
}

func (s *Server) postFile(w http.ResponseWriter, r *http.Request) {
	s.legacyInlineFilesRemoved(w, r)
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	s.legacyInlineFilesRemoved(w, r)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	s.legacyInlineFilesRemoved(w, r)
}

func parseTime(v string) time.Time { t, _ := time.Parse(time.RFC3339, v); return t }

func hasPendingRotation(g store.Group) bool {
	for _, event := range g.Events {
		if event.CompletedAt == "" {
			return true
		}
	}
	return false
}

func parseLimit(r *http.Request, def, max int) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func canonicalDeviceProof(method, path, timestamp, nonce string, body []byte) string {
	h := sha256.Sum256(body)
	return strings.Join([]string{method, path, timestamp, nonce, base64.RawURLEncoding.EncodeToString(h[:])}, "\n")
}

func publicKeyEncoded(pub ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(pub) }

func parseOpaqueJSON(value string) (json.RawMessage, error) {
	if _, err := decodeOpaque(value); err != nil {
		return nil, err
	}
	b, err := json.Marshal(url.QueryEscape(value))
	return b, err
}
