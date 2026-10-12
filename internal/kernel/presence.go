package kernel

import (
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"aries.local/aries/internal/store"
)

const (
	defaultHeartbeatInterval = 30 * time.Second
	defaultHeartbeatTimeout  = 90 * time.Second
	maxPresenceDevices       = 100000
	maxClientVersionBytes    = 64
	maxDeviceNameCharacters  = 128
)

type presenceRecord struct {
	LastSeenAt    time.Time
	ClientVersion string
}

type heartbeatRequest struct {
	ClientVersion string  `json:"client_version,omitempty"`
	DeviceName    *string `json:"device_name,omitempty"`
}

func (s *Server) heartbeatSettings() (time.Duration, time.Duration) {
	c := s.configSnapshot()
	interval, timeout := defaultHeartbeatInterval, defaultHeartbeatTimeout
	if c.HeartbeatIntervalSeconds > 0 {
		interval = time.Duration(c.HeartbeatIntervalSeconds) * time.Second
	}
	if c.HeartbeatTimeoutSeconds > 0 {
		timeout = time.Duration(c.HeartbeatTimeoutSeconds) * time.Second
	}
	return interval, timeout
}

func (s *Server) deviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	var req heartbeatRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "heartbeat request is invalid")
		return
	}
	if len(req.ClientVersion) > maxClientVersionBytes || strings.ContainsAny(req.ClientVersion, "\r\n") {
		writeError(w, r, http.StatusBadRequest, "invalid_client_version", "client_version must be at most 64 bytes and must not contain newlines")
		return
	}
	if req.DeviceName != nil {
		// Reject control characters before trimming, so a newline or tab at
		// either edge cannot be silently accepted as surrounding whitespace.
		name := *req.DeviceName
		if !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_device_name", "device_name must be valid Unicode text without control characters")
			return
		}
		name = strings.TrimSpace(name)
		if name == "" || utf8.RuneCountInString(name) > maxDeviceNameCharacters {
			writeError(w, r, http.StatusBadRequest, "invalid_device_name", "device_name must contain 1 to 128 Unicode characters after trimming whitespace")
			return
		}
		req.DeviceName = &name
	}

	now := time.Now().UTC()
	_, timeout := s.heartbeatSettings()
	s.presenceMu.Lock()
	for id, record := range s.presence {
		if now.Sub(record.LastSeenAt) >= timeout {
			delete(s.presence, id)
		}
	}
	if _, exists := s.presence[device]; !exists && len(s.presence) >= maxPresenceDevices {
		s.presenceMu.Unlock()
		writeError(w, r, http.StatusServiceUnavailable, "presence_capacity", "presence service is temporarily at capacity")
		return
	}
	if req.DeviceName != nil {
		if err := s.store.SetDeviceName(device, *req.DeviceName); err != nil {
			s.presenceMu.Unlock()
			writeError(w, r, http.StatusInternalServerError, "storage_unavailable", "could not commit device name")
			return
		}
	}
	var deviceName string
	if err := s.store.View(func(st store.State) error {
		deviceName = st.Devices[device].DeviceName
		return nil
	}); err != nil {
		s.presenceMu.Unlock()
		writeError(w, r, http.StatusInternalServerError, "storage_unavailable", "device identity is temporarily unavailable")
		return
	}
	s.presence[device] = presenceRecord{LastSeenAt: now, ClientVersion: req.ClientVersion}
	s.presenceMu.Unlock()

	response := map[string]any{
		"device_id":      device,
		"online":         true,
		"last_seen_at":   now.Format(time.RFC3339Nano),
		"client_version": req.ClientVersion,
		"expires_at":     now.Add(timeout).Format(time.RFC3339Nano),
	}
	if deviceName != "" {
		response["device_name"] = deviceName
	}
	writeJSON(w, http.StatusOK, response)
}

type presenceItem struct {
	DeviceID      string `json:"device_id"`
	Online        bool   `json:"online"`
	LastSeenAt    string `json:"last_seen_at"`
	ClientVersion string `json:"client_version,omitempty"`
}

func (s *Server) groupPresence(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	groupID := r.PathValue("group")
	var members []store.Member
	if err := s.store.View(func(st store.State) error {
		g, exists := st.Groups[groupID]
		if !exists {
			return fail(http.StatusNotFound, "group_not_found", "group not found")
		}
		self, exists := g.Members[device]
		if !exists || !self.Active {
			return fail(http.StatusForbidden, "membership_required", "active group membership is required")
		}
		for _, member := range g.Members {
			if member.Active {
				members = append(members, member)
			}
		}
		return nil
	}); err != nil {
		status, code, msg := httpError(err)
		writeError(w, r, status, code, msg)
		return
	}
	sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })

	now := time.Now().UTC()
	_, timeout := s.heartbeatSettings()
	s.presenceMu.Lock()
	items := make([]presenceItem, 0, len(members))
	for _, member := range members {
		item := presenceItem{DeviceID: member.DeviceID}
		if record, exists := s.presence[member.DeviceID]; exists {
			item.LastSeenAt = record.LastSeenAt.Format(time.RFC3339Nano)
			item.ClientVersion = record.ClientVersion
			item.Online = now.Before(record.LastSeenAt.Add(timeout))
		}
		items = append(items, item)
	}
	s.presenceMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
