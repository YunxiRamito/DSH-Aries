package kernel

import (
	"net/http"
	"strings"
	"time"

	"aries.local/aries/internal/store"
)

// rotateInvite explicitly replaces only one selected invitation. Creating an
// ordinary invitation still preserves other invitations, including those from
// different active members of the same general-purpose group.
func (s *Server) rotateInvite(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	s.mutate(w, r, device, "invite.rotate:"+group, body, func(st *store.State) (int, any, error) {
		var req struct {
			ReplaceCode string `json:"replace_code"`
		}
		if err := decodeJSON(body, &req); err != nil || req.ReplaceCode == "" || req.ReplaceCode != strings.TrimSpace(req.ReplaceCode) {
			return 0, nil, fail(400, "invalid_request", "replace_code must identify one existing group invitation")
		}
		g, exists := st.Groups[group]
		if !exists {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, exists := g.Members[device]
		if !exists || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		old, exists := st.Invites[req.ReplaceCode]
		if !exists || old.GroupID != group {
			return 0, nil, fail(404, "invite_not_found", "invitation does not belong to this group")
		}
		if old.CreatorID != device && member.Role != "creator" && member.Role != "admin" {
			return 0, nil, fail(403, "invite_rotation_forbidden", "only the inviter or group administrator may replace this invitation")
		}
		if old.Revoked {
			return 0, nil, fail(409, "invite_revoked", "invitation was already revoked or replaced")
		}
		code, replacement, err := s.newInvite(st, group, device, g.Policy, time.Now().UTC())
		if err != nil {
			return 0, nil, err
		}
		old.Revoked = true
		st.Invites[old.Code] = old
		st.Invites[code] = replacement
		return http.StatusCreated, map[string]any{
			"group_id": group, "invite_code": code, "expires_at": replacement.ExpiresAt,
			"replaced_invite_code": req.ReplaceCode,
		}, nil
	})
}
