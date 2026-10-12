package kernel

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"aries.local/aries/internal/store"
)

// unpairGroup closes exactly one two-active-member group. Holding the same
// file lock used by upload, complete, and download prevents a transfer from
// publishing or serving a blob across the durable group-close transition.
func (s *Server) unpairGroup(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.mutate(w, r, device, "group.unpair:"+group, body, func(st *store.State) (int, any, error) {
		// mutate checks a previously committed fingerprint before this schema
		// check, so changed bodies always conflict with the original operation.
		var req map[string]json.RawMessage
		if err := decodeJSON(body, &req); err != nil || req == nil || len(req) != 0 {
			return 0, nil, fail(400, "invalid_request", "unpair request must be an empty JSON object")
		}
		response := map[string]any{"group_id": group, "device_id": device, "status": "unpaired"}
		if terminal, exists := st.PairingTerminals[group]; exists {
			if !terminalParticipant(terminal, device) {
				return 0, nil, fail(403, "membership_required", "only the former pair participants may confirm this closed group")
			}
			// A simultaneous cancellation by the other original participant
			// confirms this same terminal group, never a newer group binding.
			return http.StatusOK, response, nil
		}
		g, exists := st.Groups[group]
		if !exists {
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, exists := g.Members[device]
		if !exists || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		participants := make([]string, 0, 2)
		for id, member := range g.Members {
			if member.Active {
				participants = append(participants, id)
			}
		}
		if len(participants) != 2 {
			return 0, nil, fail(409, "pair_not_two_devices", "unpair requires exactly two active group members")
		}
		sort.Strings(participants)
		st.PairingTerminals[group] = store.PairingTerminal{GroupID: group, DeviceIDs: participants, ClosedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		CloseGroupWithMembershipTerminal(st, group)
		// Physical removal remains the existing background janitor's work.
		// Never run cleanup or mutate presence before a successful commit.
		return http.StatusOK, response, nil
	})
}

// RecordMembershipExit belongs in the same durable transition as removal.
// A later active membership takes precedence over this historical receipt.
func RecordMembershipExit(st *store.State, group, device, status, role, at string) {
	if st.MembershipTerminals == nil {
		st.MembershipTerminals = map[string]map[string]store.MembershipTerminal{}
	}
	if st.MembershipTerminals[group] == nil {
		st.MembershipTerminals[group] = map[string]store.MembershipTerminal{}
	}
	st.MembershipTerminals[group][device] = store.MembershipTerminal{Status: status, Role: role, At: at}
}

// CloseGroupWithMembershipTerminal records only currently active participants.
// Historical departed or revoked members never receive closed-group receipts.
func CloseGroupWithMembershipTerminal(st *store.State, group string) {
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for id, member := range st.Groups[group].Members {
		if member.Active {
			RecordMembershipExit(st, group, id, "group_closed", member.Role, at)
		}
	}
	TombstoneGroupFiles(st, group)
	deleteGroupState(st, group)
}

func emptyObject(body []byte) bool {
	var req map[string]json.RawMessage
	return decodeJSON(body, &req) == nil && req != nil && len(req) == 0
}

// disconnectGroup removes only the caller, atomically transferring the
// creator role if explicitly requested before applying ordinary leave rules.
func (s *Server) disconnectGroup(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.mutate(w, r, device, "group.disconnect:"+group, body, func(st *store.State) (int, any, error) {
		var req map[string]json.RawMessage
		if err := decodeJSON(body, &req); err != nil || req == nil || len(req) > 1 {
			return 0, nil, fail(400, "invalid_request", "disconnect requires an object with an optional transfer_creator_to")
		}
		var successor string
		value, transfer := req["transfer_creator_to"]
		if len(req) != 0 && !transfer {
			return 0, nil, fail(400, "invalid_request", "disconnect contains an unknown field")
		}
		if transfer {
			if string(value) == "null" || json.Unmarshal(value, &successor) != nil || strings.TrimSpace(successor) == "" {
				return 0, nil, fail(400, "invalid_request", "transfer_creator_to must be a nonempty device ID")
			}
		}
		response := map[string]any{"group_id": group, "device_id": device}
		g, exists := st.Groups[group]
		if !exists {
			if receipt, exists := st.MembershipTerminals[group][device]; exists {
				if receipt.Status == "left" || receipt.Status == "group_closed" {
					if transfer && (receipt.Role != "creator" || receipt.Status == "group_closed") {
						return 0, nil, fail(400, "invalid_request", "creator transfer is not applicable to this membership receipt")
					}
					response["status"] = receipt.Status
					return 200, response, nil
				}
				return 0, nil, fail(403, "membership_required", "active group membership is required")
			}
			if len(st.MembershipTerminals[group]) != 0 || len(st.PairingTerminals[group].DeviceIDs) != 0 {
				return 0, nil, fail(403, "membership_required", "active group membership is required")
			}
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, exists := g.Members[device]
		if !exists || !member.Active {
			if receipt, exists := st.MembershipTerminals[group][device]; exists && receipt.Status == "left" {
				if transfer && receipt.Role != "creator" {
					return 0, nil, fail(400, "invalid_request", "only a departing creator may provide transfer_creator_to")
				}
				response["status"] = "left"
				return 200, response, nil
			}
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		others := 0
		for id, m := range g.Members {
			if id != device && m.Active {
				others++
			}
		}
		if transfer && (g.CreatorID != device || others == 0) {
			return 0, nil, fail(400, "invalid_request", "creator transfer is allowed only for a departing creator with active successors")
		}
		if g.CreatorID == device && others > 0 {
			if !transfer {
				return 0, nil, fail(409, "creator_transfer_required", "creator must explicitly choose an active successor before disconnecting")
			}
			next, exists := g.Members[successor]
			if !exists || !next.Active || successor == device {
				return 0, nil, fail(400, "invalid_successor", "successor must be another active member of this group")
			}
			next.Role = "creator"
			g.Members[successor] = next
			g.CreatorID = successor
		}
		if others == 0 {
			CloseGroupWithMembershipTerminal(st, group)
			response["status"] = "group_closed"
			return 200, response, nil
		}
		originalRole := member.Role
		member.Active = false
		if member.Role == "creator" {
			member.Role = "member"
		}
		g.Members[device] = member
		RemoveFileTarget(st, group, device)
		removeApprovalSlot(st, group, device)
		event, err := queueMembershipEvent(&g, device, "member_left")
		if err != nil {
			return 0, nil, err
		}
		RecordMembershipExit(st, group, device, "left", originalRole, time.Now().UTC().Format(time.RFC3339Nano))
		st.Groups[group] = g
		response["status"] = "left"
		response["creator_id"] = g.CreatorID
		response["control_event_id"] = event.ID
		response["required_generation"] = event.RequiredEpoch
		return 202, response, nil
	})
}

// closeGroup explicitly dissolves the complete group, of any member count.
func (s *Server) closeGroup(w http.ResponseWriter, r *http.Request) {
	device, body, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	s.fileLock().Lock()
	defer s.fileLock().Unlock()
	s.mutate(w, r, device, "group.close:"+group, body, func(st *store.State) (int, any, error) {
		if !emptyObject(body) {
			return 0, nil, fail(400, "invalid_request", "close request must be an empty JSON object")
		}
		response := map[string]any{"group_id": group, "device_id": device, "status": "group_closed"}
		g, exists := st.Groups[group]
		if !exists {
			if receipt, exists := st.MembershipTerminals[group][device]; exists {
				if receipt.Status == "group_closed" && receipt.Role == "creator" {
					return 200, response, nil
				}
				return 0, nil, fail(403, "creator_required", "only the group creator may close the group")
			}
			if len(st.MembershipTerminals[group]) != 0 || len(st.PairingTerminals[group].DeviceIDs) != 0 {
				return 0, nil, fail(403, "membership_required", "active group membership is required")
			}
			return 0, nil, fail(404, "group_not_found", "group not found")
		}
		member, exists := g.Members[device]
		if !exists || !member.Active {
			return 0, nil, fail(403, "membership_required", "active group membership is required")
		}
		if g.CreatorID != device {
			return 0, nil, fail(403, "creator_required", "only the group creator may close the group")
		}
		CloseGroupWithMembershipTerminal(st, group)
		return 200, response, nil
	})
}

func (s *Server) membershipStatus(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	response := map[string]any{"group_id": group, "device_id": device}
	err := s.store.View(func(st store.State) error {
		g, groupExists := st.Groups[group]
		if member, exists := g.Members[device]; exists && member.Active {
			response["status"] = "active"
			response["role"] = member.Role
			response["generation"] = g.Generation
			return nil
		}
		if receipt, exists := st.MembershipTerminals[group][device]; exists {
			response["status"] = receipt.Status
			response["changed_at"] = receipt.At
			return nil
		}
		if terminal, exists := st.PairingTerminals[group]; exists {
			if terminalParticipant(terminal, device) {
				response["status"] = "group_closed"
				response["changed_at"] = terminal.ClosedAt
				return nil
			}
			return fail(403, "membership_required", "group membership or a scoped exit receipt is required")
		}
		if groupExists || len(st.MembershipTerminals[group]) != 0 {
			return fail(403, "membership_required", "group membership or a scoped exit receipt is required")
		}
		return fail(404, "group_not_found", "group not found")
	})
	if err != nil {
		status, code, message := httpError(err)
		writeError(w, r, status, code, message)
		return
	}
	writeJSON(w, 200, response)
}

func terminalParticipant(terminal store.PairingTerminal, device string) bool {
	for _, participant := range terminal.DeviceIDs {
		if participant == device {
			return true
		}
	}
	return false
}

// pairingStatus distinguishes a scoped, durable cancellation from route or
// network errors. An active group's membership alone does not prove paired.
func (s *Server) pairingStatus(w http.ResponseWriter, r *http.Request) {
	device, _, ok := s.authorizedBody(w, r)
	if !ok {
		return
	}
	group := r.PathValue("group")
	response := map[string]any{"group_id": group, "device_id": device}
	err := s.store.View(func(st store.State) error {
		if terminal, exists := st.PairingTerminals[group]; exists {
			if !terminalParticipant(terminal, device) {
				return fail(403, "membership_required", "only the former pair participants may read this closed group")
			}
			response["status"] = "unpaired"
			response["unpaired_at"] = terminal.ClosedAt
			return nil
		}
		g, exists := st.Groups[group]
		if !exists {
			return fail(404, "group_not_found", "group not found")
		}
		member, exists := g.Members[device]
		if !exists || !member.Active {
			return fail(403, "membership_required", "active group membership is required")
		}
		response["status"] = "active"
		return nil
	})
	if err != nil {
		status, code, message := httpError(err)
		writeError(w, r, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
