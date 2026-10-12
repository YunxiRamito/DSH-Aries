package kernel

import "aries.local/aries/internal/store"

// keyConfirmation exposes receipt metadata, never the opaque key envelope.
// Acknowledgement belongs to one join/rotation delivery and one membership,
// not a device forever. Older snapshots without these bindings remain unknown.
type keyConfirmation struct {
	Status      string `json:"key_confirmation_status"`
	DeliveryID  string `json:"key_delivery_id,omitempty"`
	RecipientID string `json:"key_recipient_id,omitempty"`
	Epoch       uint64 `json:"key_epoch,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
}

func (c keyConfirmation) addTo(response map[string]any) {
	response["key_confirmation_status"] = c.Status
	if c.DeliveryID != "" {
		response["key_delivery_id"] = c.DeliveryID
		response["key_recipient_id"] = c.RecipientID
		response["key_epoch"] = c.Epoch
	}
	if c.ConfirmedAt != "" {
		response["confirmed_at"] = c.ConfirmedAt
	}
}

func applicationKeyConfirmation(st store.State, app store.Application) keyConfirmation {
	if app.KeyDeliveryID == "" {
		return keyConfirmation{Status: "unknown"}
	}
	g, exists := st.Groups[app.GroupID]
	if !exists || app.Status != "approved" {
		return keyConfirmation{Status: "revoked"}
	}
	return deliveryKeyConfirmation(st, g, app.DeviceID, app.KeyDeliveryID)
}

func memberKeyConfirmation(st store.State, g store.Group, member store.Member) keyConfirmation {
	if member.KeyDeliveryID == "" {
		return keyConfirmation{Status: "unknown"}
	}
	return deliveryKeyConfirmation(st, g, member.DeviceID, member.KeyDeliveryID)
}

func deliveryKeyConfirmation(st store.State, g store.Group, recipientID, deliveryID string) keyConfirmation {
	for _, delivery := range st.KeyDeliveries[g.ID] {
		if delivery.ID != deliveryID || delivery.GroupID != g.ID || delivery.RecipientID != recipientID {
			continue
		}
		confirmation := keyConfirmation{Status: "revoked", DeliveryID: delivery.ID, RecipientID: delivery.RecipientID, Epoch: delivery.Epoch}
		recipient, recipientExists := g.Members[delivery.RecipientID]
		sender, senderExists := g.Members[delivery.SenderID]
		if !recipientExists || !recipient.Active || !senderExists || !sender.Active ||
			recipient.KeyDeliveryID != delivery.ID || sender.JoinedAt != delivery.SenderJoinedAt ||
			delivery.Epoch != g.Generation || hasPendingRotation(g) {
			return confirmation
		}
		if delivery.SenderJoinedAt == "" || (delivery.Acknowledged && delivery.AcknowledgedAt == "") {
			confirmation.Status = "unknown"
			return confirmation
		}
		confirmation.Status = "awaiting_ack"
		if delivery.Acknowledged {
			confirmation.Status = "acknowledged"
			confirmation.ConfirmedAt = delivery.AcknowledgedAt
		}
		return confirmation
	}
	return keyConfirmation{Status: "unknown"}
}
