package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub1, priv1, pub2, priv2
}

func validEnvelope(now time.Time) Envelope {
	return Envelope{
		OriginNodeID: "A6E9",
		MessageID:    "message-123",
		Kind:         "group.control",
		Payload:      json.RawMessage(`{"group":"g-1","event":"member_left"}`),
		CreatedAt:    now.Add(-time.Second),
		ExpiresAt:    now.Add(time.Minute),
		HopLimit:     3,
		Hops:         1,
	}
}

func mustSign(t *testing.T, env Envelope, key ed25519.PrivateKey) Envelope {
	t.Helper()
	signed, err := Sign(env, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 987654321, time.FixedZone("test", 8*60*60))
	env := mustSign(t, validEnvelope(now), priv)
	if env.Version != EnvelopeVersion {
		t.Fatalf("version = %d", env.Version)
	}
	if err := Verify(env, pub, now, 4); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if _, err := env.Digest(); err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := Verify(decoded, pub, now, 4); err != nil {
		t.Fatalf("round trip Verify() error = %v", err)
	}
}

func TestVerifyRejectsTamperedSignedFields(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	original := mustSign(t, validEnvelope(now), priv)
	tests := map[string]func(*Envelope){
		"origin":     func(e *Envelope) { e.OriginNodeID = "B7F2" },
		"message id": func(e *Envelope) { e.MessageID = "message-456" },
		"kind":       func(e *Envelope) { e.Kind = "other.kind" },
		"payload":    func(e *Envelope) { e.Payload = json.RawMessage(`{"group":"g-2"}`) },
		"created":    func(e *Envelope) { e.CreatedAt = e.CreatedAt.Add(time.Second) },
		"expiry":     func(e *Envelope) { e.ExpiresAt = e.ExpiresAt.Add(time.Second) },
		"hop limit":  func(e *Envelope) { e.HopLimit-- },
		"hops":       func(e *Envelope) { e.Hops-- },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.Payload = append(json.RawMessage(nil), original.Payload...)
			mutate(&changed)
			if err := Verify(changed, pub, now, 4); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify() error = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestVerifyRejectsWrongKeyAndNode(t *testing.T) {
	pub, priv, otherPub, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	if err := Verify(env, otherPub, now, 4); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong-key Verify() error = %v", err)
	}
	env.OriginNodeID = "untrusted-node"
	if err := Verify(env, pub, now, 4); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("changed-node Verify() error = %v", err)
	}
}

func TestVerifyRejectsExpiredEnvelope(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	if err := Verify(env, pub, env.ExpiresAt, 4); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify() error = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsHopLimitViolations(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	base := validEnvelope(now)
	tests := []struct {
		name   string
		max    uint8
		mutate func(*Envelope)
	}{
		{"configured maximum", 2, func(e *Envelope) {}},
		{"current hops above envelope limit", 4, func(e *Envelope) { e.Hops = e.HopLimit + 1 }},
		{"limit above configured maximum", 4, func(e *Envelope) { e.HopLimit = 5; e.Hops = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := base
			if tc.name == "current hops above envelope limit" {
				env = mustSign(t, env, priv)
				tc.mutate(&env)
			} else {
				tc.mutate(&env)
				env = mustSign(t, env, priv)
			}
			if err := Verify(env, pub, now, tc.max); !errors.Is(err, ErrHopLimit) {
				t.Fatalf("Verify() error = %v, want ErrHopLimit", err)
			}
		})
	}
}

func TestSignAndVerifyRejectMalformedFields(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	base := validEnvelope(now)
	tests := map[string]func(*Envelope){
		"unsupported version":          func(e *Envelope) { e.Version = 2 },
		"empty origin":                 func(e *Envelope) { e.OriginNodeID = "" },
		"control character identifier": func(e *Envelope) { e.MessageID = "bad\nmessage" },
		"oversized identifier":         func(e *Envelope) { e.Kind = strings.Repeat("k", maxIdentifierBytes+1) },
		"malformed payload":            func(e *Envelope) { e.Payload = json.RawMessage(`{"broken":`) },
		"empty payload":                func(e *Envelope) { e.Payload = nil },
		"unset created time":           func(e *Envelope) { e.CreatedAt = time.Time{} },
		"nonincreasing expiry":         func(e *Envelope) { e.ExpiresAt = e.CreatedAt },
		"hops exceed limit":            func(e *Envelope) { e.Hops = e.HopLimit + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			env := base
			mutate(&env)
			if _, err := Sign(env, priv); !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrHopLimit) {
				t.Fatalf("Sign() error = %v, want invalid envelope or hop limit", err)
			}
		})
	}
	if _, err := Sign(base, ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("short private key error = %v", err)
	}
	signed := mustSign(t, base, priv)
	signed.Signature = "!"
	if err := Verify(signed, pub, now, 4); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("malformed signature error = %v", err)
	}
	if err := Verify(mustSign(t, base, priv), ed25519.PublicKey{1}, now, 4); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("short public key error = %v", err)
	}
	if err := Verify(mustSign(t, base, priv), pub, time.Time{}, 4); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("zero verification time error = %v", err)
	}
}

func TestSignCopiesPayload(t *testing.T) {
	_, priv, _, _ := testKeys(t)
	payload := json.RawMessage(`{"value":1}`)
	env := validEnvelope(time.Now().UTC())
	env.Payload = payload
	signed := mustSign(t, env, priv)
	payload[2] = 'X'
	if string(signed.Payload) != `{"value":1}` {
		t.Fatalf("signed payload mutated with caller input: %s", signed.Payload)
	}
}

func TestDigestIgnoresSignatureButTracksFields(t *testing.T) {
	_, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	d1, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = "different signature text"
	d2, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("digest unexpectedly includes signature")
	}
	env.Payload = json.RawMessage(`null`)
	d3, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("digest did not change with payload")
	}
}
