// Package federation provides a small signed-message building block for
// server-to-server federation.
//
// The package authenticates envelope bytes with Ed25519 and provides bounded
// in-memory replay protection. It does not distribute or certify node keys,
// establish peer trust, authenticate a network connection, persist replay
// state, encrypt payloads, or implement listeners/forwarding. Callers must
// resolve OriginNodeID to a trusted public key before verification and must
// integrate this package with their transport and persistence policy.
//
// HopLimit and Hops are covered by the origin signature. Consequently a relay
// cannot increment Hops in-place; a future forwarding protocol must define a
// separately authenticated hop chain or another trusted forwarding envelope.
// This package does not by itself protect against a malicious node whose key
// the caller has chosen to trust.
package federation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// EnvelopeVersion is the only envelope format currently understood.
	EnvelopeVersion uint8 = 1
	// MaxPayloadBytes limits the opaque JSON carried by a single envelope.
	// Large files should use a separately designed streaming transport.
	MaxPayloadBytes    = 1 << 20
	maxIdentifierBytes = 128
)

var (
	ErrInvalidEnvelope  = errors.New("invalid federation envelope")
	ErrInvalidSignature = errors.New("invalid federation signature")
	ErrExpired          = errors.New("federation envelope expired")
	ErrHopLimit         = errors.New("federation hop limit exceeded")
	ErrReplay           = errors.New("federation message replayed")
	ErrReplayCacheFull  = errors.New("federation replay cache full")
)

// Envelope is an origin-signed federation message. Payload is opaque to this
// package, but must contain exactly one valid JSON value. Its exact bytes are
// signed, so relays must preserve Payload without reformatting it.
//
// CreatedAt and ExpiresAt are represented in JSON using time.Time's RFC3339
// encoding. They are normalized to UTC only when signing bytes are computed.
type Envelope struct {
	Version      uint8           `json:"version"`
	OriginNodeID string          `json:"origin_node_id"`
	MessageID    string          `json:"message_id"`
	Kind         string          `json:"kind"`
	Payload      json.RawMessage `json:"payload"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	HopLimit     uint8           `json:"hop_limit"`
	Hops         uint8           `json:"hops"`
	Signature    string          `json:"signature"`
}

// Sign validates env, sets its version when Version is zero, and signs it with
// the origin node's Ed25519 private key. It returns a copy of the payload so
// later caller mutation cannot silently alter the signed envelope.
func Sign(env Envelope, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: Ed25519 private key must be %d bytes", ErrInvalidEnvelope, ed25519.PrivateKeySize)
	}
	if env.Version == 0 {
		env.Version = EnvelopeVersion
	}
	env.Payload = append(json.RawMessage(nil), env.Payload...)
	env.Signature = ""
	if err := validateFields(env); err != nil {
		return Envelope{}, err
	}
	message, err := signingBytes(env)
	if err != nil {
		return Envelope{}, err
	}
	env.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return env, nil
}

// Verify validates the envelope's shape, origin signature, expiry, and hop
// bounds. The caller must have resolved publicKey from a trusted mapping for
// env.OriginNodeID; key distribution and node identity policy are outside this
// package. now must be supplied by the caller to make time checks testable.
func Verify(env Envelope, publicKey ed25519.PublicKey, now time.Time, maxHopLimit uint8) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: Ed25519 public key must be %d bytes", ErrInvalidEnvelope, ed25519.PublicKeySize)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: verification time is required", ErrInvalidEnvelope)
	}
	if err := validateFields(env); err != nil {
		return err
	}
	if env.HopLimit > maxHopLimit || env.Hops > env.HopLimit {
		return ErrHopLimit
	}
	if !now.Before(env.ExpiresAt) {
		return ErrExpired
	}
	signature, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != env.Signature || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	message, err := signingBytes(env)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func validateFields(env Envelope) error {
	if env.Version != EnvelopeVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidEnvelope, env.Version)
	}
	if !validIdentifier(env.OriginNodeID) || !validIdentifier(env.MessageID) || !validIdentifier(env.Kind) {
		return fmt.Errorf("%w: origin node ID, message ID, and kind must be non-empty printable identifiers of at most %d bytes", ErrInvalidEnvelope, maxIdentifierBytes)
	}
	if len(env.Payload) == 0 || len(env.Payload) > MaxPayloadBytes || !json.Valid(env.Payload) {
		return fmt.Errorf("%w: payload must be one valid JSON value of at most %d bytes", ErrInvalidEnvelope, MaxPayloadBytes)
	}
	if env.CreatedAt.IsZero() || env.ExpiresAt.IsZero() || !env.ExpiresAt.After(env.CreatedAt) {
		return fmt.Errorf("%w: created_at and expires_at must be set and expires_at must be later", ErrInvalidEnvelope)
	}
	if env.Hops > env.HopLimit {
		return ErrHopLimit
	}
	return nil
}

func validIdentifier(s string) bool {
	if len(s) == 0 || len(s) > maxIdentifierBytes || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// signingBytes constructs an unambiguous canonical binary representation. It
// intentionally signs the exact payload bytes instead of interpreting their
// schema. Strings and payload use length prefixes; times use UTC Unix seconds
// plus nanoseconds, avoiding dependence on JSON field ordering or formatting.
func signingBytes(env Envelope) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("ARIES-FEDERATION-ENVELOPE\x00")
	buf.WriteByte(env.Version)
	if err := writeBytes(&buf, []byte(env.OriginNodeID)); err != nil {
		return nil, err
	}
	if err := writeBytes(&buf, []byte(env.MessageID)); err != nil {
		return nil, err
	}
	if err := writeBytes(&buf, []byte(env.Kind)); err != nil {
		return nil, err
	}
	if err := writeBytes(&buf, env.Payload); err != nil {
		return nil, err
	}
	writeTime(&buf, env.CreatedAt)
	writeTime(&buf, env.ExpiresAt)
	buf.WriteByte(env.HopLimit)
	buf.WriteByte(env.Hops)
	return buf.Bytes(), nil
}

func writeBytes(buf *bytes.Buffer, data []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data)))
	buf.Write(n[:])
	buf.Write(data)
	return nil
}

func writeTime(buf *bytes.Buffer, t time.Time) {
	t = t.UTC()
	var raw [12]byte
	binary.BigEndian.PutUint64(raw[:8], uint64(t.Unix()))
	binary.BigEndian.PutUint32(raw[8:], uint32(t.Nanosecond()))
	buf.Write(raw[:])
}

// Digest returns a SHA-256 digest of the canonical signing representation.
// It can be used as a stable transport correlation value. It does not replace
// signature verification.
func (e Envelope) Digest() ([32]byte, error) {
	if err := validateFields(e); err != nil {
		return [32]byte{}, err
	}
	message, err := signingBytes(e)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(message), nil
}
