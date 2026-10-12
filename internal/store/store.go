// Package store implements the small, single-node JSON snapshot store used by
// the first server milestone. It is intentionally not presented as a database.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Version = 1

var ErrClosed = errors.New("store is closed")
var ErrNonceReplay = errors.New("device proof nonce was already used")
var ErrNonceCapacity = errors.New("device proof nonce store is at capacity")

// Store owns one durable snapshot. Update commits a copy before publishing it
// in memory, so a failed write never exposes an uncommitted state transition.
type Store struct {
	mu              sync.RWMutex
	path            string
	data            State
	closed          bool
	nonces          map[string]int64
	nonceLogEntries int
}

type State struct {
	Version       int                      `json:"version"`
	NodeID        string                   `json:"node_id"`
	ServerCode    string                   `json:"server_code"`
	DeviceNonces  map[string]int64         `json:"device_nonces"`
	Devices       map[string]Device        `json:"devices"`
	Groups        map[string]Group         `json:"groups"`
	Invites       map[string]Invite        `json:"invites"`
	Applications  map[string]Application   `json:"applications"`
	Idempotency   map[string]Idempotent    `json:"idempotency"`
	Messages      map[string][]Message     `json:"messages"`
	KeyDeliveries map[string][]KeyDelivery `json:"key_deliveries"`
	Files         map[string]File          `json:"files"`
}

type Device struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type Group struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	AuthorityNode string              `json:"authority_node"`
	CreatorID     string              `json:"creator_id"`
	Policy        string              `json:"policy"`
	CreatedAt     string              `json:"created_at"`
	Generation    uint64              `json:"generation"`
	NextSequence  uint64              `json:"next_sequence"`
	Members       map[string]Member   `json:"members"`
	Events        []ControlEvent      `json:"events"`
	Rotations     map[string]Rotation `json:"rotations"`
}

type Member struct {
	DeviceID string `json:"device_id"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	JoinedAt string `json:"joined_at"`
}

type Invite struct {
	Code      string `json:"code"`
	GroupID   string `json:"group_id"`
	CreatorID string `json:"creator_id"`
	Policy    string `json:"policy"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
	Revoked   bool   `json:"revoked"`
}

type Application struct {
	ID         string          `json:"id"`
	InviteCode string          `json:"invite_code"`
	GroupID    string          `json:"group_id"`
	DeviceID   string          `json:"device_id"`
	Status     string          `json:"status"`
	Approvals  map[string]bool `json:"approvals"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

type ControlEvent struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	DeviceID      string `json:"device_id,omitempty"`
	RequiredEpoch uint64 `json:"required_epoch"`
	CreatedAt     string `json:"created_at"`
	CompletedAt   string `json:"completed_at,omitempty"`
	Sequence      uint64 `json:"sequence"`
}

type Rotation struct {
	EventID     string            `json:"event_id"`
	Epoch       uint64            `json:"epoch"`
	Envelopes   map[string]string `json:"envelopes"` // recipient device ID -> opaque base64url envelope
	CompletedAt string            `json:"completed_at"`
}

type Message struct {
	ID         string `json:"id"`
	GroupID    string `json:"group_id"`
	SenderID   string `json:"sender_id"`
	Epoch      uint64 `json:"epoch"`
	Ciphertext string `json:"ciphertext"`
	CreatedAt  string `json:"created_at"`
	Sequence   uint64 `json:"sequence"`
}

type File struct {
	ID                string `json:"id"`
	GroupID           string `json:"group_id"`
	SenderID          string `json:"sender_id"`
	Epoch             uint64 `json:"epoch"`
	EncryptedMetadata string `json:"encrypted_metadata"`
	Ciphertext        string `json:"ciphertext"`
	SizeBytes         int64  `json:"size_bytes"`
	CreatedAt         string `json:"created_at"`
	// Transfer fields are metadata only. Large ciphertext is stored in a
	// separate filesystem blob and never embedded in the JSON snapshot.
	ChunkSizeBytes   int64           `json:"chunk_size_bytes,omitempty"`
	ChunkCount       int             `json:"chunk_count,omitempty"`
	SHA256           string          `json:"sha256,omitempty"`
	ReceivedChunks   map[int]string  `json:"received_chunks,omitempty"`
	Targets          []string        `json:"targets,omitempty"`
	Acknowledged     map[string]bool `json:"acknowledged,omitempty"`
	DownloadCount    uint64          `json:"download_count,omitempty"`
	DownloadedBy     map[string]bool `json:"downloaded_by,omitempty"`
	Status           string          `json:"status,omitempty"`
	TombstoneReason  string          `json:"tombstone_reason,omitempty"`
	ExpiresAt        string          `json:"expires_at,omitempty"`
	CompletedAt      string          `json:"completed_at,omitempty"`
	LastDownloadedAt string          `json:"last_downloaded_at,omitempty"`
}

type KeyDelivery struct {
	ID           string `json:"id"`
	GroupID      string `json:"group_id"`
	SenderID     string `json:"sender_id"`
	RecipientID  string `json:"recipient_id"`
	Epoch        uint64 `json:"epoch"`
	Envelope     string `json:"envelope"`
	CreatedAt    string `json:"created_at"`
	Acknowledged bool   `json:"acknowledged"`
}

type Idempotent struct {
	Fingerprint string          `json:"fingerprint"`
	Status      int             `json:"status"`
	Body        json.RawMessage `json:"body"`
}

func Open(path, nodeID string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s.data); err != nil {
			return nil, fmt.Errorf("decode state snapshot (preserved at %s): %w", path, err)
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("decode state snapshot (preserved at %s): trailing data", path)
		}
		if s.data.Version != Version {
			return nil, fmt.Errorf("unsupported state version %d", s.data.Version)
		}
		if s.data.NodeID == "" {
			return nil, errors.New("state snapshot has no node identity")
		}
		changed, err := s.data.normalize()
		if err != nil {
			return nil, fmt.Errorf("invalid state snapshot: %w", err)
		}
		if changed {
			if err := s.persist(s.data); err != nil {
				return nil, fmt.Errorf("persist state snapshot migration: %w", err)
			}
		}
		if err := s.loadNonces(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read state snapshot: %w", err)
	}
	s.data = newState(nodeID)
	if err := s.persist(s.data); err != nil {
		return nil, err
	}
	if err := s.loadNonces(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadNonces() error {
	s.nonces = map[string]int64{}
	path := s.path + ".nonces"
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read device nonce log: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		b = nil
	}
	lines := bytes.Split(b, []byte{'\n'})
	recordCount := 0
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) != 2 {
			if i == len(lines)-1 {
				break // A crash may leave only the final append incomplete.
			}
			return fmt.Errorf("invalid device nonce log record at line %d", i+1)
		}
		expiresAt, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil || len(fields[0]) != 64 {
			if i == len(lines)-1 {
				break
			}
			return fmt.Errorf("invalid device nonce log record at line %d", i+1)
		}
		s.nonces[fields[0]] = expiresAt
		recordCount++
	}
	legacyCount := len(s.data.DeviceNonces)
	for key, expiry := range s.data.DeviceNonces {
		if expiry > s.nonces[key] {
			s.nonces[key] = expiry
		}
	}
	s.data.DeviceNonces = map[string]int64{}
	now := time.Now().UnixNano()
	for key, expiry := range s.nonces {
		if expiry <= now {
			delete(s.nonces, key)
		}
	}
	if len(s.nonces) > 100000 {
		return ErrNonceCapacity
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if createErr != nil {
			return fmt.Errorf("create device nonce log: %w", createErr)
		}
		if createErr = f.Close(); createErr != nil {
			return fmt.Errorf("close device nonce log: %w", createErr)
		}
		if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	} else if err != nil {
		return fmt.Errorf("inspect device nonce log: %w", err)
	}
	s.nonceLogEntries = recordCount + legacyCount
	if legacyCount > 0 || s.nonceLogEntries > len(s.nonces)*2+1000 {
		if err := s.compactNonces(); err != nil {
			return fmt.Errorf("compact device nonce log: %w", err)
		}
	}
	if legacyCount > 0 {
		if err := s.persist(s.data); err != nil {
			return fmt.Errorf("persist nonce-log migration: %w", err)
		}
	}
	return nil
}

// AcceptDeviceNonce durably records a hashed proof nonce without rewriting the
// full service snapshot on every authenticated HTTP request.
func (s *Store) AcceptDeviceNonce(key string, expiresAt, now int64, limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for nonce, expiry := range s.nonces {
		if expiry <= now {
			delete(s.nonces, nonce)
		}
	}
	if _, ok := s.nonces[key]; ok {
		return ErrNonceReplay
	}
	if len(s.nonces) >= limit {
		return ErrNonceCapacity
	}
	path := s.path + ".nonces"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = fmt.Fprintf(f, "%s %d\n", key, expiresAt)
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
	s.nonces[key] = expiresAt
	s.nonceLogEntries++
	if s.nonceLogEntries > len(s.nonces)*2+1000 {
		_ = s.compactNonces()
	}
	return nil
}

func (s *Store) compactNonces() error {
	path := s.path + ".nonces"
	f, err := os.CreateTemp(filepath.Dir(path), ".nonces-*.tmp")
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
		for key, expiry := range s.nonces {
			if _, err = fmt.Fprintf(f, "%s %d\n", key, expiry); err != nil {
				break
			}
		}
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
	if err = replaceFile(tmp, path); err != nil {
		return err
	}
	keep = true
	s.nonceLogEntries = len(s.nonces)
	return nil
}

func newState(nodeID string) State {
	return State{Version: Version, NodeID: nodeID, ServerCode: newServerCode(nodeID), DeviceNonces: map[string]int64{}, Devices: map[string]Device{}, Groups: map[string]Group{}, Invites: map[string]Invite{}, Applications: map[string]Application{}, Idempotency: map[string]Idempotent{}, Messages: map[string][]Message{}, KeyDeliveries: map[string][]KeyDelivery{}, Files: map[string]File{}}
}

func newServerCode(nodeID string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	h := sha256.Sum256([]byte(nodeID))
	value := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	var out [4]byte
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = alphabet[value%uint32(len(alphabet))]
		value /= uint32(len(alphabet))
	}
	return string(out[:])
}

func (s *State) normalize() (bool, error) {
	changed := false
	if s.ServerCode == "" {
		s.ServerCode = newServerCode(s.NodeID)
		changed = true
	}
	if len(s.ServerCode) != 4 {
		return false, errors.New("server code must contain four uppercase letters or digits")
	}
	for _, char := range s.ServerCode {
		if !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') {
			return false, errors.New("server code must contain four uppercase letters or digits")
		}
	}
	if s.DeviceNonces == nil {
		s.DeviceNonces = map[string]int64{}
		changed = true
	}
	if s.Devices == nil {
		s.Devices = map[string]Device{}
		changed = true
	}
	if s.Groups == nil {
		s.Groups = map[string]Group{}
		changed = true
	}
	if s.Invites == nil {
		s.Invites = map[string]Invite{}
		changed = true
	}
	if s.Applications == nil {
		s.Applications = map[string]Application{}
		changed = true
	}
	if s.Idempotency == nil {
		s.Idempotency = map[string]Idempotent{}
		changed = true
	}
	if s.Messages == nil {
		s.Messages = map[string][]Message{}
		changed = true
	}
	if s.KeyDeliveries == nil {
		s.KeyDeliveries = map[string][]KeyDelivery{}
		changed = true
	}
	if s.Files == nil {
		s.Files = map[string]File{}
		changed = true
	}
	for id, g := range s.Groups {
		if id != g.ID || g.ID == "" {
			return false, errors.New("group key does not match group ID")
		}
		if g.Members == nil {
			g.Members = map[string]Member{}
			changed = true
		}
		if g.Rotations == nil {
			g.Rotations = map[string]Rotation{}
			changed = true
		}
		s.Groups[id] = g
	}
	return changed, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) View(fn func(State) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	return fn(s.data)
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	copy, err := clone(s.data)
	if err != nil {
		return err
	}
	if err := fn(&copy); err != nil {
		return err
	}
	if err := s.persist(copy); err != nil {
		return err
	}
	s.data = copy
	return nil
}

// SetDeviceName updates only an existing device's display name. Heartbeats
// commonly repeat the same name; compare under the store lock so those calls
// neither clone nor persist the complete snapshot. As with Update, a failed
// durable write leaves the published device identity and name unchanged.
func (s *Store) SetDeviceName(deviceID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	device, exists := s.data.Devices[deviceID]
	if !exists || device.ID != deviceID {
		return errors.New("device identity is not registered")
	}
	if device.DeviceName == name {
		return nil
	}
	copy, err := clone(s.data)
	if err != nil {
		return err
	}
	device.DeviceName = name
	copy.Devices[deviceID] = device
	if err := s.persist(copy); err != nil {
		return err
	}
	s.data = copy
	return nil
}

func clone(v State) (State, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return State{}, err
	}
	var out State
	err = json.Unmarshal(b, &out)
	return out, err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.persist(s.data); err != nil {
		return err
	}
	s.closed = true
	return nil
}

func (s *Store) persist(state State) error {
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state snapshot: %w", err)
	}
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create state temp file: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write state snapshot: %w", err)
	}
	if err = replaceFile(tmp, s.path); err != nil {
		return fmt.Errorf("replace state snapshot: %w", err)
	}
	ok = true
	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s *Store) FileSize() int64 {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0
	}
	return info.Size()
}
