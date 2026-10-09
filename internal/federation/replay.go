package federation

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// MaxReplayCacheEntries caps caller-configured replay cache size to avoid
	// accidental unbounded reservations from configuration mistakes.
	MaxReplayCacheEntries = 1_000_000
)

// ReplayCache remembers authenticated origin/message pairs until each message
// expires. It is bounded and concurrency-safe. When full, it rejects new
// messages instead of evicting live entries, preserving replay protection for
// accepted messages. The cache is process-local and is lost on restart.
type ReplayCache struct {
	mu       sync.Mutex
	capacity int
	seen     map[replayKey]time.Time
}

type replayKey struct {
	origin string
	msgID  string
}

// NewReplayCache creates a bounded in-memory cache. Capacity must be positive.
func NewReplayCache(capacity int) (*ReplayCache, error) {
	if capacity <= 0 || capacity > MaxReplayCacheEntries {
		return nil, fmt.Errorf("replay cache capacity must be between 1 and %d", MaxReplayCacheEntries)
	}
	return &ReplayCache{capacity: capacity, seen: make(map[replayKey]time.Time)}, nil
}

// VerifyAndRemember verifies env and atomically records its origin/message ID.
// It should be called after resolving publicKey from a trusted mapping for
// env.OriginNodeID. Invalid messages are never inserted into the replay cache.
func VerifyAndRemember(env Envelope, publicKey ed25519.PublicKey, now time.Time, maxHopLimit uint8, cache *ReplayCache) error {
	if err := Verify(env, publicKey, now, maxHopLimit); err != nil {
		return err
	}
	if cache == nil {
		return errors.New("replay cache is required")
	}
	return cache.remember(replayKey{origin: env.OriginNodeID, msgID: env.MessageID}, env.ExpiresAt, now)
}

func (c *ReplayCache) remember(key replayKey, expiresAt, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for existing, expiry := range c.seen {
		if !now.Before(expiry) {
			delete(c.seen, existing)
		}
	}
	if expiry, ok := c.seen[key]; ok {
		if now.Before(expiry) {
			return ErrReplay
		}
		delete(c.seen, key)
	}
	if len(c.seen) >= c.capacity {
		return ErrReplayCacheFull
	}
	c.seen[key] = expiresAt
	return nil
}

// Len returns the current number of entries after removing entries expired at
// now. It is intended for diagnostics and tests; it does not expose identities.
func (c *ReplayCache) Len(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, expiry := range c.seen {
		if !now.Before(expiry) {
			delete(c.seen, key)
		}
	}
	return len(c.seen)
}

// String reports cache sizing without leaking message identifiers.
func (c *ReplayCache) String() string {
	if c == nil {
		return "federation replay cache <nil>"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("federation replay cache (%d/%d entries)", len(c.seen), c.capacity)
}
