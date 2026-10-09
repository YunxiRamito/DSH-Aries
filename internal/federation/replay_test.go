package federation

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyAndRememberDetectsReplay(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	cache, err := NewReplayCache(8)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndRemember(env, pub, now, 4, cache); err != nil {
		t.Fatalf("first acceptance: %v", err)
	}
	if err := VerifyAndRemember(env, pub, now, 4, cache); !errors.Is(err, ErrReplay) {
		t.Fatalf("second acceptance error = %v, want ErrReplay", err)
	}
	if got := cache.Len(now); got != 1 {
		t.Fatalf("cache length = %d, want 1", got)
	}
}

func TestReplayCacheDoesNotRememberInvalidMessage(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	cache, _ := NewReplayCache(1)
	env.Payload = []byte(`{"tampered":true}`)
	if err := VerifyAndRemember(env, pub, now, 4, cache); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid acceptance error = %v", err)
	}
	if got := cache.Len(now); got != 0 {
		t.Fatalf("invalid message occupied cache: length = %d", got)
	}
}

func TestReplayCacheRejectsWhenFullWithoutEvictingLiveEntries(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	cache, _ := NewReplayCache(1)
	first := mustSign(t, validEnvelope(now), priv)
	if err := VerifyAndRemember(first, pub, now, 4, cache); err != nil {
		t.Fatal(err)
	}
	secondData := validEnvelope(now.Add(2 * time.Minute))
	secondData.MessageID = "message-2"
	second := mustSign(t, secondData, priv)
	if err := VerifyAndRemember(second, pub, now, 4, cache); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full-cache acceptance error = %v", err)
	}
	if err := VerifyAndRemember(first, pub, now, 4, cache); !errors.Is(err, ErrReplay) {
		t.Fatalf("original record was evicted: %v", err)
	}
	if err := VerifyAndRemember(second, pub, now.Add(2*time.Minute), 4, cache); err != nil {
		t.Fatalf("accept after expiry cleanup: %v", err)
	}
}

func TestReplayCacheScopeIncludesOrigin(t *testing.T) {
	pubA, privA, pubB, privB := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	cache, _ := NewReplayCache(2)
	a := validEnvelope(now)
	a.MessageID = "same-id"
	a = mustSign(t, a, privA)
	b := validEnvelope(now)
	b.OriginNodeID = "B6E9"
	b.MessageID = "same-id"
	b = mustSign(t, b, privB)
	if err := VerifyAndRemember(a, pubA, now, 4, cache); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndRemember(b, pubB, now, 4, cache); err != nil {
		t.Fatalf("different origin was treated as replay: %v", err)
	}
}

func TestReplayCacheConcurrentDuplicateHasOneWinner(t *testing.T) {
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	cache, _ := NewReplayCache(8)
	const goroutines = 16
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var replayed atomic.Int32
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := VerifyAndRemember(env, pub, now, 4, cache)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrReplay):
				replayed.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || replayed.Load() != goroutines-1 {
		t.Fatalf("accepted=%d replayed=%d", accepted.Load(), replayed.Load())
	}
}

func TestReplayCacheConstructorAndNilCache(t *testing.T) {
	if _, err := NewReplayCache(0); err == nil {
		t.Fatal("zero capacity was accepted")
	}
	if _, err := NewReplayCache(MaxReplayCacheEntries + 1); err == nil {
		t.Fatal("capacity above the configured maximum was accepted")
	}
	pub, priv, _, _ := testKeys(t)
	now := time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	env := mustSign(t, validEnvelope(now), priv)
	if err := VerifyAndRemember(env, pub, now, 4, nil); err == nil {
		t.Fatal("nil cache was accepted")
	}
	var nilCache *ReplayCache
	if got := nilCache.Len(now); got != 0 {
		t.Fatalf("nil cache length = %d", got)
	}
}
