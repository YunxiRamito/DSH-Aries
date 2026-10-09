package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSnapshotPersistsAcrossRestartAndRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, "node_test")
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(state *State) error {
		state.Groups["g1"] = Group{ID: "g1", AuthorityNode: state.NodeID, Members: map[string]Member{"d1": {DeviceID: "d1", Role: "creator", Active: true}}, Rotations: map[string]Rotation{}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, "ignored-node")
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.View(func(state State) error {
		if state.NodeID != "node_test" {
			t.Fatalf("node identity changed: %q", state.NodeID)
		}
		if state.Groups["g1"].Members["d1"].Role != "creator" {
			t.Fatal("membership was not restored")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("{ definitely not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path, "replacement-node"); err == nil || !strings.Contains(err.Error(), "preserved at") {
		t.Fatalf("corrupt state must fail without overwriting it, got %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{ definitely not json" {
		t.Fatal("corrupt snapshot was overwritten")
	}
}

func TestOpenMigratesLegacySnapshotWithDerivedServerCodeAndNonceMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, "node_legacy0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err = json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "server_code")
	delete(legacy, "device_nonces")
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path, "ignored-node")
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var code string
	if err = migrated.View(func(state State) error {
		code = state.ServerCode
		if len(code) != 4 || state.DeviceNonces == nil {
			t.Fatalf("legacy state did not receive required metadata: code=%q nonces=%#v", code, state.DeviceNonces)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, "another-ignored-node")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.View(func(state State) error {
		if state.ServerCode != code {
			t.Fatalf("derived code was not persisted: got %q want %q", state.ServerCode, code)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceNonceLogPersistsReplayProtectionAndExpiresEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, "node_test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	active := strings.Repeat("a", 64)
	expired := strings.Repeat("b", 64)
	if err = s.AcceptDeviceNonce(active, now+int64(time.Hour), now, 2); err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptDeviceNonce(expired, now-int64(time.Second), now-int64(time.Second), 2); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, "ignored-node")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.AcceptDeviceNonce(active, now+int64(time.Hour), now, 2); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("active nonce replay was not rejected after restart: %v", err)
	}
	if err = reopened.AcceptDeviceNonce(expired, now+int64(time.Hour), now, 2); err != nil {
		t.Fatalf("expired nonce should be reusable after restart: %v", err)
	}
}

func TestUpdateDoesNotPublishFailedTransition(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"), "node_test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want := os.ErrPermission
	if err = s.Update(func(state *State) error { state.Devices["d1"] = Device{ID: "d1"}; return want }); err == nil {
		t.Fatal("expected update failure")
	}
	if err = s.View(func(state State) error {
		if _, ok := state.Devices["d1"]; ok {
			t.Fatal("failed state transition was published")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
