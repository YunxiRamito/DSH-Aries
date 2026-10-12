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

func TestDeviceNamePersistsAndFailedRenameIsNotPublished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, "node_device_name")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(func(state *State) error {
		state.Devices["dev_test"] = Device{ID: "dev_test", PublicKey: "registered-public-key", CreatedAt: "2026-10-12T00:00:00Z"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceName("dev_test", "OPPO Find X8"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	check := func(st *Store) {
		t.Helper()
		if err := st.View(func(state State) error {
			d := state.Devices["dev_test"]
			if d.DeviceName != "OPPO Find X8" || d.ID != "dev_test" || d.PublicKey != "registered-public-key" || d.CreatedAt != "2026-10-12T00:00:00Z" {
				t.Fatalf("name update changed identity or did not persist: %#v", d)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(reopened)
	// A file cannot serve as a directory. A no-op should still succeed without
	// attempting a snapshot write, while a genuine rename must fail atomically.
	s.path = filepath.Join(path, "cannot-write.json")
	if err := s.SetDeviceName("dev_test", "OPPO Find X8"); err != nil {
		t.Fatalf("unchanged name attempted to persist: %v", err)
	}
	if err := s.SetDeviceName("dev_test", "Uncommitted rename"); err == nil {
		t.Fatal("expected failed snapshot write")
	}
	check(s)
	s.path = path
	if err := s.SetDeviceName("dev_missing", "Unknown"); err == nil {
		t.Fatal("unknown device identity accepted a display name")
	}
}
