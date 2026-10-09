package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config is the stable configuration contract shared with server-management
// clients. The token itself is never stored here; only its file path is.
type Config struct {
	SchemaVersion         int    `json:"schema_version"`
	PublicListen          string `json:"public_listen"`
	AdminListen           string `json:"admin_listen"`
	DataDir               string `json:"data_dir"`
	AdminTokenFile        string `json:"admin_token_file"`
	MaxStorageBytes       int64  `json:"max_storage_bytes"`
	AllowInsecureLoopback bool   `json:"allow_insecure_loopback"`
	PeerRelayEnabled      bool   `json:"peer_relay_enabled"`
	FileStorageEnabled    bool   `json:"file_storage_enabled"`
	GroupQuotaBytes       int64  `json:"group_quota_bytes"`
	QuotaBytesPerMember   int64  `json:"quota_bytes_per_member"`
	MaxFileBytes          int64  `json:"max_file_bytes"`
	MaxFileTTLSeconds     int64  `json:"max_file_ttl_seconds"`
}

func DefaultConfig() Config {
	return Config{
		SchemaVersion:         1,
		PublicListen:          "127.0.0.1:8787",
		AdminListen:           "127.0.0.1:8788",
		DataDir:               "./data",
		AdminTokenFile:        "./secrets/admin.token",
		MaxStorageBytes:       1024 * 1024 * 1024,
		AllowInsecureLoopback: true,
		PeerRelayEnabled:      false,
		FileStorageEnabled:    true,
		GroupQuotaBytes:       1024 * 1024 * 1024,
		QuotaBytesPerMember:   0,
		MaxFileBytes:          256 * 1024 * 1024,
		MaxFileTTLSeconds:     30 * 24 * 60 * 60,
	}
}

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	// Seed defaults before decoding so configurations written before the file
	// storage fields were added retain the documented default behavior.
	c := DefaultConfig()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Clean(filepath.Join(filepath.Dir(path), c.DataDir))
	}
	if !filepath.IsAbs(c.AdminTokenFile) {
		c.AdminTokenFile = filepath.Clean(filepath.Join(filepath.Dir(path), c.AdminTokenFile))
	}
	return c, nil
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config must contain exactly one JSON object")
	}
	return nil
}

func (c Config) Validate() error {
	var fields []string
	if c.SchemaVersion != 1 {
		fields = append(fields, "schema_version must be 1")
	}
	if err := validListen("public_listen", c.PublicListen); err != nil {
		fields = append(fields, err.Error())
	}
	if err := validListen("admin_listen", c.AdminListen); err != nil {
		fields = append(fields, err.Error())
	}
	if strings.TrimSpace(c.DataDir) == "" {
		fields = append(fields, "data_dir is required")
	}
	if strings.TrimSpace(c.AdminTokenFile) == "" {
		fields = append(fields, "admin_token_file is required")
	}
	if c.MaxStorageBytes < 0 {
		fields = append(fields, "max_storage_bytes must be non-negative")
	}
	if c.GroupQuotaBytes < 0 || c.QuotaBytesPerMember < 0 || c.MaxFileBytes < 0 || c.MaxFileTTLSeconds < 0 {
		fields = append(fields, "file quotas, max_file_bytes, and max_file_ttl_seconds must be non-negative")
	}
	if len(fields) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(fields, "; "))
	}
	return nil
}

func validListen(field, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return fmt.Errorf("%s must be host:port", field)
	}
	if host != "" && net.ParseIP(host) == nil {
		if strings.ContainsAny(host, " /\\") {
			return fmt.Errorf("%s has an invalid host", field)
		}
	}
	return nil
}

func writeConfigAtomic(path string, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
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
		return fmt.Errorf("write config: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	keep = true
	return nil
}
