package client

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const tokenBytes = 32 // 256 bits of entropy.

// ReadToken reads a token file without exposing its contents in errors. On
// Unix-like systems it rejects group/world-readable files. On Windows it
// replaces inherited permissions with an ACL for the current account.
func ReadToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("token file path is required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve token file path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("token file %q does not exist; create one with `ariesctl token create --out <path>`", path)
		}
		return "", fmt.Errorf("inspect token file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("token file %q must not be a symbolic link", path)
	}
	if err := secureExistingToken(path); err != nil {
		return "", fmt.Errorf("secure token file: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("token file %q does not exist; create one with `ariesctl token create --out <path>`", path)
		}
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", fmt.Errorf("token file %q changed while opening or is not a regular file", path)
	}
	latestInfo, err := os.Lstat(path)
	if err != nil || latestInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, latestInfo) {
		return "", fmt.Errorf("token file %q changed while opening", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	token := strings.TrimSuffix(string(b), "\n")
	token = strings.TrimSuffix(token, "\r")
	if token == "" {
		return "", fmt.Errorf("token file %q is empty", path)
	}
	if strings.ContainsAny(token, "\r\n\t ") {
		return "", fmt.Errorf("token file %q must contain one token on a single line", path)
	}
	if len(b) > 4096 || len(token) > 4096 {
		return "", fmt.Errorf("token file %q is too large", path)
	}
	return token, nil
}

// CreateTokenFile writes a new random token atomically and refuses to replace
// an existing file. The secret is returned for optional one-time display.
func CreateTokenFile(path string) (string, error) {
	return createTokenFile(path, false)
}

// RotateTokenFile atomically replaces the local token file with newly
// generated material. It intentionally makes no API request; operators must
// arrange for the local server to load the new token through its secure
// bootstrap channel and restart it as required.
func RotateTokenFile(path string) (string, error) {
	return createTokenFile(path, true)
}

// RestrictFile applies the same owner-only policy used for token material. It
// is also used for the non-secret, local command metadata cache.
func RestrictFile(path string) error { return secureNewToken(path) }

func createTokenFile(path string, replace bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("output token file path is required")
	}
	secret := make([]byte, tokenBytes)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	for i := range secret {
		secret[i] = 0
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve token output path: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create token directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".aries-token-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create token temporary file: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		err = secureNewToken(tmp)
	}
	if err == nil {
		_, err = io.WriteString(f, token+"\n")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}
	if replace {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("token file %q does not exist; use `ariesctl token create` first", path)
		} else if statErr != nil {
			return "", fmt.Errorf("inspect token file: %w", statErr)
		}
		if err = os.Rename(tmp, path); err != nil {
			return "", fmt.Errorf("replace token file: %w", err)
		}
	} else {
		// A hard link makes publication atomic and fails if path already exists.
		// The temp file is on the same volume because it was created in dir.
		if err = os.Link(tmp, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return "", fmt.Errorf("token file %q already exists; use `ariesctl token rotate` to replace it", path)
			}
			return "", fmt.Errorf("publish token file: %w", err)
		}
	}
	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return token, nil
}
