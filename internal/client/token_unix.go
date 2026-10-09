//go:build !windows

package client

import (
	"fmt"
	"os"
)

func secureNewToken(path string) error {
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("set owner-only permissions: %w", err)
	}
	return nil
}

func secureExistingToken(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%q is accessible to group or other users; set permissions to 0600", path)
	}
	return nil
}
