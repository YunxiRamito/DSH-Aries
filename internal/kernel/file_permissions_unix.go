//go:build !windows

package kernel

import (
	"os"
)

func secureFileDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func secureFilePath(path string) error {
	return os.Chmod(path, 0600)
}
