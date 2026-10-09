//go:build !windows

package store

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
