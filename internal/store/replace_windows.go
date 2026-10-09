//go:build windows

package store

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func replaceFile(source, destination string) error {
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		err = os.Rename(source, destination)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 25 * time.Millisecond)
	}
	return err
}
