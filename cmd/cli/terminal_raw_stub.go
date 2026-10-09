//go:build !linux && !windows

package main

import (
	"errors"
	"io"
)

func enterRawTerminal(io.Reader) (func(), error) {
	return func() {}, errors.New("raw terminal input is not supported on this platform")
}

