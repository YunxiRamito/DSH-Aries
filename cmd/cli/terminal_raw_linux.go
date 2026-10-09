//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// enterRawTerminal switches a Linux console to one-byte, no-echo input and
// returns a restore function. It deliberately affects only the current file
// descriptor and always restores the original termios settings.
func enterRawTerminal(input io.Reader) (func(), error) {
	f, ok := input.(*os.File)
	if !ok {
		return func() {}, errors.New("interactive input is not a terminal")
	}
	var original syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&original)), 0, 0, 0); errno != 0 {
		return func() {}, errno
	}
	raw := original
	raw.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&raw)), 0, 0, 0); errno != 0 {
		return func() {}, errno
	}
	return func() {
		_, _, _ = syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&original)), 0, 0, 0)
	}, nil
}

