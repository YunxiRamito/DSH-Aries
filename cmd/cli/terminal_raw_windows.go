//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"syscall"
	"unsafe"
)

const (
	winEnableProcessedInput       = 0x0001
	winEnableLineInput            = 0x0002
	winEnableEchoInput            = 0x0004
	winEnableVirtualTerminalInput = 0x0200
)

var (
	winKernel32       = syscall.NewLazyDLL("kernel32.dll")
	winGetConsoleMode = winKernel32.NewProc("GetConsoleMode")
	winSetConsoleMode = winKernel32.NewProc("SetConsoleMode")
)

func enterRawTerminal(input io.Reader) (func(), error) {
	f, ok := input.(*os.File)
	if !ok {
		return func() {}, errors.New("interactive input is not a console")
	}
	var original uint32
	result, _, callErr := winGetConsoleMode.Call(uintptr(f.Fd()), uintptr(unsafe.Pointer(&original)))
	if result == 0 {
		return func() {}, callErr
	}
	raw := original &^ (winEnableProcessedInput | winEnableLineInput | winEnableEchoInput)
	raw |= winEnableVirtualTerminalInput
	result, _, callErr = winSetConsoleMode.Call(uintptr(f.Fd()), uintptr(raw))
	if result == 0 {
		return func() {}, callErr
	}
	return func() {
		_, _, _ = winSetConsoleMode.Call(uintptr(f.Fd()), uintptr(original))
	}, nil
}
