//go:build linux

package main

import (
	"io"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func terminalWidth(output io.Writer) int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return columns
	}
	f, ok := output.(*os.File)
	if !ok {
		return 78
	}
	var window struct {
		Rows uint16
		Cols uint16
		X    uint16
		Y    uint16
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&window)), 0, 0, 0); errno != 0 || window.Cols == 0 {
		return 78
	}
	return int(window.Cols)
}

