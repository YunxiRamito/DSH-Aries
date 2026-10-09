//go:build windows

package main

import (
	"io"
	"os"
	"strconv"
	"unsafe"
)

type winCoord struct{ X, Y int16 }
type winSmallRect struct{ Left, Top, Right, Bottom int16 }
type winConsoleScreenBufferInfo struct {
	Size              winCoord
	CursorPosition    winCoord
	Attributes        uint16
	Window            winSmallRect
	MaximumWindowSize winCoord
}

var winGetConsoleScreenBufferInfo = winKernel32.NewProc("GetConsoleScreenBufferInfo")

func terminalWidth(output io.Writer) int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return columns
	}
	f, ok := output.(*os.File)
	if !ok {
		return 78
	}
	var info winConsoleScreenBufferInfo
	result, _, _ := winGetConsoleScreenBufferInfo.Call(uintptr(f.Fd()), uintptr(unsafe.Pointer(&info)))
	if result == 0 || info.Window.Right < info.Window.Left {
		return 78
	}
	return int(info.Window.Right-info.Window.Left) + 1
}
