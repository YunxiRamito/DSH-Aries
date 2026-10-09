//go:build !linux && !windows

package main

import "io"

func terminalWidth(io.Writer) int { return 78 }

