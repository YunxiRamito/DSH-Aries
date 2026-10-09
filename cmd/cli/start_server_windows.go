//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func configureDetachedProcess(command *exec.Cmd) {
	const (
		detachedProcess = 0x00000008
		newProcessGroup = 0x00000200
		createNoWindow  = 0x08000000
	)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: detachedProcess | newProcessGroup | createNoWindow}
}
