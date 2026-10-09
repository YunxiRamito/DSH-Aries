package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"aries.local/aries/internal/client"
)

func startDetachedServer(executable, configPath, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		return 0, fmt.Errorf("create server log directory: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 0, fmt.Errorf("open server log: %w", err)
	}
	if err := client.RestrictFile(logPath); err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("protect server log: %w", err)
	}
	command := exec.Command(executable, "serve", "--config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	configureDetachedProcess(command)
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("start server process: %w", err)
	}
	pid := command.Process.Pid
	_ = command.Process.Release()
	_ = logFile.Close()
	return pid, nil
}
