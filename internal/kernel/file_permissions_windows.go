//go:build windows

package kernel

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func secureFileDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return applyFileACL(path, true)
}

func secureFilePath(path string) error {
	return applyFileACL(path, false)
}

func applyFileACL(path string, directory bool) error {
	current, err := user.Current()
	if err != nil || current.Uid == "" {
		return fmt.Errorf("cannot identify current Windows account for file storage ACL")
	}
	grant := "*" + current.Uid + ":F"
	if directory {
		grant = "*" + current.Uid + ":(OI)(CI)F"
	}
	cmd := exec.Command("icacls.exe", path, "/inheritancelevel:r", "/grant:r", grant)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not secure file storage ACL: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
