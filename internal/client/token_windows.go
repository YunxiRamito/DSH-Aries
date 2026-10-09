//go:build windows

package client

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func secureNewToken(path string) error { return setOwnerOnlyACL(path) }

func secureExistingToken(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	return setOwnerOnlyACL(path)
}

// icacls is part of supported Windows installations. Using the account SID
// avoids localized account names and grants no inherited access to the token.
func setOwnerOnlyACL(path string) error {
	current, err := user.Current()
	if err != nil || current.Uid == "" {
		return fmt.Errorf("cannot identify current Windows user")
	}
	cmd := exec.Command("icacls.exe", path, "/inheritancelevel:r", "/grant:r", "*"+current.Uid+":F")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not apply owner-only Windows ACL: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
