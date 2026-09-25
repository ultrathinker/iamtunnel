//go:build !windows

package main

import "errors"

// lockServerTree is Windows' alone: elsewhere the machine directory is
// locked by its mode (hardenServerDir), and nothing calls this.
func lockServerTree(string, bool) error {
	return errors.New("the machine directory's ACL lockdown exists on Windows only")
}
