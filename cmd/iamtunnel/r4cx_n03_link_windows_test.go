//go:build windows

package main

import (
	"os/exec"
	"testing"
)

// plantDirLink makes a directory junction at link pointing to target.
func plantDirLink(t *testing.T, target, link string) bool {
	t.Helper()
	return exec.Command("cmd", "/c", "mklink", "/J", link, target).Run() == nil
}
