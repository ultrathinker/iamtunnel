//go:build !windows

package main

import (
	"os"
	"testing"
)

// plantDirLink makes a symlink at link pointing to target.
func plantDirLink(t *testing.T, target, link string) bool {
	t.Helper()
	return os.Symlink(target, link) == nil
}
