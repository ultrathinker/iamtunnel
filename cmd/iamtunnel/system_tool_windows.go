//go:build windows

package main

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// systemTool is the full path of one of Windows' own programs - schtasks,
// cmd - in the system directory, asked of Windows itself rather than read
// from %SystemRoot%, which is an environment variable like any other
// (R1-CX F-25). A program started by name is whatever the first directory
// on %PATH% holds, and the callers start these with an administrator's
// token (server install) or from a window that may have one ("Restart as
// administrator").
func systemTool(name string) (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("could not find the Windows system directory to run %s from: %w", name, err)
	}
	return filepath.Join(dir, name), nil
}
