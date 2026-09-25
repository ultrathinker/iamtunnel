//go:build windows

package events

// syncDir is a no-op on Windows because Windows file systems do not support
// fsync on directory handles.
func syncDir(dir string) error {
	return nil
}
