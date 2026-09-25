//go:build !windows

package events

import "os"

// syncDir opens the directory and issues an fsync to flush directory entries.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
