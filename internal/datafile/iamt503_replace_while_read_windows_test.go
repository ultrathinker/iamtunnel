//go:build windows

package datafile

// IAMT-503: on Windows a rename over a file that another handle holds open
// is refused with ERROR_ACCESS_DENIED -- Go opens files without
// FILE_SHARE_DELETE, and even a reader that does share delete does not
// make MoveFileEx's replace succeed. So a WriteFileAtomic that lands while
// anybody is reading the old file failed outright, and the caller's new
// content was lost. The gateway met it on every recording's .meta: an
// admin listing recordings (which reads every .meta) at the moment a
// session finalized left that recording's start-of-session meta in place
// for good -- zero bytes out, status "recording" -- which is the flake
// TestIAMT209_PTYRecordingFetchedViaAdmin showed under load.
//
// A reader holds its handle for microseconds. The replace now waits it
// out, briefly and boundedly.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIAMT503_AReplaceWaitsOutAShortReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.meta")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenExisting(path, os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		reader.Close()
		close(released)
	}()

	werr := WriteFileAtomic(path, []byte("new"))
	<-released
	if werr != nil {
		t.Fatalf("WriteFileAtomic while a reader held the file for 150 ms: %v — the new content was lost", werr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("file holds %q after the replace, want %q", got, "new")
	}
}

func TestIAMT503_AReaderThatNeverLetsGoStillFailsTheReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.meta")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenExisting(path, os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	start := time.Now()
	werr := WriteFileAtomic(path, []byte("new"))
	took := time.Since(start)
	if werr == nil {
		t.Fatal("WriteFileAtomic succeeded while the old file stayed open — the retry must be bounded, not a guarantee")
	}
	if took > 5*time.Second {
		t.Fatalf("the refused replace took %v — the wait must stay short", took)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old" {
		t.Fatalf("a failed replace changed the file to %q", got)
	}
}
