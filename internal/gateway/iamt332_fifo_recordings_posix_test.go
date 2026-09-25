//go:build !windows

package gateway

// iamt332_fifo_recordings_posix_test.go — IAMT-332 round six, the admin
// side of the recordings reads. fileSHA256Hex and the recordings.fetch
// serving open read recording parts by final pathname; a non-regular
// entry planted at such a name (recordings live under the gateway data
// directory) was read through or hung on. Round six routes both through
// the same no-follow regular-file-only open as every other data-file
// reader; the hashes and the ranged serving keep streaming (recordings
// can be large, so no whole-file read anywhere).

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestIAMT332Round6RecordingServingRefusesAFIFOPlantedAtTheName plants a
// FIFO at a recording part's name in turn and requires each reader to
// come back promptly with the actionable refusal. The bounded-wait
// pattern is part of the test's meaning: a genuine hang fails the test
// naming the reader, it does not wedge the suite.
func TestIAMT332Round6RecordingServingRefusesAFIFOPlantedAtTheName(t *testing.T) {
	t.Run("fileSHA256Hex's stream of a recording part", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "session.cast")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("plant the FIFO: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := fileSHA256Hex(path)
			done <- err
		}()
		assertPromptRefusal(t, "fileSHA256Hex", path, done)
	})

	t.Run("recordings.fetch's serving open of an exec part", func(t *testing.T) {
		f := newFixture(t, nil)
		f.connectMachine(fakeMachineBehavior{})
		f.waitMachineOnline(t)
		client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			t.Fatalf("human dial: %v", err)
		}
		defer client.Close()
		hs := openHumanSession(t, client, f)
		ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo iamt332"}))
		if err != nil || !ok {
			t.Fatalf("exec: ok=%v err=%v", ok, err)
		}
		if _, err := hs.ch.Write([]byte("iamt332-round-six")); err != nil {
			t.Fatalf("write exec stdin: %v", err)
		}
		_ = hs.ch.CloseWrite()
		_ = hs.ch.Close()
		waitUntil(t, "exec session did not close", func() bool {
			mc, ok := f.gw.reg.get(f.machineID)
			return ok && mc.doorMachine.Snapshot().Sessions == 0
		})
		paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.exec.jsonl"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("expected exactly one finalized .exec.jsonl, paths=%v err=%v", paths, err)
		}
		// Swap the finalized part out from under the gateway: the name
		// stays, the regular file becomes a FIFO.
		path := paths[0]
		if err := os.Remove(path); err != nil {
			t.Fatalf("clear the part before planting: %v", err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("plant the FIFO: %v", err)
		}
		entries, err := scanRecordings(f.recordingsDir())
		if err != nil || len(entries) != 1 {
			t.Fatalf("recordings scan must still find the metadata, entries=%v err=%v", entries, err)
		}
		body, _ := json.Marshal(map[string]any{"proto": 1, "id": entries[0].id, "part": "exec", "offset": 0, "limit": 4096})
		done := make(chan error, 1)
		go func() {
			_, cerr := cmdRecordingsFetch(f.gw, "admin", f.clock.Now(), body)
			if cerr == nil {
				done <- nil
				return
			}
			done <- errors.New(cerr.Error())
		}()
		assertPromptRefusal(t, "recordings.fetch", path, done)
	})
}

// assertPromptRefusal requires the reader to answer promptly with the
// actionable refusal: a timeout names the reader that hung, a nil error
// names the reader that read through the planted FIFO, and anything short
// of the "not a regular file" wording fails on its own line.
func assertPromptRefusal(t *testing.T, what, path string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("%s read through a FIFO planted at %s — a recording file's name must be refused when it is not a regular file (IAMT-332 round 6)", what, path)
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do", what, path, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a recording file's name (IAMT-332 round 6)", what, path)
	}
}
