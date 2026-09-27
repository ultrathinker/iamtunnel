package record

import (
	"os"
	"strings"
	"testing"
)

// 1.50: an exec recording carries what the person sent on stdin (stream
// "stdin") and the SFTP operations of a subsystem session (type "sftp"),
// and History's reader shows both.
func TestR150_ExecRecordingKeepsStdinAndSFTPOps(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "m", Person: "p", SessionID: "r150", SubdirLayout: true,
	}, Command: "powershell -Command -"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	rec.AddBytesIn([]byte("Get-Date\r\n"))
	if err := rec.SFTPFile("open", "upload", "/C:/TEST111/car.jpg", "", 4, "abc123", "ok"); err != nil {
		t.Fatalf("SFTPFile: %v", err)
	}
	// Buffered stdin is written before the next event, so this binary
	// chunk stays separate from the text one above.
	rec.AddBytesIn([]byte{0xff, 0x00, 0xfe})
	if err := rec.SFTPFile("rename", "", "/C:/a", "/C:/b", -1, "", "denied: E_COMMAND_BLOCKED"); err != nil {
		t.Fatalf("SFTPFile: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	raw, err := os.ReadFile(rec.Paths().ExecPath)
	if err != nil {
		t.Fatalf("read exec: %v", err)
	}
	if !strings.Contains(string(raw), `"stream":"stdin"`) {
		t.Fatalf("stdin was not recorded:\n%s", raw)
	}

	vt := NewVT(120, 40)
	ParseExec(raw, nil, vt)
	got := vt.Transcript()
	for _, want := range []string{
		"Get-Date",
		"[stdin: 3 bytes of binary data]",
		"sftp upload /C:/TEST111/car.jpg (4 bytes, sha256 abc123) ok",
		"sftp rename /C:/a -> /C:/b denied: E_COMMAND_BLOCKED",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("transcript is missing %q; got:\n%s", want, got)
		}
	}
}
