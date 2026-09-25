package gateway

// iamt209_exec_fetch_e2e_test.go — IAMT-209.
//
// End-to-end coverage of the recordings.fetch wiring: a real exec
// session through the real gateway fixture (newFixture +
// connectMachine + dialHuman), the same exec session IAMT-163
// already drives for the recorder, and then a fetch driven over
// the admin wire against the same gateway.
//
// The fetch helper lives in cmd/iamtunnel (fetchRecording), so the
// gateway test re-implements its branch on top of admin.Conn — the
// same admin.Conn.RecordingsFetch calls, the same .meta-first
// probe, the same part selection. This is the byte-level canary the
// fix needs: the on-disk .exec.jsonl that the gateway wrote must
// come back verbatim through recordings.fetch.
//
// The cmd/iamtunnel side has its own unit tests
// (cmd/iamtunnel/iamt209_recordings_fetch_exec_test.go) for the
// branching; this file is the network round-trip half. Together
// they cover both halves of the end-to-end test.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// fetchRecordingViaAdmin is the cmd/iamtunnel fetchRecording logic,
// reproduced here because cmd/iamtunnel lives in a different package
// and importing it back would form a cycle. The shape is identical:
// probe .meta first, branch on recording_mode, download each part in
// chunks, verify the SHA-256 of the assembled bytes against the
// gateway's per-part hashes.
func fetchRecordingViaAdmin(t *testing.T, conn *admin.Conn, id, outDir string) []string {
	t.Helper()
	const chunk = 1 << 20

	// Step 1: probe .meta to learn the recording mode.
	metaBytes, _, err := downloadPart(t, conn, id, "meta", chunk)
	if err != nil {
		// No .meta: fall back to terminal parts (legacy pre-IAMT-163
		// recordings, recorded by builds that didn't write .meta).
		parts := []string{"cast", "txt"}
		return fetchAndWrite(t, conn, id, outDir, parts)
	}

	// Step 2: branch on recording_mode.
	mode := detectRecordingMode(metaBytes)
	parts := partsForRecordingMode(mode)
	// .meta is always useful — append last so the operator sees
	// the streamed part first.
	parts = append(parts, "meta")
	return fetchAndWrite(t, conn, id, outDir, parts)
}

// detectRecordingMode mirrors cmd/iamtunnel's helper. Tests in this
// file use the cmd/iamtunnel test file's coverage for the parsing
// edge cases (garbage, null, absent) and only call it with real
// bytes here.
func detectRecordingMode(metaBytes []byte) string {
	var meta struct {
		RecordingMode string `json:"recording_mode"`
	}
	_ = json.Unmarshal(metaBytes, &meta)
	return meta.RecordingMode
}

// partsForRecordingMode mirrors cmd/iamtunnel's mapping. Only the
// branches the gateway can produce today are listed.
func partsForRecordingMode(mode string) []string {
	if mode == "exec" {
		return []string{"exec"}
	}
	return []string{"cast", "txt"}
}

func fetchAndWrite(t *testing.T, conn *admin.Conn, id, outDir string, parts []string) []string {
	t.Helper()
	const chunk = 1 << 20
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}
	// Mirror cmd/iamtunnel/admin_exec.go's partFilenameExt table: the
	// gateway stores the lossless exec stream as `<base>.exec.jsonl`
	// (admin_role.go:1569-1570), and recordings.fetch must preserve
	// that on the way out. Keeping this table in sync is what stops
	// the e2e byte-equal canary from silently regressing when the
	// production mapping changes (IAMT-212).
	localExt := map[string]string{
		"cast": ".cast",
		"txt":  ".txt",
		"exec": ".exec.jsonl",
		"meta": ".meta",
	}
	var written []string
	for _, part := range parts {
		data, sha, err := downloadPart(t, conn, id, part, chunk)
		if err != nil {
			t.Fatalf("download %s: %v", part, err)
		}
		// verifySHA256 by hand: the test wants the bytes to be
		// trustworthy end-to-end, not just to look reasonable.
		got := shaOf(data)
		if got != sha {
			t.Fatalf("sha256 mismatch on %s: gateway=%s computed=%s", part, sha, got)
		}
		ext, ok := localExt[part]
		if !ok {
			t.Fatalf("fetchAndWrite: unknown recording part %q (no local extension; mirror admin_exec.go's partFilenameExt)", part)
		}
		dst := filepath.Join(outDir, id+ext)
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
		written = append(written, dst)
	}
	return written
}

// downloadPart mirrors cmd/iamtunnel's downloadRecordingPart loop.
// Stops at offset==total per PROTOCOL §6; PROTOCOL's zero-chunk-at-end
// rule is what keeps the loop from spinning forever on a final
// empty chunk.
func downloadPart(t *testing.T, conn *admin.Conn, id, part string, chunk int64) ([]byte, string, error) {
	t.Helper()
	var data []byte
	var offset int64
	var sha string
	for {
		res, err := conn.RecordingsFetch(id, part, offset, chunk)
		if err != nil {
			return nil, "", err
		}
		raw, derr := base64.StdEncoding.DecodeString(res.Data)
		if derr != nil {
			return nil, "", derr
		}
		data = append(data, raw...)
		sha = res.SHA256
		offset += int64(len(raw))
		if offset >= res.Total {
			break
		}
		if len(raw) == 0 {
			t.Fatalf("gateway made no progress on %s at offset %d/%d", part, offset, res.Total)
		}
	}
	return data, sha, nil
}

func shaOf(b []byte) string {
	sum := sha256.Sum256(b)
	const hex = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, by := range sum {
		out[i*2] = hex[by>>4]
		out[i*2+1] = hex[by&0x0f]
	}
	return string(out)
}

// TestIAMT209_ExecRecordingFetchedViaAdmin is the byte-level end-to-
// end canary: an exec session through the real
// gateway fixture, then the same admin wire recordings.fetch the CLI
// uses, with the same branching logic, must return a .exec.jsonl
// byte-equal to the file the gateway itself wrote.
//
// Canary: in fetchRecordingViaAdmin, change the .meta-probe branch
// to the terminal parts list. The exec recording is now fetched as
// .cast/.txt; cast fetch returns E_NOT_FOUND and the test fails on
// the t.Fatalf in downloadPart.
func TestIAMT209_ExecRecordingFetchedViaAdmin(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)

	// Step 1: drive an exec session through the same path IAMT-163
	// uses, so the gateway records it as RecordingMode:"exec".
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	const command = "whoami"
	if ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command})); err != nil || !ok {
		t.Fatalf("exec request: ok=%v err=%v", ok, err)
	}
	const marker = "iamt209-marker"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("person did not receive exec output %q; got %q", marker, got)
	}
	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()

	// Wait for the session to close and the .meta rewrite to land.
	waitUntil(t, "exec session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	// Find the recording in scanRecordings — must be exactly one.
	entries, err := scanRecordings(f.recordingsDir())
	if err != nil {
		t.Fatalf("scanRecordings: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("scanRecordings len = %d, want 1", len(entries))
	}
	gatewayExecPath := entries[0].base + ".exec.jsonl"
	if _, err := os.Stat(gatewayExecPath); err != nil {
		t.Fatalf("gateway exec recording %s missing: %v", gatewayExecPath, err)
	}

	// Step 2: drive recordings.list to surface the id we then hand
	// to recordings.fetch (the CLI does the same dance).
	var recList []admin.RecordingView
	waitUntil(t, "recordings.list never surfaced the exec recording", func() bool {
		l, lerr := root.RecordingsList(f.machineID, "", "")
		if lerr != nil || len(l) != 1 {
			return false
		}
		recList = l
		return true
	})
	if recList[0].Machine != f.machineID || recList[0].Person != f.person {
		t.Fatalf("recordings.list view = %+v, want machine=%q person=%q", recList[0], f.machineID, f.person)
	}

	// Step 3: the actual fix — fetchRecordingViaAdmin's .meta-first
	// branch routes the exec recording to .exec.jsonl, not cast/txt.
	outDir := t.TempDir()
	written := fetchRecordingViaAdmin(t, root, recList[0].ID, outDir)

	wantNames := []string{recList[0].ID + ".exec.jsonl", recList[0].ID + ".meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("fetch wrote %d files (%v), want exactly %v — pre-IAMT-209 fetch would have asked for cast/txt and failed with E_NOT_FOUND",
			len(written), written, wantNames)
	}
	for i, n := range wantNames {
		if filepath.Base(written[i]) != n {
			t.Fatalf("written[%d] = %q, want basename %q", i, filepath.Base(written[i]), n)
		}
	}

	// Step 4: byte-equal to the gateway's own .exec.jsonl.
	gwExecBytes, err := os.ReadFile(gatewayExecPath)
	if err != nil {
		t.Fatalf("read gateway .exec.jsonl: %v", err)
	}
	dlExecBytes, err := os.ReadFile(filepath.Join(outDir, recList[0].ID+".exec.jsonl"))
	if err != nil {
		t.Fatalf("read downloaded .exec.jsonl: %v", err)
	}
	if string(dlExecBytes) != string(gwExecBytes) {
		t.Fatalf("downloaded .exec.jsonl does not byte-equal the gateway file.\n--- gateway (%d bytes) ---\n%s\n--- downloaded (%d bytes) ---\n%s",
			len(gwExecBytes), gwExecBytes, len(dlExecBytes), dlExecBytes)
	}

	// Sanity: the gateway's .meta says recording_mode=exec, the
	// same shape detectRecordingMode reads.
	gwMetaBytes, err := os.ReadFile(entries[0].base + ".meta")
	if err != nil {
		t.Fatalf("read gateway .meta: %v", err)
	}
	var meta record.Metadata
	if err := json.Unmarshal(gwMetaBytes, &meta); err != nil {
		t.Fatalf("unmarshal gateway .meta: %v", err)
	}
	if meta.RecordingMode != "exec" {
		t.Fatalf("gateway .meta RecordingMode = %q, want %q", meta.RecordingMode, "exec")
	}
	if detectRecordingMode(gwMetaBytes) != "exec" {
		t.Fatalf("detectRecordingMode(gateway .meta) = %q, want %q", detectRecordingMode(gwMetaBytes), "exec")
	}
}

// TestIAMT209_PTYRecordingFetchedViaAdmin is the canary's mirror:
// the terminal branch (cast/txt) must still work end-to-end, with
// .meta appended. This is the path IAMT-209 did NOT change, so the
// test asserts "no regression" — if a future edit accidentally
// routes terminal recordings to the exec branch, this goes red.
//
// Canary: in fetchRecordingViaAdmin, force the branch to "exec"
// regardless of meta. The terminal recording is now fetched as
// .exec.jsonl, the gateway answers E_NOT_FOUND, and the test goes
// red on the t.Fatalf in downloadPart.
func TestIAMT209_PTYRecordingFetchedViaAdmin(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)

	// Drive a PTY session — same as recordOneSession in
	// iamt169_recordings_list_test.go.
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	acc := drain(hs.ch)
	if _, err := hs.ch.Write([]byte("IAMT209-PTY-INPUT")); err != nil {
		t.Fatalf("write pty input: %v", err)
	}
	if !waitContains(t, acc, "IAMT209-PTY-INPUT", 3*1e9) {
		t.Fatalf("echo back: %q", acc.get())
	}
	_ = client.Close()

	// Wait for finalize.
	//
	// IAMT-321: this wait went red once on its 10s guard and never again.
	// Investigated and left as is — there is no race here to fix. The wait
	// already synchronizes on the event itself: recordings.list walks the
	// recording directory fresh on every call (scanRecordings), and the PTY
	// recording only becomes visible when the recorder's finalize writes
	// .meta — once, with BytesOut already set — so a partial meta is
	// skipped, never misread, and once the condition can hold it stays
	// holdable. Nothing in the test sleeps through the wait. The 10s is
	// waitUntil's shared backstop, sized from the one previously observed
	// stall of this exact chain (IAMT-169: finalization blew 3s under a
	// full-suite run, hence 10s); the single red was the same class, worse
	// case — a loaded VM stretched session teardown plus finalize's
	// sync/hash/write past 10s once. Raising the guard further would be the
	// same guess, slower to fail.
	var recList []admin.RecordingView
	// 50 ms between polls, not waitUntil's shared 2 ms (IAMT-404).
	//
	// This wait is not cheap to evaluate: every poll is an admin dial, an
	// SSH round trip and a fresh walk of the recording directory. At 2 ms
	// that is five hundred of them per second, aimed at the very gateway
	// whose finalize this test is waiting for -- the wait starves the work
	// it waits on, and the more loaded the host, the worse the starvation.
	// That is why this one kept going red only in full parallel runs and
	// never alone, three times on 20.09.2026 and once before (IAMT-321),
	// and why raising the 10 s guard would have been the wrong fix: the
	// deadline was never the problem, the polling was.
	//
	// 50 ms costs at most 50 ms of extra latency on a wait that normally
	// settles in tens of milliseconds, and takes the poll load down by a
	// factor of twenty-five.
	//
	// IAMT-503 found the real cause of the reds: not the wait at all. On
	// Windows the recorder's final .meta replace was refused whenever this
	// very poll held the old .meta open for reading, and the recording
	// kept its start-of-session meta for good -- "bytesOut=0" below. The
	// replace now waits out a reader (internal/datafile, replaceEntry);
	// the last observation stays in the message so a red here says which
	// of the three it was.
	var last string
	defer func() {
		if t.Failed() {
			t.Logf("last recordings.list observation: %s", last)
		}
	}()
	waitUntilEvery(t, 10*time.Second, 50*time.Millisecond, "recordings.list never settled on the PTY recording", func() bool {
		l, lerr := root.RecordingsList(f.machineID, "", "")
		switch {
		case lerr != nil:
			last = "error: " + lerr.Error()
		case len(l) != 1:
			last = fmt.Sprintf("%d recordings", len(l))
		case l[0].BytesOut <= 0:
			last = fmt.Sprintf("bytesOut=%d", l[0].BytesOut)
		default:
			recList = l
			return true
		}
		return false
	})

	// Fetch.
	outDir := t.TempDir()
	written := fetchRecordingViaAdmin(t, root, recList[0].ID, outDir)
	wantNames := []string{recList[0].ID + ".cast", recList[0].ID + ".txt", recList[0].ID + ".meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("PTY fetch wrote %d files (%v), want exactly %v", len(written), written, wantNames)
	}
	for i, n := range wantNames {
		if filepath.Base(written[i]) != n {
			t.Fatalf("written[%d] = %q, want basename %q", i, filepath.Base(written[i]), n)
		}
	}

	// The downloaded .txt must echo back the marker we wrote.
	txtBytes, err := os.ReadFile(filepath.Join(outDir, recList[0].ID+".txt"))
	if err != nil {
		t.Fatalf("read downloaded .txt: %v", err)
	}
	if !strings.Contains(string(txtBytes), "IAMT209-PTY-INPUT") {
		t.Fatalf("downloaded .txt does not echo back the marker: %q", txtBytes)
	}
}
