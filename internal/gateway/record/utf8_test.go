package record

import (
	"os"
	"strings"
	"testing"
)

func TestUTF8SplitAcrossChunks(t *testing.T) {
	vt := NewVT(80, 24)

	// A Russian "Hello, world! 🚀" greeting
	// Cyrillic 'P' (U+041F) is 2 bytes: 0xD0 0x9F
	// '🚀' (rocket) is 4 bytes: 0xF0 0x9F 0x99 0x80
	// '世' is 3 bytes: 0xE4 0xB8 0x96

	// Chunk 1 ends with the first byte of the Cyrillic 'P' (0xD0)
	chunk1 := []byte{0xD0}
	// Chunk 2 has the second byte of the Cyrillic 'P' (0x9F) plus ASCII and first 2 bytes of '世' (0xE4, 0xB8)
	chunk2 := []byte{0x9F, ' ', 0xE4, 0xB8}
	// Chunk 3 has the 3rd byte of '世' (0x96) and first 3 bytes of rocket (0xF0, 0x9F, 0x9A)
	chunk3 := []byte{0x96, ' ', 0xF0, 0x9F, 0x9A}
	// Chunk 4 has the 4th byte of rocket (0x80) and exclamation
	chunk4 := []byte{0x80, '!'}

	chunks := [][]byte{chunk1, chunk2, chunk3, chunk4}
	for i, chunk := range chunks {
		if _, err := vt.Write(chunk); err != nil {
			t.Fatalf("Write chunk %d failed: %v", i, err)
		}
	}
	vt.Flush()

	expected := "\u041f 世 🚀!"
	actual := vt.Transcript()
	if actual != expected {
		t.Fatalf("expected UTF-8 decoded %q, got %q", expected, actual)
	}

	if strings.ContainsRune(actual, '\uFFFD') {
		t.Fatalf("found Unicode replacement character (garbage) in output: %q", actual)
	}
}

func TestUTF8MultiChunkSplits(t *testing.T) {
	// Feed a full Russian sentence 1 byte at a time through Recorder
	sentence := "\u0428\u043b\u044e\u0437 iamtunnel \u0443\u0441\u043f\u0435\u0448\u043d\u043e \u0437\u0430\u043f\u0438\u0441\u044b\u0432\u0430\u0435\u0442 \u0441\u0435\u0441\u0441\u0438\u044e \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u0442 \u043f\u0440\u0430\u0432\u0430 \u0434\u043e\u0441\u0442\u0443\u043f\u0430."
	sentenceBytes := []byte(sentence)

	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "win-srv-01",
		Person:    "ivan",
		SessionID: "utf8-byte-by-byte",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	// Write 1 byte at a time
	for i := 0; i < len(sentenceBytes); i++ {
		clock.Add(timeStep)
		_, err := rec.Write(sentenceBytes[i : i+1])
		if err != nil {
			t.Fatalf("Write byte %d failed: %v", i, err)
		}
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("rec.Close failed: %v", err)
	}

	// Read generated .txt file
	txtData, err := os.ReadFile(rec.Paths().TxtPath)
	if err != nil {
		t.Fatalf("read txt file failed: %v", err)
	}

	actualTxt := string(txtData)
	if actualTxt != sentence {
		t.Fatalf("expected %q, got %q", sentence, actualTxt)
	}

	if strings.ContainsRune(actualTxt, '\uFFFD') {
		t.Fatalf("found corrupted runes in 1-byte feed: %q", actualTxt)
	}

	// Read generated .cast file
	castData, err := os.ReadFile(rec.Paths().CastPath)
	if err != nil {
		t.Fatalf("read cast file failed: %v", err)
	}

	castStr := string(castData)
	if strings.ContainsRune(castStr, '\uFFFD') {
		t.Fatalf("found corrupted runes in .cast file: %s", castStr)
	}
}
