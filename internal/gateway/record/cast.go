package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// CastHeader represents the JSON header (line 1) of an asciinema v2 (.cast) file.
type CastHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	Command   string            `json:"command,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// CastWriter serializes terminal session events into an asciinema v2 stream.
type CastWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewCastWriter creates a CastWriter writing to w.
func NewCastWriter(w io.Writer) *CastWriter {
	return &CastWriter{w: w}
}

// WriteHeader writes the asciinema v2 header line.
func (c *CastWriter) WriteHeader(h CastHeader) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if h.Version == 0 {
		h.Version = 2
	}

	data, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("marshal cast header: %w", err)
	}

	data = append(data, '\n')
	_, err = c.w.Write(data)
	return err
}

// WriteEvent writes a single event entry [time, type, data] as a JSON line.
// In accordance with SPEC §6.5, input events ('i') are strictly prohibited
// to ensure typed passwords never reach the recording.
func (c *CastWriter) WriteEvent(t float64, eventType string, data string) error {
	if eventType == "i" {
		return errors.New("recording incoming stream ('i') is strictly prohibited by SPEC §6.5")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := []any{t, eventType, data}
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal cast event: %w", err)
	}

	b = append(b, '\n')
	_, err = c.w.Write(b)
	return err
}

// WriteOutput writes an "o" (stdout) event.
func (c *CastWriter) WriteOutput(t float64, data []byte) error {
	return c.WriteEvent(t, "o", string(data))
}

// WriteResize writes an "r" (window change) event in "WxH" format.
func (c *CastWriter) WriteResize(t float64, width, height int) error {
	return c.WriteEvent(t, "r", fmt.Sprintf("%dx%d", width, height))
}
