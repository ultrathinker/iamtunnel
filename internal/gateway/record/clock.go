package record

import (
	"sync"
	"time"
)

// Clock provides current time. It allows injecting deterministic time sources
// into recorders and rotation managers without relying on global variables or env.
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using system wall-clock time.
type RealClock struct{}

// Now returns the current system time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// SimClock provides a thread-safe deterministic clock for testing.
type SimClock struct {
	mu  sync.RWMutex
	now time.Time
}

// NewSimClock creates a SimClock initialized to the given time.
func NewSimClock(t time.Time) *SimClock {
	return &SimClock{now: t}
}

// Now returns the simulated current time.
func (c *SimClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Set sets the simulated current time.
func (c *SimClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Add advances the simulated current time by duration d and returns the new time.
func (c *SimClock) Add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}
