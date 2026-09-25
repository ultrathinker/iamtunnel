package client

import (
	"io"
	"sync"
)

// terminalSize is deliberately kept local to the client: SSH payloads are
// built only at the point where a size change is sent.
type terminalSize struct {
	cols uint32
	rows uint32
}

// localTerminal is an ownership token. Connect obtains it before doing any
// network work and owns restoring it on every return path, including panic.
// It is not configurable by callers.
type localTerminal interface {
	restore() error
	size() (terminalSize, bool)
}

type terminalOpener func(io.Reader, io.Writer) (localTerminal, error)

type inertTerminal struct{}

func (inertTerminal) restore() error             { return nil }
func (inertTerminal) size() (terminalSize, bool) { return terminalSize{}, false }

// closeOnceTerminal makes restoration idempotent. Apart from protecting the
// deferred cleanup, this keeps a failed setup from ever leaving half-applied
// console state behind. It is package-local because both Windows and Unix
// terminals share the same idempotency requirement; only the body of fn
// changes per platform.
type closeOnceTerminal struct {
	once sync.Once
	fn   func() error
	err  error
}

func (t *closeOnceTerminal) restore() error {
	t.once.Do(func() { t.err = t.fn() })
	return t.err
}
