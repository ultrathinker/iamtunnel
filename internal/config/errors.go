package config

import "fmt"

// Class is the user-facing error class; the value is the process exit
// code the CLI prints and exits with (see "iamtunnel help codes" and the
// top-level usage): 2 the invocation or a value is wrong, 3 the
// environment is broken (config file content, missing source), 4 the OS
// denies access to a configured path.
type Class int

const (
	ClassUser   Class = 2
	ClassEnv    Class = 3
	ClassDenied Class = 4
)

// Error is a classified configuration error. The CLI maps Class onto the
// exit code; the message is written for the person reading it when
// something does not work: what is wrong and what to do.
type Error struct {
	Class Class
	Msg   string
}

func (e *Error) Error() string { return e.Msg }

func userErrorf(format string, a ...any) *Error {
	return &Error{Class: ClassUser, Msg: fmt.Sprintf(format, a...)}
}

func envErrorf(format string, a ...any) *Error {
	return &Error{Class: ClassEnv, Msg: fmt.Sprintf(format, a...)}
}

func deniedErrorf(format string, a ...any) *Error {
	return &Error{Class: ClassDenied, Msg: fmt.Sprintf(format, a...)}
}
