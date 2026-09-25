package client

import "io"

// bridgeFirstThenForward implements the one ordering guarantee "client
// connect" demands: the recording banner is shown before the first
// input — the recording notice (written by the gateway,
// PROTOCOL §4, before it relays a single byte of the target machine)
// must reach the screen before this package forwards a single byte
// the person typed.
//
// It blocks on exactly one Read from fromGateway and writes whatever
// that read produced to screen before starting to forward keyboard input
// at all. Only after that does it bridge both directions concurrently.
// This is deliberately its own function, taking plain io.Reader/io.Writer
// instead of an *ssh.Channel: bridge_test.go exercises the ordering with
// two pipes and no network, so the guarantee cannot regress silently
// behind goroutine scheduling nobody is watching.
//
// It returns when fromGateway is exhausted or errors — that is the
// session's authoritative end (the gateway closes the channel when the
// target session ends, PROTOCOL §4.1); keyboard forwarding running past
// that point would only feed a channel nobody reads from any more.
// io.EOF from fromGateway is a clean end and is returned as nil, matching
// io.Copy's own convention.
func bridgeFirstThenForward(screen io.Writer, fromGateway io.Reader, toGateway io.Writer, keyboard io.Reader) error {
	buf := make([]byte, 32*1024)
	n, rerr := fromGateway.Read(buf)
	if n > 0 {
		if _, werr := screen.Write(buf[:n]); werr != nil {
			return werr
		}
	}
	if rerr != nil {
		if rerr == io.EOF {
			return nil
		}
		return rerr
	}

	go func() {
		_, _ = io.Copy(toGateway, keyboard)
		if cw, ok := toGateway.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	_, err := io.Copy(screen, fromGateway)
	return err
}
