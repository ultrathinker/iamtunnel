//go:build !windows

package main

import "errors"

// The anchor's Windows half, stubbed where there is no Windows: the
// runtime.GOOS dispatch in machine_anchor.go never reaches these on this
// platform (writeMachineEnrolmentAnchor returns before the call, the
// readers report a missing anchor first), and the headless Linux build
// compiles the package whole. Nothing calls this.
func writeMachineEnrolmentAnchorWindows(map[string]string, gatewayRecord) error {
	return errors.New("the enrolment anchor exists on Windows only")
}

func readMachineEnrolmentAnchorWindows(map[string]string) (enrolmentAnchor, error) {
	return enrolmentAnchor{}, errors.New("the enrolment anchor exists on Windows only")
}

func anchorTreeName(map[string]string) string {
	return "%ProgramData%\\iamtunnel\\machine\\<SID>"
}
