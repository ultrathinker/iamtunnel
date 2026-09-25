//go:build !windows

package main

import "testing"

// The enrolment anchor is Windows' alone (machine_anchor.go); the tests
// that mention it compile everywhere and relax nothing here.
func relaxAnchorAncestorCheck(t *testing.T) { t.Helper() }

func seedEnrolmentAnchor(t *testing.T, env map[string]string, dir string) { t.Helper() }
