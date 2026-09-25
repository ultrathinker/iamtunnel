package main

// IAMT-440 (supplementary round), machines.set-user from the command line: its usage, its
// --help and its "missing argument" line all called the second argument
// <DOMAIN\user>, while a Linux or macOS machine is entered as a local POSIX
// name, which the same command accepts.

import (
	"strings"
	"testing"
)

func TestIAMT440_SetUserHelpDoesNotAskForAWindowsDomainOnly(t *testing.T) {
	out, errs, _ := drive(t, "admin", "machines", "set-user", "--help")
	missingOut, missingErrs, _ := drive(t, "admin", "machines", "set-user")
	usageOut, usageErrs, _ := drive(t, "admin", "--help")
	for name, text := range map[string]string{
		"set-user --help":      out + errs,
		"the missing argument": missingOut + missingErrs,
		"admin usage":          usageOut + usageErrs,
	} {
		if strings.Contains(text, `<DOMAIN\user>`) || !strings.Contains(text, "<os-user>") {
			t.Errorf("%s names the OS user as a Windows account only:\n%s", name, text)
		}
	}
	if !strings.Contains(usageOut+usageErrs, "POSIX") {
		t.Errorf("the admin usage does not say what <os-user> is on Linux and macOS:\n%s", usageOut+usageErrs)
	}
}
