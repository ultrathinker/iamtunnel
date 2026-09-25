//go:build !windows

package main

// The program's folder and who may change it are a Windows question here
// (IAMT-445, exe_acl_windows.go): these are its no-op halves for the
// platforms where server install and the window reach none of it.

func lockProgramHome(dir, exe string) error { return nil }

func secureLogonTaskExe(s *streams, path, exe string) error { return nil }
