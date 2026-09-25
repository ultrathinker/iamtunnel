//go:build !windows

package main

// attachParentConsole is a Windows concern: only there is a program
// linked for a subsystem that decides whether it gets a console.
func attachParentConsole() {}
