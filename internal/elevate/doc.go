// Package elevate handles the UAC relaunch dance for the server
// role on Windows (SPEC §3.2). It does not own the door, the
// gateway, or the SSH protocol — only the elevation primitive the
// server role uses to get an admin token at startup. Linux is
// not in 1.0 (SPEC §12); on non-Windows, Relaunch returns an
// error and IsElevated returns false.
//
// The elevation primitive is intentionally narrow:
//
//   - IsElevated reports whether the current process is running
//     with the elevated token. A single CheckTokenMembership +
//     well-known SID lookup — no logon session machinery, no
//     logonuser calls, no impersonation.
//   - RelaunchElevated shells the current process out via
//     ShellExecuteEx with lpVerb="runas" so the user sees the
//     standard UAC consent prompt. If the user accepts, the
//     process restarts itself with the elevated token. The
//     caller passes a wait boolean: with wait=true the function
//     returns when the elevated child exits; with wait=false it
//     returns immediately after the child starts and the
//     original (non-elevated) process is responsible for
//     exiting. The server role uses wait=false.
//   - WhenRelaunchedAlreadyDone is the flag-and-prefix pattern
//     the child uses to detect "this process was just started
//     from the elevated parent — don't loop forever". The
//     parent sets the parent's PID into the child's argv with
//     this prefix; the child, on detecting it, makes no second
//     relaunch.
//
// There is no env-var kill switch, no exported setter that
// disables elevation, and no build tag that swaps a real impl
// for a test stub. The UAC consent prompt is part of the
// Windows security model; the package never silently bypasses
// it.
package elevate
