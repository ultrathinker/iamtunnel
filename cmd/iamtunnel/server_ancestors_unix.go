//go:build !windows

package main

// server_ancestors_unix.go - the Unix half of the F-04 boundary (R4 F-04):
// the elevated machine commands act on a registration whose every field
// they take from the data directory, so the folders above that directory
// decide whose registration this elevated process really runs.
//
// The catalogue is per-user since 1.4 (SPEC §3.2.2): $XDG_DATA_HOME (or
// $HOME) resolves it, and root's own registration therefore lives under
// /root — a root-owned chain. The hole the review named opens when the
// elevation keeps the INVOKING user's $HOME (sudo -E, older sudo
// configurations, osascript "with administrator privileges"): root then
// reads a chain the invoking non-root account owns outright, and that
// account needs no elevation to plant an enrolment.json there — a record
// naming their gateway, their fingerprint, and any local account as the
// door's osUser. The elevated start dials for it and writes its key into
// that account's authorized_keys.
//
// The rule is the review's own: every folder from the data directory's
// parent up to / must be root's and must not be group- or world-writable
// — anyone who can rename one of them can move the whole chain below away
// and put their own in its place. Plain `sudo` (root's HOME) and the
// service install's /var/lib/iamtunnel-machine both pass; a preserved
// user HOME does not, and the refusal says what to do instead.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// serverDirAncestorCheck is the ancestor check hardenServerDir runs for
// root, as a var so a test can set its world aside: a test's t.TempDir()
// sits under /tmp, which is group- and world-writable by design, so a
// root-uid test process would see the real check refuse the fixture
// rather than the product. The check's own refusals are pinned by the
// F-04 unix tests; what the seam keeps out of the way is only the
// environment.
var serverDirAncestorCheck = refuseServerDirForeignAncestors

// refuseServerDirForeignAncestors walks dir's ancestors and refuses when
// one of them could have been moved by someone other than root. A symlink
// on the way (/tmp on macOS, /var on some layouts) is followed, not
// refused: what decides the rename rights is the directory that actually
// holds the name, and that is the one stat reports.
func refuseServerDirForeignAncestors(dir string) error {
	movers, err := serverDirAncestorMovers(dir)
	if err != nil {
		return envErrf("could not check who can change the folders above the machine data directory %s: %v", dir, err)
	}
	if len(movers) > 0 {
		return deniedErrf("the folders above the machine data directory %s can be moved by %s — the machine commands run elevated and read this registration from there, and whoever renames one of those folders can put their own folders in its place. Register the machine from a plain `sudo` shell (so $HOME is root's), or point --data-dir at a root-owned path the way the service install does (/var/lib/iamtunnel-machine), and repeat.",
			dir, strings.Join(movers, ", "))
	}
	return nil
}

// serverDirAncestorMovers names the folders above dir a non-root account
// can move, empty when the whole chain is root's and closed to group and
// world.
func serverDirAncestorMovers(dir string) ([]string, error) {
	var movers []string
	seen := map[string]bool{}
	for p := filepath.Dir(filepath.Clean(dir)); !seen[p]; p = filepath.Dir(p) {
		seen[p] = true
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if mover := serverDirMover(p, info); mover != "" {
			movers = append(movers, mover)
		}
	}
	return movers, nil
}

// serverDirMover names p as movable by a non-root account when its mode
// or owner says so, empty when it is root's and closed.
func serverDirMover(p string, info os.FileInfo) string {
	if !info.IsDir() {
		return fmt.Sprintf("%s (not a directory)", p)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("%s (group- or world-writable)", p)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("%s (cannot read the owner)", p)
	}
	if stat.Uid != 0 {
		return fmt.Sprintf("%s (owned by uid %d)", p, stat.Uid)
	}
	return ""
}
