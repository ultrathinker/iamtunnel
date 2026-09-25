package record

import (
	"fmt"
	"os"
)

// AbortOrphanedRecordings repairs sessions under dir whose metadata is still
// marked status:"recording" (IAMT-165). The gateway is the single owner and
// writer of recordings: a "recording" meta that is still on disk when a NEW
// gateway process starts is by definition a leftover from a process that died
// (kill -9, power cut) before Close/Abort could finalize it. Such a session is
// never live again, yet Rotate protects "recording" sessions from both age and
// size pruning — so without this repair every crash leaves an immortal
// three-file set on disk (the IAMT-4 review, finding H3, called it a
// self-DoS: garbage accumulates until the 95% refusal threshold locks out new
// sessions).
//
// Each repaired session gets Status "aborted", Aborted true and the supplied
// exitReason; EndedAt and DurationSeconds are deliberately left untouched —
// the repair knows why the session died, not when, and inventing an end
// timestamp would falsify the record rather than complete it.
//
// The return value lists the base paths (path without extension, the same form
// RotateResult.DeletedSessions uses) of every repaired session, so the caller
// can journal one event per session. A walk error is returned, not swallowed:
// the caller must be able to refuse to start on a recordings tree it could not
// repair, instead of silently re-creating the immortal-orphan state.
func AbortOrphanedRecordings(dir, exitReason string) ([]string, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	sessions, err := scanSessions(dir)
	if err != nil {
		return nil, fmt.Errorf("scan recordings: %w", err)
	}

	repaired := make([]string, 0)
	for _, sg := range sessions {
		if sg.status != "recording" {
			continue
		}
		metaPath := sg.basePath + ".meta"
		// scanSessions read this very file a moment ago to learn the status;
		// a read that fails now is real I/O trouble, not a torn leftover.
		meta, err := ReadMeta(metaPath)
		if err != nil {
			return repaired, fmt.Errorf("read orphaned meta %s: %w", metaPath, err)
		}
		meta.Status = "aborted"
		meta.Aborted = true
		meta.ExitReason = exitReason
		if err := WriteMeta(metaPath, meta, 0600); err != nil {
			return repaired, fmt.Errorf("rewrite orphaned meta %s: %w", metaPath, err)
		}
		repaired = append(repaired, sg.basePath)
	}
	return repaired, nil
}
