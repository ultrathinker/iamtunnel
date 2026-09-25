package record

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RotateConfig specifies retention rules for recorded sessions.
//
// The two size knobs mean different things (IAMT-171, PROTOCOL §8):
//
//   - MaxTotalBytesPercent is the production form. It is a threshold on the
//     FULLNESS OF THE FILESYSTEM holding cfg.Dir (used/total, the exact
//     quantity DiskStats.UsedPercent reports and the 95% refusal check in
//     ShouldRefuseNewRecording consults). Rotate deletes the oldest
//     completed sessions until that fullness drops below the percent,
//     re-reading the stats after every deletion. It is NOT a ceiling on the
//     recordings' own bytes: a disk filled by other data must trigger
//     rotation too, otherwise refusal at 95% would fire before rotation at
//     85% ever freed anything.
//   - MaxTotalBytes is the deterministic form: an absolute ceiling on the
//     sum of the recordings' own bytes, for callers (and tests) that want a
//     byte-exact cap without faking disk stats.
//
// When both are set the byte form wins, so a caller cannot accidentally run
// both loops.
type RotateConfig struct {
	Dir                  string
	MaxAge               time.Duration
	MaxTotalBytes        int64
	MaxTotalBytesPercent int // 0..100. When > 0, prune until cfg.Dir's filesystem is fuller than this percent. 0 disables.
	Clock                Clock
}

// RotateResult summarizes the actions taken by Rotate.
type RotateResult struct {
	DeletedSessions        []string
	BytesFreed             int64
	RemainingSessions      int
	RemainingBytes         int64
	OversizedSingleSession bool
	// DiskStillOverThreshold reports that size-based pruning stopped with
	// the filesystem still at or above MaxTotalBytesPercent — either every
	// remaining session is protected ("recording") or only the never-wipe
	// newest one was left. Deleting recordings cannot fix a disk that other
	// data fills; the flag lets the caller report that instead of looping.
	DiskStillOverThreshold bool
}

type sessionGroup struct {
	basePath  string
	files     []string
	totalSize int64
	startedAt time.Time
	status    string
}

// Rotate scans cfg.Dir for recorded sessions and prunes them according to
// age and size limits. All files (.cast, .txt, .meta) belonging to
// a deleted session are removed together.
//
// The size step has two forms; see RotateConfig. The percent form measures
// the filesystem fullness of cfg.Dir through the same disk-stats seam the
// refusal check uses, re-reading it after every deletion rather than
// assuming a deletion moved the number.
func Rotate(cfg RotateConfig) (RotateResult, error) {
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}

	result := RotateResult{
		DeletedSessions: make([]string, 0),
	}

	if _, err := os.Stat(cfg.Dir); os.IsNotExist(err) {
		return result, nil
	}

	sessions, err := scanSessions(cfg.Dir)
	if err != nil {
		return result, fmt.Errorf("scan recordings: %w", err)
	}

	now := cfg.Clock.Now()

	// 1. Prune by age
	var remaining []*sessionGroup
	if cfg.MaxAge > 0 {
		cutoff := now.Add(-cfg.MaxAge)
		for _, s := range sessions {
			// Never delete sessions that are actively being recorded
			if s.status == "recording" {
				remaining = append(remaining, s)
				continue
			}

			if s.startedAt.Before(cutoff) {
				freed, err := deleteSession(s, cfg.Dir)
				if err != nil {
					return result, fmt.Errorf("delete expired session %s: %w", s.basePath, err)
				}
				result.DeletedSessions = append(result.DeletedSessions, s.basePath)
				result.BytesFreed += freed
			} else {
				remaining = append(remaining, s)
			}
		}
	} else {
		remaining = sessions
	}

	// Calculate total size of remaining sessions
	var totalBytes int64
	for _, s := range remaining {
		totalBytes += s.totalSize
	}

	// 2. Prune by total size
	if cfg.MaxTotalBytes > 0 && totalBytes > cfg.MaxTotalBytes {
		var candidates []*sessionGroup
		var protectedActive []*sessionGroup
		for _, s := range remaining {
			if s.status == "recording" {
				protectedActive = append(protectedActive, s)
			} else {
				candidates = append(candidates, s)
			}
		}

		// Sort candidates by StartedAt ascending (oldest first)
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].startedAt.Before(candidates[j].startedAt)
		})

		var keptCandidates []*sessionGroup
		for i, s := range candidates {
			if totalBytes <= cfg.MaxTotalBytes {
				keptCandidates = append(keptCandidates, candidates[i:]...)
				break
			}

			// Check if this single session exceeds the entire limit
			if s.totalSize > cfg.MaxTotalBytes {
				result.OversizedSingleSession = true
			}

			// Invariant: NEVER wipe the archive to 0!
			// The newest/last candidate must be preserved if there are no other (active) sessions.
			if len(keptCandidates) == 0 && len(protectedActive) == 0 && i == len(candidates)-1 {
				keptCandidates = append(keptCandidates, s)
				result.OversizedSingleSession = true
				break
			}

			freed, err := deleteSession(s, cfg.Dir)
			if err != nil {
				return result, fmt.Errorf("delete oversized session %s: %w", s.basePath, err)
			}
			result.DeletedSessions = append(result.DeletedSessions, s.basePath)
			result.BytesFreed += freed
			totalBytes -= freed
		}
		remaining = append(keptCandidates, protectedActive...)
	}

	// 3. Prune by disk fullness percent (IAMT-171, PROTOCOL §8). The percent
	// is a threshold on how full the FILESYSTEM holding cfg.Dir is — the same
	// quantity the 95% refusal check measures — not a ceiling on the
	// recordings' own bytes. Delete the oldest completed sessions one at a
	// time and re-read the stats after each deletion: a disk filled by other
	// data stays over the threshold no matter what is deleted, and that fact
	// must be measured, not assumed. Skipped when the byte form ran.
	if cfg.MaxTotalBytesPercent > 0 && cfg.MaxTotalBytes <= 0 {
		var candidates []*sessionGroup
		var protectedActive []*sessionGroup
		for _, s := range remaining {
			if s.status == "recording" {
				protectedActive = append(protectedActive, s)
			} else {
				candidates = append(candidates, s)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].startedAt.Before(candidates[j].startedAt)
		})

		var kept []*sessionGroup
		for {
			stats, err := diskStatsFor(cfg.Dir)
			if err != nil {
				return result, fmt.Errorf("read disk stats for %s: %w", cfg.Dir, err)
			}
			if stats.UsedPercent() < cfg.MaxTotalBytesPercent {
				kept = append(kept, candidates...)
				break
			}
			if len(candidates) == 0 {
				// Nothing deletable is left and the disk is still over the
				// threshold: report it and stop instead of looping.
				result.DiskStillOverThreshold = true
				break
			}
			// Invariant: NEVER wipe the archive to 0! The newest/last
			// candidate must be preserved if there are no other (active)
			// sessions — deleting everything would not fix a disk that other
			// data fills, it would only destroy the audit trail.
			if len(kept) == 0 && len(protectedActive) == 0 && len(candidates) == 1 {
				kept = append(kept, candidates[0])
				result.DiskStillOverThreshold = true
				break
			}
			s := candidates[0]
			candidates = candidates[1:]
			freed, err := deleteSession(s, cfg.Dir)
			if err != nil {
				return result, fmt.Errorf("delete oversized session %s: %w", s.basePath, err)
			}
			result.DeletedSessions = append(result.DeletedSessions, s.basePath)
			result.BytesFreed += freed
			totalBytes -= freed
		}
		remaining = append(kept, protectedActive...)
	}

	result.RemainingSessions = len(remaining)
	result.RemainingBytes = totalBytes

	// Check if any remaining session individually exceeds limit
	if cfg.MaxTotalBytes > 0 {
		for _, s := range remaining {
			if s.totalSize > cfg.MaxTotalBytes {
				result.OversizedSingleSession = true
				break
			}
		}
	}

	return result, nil
}

func scanSessions(rootDir string) ([]*sessionGroup, error) {
	groupMap := make(map[string]*sessionGroup)

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		basePath := ""
		switch {
		case strings.HasSuffix(path, ".exec.jsonl"):
			basePath = strings.TrimSuffix(path, ".exec.jsonl")
		case ext == ".cast" || ext == ".txt" || ext == ".meta":
			basePath = strings.TrimSuffix(path, ext)
		default:
			return nil
		}
		sg, ok := groupMap[basePath]
		if !ok {
			sg = &sessionGroup{
				basePath: basePath,
			}
			groupMap[basePath] = sg
		}
		sg.files = append(sg.files, path)

		info, err := d.Info()
		if err == nil {
			sg.totalSize += info.Size()
			if sg.startedAt.IsZero() || info.ModTime().Before(sg.startedAt) {
				sg.startedAt = info.ModTime()
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// For each session, parse .meta if available to get accurate StartedAt and Status
	sessions := make([]*sessionGroup, 0, len(groupMap))
	for _, sg := range groupMap {
		metaPath := sg.basePath + ".meta"
		meta, err := ReadMeta(metaPath)
		if err == nil {
			if !meta.StartedAt.IsZero() {
				sg.startedAt = meta.StartedAt
			}
			sg.status = meta.Status
		}
		sessions = append(sessions, sg)
	}

	return sessions, nil
}

func deleteSession(sg *sessionGroup, rootDir string) (int64, error) {
	var freed int64
	for _, f := range sg.files {
		info, err := os.Stat(f)
		if err == nil {
			freed += info.Size()
		}
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return freed, err
		}
	}

	cleanEmptyDirs(filepath.Dir(sg.basePath), rootDir)

	return freed, nil
}

// cleanEmptyDirs cleans empty subdirectories upward, stopping at rootDir without deleting rootDir itself.
//
// The listing and the removal go through os.Root opened at rootDir
// (IAMT-333, closes the walk residual audit §3.4 deferred): every level
// is listed and removed by a name resolved against the one held root
// directory, never by an absolute path re-resolved from the top - a swap
// of a directory's entry on the way cannot aim the cleanup at another
// subtree, and a name that leads outside rootDir is refused rather than
// resolved. rootDir itself is never removed: the climb stops when the
// relative name is exhausted, and the Root is never handed "." to Remove.
func cleanEmptyDirs(dir, rootDir string) {
	if rootDir == "" {
		return
	}
	cleanRoot := filepath.Clean(rootDir)
	rel, err := filepath.Rel(cleanRoot, filepath.Clean(dir))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// At or above rootDir: STOP! NEVER remove rootDir or anything above it!
		return
	}
	root, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return
	}
	defer root.Close()

	cur := filepath.ToSlash(rel)
	for {
		entries, err := fs.ReadDir(root.FS(), cur)
		if err != nil || len(entries) > 0 {
			return
		}
		if err := root.Remove(cur); err != nil {
			return
		}
		parent := filepath.Dir(cur)
		if parent == cur || parent == "." {
			// At or above rootDir: NEVER remove rootDir itself.
			return
		}
		cur = parent
	}
}
