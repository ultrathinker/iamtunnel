package winkeys

import "fmt"

// LinkedPathRefusalError is the refusal to lock down an object that is
// itself a link, or a directory its path reaches through one (R2-CX
// F-12): a junction, a symbolic link or a mounted folder. A lockdown
// holds the object the path led to when it was opened; whoever may
// repoint the link decides what the same path means afterwards, and
// the writes that follow go by the path. Platform-neutral, like
// ForeignOwnerRefusalError, so callers can recognise it with errors.As
// on every build.
type LinkedPathRefusalError struct {
	Path string
	// Resolved is where the path really led, when it went through a
	// link above the object; empty when the object itself is the link.
	Resolved string
}

func (e *LinkedPathRefusalError) Error() string {
	if e.Resolved == "" {
		return fmt.Sprintf("%s is a link (a junction, a symbolic link or a mounted folder), not the directory or file itself - give its real path", e.Path)
	}
	return fmt.Sprintf("%s is reached through a link (a junction, a symbolic link or a mounted folder) and is really %s - "+
		"whoever may repoint that link could send what is written there elsewhere; give the real path", e.Path, e.Resolved)
}
