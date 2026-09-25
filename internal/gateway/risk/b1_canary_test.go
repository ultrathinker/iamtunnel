package risk

import "testing"

// These are security canaries for B1. They intentionally verify the
// multi-path cases that must not regress to a green verdict.
func TestCanary_B1_RMDangerousChecksEveryPath(t *testing.T) {
	got := Classify("rm -rf /tmp/x /var/lib/postgresql")
	if got.Level != Red {
		t.Fatalf("rm multi-path canary: level=%s rule=%q reason=%q; want red", got.Level, got.Rule, got.Reason)
	}
	if got.Rule != "rm-recursive-outside-temp" {
		t.Fatalf("rm multi-path canary: rule=%q; want rm-recursive-outside-temp", got.Rule)
	}
}

func TestCanary_B1_RemoveItemChecksEveryPath(t *testing.T) {
	got := Classify(`Remove-Item -Recurse -Force C:\Temp\x C:\Users\me\Documents`)
	if got.Level != Red {
		t.Fatalf("Remove-Item multi-path canary: level=%s rule=%q reason=%q; want red", got.Level, got.Rule, got.Reason)
	}
	if got.Rule != "remove-item-recursive-outside-temp" {
		t.Fatalf("Remove-Item multi-path canary: rule=%q; want remove-item-recursive-outside-temp", got.Rule)
	}
}
