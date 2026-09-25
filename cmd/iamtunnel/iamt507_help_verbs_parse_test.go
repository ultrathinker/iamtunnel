package main

// iamt507_help_verbs_parse_test.go — IAMT-507.
//
// The admin help listed "goal list" and admin_exec.go carried its case,
// but adminVerbs never registered the verb, so "admin goal list" died
// with "unknown verb". R4 F-13 checks the docs against the help; this
// checks the help against the table the parser actually reads.

import (
	"sort"
	"strings"
	"testing"
)

func TestIAMT507_EveryVerbTheHelpListsIsRegistered(t *testing.T) {
	var missing []string
	for group, verbs := range r4f13AdminVerbs() {
		registered, ok := adminVerbs[group]
		if !ok {
			continue // a verb-less command like "claim"
		}
		for verb := range verbs {
			if _, ok := registered[verb]; !ok {
				missing = append(missing, group+" "+verb)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("the admin help lists verbs the parser refuses as unknown: %s", strings.Join(missing, ", "))
	}
}
