package main

// r4_f13_docs_commands_test.go — R4 F-13 (and the cheap half of P-05).
//
// RUNBOOK §4.3 — the procedure an admin follows when the gateway key is
// suspected stolen, the worst moment to find a broken step — told them to
// run "admin machines invite" (no such verb: it is "machines enrol-code
// <name>") and to paste strings with a "#SHA256:" fingerprint (the parser
// refuses the prefix). Gate 15 compares the command lists of the client,
// the CLI usage and the gateway, but not the documents. This test does:
// every "iamtunnel admin <group> <verb>" the docs name must be a verb the
// admin help lists, and no sample string may carry the SHA256: prefix.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func r4f13AdminVerbs() map[string]map[string]bool {
	verbs := map[string]map[string]bool{}
	line := regexp.MustCompile(`^  ([a-z]+) ([a-z][a-z-]*(?: \| [a-z][a-z-]*)*)`)
	for _, l := range strings.Split(adminHelp, "\n") {
		m := line.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if verbs[m[1]] == nil {
			verbs[m[1]] = map[string]bool{}
		}
		for _, v := range strings.Split(m[2], " | ") {
			verbs[m[1]][v] = true
		}
	}
	return verbs
}

func TestR4F13_TheDocsNameOnlyAdminVerbsThatExist(t *testing.T) {
	verbs := r4f13AdminVerbs()
	if !verbs["machines"]["enrol-code"] || !verbs["people"]["connection-string"] {
		t.Fatalf("could not read the admin verbs from adminHelp: %v", verbs)
	}
	use := regexp.MustCompile("admin ([a-z]+) ([a-z][a-z-]*)")
	prefixed := regexp.MustCompile(`iamtunnel(?:-enrol)?://[^ "]*#SHA256:`)
	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no docs found: %v", err)
	}
	var bad []string
	for _, doc := range docs {
		raw, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for i, l := range strings.Split(string(raw), "\n") {
			for _, m := range use.FindAllStringSubmatch(l, -1) {
				group, verb := m[1], m[2]
				if verbs[group] == nil {
					continue // not a verb group: "admin pair", prose
				}
				if !verbs[group][verb] {
					bad = append(bad, filepath.Base(doc)+":"+strconv.Itoa(i+1)+": admin "+group+" "+verb)
				}
			}
			if prefixed.MatchString(l) {
				bad = append(bad, filepath.Base(doc)+":"+strconv.Itoa(i+1)+": sample string with the SHA256: prefix the parser refuses")
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("R4 F-13: the docs tell the admin to run what the CLI does not accept:\n  %s", strings.Join(bad, "\n  "))
	}
}
