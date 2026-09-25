package main

// The no-GUI build canary (IAMT-439).

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Every file that pulls in the window must carry the !nogui tag.
//
// 23.09.2026, a live install on AWS. The gateway never opens a window,
// but it carried the window's code inside it: on Linux the window talks
// to X11 and Wayland through cgo, the linker lists libEGL, libwayland-*,
// libX11-xcb and four more in NEEDED, and the dynamic loader demands
// them BEFORE main is entered. On a bare Ubuntu Server the very first
// command on a fresh gateway — "iamtunnel version" — died with code 127
// without a single word of ours.
//
// The no-GUI build is a VARIANT, not a second source tree: the same
// files, one tag. It holds up exactly as long as no file with the window
// forgets the tag: a forgotten one pulls internal/ui back into the
// no-GUI build, gio with it, and the variant quietly stops being
// no-GUI — the red shows up not here but on somebody else's server,
// where the binary will not start.
func TestCanary_EveryWindowFileIsTaggedOutOfTheHeadlessBuild(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Tests count, and they are the half that was forgotten first:
		// go vet compiles a package's tests, so one GUI test without the
		// tag drags internal/ui back into the headless vet and the
		// variant stops being checkable at all. This file is skipped by
		// name -- it carries the import path as a string to look for.
		if name == "zz_canary_nogui_test.go" {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(body)
		if !strings.Contains(src, `"github.com/ultrathinker/iamtunnel/internal/ui"`) {
			continue
		}
		line := buildConstraintOf(src)
		if line == "" {
			t.Errorf("%s pulls in internal/ui and has no tag at all — it would land in the no-GUI build and bring the window back into it", name)
			continue
		}
		if !strings.Contains(line, "!nogui") {
			t.Errorf("%s pulls in internal/ui but its tag does not exclude nogui: %q", name, line)
		}
	}
}

// And the converse: the stub that replaces the window must be INCLUDED
// in the no-GUI build. Without this half, the previous test would pass
// on a build that simply does not compile.
func TestCanary_TheHeadlessStubIsBuiltForNogui(t *testing.T) {
	for _, name := range []string{"gui_other.go", "build_nowindow.go"} {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		line := buildConstraintOf(string(body))
		if !strings.Contains(line, "|| nogui") {
			t.Errorf("%s is not part of the no-GUI build (%q) — then it holds neither the window nor its replacement", name, line)
		}
	}
}

// The word naming which build this is gets printed ALWAYS — otherwise
// "which version is on the gateway" becomes a question with two halves,
// and the second half cannot be read from the machine itself.
func TestCanary_VersionSaysWhichBuildItIs(t *testing.T) {
	if strings.TrimSpace(buildVariant) == "" {
		t.Fatal("the build does not name itself in any way")
	}
	var out, errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &out, errs: &errs}
	if code := cmdVersion(s, nil); code != exitOK {
		t.Fatalf("version exited with code %d", code)
	}
	text := out.String()
	if !strings.Contains(text, buildVariant) {
		t.Errorf("version does not print the build variant %q: %q", buildVariant, text)
	}
	// Which variant this is, is decided by the tag the tests themselves
	// were built with: without nogui it is the full build, with it the
	// no-GUI one (R1-CX F-05: the check demanded "full" unconditionally,
	// and an ordinary go test -tags nogui ./... was red on this one
	// build alone). testedVariantWord — in
	// r1cx_f05_variant_{full,headless}_test.go.
	if !strings.Contains(buildVariant, testedVariantWord) {
		t.Errorf("the tests were built as variant %q but the build named itself %q", testedVariantWord, buildVariant)
	}
}

// buildConstraintOf returns the //go:build line of a Go source, or "".
func buildConstraintOf(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build ") {
			return line
		}
		if strings.HasPrefix(line, "package ") {
			return ""
		}
	}
	return ""
}
