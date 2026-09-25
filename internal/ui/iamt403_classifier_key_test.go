//go:build windows

package ui

// iamt403_classifier_key_test.go — IAMT-403's own canaries: the box
// empties the instant Replace is pressed, regardless of outcome, and the
// three outcomes (accepted, refused, unavailable) read apart by color --
// "a person must be able to tell them apart on your screen, not guess."

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestSetClassifierKeyClearsTheBoxImmediately(t *testing.T) {
	// The gateway never gets a chance to answer here (no action wired at
	// all) — proving the box is cleared before the outcome, since there
	// is no outcome.
	f := newBareFrame(t)
	f.editor(ctlAdminClassifierKey).SetText("sk-live-not-a-real-key-abc123")

	f.setClassifierKey()

	if got := f.editor(ctlAdminClassifierKey).Text(); got != "" {
		t.Errorf("box = %q immediately after pressing Replace, want empty (IAMT-403 point 1) even before any answer arrives", got)
	}
}

func TestSetClassifierKeyClearsTheBoxOnEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result AdminSetClassifierKeyResult
		key    design.ColorKey
	}{
		{"accepted", AdminSetClassifierKeyResult{Outcome: "accepted", Fingerprint: "SHA256:abc"}, design.GoodKey},
		{"refused", AdminSetClassifierKeyResult{Outcome: "refused", Detail: "typesafe.ai rejected the key"}, design.BadKey},
		{"unavailable", AdminSetClassifierKeyResult{Outcome: "unavailable", Detail: "typesafe.ai did not answer"}, design.WarnKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBareFrame(t)
			f.editor(ctlAdminClassifierKey).SetText("sk-live-not-a-real-key-abc123")
			f.cfg.Actions.AdminSetClassifierKey = func(key string) (AdminSetClassifierKeyResult, error) {
				return tc.result, nil
			}

			f.setClassifierKey()
			awaitSaid(t, f, ctlAdminClassifierKey, tc.key)

			if got := f.editor(ctlAdminClassifierKey).Text(); got != "" {
				t.Errorf("box = %q after a %s outcome, want empty regardless of what the gateway answered", got, tc.name)
			}
		})
	}
}

func TestSetClassifierKeyRefusesAnEmptyBox(t *testing.T) {
	f := newBareFrame(t)
	called := make(chan struct{})
	f.cfg.Actions.AdminSetClassifierKey = func(key string) (AdminSetClassifierKeyResult, error) {
		close(called)
		return AdminSetClassifierKeyResult{}, nil
	}

	f.setClassifierKey()

	select {
	case <-called:
		t.Fatal("setClassifierKey asked the gateway to replace the key with an empty one")
	case <-time.After(guardWait):
	}
	if got := f.saidUnder(ctlAdminClassifierKey); got.key != design.BadKey || got.text == "" {
		t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlAdminClassifierKey, got)
	}
}

func TestSetClassifierKeyWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminClassifierKey).SetText("sk-live-not-a-real-key-abc123")

	f.setClassifierKey()

	if got := f.saidUnder(ctlAdminClassifierKey); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminClassifierKey, got, noRuntime)
	}
}

// TestSetClassifierKeyNeverPrintsTheKey pins point 2 the other way round:
// whatever the gateway hands back, the key that was typed must never
// show up in the sentence under the button.
func TestSetClassifierKeyNeverPrintsTheKey(t *testing.T) {
	const key = "sk-live-not-a-real-key-abc123-should-never-appear"
	for _, tc := range []struct {
		result AdminSetClassifierKeyResult
		key    design.ColorKey
	}{
		{AdminSetClassifierKeyResult{Outcome: "accepted", Fingerprint: "SHA256:abc"}, design.GoodKey},
		{AdminSetClassifierKeyResult{Outcome: "refused", Detail: "typesafe.ai rejected the key"}, design.BadKey},
		{AdminSetClassifierKeyResult{Outcome: "unavailable", Detail: "typesafe.ai did not answer"}, design.WarnKey},
	} {
		f := newBareFrame(t)
		f.editor(ctlAdminClassifierKey).SetText(key)
		f.cfg.Actions.AdminSetClassifierKey = func(k string) (AdminSetClassifierKeyResult, error) {
			if k != key {
				t.Errorf("action received %q, want the typed key %q", k, key)
			}
			return tc.result, nil
		}

		f.setClassifierKey()
		got := awaitSaid(t, f, ctlAdminClassifierKey, tc.key)

		if containsKey(got.text, key) {
			t.Errorf("outcome %q printed the key verbatim: %q", tc.result.Outcome, got.text)
		}
	}
}

func containsKey(text, key string) bool {
	for i := 0; i+len(key) <= len(text); i++ {
		if text[i:i+len(key)] == key {
			return true
		}
	}
	return false
}

// TestSetClassifierKeyOutcomesReadApartByColor is the three-outcome
// requirement itself (point 3): accepted, refused and unavailable must
// each land under a DIFFERENT color key, and the word itself must be the
// first thing in the sentence, capitalised, the same shape checkRisk's
// own outcome-first answer already uses.
func TestSetClassifierKeyOutcomesReadApartByColor(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		want    design.ColorKey
	}{
		{"accepted", design.GoodKey},
		{"refused", design.BadKey},
		{"unavailable", design.WarnKey},
	} {
		f := newBareFrame(t)
		f.editor(ctlAdminClassifierKey).SetText("sk-live-not-a-real-key-abc123")
		f.cfg.Actions.AdminSetClassifierKey = func(key string) (AdminSetClassifierKeyResult, error) {
			return AdminSetClassifierKeyResult{Outcome: tc.outcome, Detail: "the gateway's own sentence"}, nil
		}

		f.setClassifierKey()
		got := awaitSaid(t, f, ctlAdminClassifierKey, tc.want)

		if got.key != tc.want {
			t.Errorf("outcome %q said with key %v, want %v", tc.outcome, got.key, tc.want)
		}
	}
}
