//go:build windows

package ui

// zz_accept_m10_extend_gui_test.go — the GUI half of M-10's canaries, for
// the parts a screenshot would not show, driven at the same layer
// iamt391_grantform_test.go drives grantAccess: the actions module, not
// a rendered frame. The extend form reuses the grant form's own
// machinery (untilFromPreset, the combo, begin's status line), so what
// is actually M-10's here is small and exactly bounded: the box is
// cleared when the form opens, an EMPTY box is refused rather than read
// as indefinite, and the word the box holds resolves the same way the
// grant form resolves it before it travels.

import (
	"testing"
	"time"
)

const m10ctl = "admin/extend/alice/win-srv01"

func TestM10ExtendFormClearsTheBoxOnOpen(t *testing.T) {
	f := newBareFrame(t)
	f.editor(m10ctl + "/box").SetText("2026-01-01T00:00:00Z")

	f.extendForm(m10ctl)
	if !f.disclosedForm(m10ctl) {
		t.Fatal("extendForm did not open the form")
	}
	if got := f.editor(m10ctl + "/box").Text(); got != "" {
		t.Errorf("box holds %q after the form opened, want it cleared — a stale deadline left over from a previous open must never look like the one being applied now", got)
	}

	f.extendForm(m10ctl)
	if f.disclosedForm(m10ctl) {
		t.Fatal("extendForm did not close the form on the second press")
	}
}

func TestM10ExtendAccessRefusesAnEmptyBox(t *testing.T) {
	f := newBareFrame(t)
	f.extendForm(m10ctl) // a fresh form, box empty

	asked := make(chan string, 1)
	f.cfg.Actions.AdminExtend = func(person, machine, until string) (string, error) {
		asked <- until
		return "", nil
	}

	f.extendAccess(m10ctl, "alice", "win-srv01")

	select {
	case until := <-asked:
		t.Fatalf("an empty box reached the gateway as until=%q — making access indefinite must take the deliberate word \"until revoked\", not one accidental press on an untouched form", until)
	case <-time.After(guardWait):
	}

	if said := f.saidUnder(m10ctl); said.text == "" {
		t.Error("the refusal left no word under the form — the reader is left pressing a button that silently does nothing")
	}
}

func TestM10ExtendAccessWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.extendForm(m10ctl)
	f.editor(m10ctl + "/box").SetText("1 hour")
	// AdminExtend deliberately left nil: a Frame without a runtime (the
	// offscreen shot) must say so, never silently do nothing.

	f.extendAccess(m10ctl, "alice", "win-srv01")

	if said := f.saidUnder(m10ctl); said.text == "" {
		t.Error("no runtime and no word about it — the button read as dead rather than unavailable")
	}
}

func TestM10ExtendAccessResolvesTheDeadlineTheGrantFormDoes(t *testing.T) {
	cases := []struct {
		name string
		word string
	}{
		{"preset one hour", "1 hour"},
		{"preset until revoked", "until revoked"},
		{"typed RFC 3339 passes through", "2026-09-13T18:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBareFrame(t)
			f.extendForm(m10ctl)
			f.editor(m10ctl + "/box").SetText(tc.word)

			asked := make(chan [3]string, 1)
			f.cfg.Actions.AdminExtend = func(person, machine, until string) (string, error) {
				asked <- [3]string{person, machine, until}
				return "extended", nil
			}

			before := time.Now()
			f.extendAccess(m10ctl, "alice", "win-srv01")

			select {
			case got := <-asked:
				if got[0] != "alice" || got[1] != "win-srv01" {
					t.Fatalf("extend asked for %q -> %q, want the pair of the row whose button was pressed", got[0], got[1])
				}
				until := got[2]
				switch tc.word {
				case "until revoked":
					if until != "" {
						t.Fatalf(`"until revoked" reached the gateway as until=%q, want the empty string the wire reads as indefinite`, until)
					}
				case "1 hour":
					at, err := time.Parse(time.RFC3339, until)
					if err != nil {
						t.Fatalf("extend resolved %q to until=%q, which is not RFC 3339: %v", tc.word, until, err)
					}
					const slack = time.Second
					if at.Before(before.Add(time.Hour-slack)) || at.After(before.Add(time.Hour+slack)) {
						t.Errorf("extend resolved %q to %s, want roughly one hour from the press", tc.word, at)
					}
				default:
					if until != tc.word {
						t.Errorf("extend rewrote a typed instant %q into %q", tc.word, until)
					}
				}
			case <-time.After(guardWait):
				t.Fatal("extendAccess asked the gateway nothing")
			}
		})
	}
}
