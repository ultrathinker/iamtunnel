//go:build windows || linux || darwin

package ui

// Everything about this gateway that an administrator can change, in one
// window (21.09.2026).
//
// The maintainer's words: a small square button at the end of the row,
// holding all these settings, where one can choose the internal check,
// the AI check only, or both -- in short, all the settings for this
// server shown there, in a pop-up.
//
// WHY THESE SETTINGS AND NOT OTHERS. The two controls here are the pair
// that decides what happens to a command: WHO judges it (rules / ai /
// both) and WHAT is done when the answer is red (log / warn / ask /
// block). They have always belonged together and never sat together --
// the mode was on the Admin tab, and the choice of checkers was in a file
// on the gateway host, reachable only over SSH and only with a restart.
// One of them being three screens from the other is why the maintainer asked
// for this window from the row he actually works in.
//
// THEY ARE GATEWAY-WIDE, AND THE WINDOW SAYS SO. Opening from one
// machine's row makes it easy to read them as that machine's settings.
// They are not: every person and every machine on this gateway is judged
// by them. The heading says it in a sentence rather than leaving the
// context to imply something false.
//
// WHO MAY CHANGE THEM. The same rule as the mode and the goal, for the
// same reason: a machine holding an administrator's key may, and the
// gateway grades the request by that key whatever this window believes.
// Anyone else sees the settings and is told who to ask -- a greyed-out
// control invites hunting for the way to un-grey it.

import (
	"context"
	"errors"
	"image"
	"strings"
	"sync"
	"testing"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// errNoRuntime marks the case where the window was built without an
// action to call. The human sentence for it is the package's noRuntime;
// an error VALUE carries the case, and the text is chosen where it is
// shown, which is also what keeps the error string lower-case and
// punctuation-free the way Go expects.
var errNoRuntime = errors.New("window opened without a runtime")

// riskSourceWords is the classifier choice in the gateway's own
// vocabulary. The MODE words are not repeated here: riskModeWords() in
// live_watch.go is the single list a canary reads against the gateway's
// constants, and a second copy would be the thing that canary exists to
// prevent.
var riskSourceWords = []string{"rules", "ai", "both"}

// riskSourceExplained is the one-line meaning of each choice. A person
// picking between three words that all sound reasonable deserves to know
// what each costs.
func riskSourceExplained(word string) string {
	switch word {
	case "rules":
		return "Only the gateway's own patterns. Nothing about your commands leaves this gateway, " +
			"and a declared goal cannot help — patterns read text, not context."
	case "ai":
		return "Only the AI classifier. It weighs each command against the goal declared for that " +
			"access, and the gateway's own patterns no longer decide anything."
	case "both":
		return "The strictest: a command passes unhindered only when BOTH allow it. If the AI cannot " +
			"be reached, nothing is judged and every command waits for you."
	}
	return ""
}

func riskModeExplained(word string) string {
	switch word {
	case "log":
		return "Nothing is stopped; the journal records what was judged dangerous."
	case "warn":
		return "A dangerous command runs, with a warning ahead of it."
	case "ask":
		return "A dangerous command stops and waits for you to allow it, once."
	case "block":
		return "A dangerous command is refused outright, with no way to allow it from here."
	}
	return ""
}

// settingsFacts is what the window shows and changes.
type settingsFacts struct {
	Classifier       string
	ClassifierSource string
	ClassifierKey    bool
	Mode             string
	ModeSource       string
}

// settingsOf lifts the gateway-wide risk settings out of a whole fetch of
// its lists. Separated from the drawing for the same reason goalOf is:
// the window opens a real operating-system window and no test may enter
// it, so the part worth testing must be reachable without one.
func settingsOf(lists AdminLists) settingsFacts {
	return settingsFacts{
		Classifier:       lists.RiskMode.Classifier,
		ClassifierSource: lists.RiskMode.ClassifierSource,
		ClassifierKey:    lists.RiskMode.ClassifierKey,
		Mode:             lists.RiskMode.Mode,
		ModeSource:       lists.RiskMode.Source,
	}
}

// settingsRefusal is the sentence for a choice this gateway cannot take,
// or "" when it can. It is the window's half of the gateway's own guard,
// said before the press rather than after it.
func settingsRefusal(facts settingsFacts, want string) string {
	if want != "rules" && !facts.ClassifierKey {
		return "This gateway has no AI classifier key, so it cannot use the AI. Set a key first — " +
			"Admin → Classifier. Without one, every single command would stop and wait " +
			"for a person."
	}
	return ""
}

func (f *Frame) openSettingsWindow() {
	if testing.Testing() {
		panic("ui: openSettingsWindow invoked in test binary; tests must never open a real window")
	}
	f.mu.Lock()
	id := f.snap.Admin.ThisMachine
	facts := settingsFacts{
		Classifier:       f.snap.Admin.RiskMode.Classifier,
		ClassifierSource: f.snap.Admin.RiskMode.ClassifierSource,
		ClassifierKey:    f.snap.Admin.RiskMode.ClassifierKey,
		Mode:             f.snap.Admin.RiskMode.Mode,
		ModeSource:       f.snap.Admin.RiskMode.Source,
	}
	f.mu.Unlock()

	admin := ""
	if id != nil {
		admin = id.Person
	}
	gateway := ""
	if id != nil {
		gateway = id.Gateway
	}

	// Read afresh rather than trusting the Frame's copy: the Admin tab
	// may never have been opened in this run, and settings shown from a
	// snapshot that was never filled would be blank or stale.
	var load func() (settingsFacts, error)
	if ask := f.cfg.Actions.AdminList; ask != nil {
		load = func() (settingsFacts, error) {
			lists, err := ask(context.Background())
			if err != nil {
				return settingsFacts{}, err
			}
			return settingsOf(lists), nil
		}
	}

	go runSettingsWindow(f.windowTheme(), gateway, admin, facts, load,
		f.cfg.Actions.AdminRiskSource, f.cfg.Actions.AdminRiskMode, f.refreshAdminLists)
}

func runSettingsWindow(
	theme *design.Theme,
	gateway, adminPerson string,
	facts settingsFacts,
	load func() (settingsFacts, error),
	setSource func(classifier string) (RiskSourceResult, error),
	setMode func(mode string) (RiskModeResult, error),
	after func(),
) {
	defer guardWindow("settings window", nil)

	w := new(app.Window)
	title := "iamtunnel - gateway settings"
	if gateway != "" {
		title += " - " + gateway
	}
	w.Option(app.Title(title), app.Size(unit.Dp(720), unit.Dp(620)))
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var closeBtn widget.Clickable
	var noteSel widget.Selectable
	var page widget.List
	page.Axis = layout.Vertical

	sourceBtns := map[string]*widget.Clickable{}
	for _, word := range riskSourceWords {
		sourceBtns[word] = new(widget.Clickable)
	}
	modeBtns := map[string]*widget.Clickable{}
	for _, word := range riskModeWords() {
		modeBtns[strings.ToLower(word)] = new(widget.Clickable)
	}

	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	busy := false
	current := facts

	if load != nil {
		go func() {
			fresh, err := load()
			mu.Lock()
			if err != nil {
				text := err.Error()
				if errors.Is(err, errNoRuntime) {
					text = noRuntime
				}
				note, noteKey = text, design.BadKey
			} else {
				current = fresh
			}
			mu.Unlock()
			w.Invalidate()
		}()
	}

	// apply is one press: refuse locally where the gateway would refuse,
	// otherwise send and report what came back in the gateway's words.
	apply := func(what string, send func() (string, string, error)) {
		mu.Lock()
		if busy || adminPerson == "" {
			mu.Unlock()
			return
		}
		busy = true
		note, noteKey = "Changing "+what+".", design.MutedKey
		mu.Unlock()

		go func() {
			said, _, err := send()
			mu.Lock()
			if err != nil {
				note, noteKey = err.Error(), design.BadKey
			} else {
				note, noteKey = said, design.GoodKey
			}
			busy = false
			mu.Unlock()
			if err == nil && load != nil {
				if fresh, lerr := load(); lerr == nil {
					mu.Lock()
					current = fresh
					mu.Unlock()
				}
			}
			if err == nil && after != nil {
				after()
			}
			w.Invalidate()
		}()
	}

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if closeBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			mu.Lock()
			shown, shownNote, shownKey, shownBusy := current, note, noteKey, busy
			mu.Unlock()

			for _, word := range riskSourceWords {
				if !sourceBtns[word].Clicked(gtx) || word == shown.Classifier {
					continue
				}
				if refusal := settingsRefusal(shown, word); refusal != "" {
					mu.Lock()
					note, noteKey = refusal, design.BadKey
					mu.Unlock()
					continue
				}
				pick := word
				apply("who checks commands", func() (string, string, error) {
					if setSource == nil {
						return "", "", errNoRuntime
					}
					res, err := setSource(pick)
					if err != nil {
						return "", "", err
					}
					if !res.Changed {
						return "Already " + res.Classifier + "; nothing changed.", res.Classifier, nil
					}
					return "Now " + res.Classifier + ", was " + res.Previous +
						". It takes effect on the next command and survives a restart.", res.Classifier, nil
				})
			}
			for _, capitalised := range riskModeWords() {
				word := strings.ToLower(capitalised)
				if !modeBtns[word].Clicked(gtx) || word == shown.Mode {
					continue
				}
				pick := word
				apply("what happens to a dangerous command", func() (string, string, error) {
					if setMode == nil {
						return "", "", errNoRuntime
					}
					res, err := setMode(pick)
					if err != nil {
						return "", "", err
					}
					if !res.Changed {
						return "Already " + res.Mode + "; nothing changed.", res.Mode, nil
					}
					return "Now " + res.Mode + ", was " + res.Previous + ".", res.Mode, nil
				})
			}

			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.PageScrollbar(theme, &page).Layout(gtx, 1,
							func(gtx layout.Context, _ int) layout.Dimensions {
								return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
									func(gtx layout.Context) layout.Dimensions {
										return settingsBody(gtx, theme, gateway, adminPerson, shown,
											shownNote, shownKey, shownBusy, sourceBtns, modeBtns, &noteSel)
									})
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Dimensions{}
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &closeBtn, "Close")
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}

// settingsBody is everything the window scrolls. The actions stay below
// it, outside the scroller, for the reason the goal window's do: a person
// must never have to scroll to reach the way out.
func settingsBody(
	gtx layout.Context,
	th *design.Theme,
	gateway, adminPerson string,
	facts settingsFacts,
	note string,
	noteKey design.ColorKey,
	busy bool,
	sourceBtns, modeBtns map[string]*widget.Clickable,
	noteSel *widget.Selectable,
) layout.Dimensions {
	where := "this gateway"
	if gateway != "" {
		where = gateway
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Heading(gtx, th, "Settings for "+where)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, th,
				"These apply to the WHOLE gateway — every person and every machine on it, not just the "+
					"one whose row you opened this from. They take effect on the next command and survive "+
					"a restart of the gateway.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, th, "who checks each command"+originWord(facts.ClassifierSource))
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if adminPerson == "" {
				return design.Fixed(gtx, th, orDash(facts.Classifier))
			}
			dims, _ := design.Segmented(gtx, th, riskSourceWords, facts.Classifier,
				func(word string) *widget.Clickable { return sourceBtns[word] })
			return dims
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, th, riskSourceExplained(facts.Classifier))
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if facts.ClassifierKey {
				return layout.Dimensions{}
			}
			return design.Hint(gtx, th,
				"No AI classifier key is set on this gateway, so \"ai\" and \"both\" cannot be chosen.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Wide)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, th, "what happens to a dangerous command"+originWord(facts.ModeSource))
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if adminPerson == "" {
				return design.Fixed(gtx, th, orDash(facts.Mode))
			}
			dims, _ := design.Segmented(gtx, th, riskModeWords(), facts.Mode,
				func(word string) *widget.Clickable { return modeBtns[strings.ToLower(word)] })
			return dims
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, th, riskModeExplained(facts.Mode))
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),

		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if busy {
				return design.Hint(gtx, th, "Asking the gateway…")
			}
			return design.Said(gtx, th, noteSel, note, noteKey)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if adminPerson != "" {
				return layout.Dimensions{}
			}
			return design.Hint(gtx, th,
				"Only an administrator of this gateway can change these, and this machine holds no "+
					"administrator key. Ask whoever gave you this access. That is deliberate: somebody "+
					"who could switch the checking off is somebody the checking does not protect against.")
		}),
	)
}

// originWord says whether a setting is the one the gateway's settings
// file carries or one somebody switched while it was running. It matters:
// a live switch outlives a restart, and a person looking at "both" wants
// to know whether that came from the file they edited or from a press.
func originWord(source string) string {
	switch source {
	case "live":
		return " — switched here, not from the settings file"
	case "config":
		return " — from the gateway's settings file"
	}
	return ""
}
