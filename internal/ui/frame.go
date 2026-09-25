//go:build windows || linux || darwin

package ui

import (
	"context"
	"image"
	"strconv"
	"strings"
	"sync"
	"time"

	giofont "gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Standard tab names matching SPEC §7.1 (English text).
const (
	TabGuide    = "Guide"
	TabSetUp    = "Set up"
	TabClient   = "Client"
	TabServer   = "Server"
	TabGateway  = "Gateway"
	TabSession  = "Session"
	TabAdmin    = "Admin"
	TabHistory  = "History"
	TabSettings = "Settings"
)

// FrameConfig specifies initial configuration for the Window Frame.
type FrameConfig struct {
	// Enrolled indicates whether this machine is already enrolled.
	// When true, the "Set up" tab is omitted (SPEC §7.1).
	Enrolled bool

	// InitialTab specifies which tab to open first. Empty means the
	// frame decides: Set up on an unenrolled machine, otherwise Server
	// while someone is in, otherwise Client.
	InitialTab string

	// StillFrame suppresses every animation in the window: the masthead's
	// elevation button stops breathing and the frame renders as one fixed
	// picture. The offscreen shot (§7.2) and the pixel tests set it,
	// because a screenshot of a pulsing control is a different image on
	// every run, and a test that compares pixels would then be measuring
	// the clock.
	StillFrame bool

	// HasAdminRights indicates whether the process is already running as
	// Administrator. The elevation notice is shown exactly when this is
	// false — visibility is derived here once, and nothing may flip it
	// afterwards.
	HasAdminRights bool

	// ForceTheme overrides the live system theme. Defaults to ThemeAuto.
	ForceTheme ThemeOverride

	// ThemeSource supplies the live dark/light signal. Defaults to the
	// platform source (the Windows registry, the $GTK_THEME stand-in on
	// Linux); tests can supply their own to exercise live theme
	// switching without touching the real thing.
	ThemeSource ThemeSource

	// Snap is the reality the five screens draw: who is in, until when,
	// whether the session is recorded, which machines the client may
	// enter. The zero value renders as an honest idle machine.
	Snap Snapshot

	// OnWindowReady, when set, is called exactly once AFTER the first
	// frame was SUBMITTED to the window system: the event loop in gui.go
	// fires it right after e.Frame returned for the first FrameEvent, on
	// the UI goroutine — deliberately NOT from Layout, whose return only
	// means the operations were built, not that the window system was
	// ever handed them. Gio acknowledges no actual composition (there is
	// no "the compositor showed it" callback), so a submitted frame is
	// the strongest "the window is up" signal there is. The Linux restart
	// handover uses it (IAMT-295): the elevated copy announces itself
	// only once that submission is a fact, so a display it cannot reach
	// still reads, in the original, as a child that exited without the
	// ready line. Runs on the window loop's goroutine — keep it cheap and
	// non-blocking.
	OnWindowReady func()

	// Actions is what the window may ASK the roles to do when a person
	// presses a button, and the way it asks for a repaint afterwards. The
	// zero value is a window that draws but performs nothing, which is
	// exactly what the offscreen shot and every test want: none of them
	// may reach a gateway or a data directory. The role work itself lives
	// in cmd/iamtunnel, where the CLI verbs already assemble it; the
	// window only decides WHEN it runs and how its outcome is worded.
	Actions Actions

	// resolver is the font provider; nil means the platform default. On
	// Windows it holds a *winfonts.Resolver (tests inject a mock there);
	// the platform font seam (fonts_windows.go / fonts_linux.go) unpacks
	// it. Unexported on purpose: font provenance is not a caller's switch.
	resolver any
}

// ThemeOverride selects how Frame picks its theme. The zero value is
// ThemeAuto. It is an ordinary constant type — no exported mutable
// sentinels a caller could reassign.
type ThemeOverride int

const (
	// ThemeAuto follows the live Windows registry setting.
	ThemeAuto ThemeOverride = iota
	// ThemeLight forces the light palette regardless of the system setting.
	ThemeLight
	// ThemeDark forces the dark palette regardless of the system setting.
	ThemeDark
)

// Frame implements the Telescope window frame for iamtunnel:
//   - Masthead "IAMTUNNEL" at the top
//   - The recording strip, above the tabs, whenever someone is working
//   - Custom tab strip that does NOT jump on tab switch
//   - The elevation button at the right of the masthead, breathing slowly,
//     present exactly while Administrator rights are missing (1.3)
//   - The five screens of §7.1, drawn from the Snapshot
//   - Live theme switching following the system theme without restarting
//
// The frame exposes no mutator for what the screens must always show:
// the recording strip appears whenever the snapshot says someone is in,
// the elevation button appears exactly when admin rights are missing —
// asked of the config on every frame, never stored — and the tab bodies
// are built from the snapshot alone.
type Frame struct {
	cfg  FrameConfig
	snap Snapshot

	// identityWrittenAt is when an action of THIS window last changed who
	// this machine is on its gateway. A status tick that read the saved
	// connection before that instant is stale, and its identity is
	// discarded rather than applied — see LiveUpdate.At for the sequence
	// that made this necessary.
	identityWrittenAt time.Time

	// gatewayGen counts the switches of gateway this window has made
	// (R1-CX F-16). An answer asked of one gateway lands only if the
	// window still looks at it: gatewayGen is compared, under mu, in the
	// same revision that would write the answer. gatewayCtx is the
	// context the current gateway's requests run under, and gatewayStop
	// cancels it at the next switch; gatewaySwitchedAt is when that
	// switch happened, for the status tick, which stamps when it looked
	// (LiveUpdate.At) rather than carrying a generation.
	gatewayGen        uint64
	gatewayCtx        context.Context
	gatewayStop       context.CancelFunc
	gatewaySwitchedAt time.Time

	tabs   *design.Tabs
	theme  *design.Theme
	shaper *text.Shaper
	// faces is the resolved font collection, kept so a second window can
	// be given a shaper of its OWN. See windowTheme.
	faces []giofont.FontFace
	// hwnd is the main window's OS handle, for flashing the taskbar
	// button when a command is held. Zero off Windows.
	hwnd uintptr
	// heldSeen remembers which held commands have already been announced,
	// so polling does not re-ring the same one every few seconds.
	heldSeen    map[string]bool
	themeSource ThemeSource
	isDark      bool
	// lastThemePoll is when the ThemeSource was last ASKED for the
	// system answer (IAMT-381/382). Stamped by CheckThemeSync at the
	// moment it probes, read by Layout to keep the per-frame probe to
	// once a second; an explicit CheckThemeSync call never consults it,
	// so a deliberate request still switches instantly.
	lastThemePoll time.Time
	animStart     time.Time
	btns          map[string]*widget.Clickable
	eds           map[string]*widget.Editor

	// sels is the text-selection state of each copyable box, keyed the
	// same way the editors and the buttons are. It must outlive the
	// frame that draws it for the same reason a scrollbar's drag must:
	// a selection rebuilt every frame would be lost the instant the
	// mouse moved (IAMT-355).
	sels map[string]*widget.Selectable

	// lastDrawnTab is the tab the previous frame drew, and the whole of
	// how this window knows somebody has just ARRIVED somewhere
	// (IAMT-363, IAMT-365).
	//
	// Every tab that shows a list asks its source on entry, because the
	// maintainer said the obvious thing twice: switching to a tab means
	// wanting to see the current state. The lists live on a
	// gateway several people can change at once, so a window that kept
	// showing the answer it got when it opened would be worse than one
	// that showed nothing. The first version of this covered only the
	// Admin tab, which is exactly the kind of half-fix that teaches a
	// person not to trust the other half.
	lastDrawnTab string

	// disclosed holds the forms a person has opened (IAMT-359). A form
	// that ADDS to a list is closed until asked for and closes itself on
	// success: the list is what the screen is for, and a form standing
	// permanently above it is furniture nobody asked to keep.
	//
	// Touched only on the layout goroutine, like lists and subTabs.
	disclosed map[string]bool

	// expanded holds the combo boxes whose panel of choices is open.
	expanded map[string]bool

	// watch is the session the Live sub-tab is following, or nil
	// (IAMT-360). Touched only on the layout goroutine and by the
	// action it starts, which runs one at a time under begin().
	watch *watchState

	// confirming holds the controls whose first press only armed them
	// (IAMT-356). Touched only on the layout goroutine, like lists.
	confirming map[string]bool

	// lastRecordingStripShown and lastStopButtonShown are the layout-level
	// (not pixel-level) invariants the off-Windows platforms assert on.
	// The Windows offscreen shot also depends on them being truthful,
	// because the pixel-level test in verify_iamt66_test.go reddens when
	// either flag flips the wrong way around a layout pass. Both fields
	// are set by the layouts themselves (layoutRecordingStrip and
	// layoutServerScreen respectively) and read by Linux tests in
	// invariants_linux_test.go (IAMT-255), where the offscreen GPU
	// emulator is not wired into the build policy.
	lastRecordingStripShown bool
	lastStopButtonShown     bool

	// lastUnknownStripShown is layoutUnknownStatusStrip's own testable
	// flag (F-GUI-2), the same discipline as the two above.
	lastUnknownStripShown bool

	// lastServerFactsUnknown is the same kind of layout-level,
	// off-Windows-testable flag as the two above, for IAMT-311: it
	// mirrors Server.Unknown exactly as the layout pass drew it, so a
	// Linux test can pin that layoutServerScreen actually saw the
	// tri-state fact — not merely that ServerState carries the field —
	// without the headless GPU renderer.
	lastServerFactsUnknown bool

	// mu guards the two things a background operation writes while the
	// drawing goroutine may be reading them: the snapshot handed over
	// from outside (or by a finished action), and the status line under
	// each control. Nothing else is shared — the theme, the tabs and the
	// rights fact are decided once, on the goroutine that built the
	// frame, and never again.
	mu      sync.Mutex
	pending *Snapshot
	said    map[string]saying
	working map[string]bool

	// approvals holds, per exec row, the one pending "ask"-mode approval
	// the gateway last handed that row (IAMT-394). It is kept apart from
	// said because it outlives no run but its own: a fresh run either
	// replaces it or clears it, and a row with nothing here draws no
	// second button. Guarded by mu.
	approvals map[string]string

	// restarting is set while "Restart as administrator" waits for the
	// Windows consent, so a second click starts no second relaunch
	// (IAMT-232). Guarded by mu.
	restarting bool

	// lists is the scroll state of each tab's page, owned by this window
	// and touched only on the layout goroutine (IAMT-229). A widget.List
	// rather than a layout.List since IAMT-334: it carries the scrollbar's
	// own state (drag, hover, track clicks) beside the scroll offset, and
	// the two must live for as long as the tab does — a scrollbar rebuilt
	// every frame would lose the drag halfway through it.
	lists map[string]*widget.List

	// subTabs remembers which sub-tab is open inside each tab, keyed by
	// the tab's own name (SPEC §7.1, 1.3). Touched only on the layout
	// goroutine, like lists.
	subTabs map[string]string

	// windowReadyDone guards the one-shot OnWindowReady: the flag is
	// touched only on the window loop's goroutine (the one that runs
	// Layout and submits the frames — see drawSubmittedFrame in gui.go).
	windowReadyDone bool

	// sessionUI is the live terminal viewer and tailing state for the
	// Session tab (IAMT-341, contract §4).
	sessionUI *sessionScreenState

	// lastActiveTab tracks tab switches to manage session polling lifecycle.
	lastActiveTab string

	// liveSubTabLastFetch is the last time the Live sub-tab's empty-card
	// promise was fulfilled — the moment we asked the gateway for a list
	// that came back empty. Used to throttle re-asks so an idle tab
	// does not dial sixty times a second.
	liveSubTabLastFetch time.Time
}

// pageList is the scroll state of the current tab's page, together with
// the state of that page's scrollbar (IAMT-334).
// namedList is the scroll state of one inner scrolling area -- a panel
// inside a page, not the page itself (IAMT-366). Kept for the window's
// life like every other control state: a list rebuilt each frame loses
// the scroll position the moment anything redraws.
func (f *Frame) namedList(name string) *widget.List {
	if f.lists == nil {
		f.lists = map[string]*widget.List{}
	}
	l, ok := f.lists[name]
	if !ok {
		l = &widget.List{List: layout.List{Axis: layout.Vertical}}
		f.lists[name] = l
	}
	return l
}

func (f *Frame) pageList() *widget.List {
	if f.lists == nil {
		f.lists = map[string]*widget.List{}
	}
	name := f.tabs.Current()
	l, ok := f.lists[name]
	if !ok {
		l = &widget.List{List: layout.List{Axis: layout.Vertical}}
		f.lists[name] = l
	}
	return l
}

// NewFrame constructs a new Window Frame with resolved fonts and initial theme.
func NewFrame(cfg FrameConfig) (*Frame, error) {
	// 1. Resolve fonts per SPEC §7.1 preference lists. A missing font is
	// a substitution, never a refusal: the platform seam (fonts_windows.go
	// / fonts_linux.go) falls back to the embedded gofont on its own.
	faces := platformFonts(cfg.resolver)
	shaper := text.NewShaper(text.NoSystemFonts(), text.WithCollection(faces))

	// 2. Determine initial theme
	source := cfg.ThemeSource
	if source == nil {
		source = defaultThemeSource
	}

	isDark := source.IsDark()
	switch cfg.ForceTheme {
	case ThemeLight:
		isDark = false
	case ThemeDark:
		isDark = true
	}

	pal := design.LightPalette()
	if isDark {
		pal = design.DarkPalette()
	}

	th := design.NewTheme(pal, shaper)

	f := &Frame{
		cfg:         cfg,
		snap:        cfg.Snap,
		tabs:        design.NewTabs(),
		theme:       th,
		shaper:      shaper,
		faces:       faces,
		themeSource: source,
		isDark:      isDark,
		animStart:   time.Now(),
		btns:        make(map[string]*widget.Clickable),
		eds:         make(map[string]*widget.Editor),
		sels:        make(map[string]*widget.Selectable),
		confirming:  make(map[string]bool),
		disclosed:   make(map[string]bool),
		expanded:    make(map[string]bool),
		said:        make(map[string]saying),
		working:     make(map[string]bool),
	}
	f.sessionUI = newSessionScreenState(f)

	// 3. Register tabs per SPEC §7.1, each body drawn from the snapshot.
	//
	// Guide stands FIRST, and on every machine (IAMT-359). The process
	// spans three computers and every window looks the same on all of
	// them; the chart is the only place that says which computer this is
	// and what happens next on it. It stays after setup is finished,
	// because the question "whose turn is it now" keeps being asked long
	// after the first day.
	f.tabs.Add(TabGuide, f.makeTabBody(TabGuide))
	if !cfg.Enrolled {
		f.tabs.Add(TabSetUp, f.makeTabBody(TabSetUp))
	}
	f.tabs.Add(TabClient, f.makeTabBody(TabClient))
	f.tabs.Add(TabServer, f.makeTabBody(TabServer))
	// Gateway stands beside Server because they are the two halves of
	// what this one binary can be: the machine people enter, and the
	// meeting point they enter it through. It is shown on every
	// computer, including the ones that will never be a gateway -- the
	// screen exists to be FOUND by somebody in front of a fresh server
	// who does not yet know the program can do this (IAMT-434).
	f.tabs.Add(TabGateway, f.makeTabBody(TabGateway))
	f.tabs.Add(TabSession, f.makeTabBody(TabSession))
	f.tabs.Add(TabAdmin, f.makeTabBody(TabAdmin))
	// History is a tab of its own, not an eighth sub-tab of Admin
	// (21.09.2026). Admin's sub-tabs are things you DO -- hand out
	// access, take it back, change a mode -- and each is a short page.
	// History is a thing you READ: a filter bar, a page of rows and a
	// way through them, and it would have overflowed the default window
	// the moment it joined a page already at gate 17's limit.
	f.tabs.Add(TabHistory, f.makeTabBody(TabHistory))
	f.tabs.Add(TabSettings, f.makeTabBody(TabSettings))

	// Set initial tab
	initial := cfg.InitialTab
	if initial == "" {
		switch {
		case !cfg.Enrolled:
			initial = TabSetUp
		case cfg.Snap.Server.MaybeBusy():
			// The maintainer's main screen is the one that shows who is in —
			// or, when that could not be learned at all, the one that
			// says so and still offers Stop (F-GUI-2).
			initial = TabServer
		default:
			initial = TabClient
		}
	}
	f.tabs.Show(initial)

	// 4. The elevation notice: shown exactly when rights are missing.
	// There is no setter — visibility is derived once, here.
	// No notice slot under the tab strip since 1.3: the elevation control
	// is one button in the masthead (layoutElevationButton), and the
	// refusal it used to explain is said under whatever button needed the
	// rights.

	return f, nil
}

// makeTabBody returns the fixed body of a screen. Bodies are built from
// the snapshot only; no override can swap a screen (and its unconditional
// parts) out.
func (f *Frame) makeTabBody(tabName string) layout.Widget {
	tab := tabName
	return func(gtx layout.Context) layout.Dimensions {
		// Arriving is drawn-now-and-not-drawn-last-frame. Decided here,
		// in the body of the tab actually being shown, rather than in a
		// tab-change callback: this is the one place that certainly runs
		// for the right tab, on the layout goroutine, once per frame.
		entered := !strings.EqualFold(f.lastDrawnTab, tab)
		f.lastDrawnTab = tab
		if entered {
			f.tabEntered(tab)
		}
		switch {
		case strings.EqualFold(tab, TabGuide):
			return f.layoutGuideScreen(gtx)
		case strings.EqualFold(tab, TabSetUp):
			return f.layoutSetupScreen(gtx)
		case strings.EqualFold(tab, TabClient):
			return f.layoutClientScreen(gtx)
		case strings.EqualFold(tab, TabServer):
			return f.layoutServerScreen(gtx)
		case strings.EqualFold(tab, TabGateway):
			return f.layoutGatewayScreen(gtx)
		case strings.EqualFold(tab, TabSession):
			return f.layoutSessionScreen(gtx)
		case strings.EqualFold(tab, TabAdmin):
			return f.layoutAdminScreen(gtx)
		case strings.EqualFold(tab, TabHistory):
			return f.layoutHistoryScreen(gtx)
		case strings.EqualFold(tab, TabSettings):
			return f.layoutSettingsScreen(gtx)
		default:
			return layout.Dimensions{}
		}
	}
}

// tabEntered asks each tab's source for what it shows, the moment
// somebody arrives on it (IAMT-365).
//
// Only where there IS something to ask: a window built without actions
// (the screenshot tool, the tests) must not fill its status lines with
// "this window performs nothing" simply because a tab was drawn.
func (f *Frame) tabEntered(tab string) {
	switch {
	case strings.EqualFold(tab, TabAdmin):
		if f.cfg.Actions.AdminList != nil {
			f.refreshAdminLists()
		}
	case strings.EqualFold(tab, TabHistory):
		// The journal is only read when somebody looks at it. Polling a
		// month of history in the background would be a dial-in to the
		// gateway every few seconds for an answer nobody is reading.
		if f.cfg.Actions.SessionsHistory != nil && len(f.snap.History.Rows) == 0 {
			f.refreshHistory(0)
		}
		// The person filter's dropdown is made of the gateway's people,
		// and an administrator may reach History without having opened
		// Admin first.
		if f.cfg.Actions.AdminList != nil && len(f.snap.Admin.People) == 0 {
			f.refreshAdminLists()
		}
	case strings.EqualFold(tab, TabGateway):
		// Whether this computer is a gateway changes from outside this
		// window -- somebody stops the service, a colleague spends the
		// one-time claim string -- so the tab asks every time it is
		// opened rather than trusting what it learned at startup.
		if f.cfg.Actions.GatewayStatus != nil {
			f.refreshGatewayState()
		}
	case strings.EqualFold(tab, TabClient):
		// Which machines this person may enter, and until when. Only
		// the gateway knows it, and a grant can be revoked between two
		// glances at this tab.
		if f.cfg.Actions.Machines != nil {
			f.refreshMachines()
		}
		// The goal and the mode of each row come from the gateway's
		// GRANT, which lives in the admin lists. A person may reach this
		// tab without ever opening Admin, and the Goal button would then
		// open on an empty answer.
		if f.cfg.Actions.AdminList != nil && len(f.snap.Admin.Grants) == 0 {
			f.refreshAdminLists()
		}
	}
}

// btn returns the clickable state for a named control, creating it on
// first use. Clicks are consumed by the runtime in a later phase; the
// controls already draw and hold their state here.
func (f *Frame) btn(name string) *widget.Clickable {
	b, ok := f.btns[name]
	if !ok {
		b = new(widget.Clickable)
		f.btns[name] = b
	}
	return b
}

// subTab reports which sub-tab of the current tab is open, defaulting to
// the first one the caller offers (SPEC §7.1, 1.3).
//
// The choice is remembered PER TAB, not globally: leaving Admin on its
// Machines sub-tab, going to Client and coming back must land on Machines
// again. A single shared "current sub-tab" would scatter the person every
// time they looked at another tab, which is the same disorientation
// sub-tabs were introduced to remove.
func (f *Frame) subTab(items []string) string {
	if len(items) == 0 {
		return ""
	}
	cur, ok := f.subTabs[f.tabs.Current()]
	if !ok {
		return items[0]
	}
	for _, it := range items {
		if strings.EqualFold(it, cur) {
			return it
		}
	}
	// The remembered sub-tab is gone — renamed, or the tab now offers a
	// different set. Falling back to the first one is the only honest
	// answer; refusing to draw would leave a blank tab.
	return items[0]
}

// subTabStrip draws the second-level strip for the current tab and
// records a press. The Clickables are keyed by tab AND word, so two tabs
// that happen to offer a sub-tab of the same name do not share one
// button — pressing "Machines" under Admin must not also press
// "Machines" under Client.
func (f *Frame) subTabStrip(gtx layout.Context, items []string) layout.Dimensions {
	parent := f.tabs.Current()
	dims, pressed := design.SubTabStrip(gtx, f.theme, items, f.subTab(items), func(word string) *widget.Clickable {
		return f.btn("subtab/" + parent + "/" + word)
	})
	if pressed != "" {
		if f.subTabs == nil {
			f.subTabs = map[string]string{}
		}
		f.subTabs[parent] = pressed
	}
	return dims
}

// CurrentTab returns the name of the currently selected tab.
func (f *Frame) CurrentTab() string {
	return f.tabs.Current()
}

// SelectTab switches to the tab with the given name.
func (f *Frame) SelectTab(name string) {
	f.tabs.Show(name)
}

// selectSubTab opens a named sub-tab inside the current tab, the same
// way pressing it would. Matching is case-insensitive, because the
// strip's words are drawn in capitals and nobody types them that way.
//
// It cannot validate the name: which sub-tabs a tab offers is decided
// inside that tab's own layout function, at draw time, and nothing
// outside knows the list before the first frame. An unknown name is
// therefore not refused here — subTab falls back to the first sub-tab
// when it cannot find what was remembered, so a typo shows the tab's
// opening sub-tab rather than a blank page.
func (f *Frame) selectSubTab(name string) {
	if name == "" {
		return
	}
	if f.subTabs == nil {
		f.subTabs = map[string]string{}
	}
	f.subTabs[f.tabs.Current()] = name
}

// IsDark reports whether the frame is currently rendered in dark theme.
func (f *Frame) IsDark() bool {
	return f.isDark
}

// CheckThemeSync queries the configured ThemeSource and updates the live theme if it
// changed. This achieves live theme switching without restarting the window.
//
// Asking is remembered (IAMT-381/382): the stamp is written exactly where
// the probe happens, so the per-frame caller can keep the OS read to once
// a second while a deliberate call from anywhere else stays instant.
func (f *Frame) CheckThemeSync() bool {
	if f.cfg.ForceTheme != ThemeAuto {
		return false
	}

	f.lastThemePoll = time.Now()
	systemIsDark := f.themeSource.IsDark()
	if systemIsDark != f.isDark {
		f.isDark = systemIsDark
		var pal design.Palette
		if f.isDark {
			pal = design.DarkPalette()
		} else {
			pal = design.LightPalette()
		}
		f.theme = design.NewTheme(pal, f.shaper)
		return true
	}
	return false
}

// layoutElevationButton is the elevation control in its 1.3 form: one
// button at the right edge of the masthead, no word of explanation beside
// it, breathing slowly, and absent entirely once the rights are there
// (SPEC §7.1, decision of the maintainer 17.09.2026).
//
// What it replaces, and why. Until 1.3 the same button sat under the tab
// strip behind two lines of warning text — "Administrator rights are
// required to open the door. Press Restart as administrator — Windows
// will ask for consent." — on EVERY tab, including the four where
// elevation changes nothing. A warning that is always on screen is
// furniture: the maintainer's live run went past it without reading it, which
// is exactly what permanent warnings train people to do. The rule now is
// that a refusal appears where it happened — under the button that was
// pressed — and the masthead only carries the standing offer to fix it.
//
// The pulse is SoftPulseWidget rather than PulseWidget: slower, and it
// never fades far. See SoftPulseOpacity for why an alarm cadence is the
// wrong shape for an invitation. It stops on an inactive window, so a
// background copy of the program does not blink at the corner of the eye.
func (f *Frame) layoutElevationButton(gtx layout.Context) layout.Dimensions {
	if f.cfg.HasAdminRights {
		// Nothing to offer — but the SPACE is still reserved. Drawing
		// nothing and returning a zero box would make the masthead shorter
		// exactly when rights appear, and every rule, tab and screen below
		// it would jump by the difference. The button's own height is
		// measured by laying it out into a macro that is then thrown away,
		// so the reservation is whatever the button actually is today
		// rather than a number copied here and left to rot.
		// TestVerifyTabStripHeightNeverMoves is what holds this.
		macro := op.Record(gtx.Ops)
		dims := design.SecondaryButton(gtx, f.theme, f.btn(ctlRestartAdmin), "Restart as administrator")
		macro.Stop()
		return layout.Dimensions{Size: image.Pt(0, dims.Size.Y)}
	}
	if f.btn(ctlRestartAdmin).Clicked(gtx) {
		if restart := f.cfg.Actions.RestartAsAdmin; restart != nil {
			f.mu.Lock()
			already := f.restarting
			f.restarting = true
			f.mu.Unlock()
			if !already {
				go func() {
					if err := restart(); err != nil {
						f.mu.Lock()
						f.restarting = false
						f.mu.Unlock()
						f.say(ctlServerStart, "Could not restart as administrator: "+err.Error(), design.BadKey)
					}
				}()
			}
		}
	}

	return design.SoftPulseWidget(gtx, f.windowActive(), f.animStart, func(gtx layout.Context) layout.Dimensions {
		return design.SecondaryButton(gtx, f.theme, f.btn(ctlRestartAdmin), "Restart as administrator")
	})
}

// layoutHeldButton is the masthead's second control: it appears only
// while the gateway is holding a command for this person, and pressing it
// goes straight to the list (21.09.2026).
//
// The maintainer asked for it beside "Restart as administrator" and for the
// word on it to be one or two, and both parts matter. A held command is
// news that arrives while you are looking at some other tab, so the
// notice has to live in the furniture that is on screen whatever tab is
// open; and a long label in the masthead would push the title about every
// time the count changed.
//
// It pulses, on the same soft cadence as the elevation button rather than
// an alarm one, and for the same reason: it is an invitation, and the
// thing waiting behind it is a question, not a failure. Unlike the
// elevation button it reserves NO space when idle -- elevation is a
// standing fact of the session, while this is an event, and a permanent
// gap held open for an event that has not happened is a masthead with a
// hole in it.
func (f *Frame) layoutHeldButton(gtx layout.Context) layout.Dimensions {
	f.mu.Lock()
	n := len(f.snap.Client.Held)
	f.mu.Unlock()
	if n == 0 {
		return layout.Dimensions{}
	}
	if f.btn(ctlHeldOpen).Clicked(gtx) {
		f.SelectTab(TabClient)
		f.subTabs[TabClient] = "Machines"
		stopCallingForAttention(f.mainHandle())
	}
	word := "1 held"
	if n > 1 {
		word = strconv.Itoa(n) + " held"
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.SoftPulseWidget(gtx, f.windowActive(), f.animStart, func(gtx layout.Context) layout.Dimensions {
				return design.AlertButton(gtx, f.theme, f.btn(ctlHeldOpen), word)
			})
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
	)
}

// mainHandle reports the main window's OS handle under the lock.
func (f *Frame) mainHandle() uintptr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hwnd
}

// windowActive reports whether this window should animate. The offscreen
// shot and the tests pass false through the same seam the old notice used
// (isElevationTab), so a still picture of a breathing control is the same
// picture every run instead of a different one each time.
func (f *Frame) windowActive() bool {
	return !f.cfg.StillFrame
}

// stillFrameNow is the instant a still picture is taken at. The pairing
// card is the one place a screen compares a snapshot value against the
// wall clock — a window either has time left on it or has lapsed — and
// the shot's example snapshot is a set of pinned dates. With time.Now()
// those two disagree the moment the pinned dates fall into the past, and
// the picture silently turns into the expired-window one. Pinning the
// comparison here is what actually makes "times are pinned so the
// pictures are byte-comparable" true of this card.
//
// It is deliberately a few minutes before the example window's expiry,
// so the still shows a window that is open, which is the state worth
// looking at.
var stillFrameNow = time.Date(2026, 9, 12, 16, 41, 0, 0, time.UTC)

// now is the frame's notion of the present: the wall clock in a live
// window, a pinned instant in a still one.
func (f *Frame) now() time.Time {
	if f.cfg.StillFrame {
		return stillFrameNow
	}
	return time.Now()
}

// layoutRecordingStrip is the strip above the tabs, shown whenever the
// way in to this machine is open: the button that cuts everything off
// is visible at once and is not hidden behind tabs. It
// appears exactly when the snapshot says AccessOpen, and never
// otherwise; there is no switch for it.
//
// IT USED TO CLAIM MORE THAN IT KNEW (21.09.2026). The words were
// "Recording — alice is working on this machine until 18:00 UTC", and
// what stands behind them, on a real install, is one boolean from the
// control port: the door is up. Nobody need be attached. The same window
// said so itself two tabs away — Session and Admin -> Live ask the
// gateway about attached terminals and answered "nobody is inside any
// machine at this moment" — and a person who saw the strip, went to
// Session to watch, and was told nobody was there had to decide which of
// his own screens to disbelieve.
//
// So the strip now says the thing it actually checked, and says the
// other thing only when it has been told it: a name and a deadline are
// drawn when the snapshot carries them, and left out when it does not,
// rather than printed as em-dashes to keep the sentence's shape.
func (f *Frame) layoutRecordingStrip(gtx layout.Context) layout.Dimensions {
	s := f.snap.Server
	if !s.AccessOpen() {
		// The strip is absent; the flag was already reset at the start
		// of this Layout pass (frame.go::Layout), so the element-by-element
		// "false" path here is a no-op — but leaving it in keeps the
		// conditional obvious to a reader scanning the layout function.
		return layout.Dimensions{}
	}
	f.lastRecordingStripShown = true

	if f.btn("strip/stop").Clicked(gtx) {
		f.stopServer()
	}

	text := accessStripText(s)

	return widget.Border{
		Color:        f.theme.Color(design.BadKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
			Left: unit.Dp(design.Pad), Right: unit.Dp(design.Pad),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Middle,
			}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.BadKey, false)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.Deck(gtx, f.theme, text)
						})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// The button names its object (21.09.2026). It said
					// "Stop now" inside a strip whose first word was
					// "Recording", four inches above the Server tab's own
					// red "STOP — cut access now", and the nearest word
					// made the natural reading "stop recording" — the
					// exact opposite of what somebody pressing a red
					// button on this strip wants.
					return design.DangerButton(gtx, f.theme, f.btn("strip/stop"), "Cut access now")
				}),
			)
		})
	})
}

// accessStripText is the strip's sentence, built from what the snapshot
// actually carries and nothing more. Separated from the drawing so the
// wording can be tested without a window.
//
// Three shapes, in order of how much is known:
//
//	"Access is open — anyone granted this machine may enter now"
//	"Access is open — alice may enter"
//	"Access is open — alice may enter until 18:00 UTC"
//
// None of them claims anybody is attached. That claim belongs to the
// Session tab and to Admin -> Live, which ask the gateway a different
// question and are the only two places that can answer it.
func accessStripText(s ServerState) string {
	const head = "Access is open — "
	if len(s.Sessions) == 0 {
		return head + "anyone granted this machine may enter now"
	}
	first := s.Sessions[0]
	person := strings.TrimSpace(clipStr(first.Person, 24))
	text := head
	if person == "" {
		text += "anyone granted this machine may enter now"
	} else {
		text += person + " may enter"
		if !first.Until.IsZero() {
			// The stamp, not a countdown. A countdown belongs only where
			// something asks for a frame every second to keep it honest
			// (the pairing card does; this strip does not -- it moves
			// when the status poll ticks, every three seconds), and a
			// clock that lags by three seconds on the most-seen element
			// in the window is worse than no clock.
			text += " until " + untilText(first.Until)
		}
	}
	if n := len(s.Sessions); n > 1 {
		text += " · +" + strconv.Itoa(n-1) + " more"
	}
	return text
}

// layoutUnknownStatusStrip is the F-GUI-2 counterpart of
// layoutRecordingStrip, in the same slot above the tabs: it appears
// exactly when the server's status could not be learned at all
// (Server.Unknown), because Recording() is always false in that state
// (Sessions is a bare zero value there — there is no session identity
// or deadline to show, which is exactly why this is a SEPARATE strip
// rather than a Recording() fallback that would have to invent one) and
// the recording strip would otherwise silently disappear over a machine
// that may in fact have a live, recorded session. It offers the same
// Stop control as the recording strip — an unreachable status is not a
// reason to withhold the one action that might still work.
func (f *Frame) layoutUnknownStatusStrip(gtx layout.Context) layout.Dimensions {
	s := f.snap.Server
	if !s.Unknown {
		return layout.Dimensions{}
	}
	f.lastUnknownStripShown = true

	if f.btn("strip/stop").Clicked(gtx) {
		f.stopServer()
	}

	return widget.Border{
		Color:        f.theme.Color(design.WarnKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
			Left: unit.Dp(design.Pad), Right: unit.Dp(design.Pad),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Middle,
			}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.WarnKey, false)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.Deck(gtx, f.theme, "Status unknown — this window cannot see whether a session is active. "+s.unknownText())
						})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.DangerButton(gtx, f.theme, f.btn("strip/stop"), "Cut access now")
				}),
			)
		})
	})
}

// Layout renders the entire window frame. It only BUILDS the operations;
// they are submitted by the caller afterwards (drawSubmittedFrame in
// gui.go), which is also where the one-shot OnWindowReady is fired — a
// Layout that returned has not necessarily produced a window anything
// will ever show.
func (f *Frame) Layout(gtx layout.Context) layout.Dimensions {
	// Take delivery of a snapshot handed over since the last frame, so
	// the whole pass draws ONE reality and never half of two.
	f.takeSnapshot()

	// IAMT-255 layout-level invariants reset at the START of every
	// pass (NOT inside the conditional layout routines that set them).
	// If a pass takes a tab where neither layoutRecordingStrip nor
	// layoutServerScreen is called, the flags must still fall back to
	// false — a "shown once and never cleared" bool is the wrong
	// contract for "shown this pass", and the off-Windows tests below
	// would redden if a stale "true" leaked across passes.
	f.lastRecordingStripShown = false
	f.lastStopButtonShown = false
	f.lastServerFactsUnknown = false
	f.lastUnknownStripShown = false

	// Sync theme live from the configured ThemeSource — but the OS probe
	// is answered at most once a second (IAMT-381/382): a frame pass runs
	// many times a second, and an API read on every pass buys nothing a
	// once-a-second read would miss. An explicit CheckThemeSync call is
	// NOT throttled: the throttle lives only in this per-frame path, so a
	// deliberate request still switches instantly.
	if f.cfg.ForceTheme == ThemeAuto && time.Since(f.lastThemePoll) >= time.Second {
		f.CheckThemeSync()
	}

	// Track tab switch to start/stop session tailing poller (IAMT-341).
	curTab := f.tabs.Current()
	if curTab != f.lastActiveTab {
		if f.sessionUI != nil {
			if strings.EqualFold(curTab, TabSession) {
				f.sessionUI.onTabOpen()
			} else if strings.EqualFold(f.lastActiveTab, TabSession) {
				f.sessionUI.onTabClose()
			}
		}
		f.lastActiveTab = curTab
	}

	// Fill background with Page color
	bg := f.theme.Color(design.PageKey)
	paint.FillShape(gtx.Ops, bg, clip.Rect(image.Rect(0, 0, gtx.Constraints.Max.X, gtx.Constraints.Max.Y)).Op())

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// 1. Masthead "IAMTUNNEL" at the top, and at its right edge the
		// one control that used to live under the tab strip: the
		// elevation button (SPEC §7.1, decision of 17.09.2026).
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top:    unit.Dp(design.Gap),
				Left:   design.EdgeDp,
				Right:  design.EdgeDp,
				Bottom: unit.Dp(design.Tight),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{
					Axis:      layout.Horizontal,
					Alignment: layout.Middle,
				}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						lbl := material.Label(f.theme.Material, design.TitleSp, "IAMTUNNEL")
						lbl.Color = f.theme.Color(design.InkKey)
						lbl.Font = f.theme.SerifFont
						return lbl.Layout(gtx)
					}),
					layout.Rigid(f.layoutHeldButton),
					layout.Rigid(f.layoutElevationButton),
				)
			})
		}),
		// 2. The recording strip: above the tabs, unmissable, whenever
		// someone is working on this machine — or, when the status could
		// not be learned at all (F-GUI-2), the unknown-status strip in
		// the same slot: Recording() is always false in that state, and
		// silently showing nothing there is the same "unknown read as
		// false" mistake IAMT-311 fixed for the facts underneath it.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			var strip layout.Widget
			switch {
			case f.snap.Server.Unknown:
				strip = f.layoutUnknownStatusStrip
			case f.snap.Server.AccessOpen():
				strip = f.layoutRecordingStrip
			default:
				return layout.Dimensions{}
			}
			return layout.Inset{
				Left:   design.EdgeDp,
				Right:  design.EdgeDp,
				Bottom: unit.Dp(design.Tight),
			}.Layout(gtx, strip)
		}),
		// 3. Tab strip with notice slot under tabs, and content area
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return f.tabs.Layout(gtx, f.theme)
		}),
	)
}

// windowReady fires cfg.OnWindowReady once, and only once — called by
// the event loop in gui.go, right after the first frame was submitted
// (drawSubmittedFrame; see OnWindowReady for why that and not Layout).
// Zero value (no callback — the offscreen shot, most tests) draws
// exactly as before.
func (f *Frame) windowReady() {
	if f.windowReadyDone {
		return
	}
	f.windowReadyDone = true
	if f.cfg.OnWindowReady != nil {
		f.cfg.OnWindowReady()
	}
}

// windowTheme builds a theme for a SECOND window: same palette, same
// fonts, but a shaper of its own.
//
// It exists because of a crash the maintainer hit on 21.09.2026 that
// could be
// read straight off the stack: "index out of range [58] with length 57"
// inside gio's text.Shaper.NextGlyph, thrown from the mode window -- and
// the same panic in the main window in the same second.
//
// Every window the product opens ran its own goroutine but drew with the
// Frame's single theme, and a theme carries one *text.Shaper. A shaper is
// not safe for two goroutines: it keeps the run it is walking in its own
// fields, so a second window laying out text scribbles over the first
// one's position and somebody indexes past the end of a glyph run. The
// main window is always drawing, so ANY second window was a coin toss.
//
// This has been true since the transcript window (IAMT-366) and simply
// had not been caught -- that window is opened rarely and watched
// quietly. Three more windows in two days made it a matter of when.
//
// The fonts are not resolved again: the faces are already in hand, and
// re-reading them from the system per window would trade a race for a
// stutter.
func (f *Frame) windowTheme() *design.Theme {
	f.mu.Lock()
	pal := f.theme.Palette
	faces := f.faces
	f.mu.Unlock()
	return design.NewTheme(pal, text.NewShaper(text.NoSystemFonts(), text.WithCollection(faces)))
}
