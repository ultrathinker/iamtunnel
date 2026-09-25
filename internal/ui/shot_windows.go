//go:build windows

package ui

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"strings"
	"time"

	"gioui.org/gpu/headless"
	"gioui.org/io/input"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
)

// DefaultShotWidth and DefaultShotHeight define the standard resolution for offscreen window snapshots.
const (
	DefaultShotWidth  = 1024
	DefaultShotHeight = 700
)

// Shot renders an offscreen snapshot of the specified tab screen in Light or Dark theme
// without opening a graphical window (SPEC §7.2).
// It saves the result as a PNG file to outPath (if non-empty) and returns the rendered image.
//
// The picture shows the screens filled with exampleSnapshot(): shot exists to
// verify the looks, so it draws a realistic machine, not an empty one. The
// example data is fixed (no clock, no network), which keeps the pictures
// reproducible.
func Shot(tabName string, isDark bool, width, height int, outPath string) (*image.RGBA, error) {
	return ShotSub(tabName, "", isDark, width, height, outPath)
}

// ShotSub is Shot with a named sub-tab opened inside the tab (1.3).
// Without it a screenshot could only ever show a tab's opening sub-tab,
// which since the sub-tabs went in is a minority of what the window can
// draw — four of the five tabs now hold parts a picture could not
// reach.
//
// An unrecognised sub-tab name draws the tab's first one rather than
// failing: which sub-tabs exist is decided inside each tab's layout at
// draw time, so there is no list to check a name against before the
// first frame (see Frame.selectSubTab).
func ShotSub(tabName, subTab string, isDark bool, width, height int, outPath string) (*image.RGBA, error) {
	if width <= 0 {
		width = DefaultShotWidth
	}
	if height <= 0 {
		height = DefaultShotHeight
	}

	w, err := headless.NewWindow(width, height)
	if err != nil {
		return nil, fmt.Errorf("headless.NewWindow failed: %w", err)
	}
	defer w.Release()

	forceTheme := ThemeLight
	if isDark {
		forceTheme = ThemeDark
	}

	tab := tabForScreen(tabName)

	frame, err := NewFrame(FrameConfig{
		Enrolled:       false, // Show all tabs including "Set up"
		InitialTab:     tab,
		HasAdminRights: false, // Show the masthead's elevation button
		StillFrame:     true,  // A picture is a document, not a moment (1.3)
		ForceTheme:     forceTheme,
		Snap:           exampleSnapshot(),
	})
	if err != nil {
		return nil, fmt.Errorf("NewFrame failed: %w", err)
	}

	frame.SelectTab(tab)
	frame.selectSubTab(subTab)

	img, err := renderFrameOffscreen(frame, width, height)
	if err != nil {
		return nil, err
	}

	if outPath != "" {
		outFile, err := os.Create(outPath)
		if err != nil {
			return nil, fmt.Errorf("failed creating output file %s: %w", outPath, err)
		}
		defer outFile.Close()

		if err := png.Encode(outFile, img); err != nil {
			return nil, fmt.Errorf("failed encoding PNG %s: %w", outPath, err)
		}
	}

	return img, nil
}

// renderFrameOffscreen draws one frame pass into a fresh offscreen buffer
// of the given size and reads the pixels back. It is the single place the
// window meets the GPU headlessly — Shot and the tests all go through it.
func renderFrameOffscreen(f *Frame, width, height int) (*image.RGBA, error) {
	w, err := headless.NewWindow(width, height)
	if err != nil {
		return nil, fmt.Errorf("headless.NewWindow failed: %w", err)
	}
	defer w.Release()

	var ops op.Ops
	gtx := layout.Context{
		Ops:         &ops,
		Constraints: layout.Exact(image.Pt(width, height)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		// A live window lays out with an input source attached; without
		// one gtx.Enabled() is false and every control renders in its
		// disabled style. A bare router is exactly what a real window
		// hands the frame, minus the events.
		Source: new(input.Router).Source(),
	}

	// Pin the pulse to its bright phase: the picture is a document, not
	// a moment.
	f.animStart = time.Now()

	f.Layout(gtx)

	if err := w.Frame(gtx.Ops); err != nil {
		return nil, fmt.Errorf("window.Frame failed: %w", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	if err := w.Screenshot(img); err != nil {
		return nil, fmt.Errorf("window.Screenshot failed: %w", err)
	}
	return img, nil
}

// tabForScreen maps the canonical shot screen name (config.ParseScreen)
// to the tab name of §7.1.
func tabForScreen(screen string) string {
	switch strings.ToLower(screen) {
	case "setup":
		return TabSetUp
	case "client":
		return TabClient
	case "server":
		return TabServer
	case "gateway":
		return TabGateway
	case "session":
		return TabSession
	case "admin":
		return TabAdmin
	case "settings":
		return TabSettings
	default:
		return screen
	}
}

// exampleSnapshot is the fixed reality the shot pictures show: a machine
// named win-srv01 with a specialist alice working on it and recorded, a
// client side with two machines, a small admin ledger. Times are pinned
// so the pictures are byte-comparable across runs of the same build.
func exampleSnapshot() Snapshot {
	until := time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)
	started := time.Date(2026, 9, 12, 16, 41, 0, 0, time.UTC)
	opened := time.Date(2026, 9, 12, 16, 40, 12, 0, time.UTC)
	idle := time.Date(2026, 9, 12, 17, 40, 0, 0, time.UTC)
	hard := time.Date(2026, 9, 13, 0, 40, 0, 0, time.UTC)
	untilEarlier := time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)

	return Snapshot{
		// The Gateway tab as a fresh user will first meet it: a fresh
		// Windows server, the program run from wherever it was copied,
		// nothing installed yet. Both warnings show on purpose -- this
		// is the TALLEST the screen ever gets, so gate 17 measures the
		// case that could actually overflow rather than the tidy one.
		Gateway: GatewayState{
			Supported:    true,
			Platform:     "windows",
			DataDir:      `C:\ProgramData\iamtunnel\gateway`,
			ExePath:      `C:\Users\Admin\Downloads\iamtunnel.exe`,
			ExeReachable: false,
			WantedExeDir: `C:\Program Files\iamtunnel`,
			Elevated:     false,
		},
		Server: ServerState{
			Waiting:     true,
			SshdRunning: true,
			Door: DoorState{
				State:        "open",
				Opened:       opened,
				IdleDeadline: idle,
				HardDeadline: hard,
			},
			Sessions: []Session{
				{Person: "alice", Started: started, Until: until},
			},
		},
		Client: ClientState{
			Configured: true,
			Connected:  false,
			// A REAL, COMPLETE key (21.09.2026). It used to be an
			// abbreviated one with an ellipsis in the middle, which
			// parses as nothing -- so the fingerprint row this screen
			// grew on 21.09.2026 was invisible in every picture of it,
			// and the box was sized against a string production never
			// draws. The private half was thrown away the second it was
			// generated; a public key is public.
			PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMF8QFCWL8KvHHnTYLoCTLj5d99bYam30pxCK+B8+y/c alice@workstation",
			ActiveMachine: "win-srv01",
			ActiveUntil:   until,
			Machines: []MachineAccess{
				{Name: "win-srv01", Online: true, SshdListening: true, Until: until},
				{Name: "backup-db02", Online: false, SshdListening: false, Until: untilEarlier},
			},
		},
		Admin: AdminState{
			// THIS MACHINE HAS JOINED (22.09.2026). Without an identity
			// the fixture drew the "Become an administrator" form on
			// Admin -> People and nothing else, and Client -> Connection
			// could not say what it had saved -- so the pictures showed
			// the state a machine is in for one minute of its life and
			// never the one it is in for the rest.
			ThisMachine: &AdminIdentity{
				Person:  "alice",
				Gateway: "gw.example.net:2022",
				HostKey: "SHA256:QkNrqPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo",
			},
			People: []Person{
				{Name: "alice", Admin: true, Keys: 2, KeyList: []PersonKey{
					{Fingerprint: "SHA256:7vQm0bY2cVxq1kR3JtF9wL8aP4sN6hZ0eU5iO2yT1gC", Added: "2026-09-10T09:12:00Z"},
					{Fingerprint: "SHA256:Hc4pZ8xK2mW7nQ1rT5vB9yL3jF6dS0aE8uG2iO4kN1M", Added: "2026-09-11T14:03:00Z"},
				}},
				{Name: "bob", Keys: 1, KeyList: []PersonKey{
					{Fingerprint: "SHA256:Rb2kY7wQ9mX1nV4pT8zL3cJ6hF0dS5aE2uG7iO9kN4P", Added: "2026-09-12T08:30:00Z"},
				}},
			},
			// IDs and the IAMT-499 facts: one machine whose sshd key
			// changed, so a picture of Manage shows the rekey form.
			Machines: []AdminMachine{
				{ID: "win-srv01", Name: "win-srv01", State: "verified", DoorState: "open", Online: true,
					OSUser: `WIN-SRV01\support`, OSUserStatus: "verified", HostKeyStatus: "match"},
				{ID: "backup-db02", Name: "backup-db02", State: "enrolled",
					OSUser: `BACKUP-DB02\svc`, OSUserStatus: "pending", HostKeyStatus: "mismatch",
					ObservedFingerprint: "SHA256:Wn5tQ2xB8mK1rV7pZ4yL9cJ3hF6dS0aE5uG8iO1kN2R"},
			},
			Grants: []Grant{
				{Person: "alice", Machine: "win-srv01", Until: until},
			},
			// A POLICY THAT HAS BEEN READ (21.09.2026). The fixture
			// carried no RiskMode at all, so every picture of Admin ->
			// Safety showed "Checked by: UNKNOWN · when red: — ·
			// source: unknown" -- the never-fetched state, over this
			// product's whole differentiator, in every screenshot
			// anybody has ever reviewed. The never-fetched state is
			// worth ONE look; what the page says the rest of the time
			// is worth all the others.
			RiskMode: RiskMode{
				Mode:                     "ask",
				Source:                   "gateway",
				Classifier:               "both",
				ClassifierSource:         "gateway",
				ClassifierKey:            true,
				ClassifierKeyFingerprint: "SHA256:8Qk3rPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo",
			},
			// An OPEN pairing window, because the shut one is the state
			// with nothing in it to look at: the whole point of the
			// card since 1.3 is the one line it prints, and a picture
			// that never shows that line cannot show whether it looks
			// right. The values are the shape of a real window, with a
			// fingerprint of the right length — a truncated one would
			// make the box look narrower than it ever is in use.
			Pairing: &PairingWindow{
				Pin:     "812495",
				Ref:     "gw.example.net:2022#SHA256:QkNrqPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo",
				Expires: time.Date(2026, 9, 12, 16, 42, 30, 0, time.UTC),
			},
		},
		// Setup carries the ACCOUNT as well as the name (1.4). Without
		// it the pictures — and gate 17, which measures the same
		// fixture — would size the registration row against a string
		// production never draws: since 1.4 the row is the pair, and
		// the pair is the longer half of it. The account is a domain
		// principal of realistic length for the same reason the
		// pairing fingerprint above is full length.
		Setup: SetupState{
			MachineName: "win-srv01",
			OSUser:      `EXAMPLE\dana`,
			Status:      "enrolled",
			Detail:      "registered — the first entry check has not passed yet",
		},
		Settings: SettingsState{
			Version:         "dev",
			Platform:        "windows/amd64",
			ConfigPath:      `C:\ProgramData\iamtunnel\config.json`,
			DataDir:         `C:\Users\dana\AppData\Local\iamtunnel\server`,
			Port:            2222,
			RetentionDays:   90,
			DiskStopPercent: 85,
		},
	}
}

// CountDistinctColors counts unique RGBA colors present in an image (capped at maxCount).
func CountDistinctColors(img image.Image, maxCount int) int {
	bounds := img.Bounds()
	colors := make(map[uint32]struct{})

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, a := c.RGBA()
			key := (r&0xFF00)<<16 | (g&0xFF00)<<8 | (b & 0xFF00) | (a >> 8)
			colors[key] = struct{}{}
			if len(colors) >= maxCount {
				return len(colors)
			}
		}
	}
	return len(colors)
}
