//go:build windows

// Independent acceptance tests. Each one is shown to be sensitive by
// breaking the product code it guards, observing the test redden, and
// then restoring the product code.
package ui

import (
	"image"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
	"github.com/ultrathinker/iamtunnel/internal/ui/winfonts"
)

// TestLiveThemeSwitchEndToEnd proves that flipping the ThemeSource is
// observable through the real Frame.Layout path (not only via a direct
// CheckThemeSync call). If product code stops calling CheckThemeSync
// inside Layout, the live-switch promise is broken — this test reddens.
//
// Reworked for IAMT-381/382: the per-frame probe is throttled to once a
// second, so a flip is no longer picked up by the very next pass inside
// the same second — that immediate re-ask is exactly what the throttle
// exists to stop (TestIAMT381 pins it). The promise that remains, and
// what this test now states: within one second the OS is asked once,
// the flip is NOT invented early, and once the throttle window has
// elapsed the very next Layout pass picks the flip up on its own.
func TestLiveThemeSwitchEndToEnd(t *testing.T) {
	src := &fakeThemeSource{dark: false}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		ForceTheme:  ThemeAuto,
		ThemeSource: src,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}

	// Drive one Layout pass while Light
	ops1 := &op.Ops{}
	gtx1 := layout.Context{
		Ops:         ops1,
		Constraints: layout.Exact(image.Pt(400, 200)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
	frame.Layout(gtx1)
	if frame.IsDark() {
		t.Fatalf("expected Light after first Layout, got Dark")
	}
	if got := frame.theme.Color(design.PageKey); got != design.LightPalette().Page {
		t.Fatalf("expected Light Page color, got %v", got)
	}

	// Flip source to Dark, drive another pass INSIDE the same second:
	// the throttle must keep the old answer rather than re-ask early.
	src.dark = true
	ops2 := &op.Ops{}
	gtx2 := layout.Context{
		Ops:         ops2,
		Constraints: layout.Exact(image.Pt(400, 200)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
	frame.Layout(gtx2)
	if frame.IsDark() {
		t.Fatalf("expected the throttled pass to keep Light, got Dark — the per-frame probe ran twice inside one second (IAMT-381/382)")
	}

	// Let the once-a-second window elapse (backdating the stamp, the way
	// a real second of wall time would) and drive one more pass: the flip
	// must now arrive through Layout alone.
	frame.lastThemePoll = frame.lastThemePoll.Add(-time.Second)
	ops3 := &op.Ops{}
	gtx3 := layout.Context{
		Ops:         ops3,
		Constraints: layout.Exact(image.Pt(400, 200)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
	frame.Layout(gtx3)
	if !frame.IsDark() {
		t.Fatalf("expected Dark after the throttle window elapsed, got Light — live switching through Layout is broken")
	}
	if got := frame.theme.Color(design.PageKey); got != design.DarkPalette().Page {
		t.Fatalf("expected Dark Page color after live switch, got %v", got)
	}
}

// TestPaletteSwapReplacesTheme proves CheckThemeSync actually replaces
// the underlying Theme object (not merely toggles f.isDark). If product
// code stops doing f.theme = design.NewTheme(pal, f.shaper), the
// current palette stays Light while IsDark reports true — this test
// reddens.
func TestPaletteSwapReplacesTheme(t *testing.T) {
	src := &fakeThemeSource{dark: false}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		ForceTheme:  ThemeAuto,
		ThemeSource: src,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}
	initialTheme := frame.theme

	src.dark = true
	changed := frame.CheckThemeSync()
	if !changed {
		t.Fatalf("expected CheckThemeSync to report true after source flip")
	}
	if frame.theme == initialTheme {
		t.Fatalf("expected Theme to be replaced on swap, but pointer is identical")
	}
	if got := frame.theme.Palette; got.Page != design.DarkPalette().Page {
		t.Fatalf("expected new palette Page = Dark, got %v", got.Page)
	}
	if got := frame.theme.Palette; got.Ink != design.DarkPalette().Ink {
		t.Fatalf("expected new palette Ink = Dark, got %v", got.Ink)
	}
}

// TestRegistryOpenKeyReadOnly scans this package's source for every
// registry.OpenKey invocation and proves every single one passes
// registry.READ. If product code adds a registry.OpenKey(...,
// registry.SET) or registry.ALL_ACCESS anywhere in the reviewed
// packages, this test reddens. It also scans for setenv/unsetenv,
// registry.Set*, SetStringValue, RegSetValueEx and similar write paths.
func TestRegistryOpenKeyReadOnly(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	switch filepath.Base(root) {
	case "ui", "winfonts", "design":
		root = filepath.Dir(filepath.Dir(root))
	}

	forbidden := []string{
		"registry.ALL_ACCESS",
		"registry.WRITE",
		"registry.SetStringValue",
		"registry.SetIntegerValue",
		"registry.SetBinaryValue",
		"registry.CreateKey",
		"registry.DeleteKey",
		"registry.DeleteValue",
		"RegSetValueEx",
		"RegCreateKeyEx",
		"RegDeleteValue",
		"RegDeleteKey",
		"os.Setenv",
		"os.Unsetenv",
		"SPI_SET",
	}

	bad := map[string][]string{}

	scanDir := filepath.Join(root, "internal", "ui")
	walkErr := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "accept_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		for _, f := range forbidden {
			if strings.Contains(src, f) {
				bad[rel] = append(bad[rel], f)
			}
		}
		if strings.Contains(src, "registry.OpenKey") {
			idx := 0
			for {
				j := strings.Index(src[idx:], "registry.OpenKey")
				if j < 0 {
					break
				}
				idx += j
				end := idx + len("registry.OpenKey")
				close := strings.Index(src[end:], ")")
				if close < 0 {
					break
				}
				callText := src[idx : end+close+1]
				if !strings.Contains(callText, "registry.READ") {
					bad[rel] = append(bad[rel], "registry.OpenKey without registry.READ: "+callText)
				}
				idx = end + close + 1
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk failed: %v", walkErr)
	}

	if len(bad) > 0 {
		for p, hits := range bad {
			t.Errorf("file %s contains forbidden registry/system write tokens: %v", p, hits)
		}
		t.FailNow()
	}
}

// TestMissingFontFallbackNeverErrors proves ResolvePreference falls
// back to gofont when the registry has nothing (empty mock). If
// product code starts returning an error instead of stepping down
// to the fallback when no fonts are registered, this test reddens.
func TestMissingFontFallbackNeverErrors(t *testing.T) {
	r := winfonts.NewMockResolver(map[string]string{}, "")

	prefs := []string{
		"SomeFontThatDoesNotExist",
		"AnotherMissingFont",
		"AndOneMore",
	}

	for _, p := range prefs {
		res, err := r.ResolvePreference([]string{p}, "serif")
		if err != nil {
			t.Errorf("ResolvePreference(%q) returned error on missing font: %v", p, err)
		}
		if !res.IsFallback {
			t.Errorf("ResolvePreference(%q) should fall back when font is missing, got non-fallback", p)
		}
		if res.Family != "Go" {
			t.Errorf("ResolvePreference(%q) fallback Family = %q, want Go", p, res.Family)
		}
		if len(res.Faces) == 0 {
			t.Errorf("ResolvePreference(%q) returned no faces in fallback", p)
		}
	}

	res, err := r.ResolvePreference(nil, "serif")
	if err != nil {
		t.Errorf("ResolvePreference(nil) returned error: %v", err)
	}
	if !res.IsFallback {
		t.Errorf("ResolvePreference(nil) should fall back when preference list is empty")
	}
}

// TestTabStripHeightFontMissing builds a frame and proves the tab
// strip height stays invariant across every tab and across both
// notice-visible states. If product code lets the tab strip reflow
// when font loading fails or notice visibility toggles, this test
// reddens.
func TestTabStripHeightFontMissing(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:       false,
		HasAdminRights: false,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}

	tabs := []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings}
	var baseline int

	looseConstraints := layout.Constraints{
		Min: image.Pt(0, 0),
		Max: image.Pt(800, 600),
	}

	for i, name := range tabs {
		frame.SelectTab(name)

		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: looseConstraints,
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		dims := frame.tabs.LayoutStrip(gtx, frame.theme)
		if dims.Size.Y <= 0 {
			t.Fatalf("tab strip height must be non-zero on tab %q, got %d", name, dims.Size.Y)
		}
		if i == 0 {
			baseline = dims.Size.Y
		} else if dims.Size.Y != baseline {
			t.Errorf("tab strip height changed on tab %q: got %d, want %d", name, dims.Size.Y, baseline)
		}
	}

	// The elevation notice is no longer settable after construction: it is
	// shown exactly when HasAdminRights is false (IAMT-66 removed the
	// exported setter, which was itself a way to switch the invariant off).
	// The claim this loop makes is unchanged — the strip height must not
	// depend on whether the notice is there — so it is now made by building
	// a second frame that differs only in that one fact.
	for _, hasRights := range []bool{true, false} {
		other, err := NewFrame(FrameConfig{Enrolled: false, HasAdminRights: hasRights})
		if err != nil {
			t.Fatalf("NewFrame(HasAdminRights=%v) failed: %v", hasRights, err)
		}
		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: looseConstraints,
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		dims := other.tabs.LayoutStrip(gtx, other.theme)
		if dims.Size.Y != baseline {
			t.Errorf("tab strip height changed with hasAdminRights=%v: got %d, want %d", hasRights, dims.Size.Y, baseline)
		}
	}
}

// TestThemeOverrideIsAConstantType proves ThemeAuto / ThemeLight /
// ThemeDark cannot become a way to switch the theme invariant off at a
// distance. The original version of this test asserted the weaker shape
// found in review — a struct with one unexported field, which is
// still a package-level mutable VALUE. IAMT-66 replaced it with a real
// named integer constant type, so the claim is now stated directly: the
// type is a basic kind (nothing to mutate, nothing to forge that is not
// already an ordinary constant), and the three sentinels are distinct.
// If product code turns it back into a struct, a pointer, a map, a slice
// or any other reference kind, this test reddens.
func TestThemeOverrideIsAConstantType(t *testing.T) {
	k := reflect.TypeOf(ThemeAuto).Kind()
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.String:
	default:
		t.Fatalf("ThemeOverride kind = %v; it must be a basic constant kind, otherwise the three sentinels are mutable state", k)
	}
	if ThemeAuto == ThemeLight || ThemeAuto == ThemeDark || ThemeLight == ThemeDark {
		t.Fatalf("theme sentinels must be distinct: auto=%v light=%v dark=%v", ThemeAuto, ThemeLight, ThemeDark)
	}
}

// TestPlatformSplitTags is a build-tag-aware guard for the IAMT-252
// split and its IAMT-262 macOS extension: it runs on the host platform
// and checks the first line of every file whose platform allegiance
// matters. windowsOnly must stay //go:build windows — it is real Windows
// API (the registry theme reader, the registry fonts, the offscreen shot)
// and must never leak onto Linux or macOS. linuxOnly and darwinOnly must
// stay //go:build linux and //go:build darwin — they are that platform's
// API and its own wording of the window's notices (IAMT-262 pulled those
// sentences out of the shared files, where they had said "Windows" on
// every platform). shared must stay //go:build windows || linux ||
// darwin — the frame, screens and design package all three platforms
// compile verbatim. If product code retags any of them (platform API
// joining a build it does not belong to, or a shared file vanishing from
// one), this test reddens.
func TestPlatformSplitTags(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("running on %s, this guard is a windows-host reminder", runtime.GOOS)
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	switch filepath.Base(root) {
	case "ui", "winfonts", "design":
		root = filepath.Dir(filepath.Dir(root))
	}

	windowsOnly := []string{
		"internal/ui/theme_windows.go",
		"internal/ui/fonts_windows.go",
		"internal/ui/shot_windows.go",
		"internal/ui/notice_windows.go",
		"internal/ui/winfonts/loader.go",
		"internal/ui/winfonts/registry.go",
		"internal/ui/winfonts/resolver.go",
	}
	linuxOnly := []string{
		"internal/ui/theme_linux.go",
		"internal/ui/fonts_linux.go",
		"internal/ui/notice_linux.go",
	}
	darwinOnly := []string{
		"internal/ui/theme_darwin.go",
		"internal/ui/fonts_darwin.go",
		"internal/ui/notice_darwin.go",
	}
	shared := []string{
		"internal/ui/state.go",
		"internal/ui/live.go",
		"internal/ui/screens.go",
		"internal/ui/frame.go",
		"internal/ui/gui.go",
		"internal/ui/theme.go",
		"internal/ui/design/tokens.go",
		"internal/ui/design/palette.go",
		"internal/ui/design/pieces.go",
		"internal/ui/design/theme.go",
		"internal/ui/design/textbox.go",
	}
	for _, rel := range windowsOnly {
		if first := firstBuildLine(t, root, rel); first != "//go:build windows" {
			t.Errorf("file %s must stay Windows-only, first line %q", rel, first)
		}
	}
	for _, rel := range darwinOnly {
		if first := firstBuildLine(t, root, rel); first != "//go:build darwin" {
			t.Errorf("file %s must stay macOS-only, first line %q", rel, first)
		}
	}
	for _, rel := range linuxOnly {
		if first := firstBuildLine(t, root, rel); first != "//go:build linux" {
			t.Errorf("file %s must stay Linux-only, first line %q", rel, first)
		}
	}
	for _, rel := range shared {
		if first := firstBuildLine(t, root, rel); first != "//go:build windows || linux || darwin" {
			t.Errorf("file %s must build on all three platforms, first line %q", rel, first)
		}
	}
}

// firstBuildLine reads a source file from the repo root and returns its
// first line — where a Go build constraint must live to be a constraint.
func firstBuildLine(t *testing.T, root, rel string) string {
	t.Helper()
	full := filepath.Join(root, rel)
	b, err := os.ReadFile(full)
	if err != nil {
		t.Errorf("file %s not found: %v", rel, err)
		return ""
	}
	src := string(b)
	if idx := strings.Index(src, "\n"); idx > 0 {
		return strings.TrimSuffix(src[:idx], "\r")
	}
	return src
}
