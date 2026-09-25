package macos

import (
	"errors"
	"reflect"
	"testing"
)

// TestIsDarkFromDefaults covers the answers defaults(1) actually gives.
// The important one is the second: the key's absence is macOS's way of
// saying "Light", and it arrives as a non-zero exit — if that were
// treated as an error, every Mac that has never been switched to Dark
// would fail its theme probe.
func TestIsDarkFromDefaults(t *testing.T) {
	missing := errors.New(`exit status 1 (stderr: The domain/default pair of (kCFPreferencesAnyApplication, AppleInterfaceStyle) does not exist)`)
	cases := []struct {
		name string
		out  string
		err  error
		want bool
	}{
		{"dark", "Dark\n", nil, true},
		{"dark without a newline", "Dark", nil, true},
		{"key absent means light", "", missing, false},
		{"key present but light", "Light\n", nil, false},
		{"empty answer", "", nil, false},
		{"unrecognised answer", "something else\n", nil, false},
		{"probe error", "", errors.New("exec: \"defaults\": executable file not found in $PATH"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDarkFromDefaults([]byte(tc.out), tc.err); got != tc.want {
				t.Errorf("IsDarkFromDefaults(%q, %v) = %v, want %v", tc.out, tc.err, got, tc.want)
			}
		})
	}
}

// TestSystemThemeIsDarkAsksTheGlobalPreference pins the production probe:
// `defaults read -g AppleInterfaceStyle` and nothing else, with the
// answer coming from the seam (so no defaults(1) runs in a test).
func TestSystemThemeIsDarkAsksTheGlobalPreference(t *testing.T) {
	var gotName string
	var gotArgs []string
	install := func(out []byte, err error) {
		orig := outputFn
		outputFn = func(name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, append([]string(nil), args...)
			return out, err
		}
		t.Cleanup(func() { outputFn = orig })
	}

	install([]byte("Dark\n"), nil)
	if !SystemThemeIsDark() {
		t.Errorf("SystemThemeIsDark() = false for a Dark answer")
	}
	if gotName != defaultsPath {
		t.Errorf("probe ran %q, want %s", gotName, defaultsPath)
	}
	if want := []string{"read", "-g", "AppleInterfaceStyle"}; !reflect.DeepEqual(gotArgs, want) {
		t.Errorf("probe args = %v, want %v", gotArgs, want)
	}

	install(nil, errors.New("does not exist"))
	if SystemThemeIsDark() {
		t.Errorf("SystemThemeIsDark() = true for a missing key; the absence of AppleInterfaceStyle is Light")
	}
}

// TestProductionSeamsRefuseTestBinaries is the canary for the two seams:
// if either default stops panicking under testing.Testing(), a test that
// forgets to install a fake would open a real Terminal window or ask a
// real person for an administrator password. The commands used here are
// inert ("true"), so even if the guard is removed this test cannot have a
// side effect — it just goes red.
func TestProductionSeamsRefuseTestBinaries(t *testing.T) {
	cases := map[string]func(){
		"outputFn": func() { _, _ = runOutput("true") },
		"startFn":  func() { _ = runStartDetached("true") },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("%s ran inside a test binary instead of refusing", name)
				}
			}()
			call()
		})
	}
}
